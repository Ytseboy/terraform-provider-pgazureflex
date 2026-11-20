package pgclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServerCapabilities describes the PostgreSQL instance and Azure Flexible Server features discovered at connect time.
type ServerCapabilities struct {
	VersionNum             int
	VersionString          string
	CurrentUser            string
	IsSuperuser            bool
	IsAzurePGAdmin         bool
	IsAzureFlexibleServer  bool
	HasPGAADAuth           bool
	AllowedExtensions      []string
	SharedPreloadLibraries []string
	SSLInUse               bool
	SSLVersion             string
	SSLCipher              string
}

// Client manages per-database connection pools and Azure Flexible Server helpers.
type Client struct {
	cfg      Config
	tlsCfg   *tls.Config
	pw       PasswordProvider
	capsOnce sync.Once
	caps     ServerCapabilities
	capsErr  error

	mu    sync.Mutex
	pools map[string]*pgxpool.Pool

	// roleMu serializes temporary role membership mutations so concurrent resources
	// don't race while granting/revoking membership for azure_pg_admin ownership ops.
	roleMu sync.Mutex
}

// NewClient validates cfg, initializes authentication and TLS, and returns a ready Client.
func NewClient(cfg Config) (*Client, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		return nil, err
	}

	pw, err := NewPasswordProvider(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:    cfg,
		tlsCfg: tlsCfg,
		pw:     pw,
		pools:  make(map[string]*pgxpool.Pool),
	}, nil
}

// Config returns a copy of the resolved Client configuration.
func (c *Client) Config() Config {
	return c.cfg
}

// Pool returns (creating lazily if needed) a connection pool for the specified database.
// Passing an empty string connects to the provider's configured default database.
func (c *Client) Pool(ctx context.Context, database string) (*pgxpool.Pool, error) {
	if database == "" {
		database = c.cfg.Database
	}

	c.mu.Lock()
	if p, ok := c.pools[database]; ok {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	poolCfg, err := c.buildPoolConfig(database)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool for database %q: %w", database, err)
	}

	// Verify connectivity immediately so misconfigurations fail fast with clear context.
	pingCtx, cancel := context.WithTimeout(ctx, c.cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to PostgreSQL %s:%d/%s as %q (auth_mode=%s, sslmode=%s): %w",
			c.cfg.Host, c.cfg.Port, database, c.cfg.Username, c.cfg.AuthMode, c.cfg.SSLMode, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.pools[database]; ok {
		// Another goroutine raced and won; close ours and return existing.
		pool.Close()
		return existing, nil
	}
	c.pools[database] = pool
	return pool, nil
}

func (c *Client) buildPoolConfig(database string) (*pgxpool.Config, error) {
	poolCfg, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}

	poolCfg.ConnConfig.Host = c.cfg.Host
	poolCfg.ConnConfig.Port = uint16(c.cfg.Port)
	poolCfg.ConnConfig.Database = database
	poolCfg.ConnConfig.User = c.cfg.Username
	poolCfg.ConnConfig.ConnectTimeout = c.cfg.ConnectTimeout
	poolCfg.ConnConfig.TLSConfig = c.tlsCfg
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "terraform-provider-pgazureflex"

	// Inject password or refreshed Entra ID bearer token before each physical connection.
	poolCfg.BeforeConnect = func(ctx context.Context, connCfg *pgx.ConnConfig) error {
		secret, err := c.pw.GetPassword(ctx)
		if err != nil {
			return err
		}
		connCfg.Password = secret
		return nil
	}

	poolCfg.MaxConns = c.cfg.MaxConnections
	poolCfg.MinConns = 0
	poolCfg.MaxConnIdleTime = 2 * time.Minute
	poolCfg.MaxConnLifetime = 20 * time.Minute

	return poolCfg, nil
}

// CloseDatabasePool closes and removes any cached pool targeting the specified database.
// Useful before DROP DATABASE so the provider itself does not hold an open session.
func (c *Client) CloseDatabasePool(database string) {
	if database == "" {
		return
	}
	c.mu.Lock()
	pool, ok := c.pools[database]
	if ok {
		delete(c.pools, database)
	}
	c.mu.Unlock()

	if ok && pool != nil {
		pool.Close()
	}
}

// Close closes all open database pools.
func (c *Client) Close() {
	c.mu.Lock()
	pools := c.pools
	c.pools = make(map[string]*pgxpool.Pool)
	c.mu.Unlock()

	for _, p := range pools {
		if p != nil {
			p.Close()
		}
	}
}

// Capabilities queries and caches server version, privilege level, and Azure Flexible Server metadata.
func (c *Client) Capabilities(ctx context.Context) (ServerCapabilities, error) {
	c.capsOnce.Do(func() {
		c.caps, c.capsErr = c.discoverCapabilities(ctx)
	})
	return c.caps, c.capsErr
}

// RefreshCapabilities re-queries server capabilities without relying on cache (used by data sources).
func (c *Client) RefreshCapabilities(ctx context.Context) (ServerCapabilities, error) {
	return c.discoverCapabilities(ctx)
}

func (c *Client) discoverCapabilities(ctx context.Context) (ServerCapabilities, error) {
	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return ServerCapabilities{}, err
	}

	var caps ServerCapabilities

	var versionNumStr string
	err = pool.QueryRow(ctx, `
		SELECT
			current_setting('server_version_num'),
			version(),
			current_user,
			(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
	`).Scan(&versionNumStr, &caps.VersionString, &caps.CurrentUser, &caps.IsSuperuser)
	if err != nil {
		return ServerCapabilities{}, fmt.Errorf("failed to inspect PostgreSQL server capabilities: %w", err)
	}

	if v, convErr := strconv.Atoi(versionNumStr); convErr == nil {
		caps.VersionNum = v
	}

	if c.cfg.Superuser != nil {
		caps.IsSuperuser = *c.cfg.Superuser
	}

	// Detect azure_pg_admin membership (standard admin role on Azure Flexible Server).
	_ = pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin')
		   AND pg_has_role(current_user, 'azure_pg_admin', 'MEMBER')
	`).Scan(&caps.IsAzurePGAdmin)

	// Detect pgaadauth (Azure Flexible Server Microsoft Entra ID integration).
	_ = pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_proc WHERE proname = 'pgaadauth_create_principal_with_oid'
		)
	`).Scan(&caps.HasPGAADAuth)

	// Read azure.extensions allowlist if present.
	var azureExtSetting string
	hasAzureExtGUC := false
	if err := pool.QueryRow(ctx, `SELECT current_setting('azure.extensions', true)`).Scan(&azureExtSetting); err == nil {
		// Also check pg_settings so empty string still counts as existing GUC.
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'azure.extensions')`).Scan(&hasAzureExtGUC)
		caps.AllowedExtensions = ParseCSVSetting(azureExtSetting)
	}

	var preloadSetting string
	if err := pool.QueryRow(ctx, `SELECT current_setting('shared_preload_libraries', true)`).Scan(&preloadSetting); err == nil {
		caps.SharedPreloadLibraries = ParseCSVSetting(preloadSetting)
	}

	// Read TLS status for the current backend connection.
	var sslVer, sslCipher *string
	_ = pool.QueryRow(ctx, `
		SELECT COALESCE(ssl, false), version, cipher
		FROM pg_stat_ssl
		WHERE pid = pg_backend_pid()
	`).Scan(&caps.SSLInUse, &sslVer, &sslCipher)
	if sslVer != nil {
		caps.SSLVersion = *sslVer
	}
	if sslCipher != nil {
		caps.SSLCipher = *sslCipher
	}

	if c.cfg.AzureFlexibleServer != nil {
		caps.IsAzureFlexibleServer = *c.cfg.AzureFlexibleServer
	} else {
		caps.IsAzureFlexibleServer = c.cfg.IsAzureHostname() || caps.IsAzurePGAdmin || caps.HasPGAADAuth || hasAzureExtGUC
	}

	return caps, nil
}

// RetryTransient executes fn with short exponential backoff on retryable PostgreSQL SQLSTATE errors
// (such as concurrent DDL tuple update conflicts XX000/40001/40P01/55006).
func RetryTransient(ctx context.Context, fn func() error) error {
	const maxAttempts = 5
	backoff := 100 * time.Millisecond

	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !isRetryablePgError(err) || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return err
}

func isRetryablePgError(err error) bool {
	if err == nil {
		return false
	}
	code := PgErrorCode(err)
	switch code {
	case "40001", // serialization_failure
		"40P01", // deadlock_detected
		"55006": // object_in_use
		return true
	}
	// PostgreSQL raises "tuple concurrently updated" with SQLSTATE XX000 when concurrent
	// Terraform resources run GRANT/REVOKE or ALTER DEFAULT PRIVILEGES in parallel.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "tuple concurrently updated") || strings.Contains(msg, "tuple concurrently deleted") {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}
