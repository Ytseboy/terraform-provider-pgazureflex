package pgclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// AuthMode controls how the provider authenticates to PostgreSQL.
type AuthMode string

const (
	AuthModePassword              AuthMode = "password"
	AuthModeAzureDefault          AuthMode = "azure_default"
	AuthModeAzureCLI              AuthMode = "azure_cli"
	AuthModeAzureManagedIdentity  AuthMode = "azure_managed_identity"
	AuthModeAzureClientSecret     AuthMode = "azure_client_secret"
	AuthModeAzureWorkloadIdentity AuthMode = "azure_workload_identity"
	AuthModeAccessToken           AuthMode = "access_token"
)

// AzureCloud identifies the Azure sovereign cloud for Entra ID authentication.
type AzureCloud string

const (
	AzureCloudPublic       AzureCloud = "public"
	AzureCloudUSGovernment AzureCloud = "usgovernment"
	AzureCloudChina        AzureCloud = "china"
)

const (
	// DefaultAzureOSSScope is the OAuth2 scope for Azure Database for PostgreSQL (Public cloud).
	DefaultAzureOSSScope = "https://ossrdbms-aad.database.windows.net/.default"
	// USGovAzureOSSScope is the OAuth2 scope for Azure US Government.
	USGovAzureOSSScope = "https://ossrdbms-aad.database.usgovcloudapi.net/.default"
	// ChinaAzureOSSScope is the OAuth2 scope for Azure China (21Vianet).
	ChinaAzureOSSScope = "https://ossrdbms-aad.database.chinacloudapi.cn/.default"
)

// Config defines all connection, authentication, TLS, and Azure Flexible Server options.
type Config struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string

	AuthMode AuthMode

	// Azure Entra ID authentication settings.
	AzureTenantID      string
	AzureClientID      string
	AzureClientSecret  string
	AzureAccessToken   string
	AzureTokenScope    string
	AzureCloud         AzureCloud
	AzureAuthorityHost string             // Optional override (e.g. custom/sovereign Entra authority or mock server in tests)
	AzureTransport     policy.Transporter // Optional custom HTTP transporter for Azure SDK calls (useful in tests/proxies)

	// TLS / SSL configuration.
	SSLMode     string
	SSLRootCert string
	SSLCert     string
	SSLKey      string

	// Connection pool & timeout tuning.
	ConnectTimeout time.Duration
	MaxConnections int32

	// Azure Flexible Server behavior tuning.
	// Nil means auto-detect from server host/capabilities.
	AzureFlexibleServer     *bool
	Superuser               *bool
	AutoGrantRoleMembership bool
	ExpectedVersion         string
}

// ApplyDefaults populates omitted fields with Azure-safe defaults.
func (c *Config) ApplyDefaults() {
	if c.Port == 0 {
		c.Port = 5432
	}
	if c.Database == "" {
		c.Database = "postgres"
	}
	if c.AuthMode == "" {
		c.AuthMode = AuthModePassword
	}
	if c.AzureCloud == "" {
		c.AzureCloud = AzureCloudPublic
	}
	if c.AzureTokenScope == "" {
		switch c.AzureCloud {
		case AzureCloudUSGovernment:
			c.AzureTokenScope = USGovAzureOSSScope
		case AzureCloudChina:
			c.AzureTokenScope = ChinaAzureOSSScope
		default:
			c.AzureTokenScope = DefaultAzureOSSScope
		}
	}
	if c.SSLMode == "" {
		// Azure Database for PostgreSQL Flexible Server enforces TLS by default.
		c.SSLMode = "require"
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 4
	}
}

// Validate checks configuration consistency before attempting to connect.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}
	if strings.TrimSpace(c.Username) == "" {
		return fmt.Errorf("username is required")
	}

	switch c.AuthMode {
	case AuthModePassword,
		AuthModeAzureDefault,
		AuthModeAzureCLI,
		AuthModeAzureManagedIdentity,
		AuthModeAzureWorkloadIdentity:
		// valid
	case AuthModeAzureClientSecret:
		if c.AzureTenantID == "" || c.AzureClientID == "" || c.AzureClientSecret == "" {
			return fmt.Errorf("auth_mode %q requires azure_tenant_id, azure_client_id, and azure_client_secret", c.AuthMode)
		}
	case AuthModeAccessToken:
		if c.AzureAccessToken == "" {
			return fmt.Errorf("auth_mode %q requires azure_access_token", c.AuthMode)
		}
	default:
		return fmt.Errorf("unsupported auth_mode %q", c.AuthMode)
	}

	switch c.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		// valid
	default:
		return fmt.Errorf("unsupported sslmode %q", c.SSLMode)
	}

	switch c.AzureCloud {
	case AzureCloudPublic, AzureCloudUSGovernment, AzureCloudChina:
		// valid
	default:
		return fmt.Errorf("unsupported azure_cloud %q", c.AzureCloud)
	}

	return nil
}

// IsAzureHostname returns true if the configured host matches an Azure PostgreSQL endpoint.
func (c *Config) IsAzureHostname() bool {
	h := strings.ToLower(strings.TrimSpace(c.Host))
	return strings.HasSuffix(h, ".postgres.database.azure.com") ||
		strings.HasSuffix(h, ".postgres.database.usgovcloudapi.net") ||
		strings.HasSuffix(h, ".postgres.database.chinacloudapi.cn")
}

// BuildTLSConfig constructs a *tls.Config according to SSLMode and optional certificate inputs.
// Returns nil when SSLMode is "disable".
func (c *Config) BuildTLSConfig() (*tls.Config, error) {
	if c.SSLMode == "disable" {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	switch c.SSLMode {
	case "allow", "prefer", "require":
		// PostgreSQL libpq semantics: encrypt transport without hostname/CA verification
		// unless verify-ca or verify-full is requested.
		tlsCfg.InsecureSkipVerify = true
	case "verify-ca":
		// Verify certificate chain against RootCAs, but skip hostname match.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         tlsCfg.RootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	case "verify-full":
		tlsCfg.InsecureSkipVerify = false
		tlsCfg.ServerName = c.Host
	}

	if c.SSLRootCert != "" {
		pemBytes, err := loadPEMOrFile(c.SSLRootCert)
		if err != nil {
			return nil, fmt.Errorf("failed to load ssl_root_cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("failed to parse PEM certificates from ssl_root_cert")
		}
		tlsCfg.RootCAs = pool
	}

	if c.SSLCert != "" || c.SSLKey != "" {
		if c.SSLCert == "" || c.SSLKey == "" {
			return nil, fmt.Errorf("both ssl_cert and ssl_key must be provided together")
		}
		certPEM, err := loadPEMOrFile(c.SSLCert)
		if err != nil {
			return nil, fmt.Errorf("failed to load ssl_cert: %w", err)
		}
		keyPEM, err := loadPEMOrFile(c.SSLKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load ssl_key: %w", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client TLS keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return tlsCfg, nil
}

func loadPEMOrFile(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if strings.Contains(trimmed, "-----BEGIN ") {
		return []byte(trimmed), nil
	}
	return os.ReadFile(trimmed)
}
