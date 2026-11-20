package pgclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EntraPrincipal represents a Microsoft Entra ID principal registered in Azure Flexible Server
// via the pgaadauth extension.
type EntraPrincipal struct {
	RoleName      string
	PrincipalType string // "user", "group", or "service"
	ObjectID      string
	IsAdmin       bool
	IsMFA         bool
}

// WithRoleMembership executes fn while ensuring the connecting user holds membership in targetRole.
func (c *Client) WithRoleMembership(ctx context.Context, database, targetRole string, fn func(pool *pgxpool.Pool) error) error {
	if targetRole == "" {
		pool, err := c.Pool(ctx, database)
		if err != nil {
			return err
		}
		return fn(pool)
	}
	return c.WithRoleMemberships(ctx, database, []string{targetRole}, fn)
}

// WithRoleMemberships executes fn while ensuring the connecting user holds SET + INHERIT
// membership in every non-empty role listed in targetRoles.
//
// Acquires `roleMu` once across all roles (preventing re-entrant mutex deadlocks when an
// operation needs two roles simultaneously, such as `ALTER DATABASE ... OWNER TO` from an
// existing owner to a new owner, or `REASSIGN OWNED BY old TO new`).
//
// On PostgreSQL 16+, preserves any pre-existing `ADMIN OPTION` row by revoking only the
// temporary `SET` / `INHERIT` options added during the call.
func (c *Client) WithRoleMemberships(ctx context.Context, database string, targetRoles []string, fn func(pool *pgxpool.Pool) error) error {
	pool, err := c.Pool(ctx, database)
	if err != nil {
		return err
	}

	if !c.cfg.AutoGrantRoleMembership {
		return fn(pool)
	}

	caps, err := c.Capabilities(ctx)
	if err != nil {
		return err
	}

	if caps.IsSuperuser {
		return fn(pool)
	}

	// Deduplicate roles and filter out empty / current user.
	seen := make(map[string]bool, len(targetRoles))
	var roles []string
	for _, r := range targetRoles {
		r = strings.TrimSpace(r)
		if r == "" || strings.EqualFold(r, caps.CurrentUser) || seen[strings.ToLower(r)] {
			continue
		}
		seen[strings.ToLower(r)] = true
		roles = append(roles, r)
	}
	if len(roles) == 0 {
		return fn(pool)
	}

	// Serialize role membership toggles to avoid races across parallel Terraform workers.
	c.roleMu.Lock()
	defer c.roleMu.Unlock()

	type grantRecord struct {
		role         string
		hasDirectRow bool
		hasSetOption bool
		hasInherit   bool
	}
	var granted []grantRecord

	for _, targetRole := range roles {
		var (
			hasDirectRow bool
			hasSetOption bool
			hasInherit   bool
		)

		if caps.VersionNum >= 160000 {
			err = pool.QueryRow(ctx, `
				SELECT
					COUNT(*) > 0,
					COALESCE(bool_or(m.set_option), false),
					COALESCE(bool_or(m.inherit_option), false)
				FROM pg_auth_members m
				JOIN pg_roles r ON r.oid = m.roleid
				JOIN pg_roles mem ON mem.oid = m.member
				WHERE r.rolname = $1 AND mem.rolname = $2
			`, targetRole, caps.CurrentUser).Scan(&hasDirectRow, &hasSetOption, &hasInherit)
		} else {
			err = pool.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1
					FROM pg_auth_members m
					JOIN pg_roles r ON r.oid = m.roleid
					JOIN pg_roles mem ON mem.oid = m.member
					WHERE r.rolname = $1 AND mem.rolname = $2
				)
			`, targetRole, caps.CurrentUser).Scan(&hasDirectRow)
			hasSetOption = hasDirectRow
			hasInherit = hasDirectRow
		}
		if err != nil {
			// Best-effort cleanup of anything already granted before returning.
			for i := len(granted) - 1; i >= 0; i-- {
				revokeTempRole(pool, caps, granted[i].role, granted[i].hasDirectRow, granted[i].hasSetOption, granted[i].hasInherit)
			}
			return fmt.Errorf("failed to check membership of %q in %q: %w", caps.CurrentUser, targetRole, err)
		}

		if !hasSetOption || !hasInherit {
			grantSQL := fmt.Sprintf("GRANT %s TO %s", QuoteIdent(targetRole), QuoteIdent(caps.CurrentUser))
			if caps.VersionNum >= 160000 {
				grantSQL = fmt.Sprintf("GRANT %s TO %s WITH SET TRUE, INHERIT TRUE", QuoteIdent(targetRole), QuoteIdent(caps.CurrentUser))
			}
			if grantErr := RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, grantSQL)
				return execErr
			}); grantErr == nil {
				granted = append(granted, grantRecord{
					role:         targetRole,
					hasDirectRow: hasDirectRow,
					hasSetOption: hasSetOption,
					hasInherit:   hasInherit,
				})
			}
		}
	}

	defer func() {
		for i := len(granted) - 1; i >= 0; i-- {
			g := granted[i]
			revokeTempRole(pool, caps, g.role, g.hasDirectRow, g.hasSetOption, g.hasInherit)
		}
	}()

	return fn(pool)
}

func revokeTempRole(pool *pgxpool.Pool, caps ServerCapabilities, targetRole string, hasDirectRow, hasSetOption, hasInherit bool) {
	if caps.VersionNum >= 160000 && hasDirectRow {
		if !hasSetOption {
			_ = RetryTransient(context.Background(), func() error {
				_, execErr := pool.Exec(context.Background(), fmt.Sprintf("REVOKE SET OPTION FOR %s FROM %s", QuoteIdent(targetRole), QuoteIdent(caps.CurrentUser)))
				return execErr
			})
		}
		if !hasInherit {
			_ = RetryTransient(context.Background(), func() error {
				_, execErr := pool.Exec(context.Background(), fmt.Sprintf("REVOKE INHERIT OPTION FOR %s FROM %s", QuoteIdent(targetRole), QuoteIdent(caps.CurrentUser)))
				return execErr
			})
		}
		return
	}
	revokeSQL := fmt.Sprintf("REVOKE %s FROM %s", QuoteIdent(targetRole), QuoteIdent(caps.CurrentUser))
	_ = RetryTransient(context.Background(), func() error {
		_, execErr := pool.Exec(context.Background(), revokeSQL)
		return execErr
	})
}

// WithDatabaseOwnerMembership looks up the owner of `database` and runs fn inside
// WithRoleMembership for that owner, allowing non-superuser `azure_pg_admin` callers
// to manage extensions, grants, schemas, and publications inside databases owned by
// dedicated application owner roles.
func (c *Client) WithDatabaseOwnerMembership(ctx context.Context, database string, fn func(pool *pgxpool.Pool) error) error {
	pool, err := c.Pool(ctx, database)
	if err != nil {
		return err
	}

	var dbOwner string
	if err := pool.QueryRow(ctx, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1`, database).Scan(&dbOwner); err != nil {
		return fn(pool)
	}
	return c.WithRoleMembership(ctx, database, dbOwner, fn)
}

// DiagnoseAzureExtensionError enriches extension creation failures on Azure Flexible Server
// with actionable remediation guidance referencing `azure.extensions` and `shared_preload_libraries`.
func (c *Client) DiagnoseAzureExtensionError(ctx context.Context, extName string, err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	isAllowlistErr := strings.Contains(msg, "not allow-listed") ||
		strings.Contains(msg, "not allowlisted") ||
		strings.Contains(msg, "azure.extensions") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "shared_preload_libraries")

	if !isAllowlistErr {
		return err
	}

	caps, capErr := c.RefreshCapabilities(ctx)
	if capErr != nil {
		return fmt.Errorf("%w (Azure Flexible Server hint: ensure %q is added to the server parameter 'azure.extensions' and, if required, 'shared_preload_libraries')", err, extName)
	}

	return fmt.Errorf(
		"%w\n\nAzure Flexible Server remediation:\n"+
			"  1. Add %q to the `azure.extensions` server parameter (e.g., via `azurerm_postgresql_flexible_server_configuration`).\n"+
			"  2. If the extension requires preloading (e.g. pg_stat_statements, pg_cron, timescaledb, pgaudit, anon), also add it to `shared_preload_libraries` and restart the server.\n"+
			"  Current azure.extensions: [%s]\n"+
			"  Current shared_preload_libraries: [%s]",
		err,
		extName,
		strings.Join(caps.AllowedExtensions, ", "),
		strings.Join(caps.SharedPreloadLibraries, ", "),
	)
}

// ListEntraPrincipals queries Azure Flexible Server's pgaadauth_list_principals(false) function.
func (c *Client) ListEntraPrincipals(ctx context.Context) ([]EntraPrincipal, error) {
	caps, err := c.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasPGAADAuth {
		return nil, fmt.Errorf("pgaadauth functions are not available on this PostgreSQL server; ensure Microsoft Entra ID authentication is enabled on your Azure Flexible Server")
	}

	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return nil, err
	}

	// pgaadauth_list_principals(isAdminOnly bool) returns:
	//   rolname text, principalType text, objectId text, isAdmin bool, isMfa bool
	rows, err := pool.Query(ctx, `SELECT rolname, principalType, objectId, isAdmin, isMfa FROM pgaadauth_list_principals(false)`)
	if err != nil {
		return nil, fmt.Errorf("failed to list Microsoft Entra ID principals via pgaadauth_list_principals: %w", err)
	}
	defer rows.Close()

	var principals []EntraPrincipal
	for rows.Next() {
		var p EntraPrincipal
		if err := rows.Scan(&p.RoleName, &p.PrincipalType, &p.ObjectID, &p.IsAdmin, &p.IsMFA); err != nil {
			return nil, fmt.Errorf("failed to scan Entra ID principal row: %w", err)
		}
		p.PrincipalType = strings.ToLower(strings.TrimSpace(p.PrincipalType))
		principals = append(principals, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return principals, nil
}

// GetEntraPrincipal looks up a single Microsoft Entra ID principal by PostgreSQL role name.
func (c *Client) GetEntraPrincipal(ctx context.Context, roleName string) (*EntraPrincipal, error) {
	list, err := c.ListEntraPrincipals(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].RoleName == roleName {
			return &list[i], nil
		}
	}
	return nil, nil
}

// CreateEntraPrincipal creates a Microsoft Entra ID role in Azure Flexible Server.
// When objectID is provided, it uses pgaadauth_create_principal_with_oid (recommended for IaC
// and private VNet servers because it requires no outbound Graph API call).
func (c *Client) CreateEntraPrincipal(ctx context.Context, roleName, objectID, principalType string, isAdmin, isMFA bool) error {
	caps, err := c.Capabilities(ctx)
	if err != nil {
		return err
	}
	if !caps.HasPGAADAuth {
		return fmt.Errorf("pgaadauth functions are not available on this PostgreSQL server; enable Microsoft Entra ID authentication on the Azure Flexible Server first")
	}

	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return err
	}

	return RetryTransient(ctx, func() error {
		if strings.TrimSpace(objectID) != "" {
			var res string
			return pool.QueryRow(
				ctx,
				`SELECT pgaadauth_create_principal_with_oid($1, $2, $3, $4, $5)`,
				roleName, objectID, strings.ToLower(principalType), isAdmin, isMFA,
			).Scan(&res)
		}
		var res string
		return pool.QueryRow(
			ctx,
			`SELECT pgaadauth_create_principal($1, $2, $3)`,
			roleName, isAdmin, isMFA,
		).Scan(&res)
	})
}

// DropRoleWithCleanup safely drops a role, optionally reassigning and/or dropping owned objects
// across the specified database (or default database).
func (c *Client) DropRoleWithCleanup(ctx context.Context, roleName string, reassignTo string, dropOwned bool) error {
	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return err
	}

	if reassignTo != "" {
		err = c.WithRoleMemberships(ctx, c.cfg.Database, []string{roleName, reassignTo}, func(p *pgxpool.Pool) error {
			sql := fmt.Sprintf("REASSIGN OWNED BY %s TO %s", QuoteIdent(roleName), QuoteIdent(reassignTo))
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
		if err != nil {
			return fmt.Errorf("failed to REASSIGN OWNED BY %q TO %q: %w", roleName, reassignTo, err)
		}
	}

	if dropOwned {
		err = c.WithRoleMembership(ctx, c.cfg.Database, roleName, func(p *pgxpool.Pool) error {
			sql := fmt.Sprintf("DROP OWNED BY %s", QuoteIdent(roleName))
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
		if err != nil {
			return fmt.Errorf("failed to DROP OWNED BY %q: %w", roleName, err)
		}
	}

	return RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", QuoteIdent(roleName)))
		return execErr
	})
}

// EntraSecurityLabel represents a parsed Azure Flexible Server `pgaadauth` PostgreSQL security label:
// `aadauth,oid=<uuid>,type=<user|group|service>[,admin][,mfa]`.
type EntraSecurityLabel struct {
	ObjectID      string
	PrincipalType string // "user", "group", or "service"
	IsAdmin       bool
	IsMFA         bool
}

// FormatPGAADAuthSecurityLabel formats a canonical Azure Flexible Server `pgaadauth` security label string.
func FormatPGAADAuthSecurityLabel(objectID, principalType string, isAdmin, isMFA bool) (string, error) {
	oid := strings.TrimSpace(objectID)
	if oid == "" {
		return "", fmt.Errorf("object_id is required for pgaadauth security label")
	}
	ptype := strings.ToLower(strings.TrimSpace(principalType))
	switch ptype {
	case "user", "group", "service":
		// valid
	default:
		return "", fmt.Errorf("invalid principal_type %q: must be one of user, group, service", principalType)
	}

	parts := []string{
		"aadauth",
		"oid=" + oid,
		"type=" + ptype,
	}
	if isAdmin {
		parts = append(parts, "admin")
	}
	if isMFA {
		parts = append(parts, "mfa")
	}
	return strings.Join(parts, ","), nil
}

// ParsePGAADAuthSecurityLabel parses an Azure Flexible Server `pgaadauth` security label from pg_shseclabel.
func ParsePGAADAuthSecurityLabel(raw string) (*EntraSecurityLabel, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty pgaadauth security label")
	}

	parts := strings.Split(trimmed, ",")
	if len(parts) == 0 || !strings.EqualFold(strings.TrimSpace(parts[0]), "aadauth") {
		return nil, fmt.Errorf("unexpected pgaadauth security label %q: must start with 'aadauth'", raw)
	}

	out := &EntraSecurityLabel{}
	for _, token := range parts[1:] {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "oid="):
			out.ObjectID = strings.TrimSpace(t[4:])
		case strings.HasPrefix(lower, "type="):
			out.PrincipalType = strings.ToLower(strings.TrimSpace(t[5:]))
		case lower == "admin":
			out.IsAdmin = true
		case lower == "mfa":
			out.IsMFA = true
		}
	}

	if out.ObjectID == "" {
		return nil, fmt.Errorf("pgaadauth security label %q is missing oid=<uuid>", raw)
	}
	if out.PrincipalType == "" {
		return nil, fmt.Errorf("pgaadauth security label %q is missing type=<user|group|service>", raw)
	}
	return out, nil
}

// SetEntraSecurityLabel binds or updates a Microsoft Entra ID identity mapping on an existing
// PostgreSQL role via `SECURITY LABEL FOR "pgaadauth" ON ROLE ... IS '...'`.
func (c *Client) SetEntraSecurityLabel(ctx context.Context, roleName, objectID, principalType string, isAdmin, isMFA bool) (string, error) {
	label, err := FormatPGAADAuthSecurityLabel(objectID, principalType, isAdmin, isMFA)
	if err != nil {
		return "", err
	}

	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return "", err
	}

	sql := fmt.Sprintf(`SECURITY LABEL FOR "pgaadauth" ON ROLE %s IS %s`, QuoteIdent(roleName), QuoteLiteral(label))
	if err := RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	}); err != nil {
		return "", fmt.Errorf("failed to set pgaadauth security label on role %q (ensure Microsoft Entra ID auth / pgaadauth is enabled on Azure Flexible Server): %w", roleName, err)
	}
	return label, nil
}

// ClearEntraSecurityLabel removes the Microsoft Entra ID security label from a PostgreSQL role
// without dropping the role or its owned objects.
func (c *Client) ClearEntraSecurityLabel(ctx context.Context, roleName string) error {
	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return err
	}

	sql := fmt.Sprintf(`SECURITY LABEL FOR "pgaadauth" ON ROLE %s IS NULL`, QuoteIdent(roleName))
	if err := RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	}); err != nil {
		if IsUndefinedObject(err) {
			return nil
		}
		return fmt.Errorf("failed to clear pgaadauth security label on role %q: %w", roleName, err)
	}
	return nil
}

// GetEntraSecurityLabel reads the active `pgaadauth` security label mapping for a role from `pg_shseclabel`
// (falling back to `pgaadauth_list_principals` if available). Returns (nil, "", nil) if unmapped.
func (c *Client) GetEntraSecurityLabel(ctx context.Context, roleName string) (*EntraSecurityLabel, string, error) {
	pool, err := c.Pool(ctx, c.cfg.Database)
	if err != nil {
		return nil, "", err
	}

	var rawLabel string
	err = pool.QueryRow(ctx, `
		SELECT s.label
		FROM pg_shseclabel s
		JOIN pg_roles r ON r.oid = s.objoid
		WHERE s.classoid = 'pg_authid'::regclass
		  AND s.provider = 'pgaadauth'
		  AND r.rolname = $1
	`, roleName).Scan(&rawLabel)
	if err == nil && rawLabel != "" {
		parsed, parseErr := ParsePGAADAuthSecurityLabel(rawLabel)
		if parseErr != nil {
			return nil, rawLabel, parseErr
		}
		return parsed, rawLabel, nil
	}

	// Fall back to pgaadauth_list_principals(false) if present on the server.
	caps, capErr := c.Capabilities(ctx)
	if capErr == nil && caps.HasPGAADAuth {
		p, listErr := c.GetEntraPrincipal(ctx, roleName)
		if listErr != nil {
			return nil, "", listErr
		}
		if p != nil {
			lbl, _ := FormatPGAADAuthSecurityLabel(p.ObjectID, p.PrincipalType, p.IsAdmin, p.IsMFA)
			return &EntraSecurityLabel{
				ObjectID:      p.ObjectID,
				PrincipalType: p.PrincipalType,
				IsAdmin:       p.IsAdmin,
				IsMFA:         p.IsMFA,
			}, lbl, nil
		}
	}

	return nil, "", nil
}
