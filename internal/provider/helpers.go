package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func configureClientFromProviderData(providerData any, diags *diag.Diagnostics) *pgclient.Client {
	if providerData == nil {
		return nil
	}
	client, ok := providerData.(*pgclient.Client)
	if !ok {
		diags.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected *pgclient.Client, got: %T. Please report this issue to the provider developers.", providerData),
		)
		return nil
	}
	return client
}

func setToStringSlice(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(s.ElementsAs(ctx, &out, false)...)
	sort.Strings(out)
	return out
}

func mapToStringMap(ctx context.Context, m types.Map, diags *diag.Diagnostics) map[string]string {
	if m.IsNull() || m.IsUnknown() {
		return nil
	}
	out := make(map[string]string)
	diags.Append(m.ElementsAs(ctx, &out, false)...)
	return out
}

func stringSliceToSet(ctx context.Context, vals []string, diags *diag.Diagnostics) types.Set {
	if vals == nil {
		vals = []string{}
	}
	sort.Strings(vals)
	s, d := types.SetValueFrom(ctx, types.StringType, vals)
	diags.Append(d...)
	return s
}

func stringSliceToList(ctx context.Context, vals []string, diags *diag.Diagnostics) types.List {
	if vals == nil {
		vals = []string{}
	}
	l, d := types.ListValueFrom(ctx, types.StringType, vals)
	diags.Append(d...)
	return l
}

func stringMapToTFMap(ctx context.Context, vals map[string]string, diags *diag.Diagnostics) types.Map {
	if vals == nil {
		vals = map[string]string{}
	}
	m, d := types.MapValueFrom(ctx, types.StringType, vals)
	diags.Append(d...)
	return m
}

// parsePGConfigArray parses pg_db_role_setting.setconfig / pg_roles.rolconfig entries of the form "key=value".
func parsePGConfigArray(entries []string) map[string]string {
	res := make(map[string]string, len(entries))
	for _, entry := range entries {
		idx := strings.IndexByte(entry, '=')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(entry[:idx])
		v := strings.TrimSpace(entry[idx+1:])
		res[k] = v
	}
	return res
}

// syncRoleMemberships diffs desired vs current role memberships for roleName, ignoring excludedRoles
// (e.g. azure_pg_admin when managed separately by is_admin on pgazureflex_entra_role).
func syncRoleMemberships(ctx context.Context, pool *pgxpool.Pool, roleName string, desired []string, exclude map[string]bool) error {
	current, err := readRoleMemberships(ctx, pool, roleName, exclude)
	if err != nil {
		return err
	}

	curSet := make(map[string]bool, len(current))
	for _, r := range current {
		curSet[r] = true
	}
	desSet := make(map[string]bool, len(desired))
	for _, r := range desired {
		if exclude[r] {
			continue
		}
		desSet[r] = true
	}

	for r := range desSet {
		if !curSet[r] {
			sql := fmt.Sprintf("GRANT %s TO %s", pgclient.QuoteIdent(r), pgclient.QuoteIdent(roleName))
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, sql)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to GRANT %q TO %q: %w", r, roleName, err)
			}
		}
	}

	for r := range curSet {
		if !desSet[r] {
			sql := fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent(r), pgclient.QuoteIdent(roleName))
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, sql)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to REVOKE %q FROM %q: %w", r, roleName, err)
			}
		}
	}

	return nil
}

func readRoleMemberships(ctx context.Context, pool *pgxpool.Pool, roleName string, exclude map[string]bool) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT r.rolname
		FROM pg_auth_members m
		JOIN pg_roles r ON r.oid = m.roleid
		JOIN pg_roles mem ON mem.oid = m.member
		WHERE mem.rolname = $1
		ORDER BY r.rolname
	`, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to query role memberships for %q: %w", roleName, err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		if exclude[r] {
			continue
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// syncEntityParameters applies ALTER <ENTITY> <name> SET / RESET for desired vs current parameters.
func syncEntityParameters(ctx context.Context, pool *pgxpool.Pool, entityKeyword, entityName string, desired, current map[string]string) error {
	for k := range current {
		if _, keep := desired[k]; !keep {
			sql := fmt.Sprintf("ALTER %s %s RESET %s", entityKeyword, pgclient.QuoteIdent(entityName), pgclient.QuoteIdent(k))
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, sql)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to reset parameter %q on %s %q: %w", k, entityKeyword, entityName, err)
			}
		}
	}

	for k, v := range desired {
		if curVal, exists := current[k]; exists && curVal == v {
			continue
		}
		sql := fmt.Sprintf("ALTER %s %s SET %s = %s",
			entityKeyword,
			pgclient.QuoteIdent(entityName),
			pgclient.QuoteIdent(k),
			pgclient.QuoteLiteral(v),
		)
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, sql)
			return execErr
		}); err != nil {
			return fmt.Errorf("failed to set parameter %q=%q on %s %q: %w", k, v, entityKeyword, entityName, err)
		}
	}
	return nil
}

// splitTwoPartID parses an import ID of the form "part1.part2" (splitting on the first dot).
func splitTwoPartID(id string) (string, string, error) {
	idx := strings.IndexByte(id, '.')
	if idx <= 0 || idx >= len(id)-1 {
		return "", "", fmt.Errorf("expected import ID in format '<database>.<name>', got %q", id)
	}
	return id[:idx], id[idx+1:], nil
}
