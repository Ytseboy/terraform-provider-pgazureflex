package pgclient

import (
	"errors"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// QuoteIdent safely quotes a single PostgreSQL identifier (e.g., table, role, database name).
func QuoteIdent(ident string) string {
	return pgx.Identifier{ident}.Sanitize()
}

// QuoteQualifiedIdent safely quotes a dot-separated identifier path (e.g., schema.table).
func QuoteQualifiedIdent(parts ...string) string {
	return pgx.Identifier(parts).Sanitize()
}

// QuoteLiteral safely quotes a string literal for PostgreSQL SQL statements where bound
// parameters ($1) are not permitted by PostgreSQL DDL syntax (e.g. ALTER ROLE PASSWORD, SET).
func QuoteLiteral(val string) string {
	escaped := strings.ReplaceAll(val, "'", "''")
	return "'" + escaped + "'"
}

// PgErrorCode extracts the 5-character PostgreSQL SQLSTATE code from err, or "" if not a PgError.
func PgErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// IsUndefinedObject returns true for SQLSTATE 42704 (undefined_object).
func IsUndefinedObject(err error) bool {
	return PgErrorCode(err) == "42704"
}

// IsInvalidCatalogName returns true for SQLSTATE 3D000 (invalid_catalog_name, e.g. missing database).
func IsInvalidCatalogName(err error) bool {
	return PgErrorCode(err) == "3D000"
}

// IsDuplicateObject returns true for SQLSTATE 42710 (duplicate_object) or 42P04 (duplicate_database).
func IsDuplicateObject(err error) bool {
	code := PgErrorCode(err)
	return code == "42710" || code == "42P04" || code == "42P06"
}

// IsInsufficientPrivilege returns true for SQLSTATE 42501 (insufficient_privilege).
func IsInsufficientPrivilege(err error) bool {
	return PgErrorCode(err) == "42501"
}

// ParseCSVSetting parses a PostgreSQL comma-separated GUC value into a trimmed, sorted slice.
func ParseCSVSetting(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p == "" {
			continue
		}
		if _, exists := seen[p]; exists {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ValidPrivilegesByObjectType lists the canonical PostgreSQL privileges valid for each object type.
var ValidPrivilegesByObjectType = map[string][]string{
	"database":  {"CONNECT", "CREATE", "TEMPORARY"},
	"schema":    {"CREATE", "USAGE"},
	"table":     {"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"},
	"sequence":  {"SELECT", "UPDATE", "USAGE"},
	"function":  {"EXECUTE"},
	"procedure": {"EXECUTE"},
	"routine":   {"EXECUTE"},
	"type":      {"USAGE"},
}

// NormalizePrivileges canonicalizes privilege names (uppercase, TEMP->TEMPORARY, ALL->expanded list),
// deduplicates, and sorts them.
func NormalizePrivileges(objectType string, privs []string) []string {
	objType := strings.ToLower(strings.TrimSpace(objectType))
	expanded := make(map[string]struct{})

	for _, p := range privs {
		up := strings.ToUpper(strings.TrimSpace(p))
		switch up {
		case "TEMP":
			up = "TEMPORARY"
		case "ALL", "ALL PRIVILEGES":
			for _, v := range ValidPrivilegesByObjectType[objType] {
				expanded[v] = struct{}{}
			}
			continue
		}
		if up != "" {
			expanded[up] = struct{}{}
		}
	}

	out := make([]string, 0, len(expanded))
	for p := range expanded {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// EqualStringSets compares two slices of strings as sets (order-insensitive).
func EqualStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
