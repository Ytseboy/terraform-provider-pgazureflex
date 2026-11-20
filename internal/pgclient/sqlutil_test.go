package pgclient

import (
	"testing"
)

func TestQuoteIdent(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"users", `"users"`},
		{"app-db", `"app-db"`},
		{`weird"name`, `"weird""name"`},
		{"user@contoso.com", `"user@contoso.com"`},
	}
	for _, tc := range tests {
		if got := QuoteIdent(tc.in); got != tc.want {
			t.Errorf("QuoteIdent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	if got := QuoteLiteral("p'ssword"); got != "'p''ssword'" {
		t.Fatalf("QuoteLiteral got %q", got)
	}
}

func TestParseCSVSetting(t *testing.T) {
	got := ParseCSVSetting(" uuid-ossp, pg_stat_statements , vector, uuid-ossp ")
	want := []string{"pg_stat_statements", "uuid-ossp", "vector"}
	if !EqualStringSets(got, want) {
		t.Fatalf("ParseCSVSetting got %v, want %v", got, want)
	}
	if empty := ParseCSVSetting("   "); len(empty) != 0 {
		t.Fatalf("expected empty slice, got %v", empty)
	}
}

func TestNormalizePrivileges(t *testing.T) {
	got := NormalizePrivileges("database", []string{"connect", "temp"})
	want := []string{"CONNECT", "TEMPORARY"}
	if !EqualStringSets(got, want) {
		t.Fatalf("NormalizePrivileges(database) = %v, want %v", got, want)
	}

	gotAll := NormalizePrivileges("schema", []string{"ALL PRIVILEGES"})
	wantAll := []string{"CREATE", "USAGE"}
	if !EqualStringSets(gotAll, wantAll) {
		t.Fatalf("NormalizePrivileges(schema ALL) = %v, want %v", gotAll, wantAll)
	}
}

func TestConfigValidationAndDefaults(t *testing.T) {
	cfg := Config{
		Host:     "myserver.postgres.database.azure.com",
		Username: "pgadmin",
	}
	cfg.ApplyDefaults()

	if cfg.Port != 5432 {
		t.Errorf("expected port 5432, got %d", cfg.Port)
	}
	if cfg.SSLMode != "require" {
		t.Errorf("expected sslmode require, got %q", cfg.SSLMode)
	}
	if !cfg.IsAzureHostname() {
		t.Errorf("expected IsAzureHostname to be true for %q", cfg.Host)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// Client secret mode missing fields should fail validation.
	badCfg := Config{
		Host:     "myserver.postgres.database.azure.com",
		Username: "sp-app",
		AuthMode: AuthModeAzureClientSecret,
	}
	badCfg.ApplyDefaults()
	if err := badCfg.Validate(); err == nil {
		t.Fatal("expected error for incomplete azure_client_secret config")
	}

	// US Government cloud scope check.
	govCfg := Config{
		Host:       "myserver.postgres.database.usgovcloudapi.net",
		Username:   "admin",
		AuthMode:   AuthModeAzureDefault,
		AzureCloud: AzureCloudUSGovernment,
	}
	govCfg.ApplyDefaults()
	if govCfg.AzureTokenScope != USGovAzureOSSScope {
		t.Errorf("expected USGov scope %q, got %q", USGovAzureOSSScope, govCfg.AzureTokenScope)
	}
	if !govCfg.IsAzureHostname() {
		t.Errorf("expected IsAzureHostname to be true for USGov host")
	}
}

func TestPGAADAuthSecurityLabelFormatAndParse(t *testing.T) {
	tests := []struct {
		name      string
		oid       string
		ptype     string
		isAdmin   bool
		isMFA     bool
		wantLabel string
	}{
		{
			name:      "managed identity basic",
			oid:       "11111111-2222-3333-4444-555555555555",
			ptype:     "service",
			wantLabel: "aadauth,oid=11111111-2222-3333-4444-555555555555,type=service",
		},
		{
			name:      "entra admin group with mfa",
			oid:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			ptype:     "group",
			isAdmin:   true,
			isMFA:     true,
			wantLabel: "aadauth,oid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,type=group,admin,mfa",
		},
		{
			name:      "entra user with mfa only",
			oid:       "99999999-8888-7777-6666-555555555555",
			ptype:     "USER",
			isMFA:     true,
			wantLabel: "aadauth,oid=99999999-8888-7777-6666-555555555555,type=user,mfa",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatPGAADAuthSecurityLabel(tc.oid, tc.ptype, tc.isAdmin, tc.isMFA)
			if err != nil {
				t.Fatalf("FormatPGAADAuthSecurityLabel failed: %v", err)
			}
			if got != tc.wantLabel {
				t.Fatalf("got label %q, want %q", got, tc.wantLabel)
			}

			parsed, err := ParsePGAADAuthSecurityLabel(got)
			if err != nil {
				t.Fatalf("ParsePGAADAuthSecurityLabel(%q) failed: %v", got, err)
			}
			if parsed.ObjectID != tc.oid || parsed.IsAdmin != tc.isAdmin || parsed.IsMFA != tc.isMFA {
				t.Fatalf("round-trip mismatch: got %+v", parsed)
			}
		})
	}

	if _, err := FormatPGAADAuthSecurityLabel("11111111-2222-3333-4444-555555555555", "invalid", false, false); err == nil {
		t.Fatal("expected error for invalid principal_type")
	}
	if _, err := ParsePGAADAuthSecurityLabel("not-aadauth,oid=abc"); err == nil {
		t.Fatal("expected error for invalid label prefix")
	}
}
