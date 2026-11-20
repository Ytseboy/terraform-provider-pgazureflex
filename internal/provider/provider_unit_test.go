package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestProviderConfigureValidationAndEnvFallbacks(t *testing.T) {
	ctx := context.Background()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("failed to create provider server: %v", err)
	}
	schemaResp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema: %v", err)
	}
	provType := schemaResp.Provider.ValueType()

	// Clear PG env vars so tests are deterministic
	for _, k := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGAZUREFLEX_AUTH_MODE", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"} {
		t.Setenv(k, "")
	}

	t.Run("missing host fails cleanly", func(t *testing.T) {
		vals := nullObjectValues(provType)
		vals["username"] = tftypes.NewValue(tftypes.String, "admin")
		dv, _ := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, vals))
		resp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &dv})
		if err != nil {
			t.Fatalf("RPC error: %v", err)
		}
		if len(resp.Diagnostics) == 0 || resp.Diagnostics[0].Severity != tfprotov6.DiagnosticSeverityError {
			t.Fatal("expected error diagnostic when host is missing")
		}
	})

	t.Run("incomplete azure_client_secret fails cleanly", func(t *testing.T) {
		vals := nullObjectValues(provType)
		vals["host"] = tftypes.NewValue(tftypes.String, "flex.postgres.database.azure.com")
		vals["username"] = tftypes.NewValue(tftypes.String, "sp-app")
		vals["auth_mode"] = tftypes.NewValue(tftypes.String, "azure_client_secret")
		dv, _ := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, vals))
		resp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &dv})
		if err != nil {
			t.Fatalf("RPC error: %v", err)
		}
		if len(resp.Diagnostics) == 0 || !strings.Contains(resp.Diagnostics[0].Detail, "azure_tenant_id") {
			t.Fatalf("expected missing azure_client_secret fields diagnostic, got: %+v", resp.Diagnostics)
		}
	})

	t.Run("env var fallback configures successfully", func(t *testing.T) {
		t.Setenv("PGHOST", "envhost.postgres.database.azure.com")
		t.Setenv("PGPORT", "5432")
		t.Setenv("PGUSER", "envadmin")
		t.Setenv("PGAZUREFLEX_AUTH_MODE", "access_token")
		t.Setenv("PGAZUREFLEX_ACCESS_TOKEN", "fake-jwt")

		vals := nullObjectValues(provType)
		dv, _ := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, vals))
		resp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &dv})
		if err != nil {
			t.Fatalf("RPC error: %v", err)
		}
		assertNoErrorDiags(t, "ConfigureProvider(env)", resp.Diagnostics)
	})

	t.Run("unknown host returns unknown config error", func(t *testing.T) {
		vals := nullObjectValues(provType)
		vals["host"] = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
		vals["username"] = tftypes.NewValue(tftypes.String, "admin")
		dv, _ := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, vals))
		resp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &dv})
		if err != nil {
			t.Fatalf("RPC error: %v", err)
		}
		if len(resp.Diagnostics) == 0 || resp.Diagnostics[0].Severity != tfprotov6.DiagnosticSeverityError {
			t.Fatal("expected error diagnostic when host is unknown")
		}
	})
}

func TestProviderHelpersAndSQLBuilders(t *testing.T) {
	// parsePGConfigArray
	cfgMap := parsePGConfigArray([]string{"work_mem=16MB", "search_path=core, public", "malformed"})
	if cfgMap["work_mem"] != "16MB" || cfgMap["search_path"] != "core, public" || len(cfgMap) != 2 {
		t.Fatalf("unexpected parsePGConfigArray output: %+v", cfgMap)
	}

	// splitTwoPartID
	db, obj, err := splitTwoPartID("orders_db.core")
	if err != nil || db != "orders_db" || obj != "core" {
		t.Fatalf("splitTwoPartID got (%q, %q, %v)", db, obj, err)
	}
	if _, _, err := splitTwoPartID("nodot"); err == nil {
		t.Fatal("expected error for invalid two-part ID")
	}

	// formatQualifiedObject with function signature
	if got := formatQualifiedObject("core", "calc_total(integer, text)", true); got != `"core"."calc_total"(integer, text)` {
		t.Fatalf("formatQualifiedObject(fn) = %q", got)
	}
	if got := formatQualifiedObject("core", "events", false); got != `"core"."events"` {
		t.Fatalf("formatQualifiedObject(table) = %q", got)
	}

	// buildGrantTargetClause
	if got, err := buildGrantTargetClause("orders", "table", "core", nil); err != nil || got != `ALL TABLES IN SCHEMA "core"` {
		t.Fatalf("buildGrantTargetClause(all tables) = %q, %v", got, err)
	}
	if got, err := buildGrantTargetClause("orders", "database", "", nil); err != nil || got != `DATABASE "orders"` {
		t.Fatalf("buildGrantTargetClause(database) = %q, %v", got, err)
	}

	// validateGrantModel
	var diags diag.Diagnostics
	privSet, _ := types.SetValueFrom(context.Background(), types.StringType, []string{"CONNECT"})
	badGrant := &grantModel{
		Database:   types.StringValue("orders"),
		Role:       types.StringValue("app"),
		ObjectType: types.StringValue("schema"),
		Schema:     types.StringValue(""),
		Privileges: privSet,
	}
	if err := validateGrantModel(context.Background(), badGrant, &diags); err == nil {
		t.Fatal("expected validation error when schema is omitted for schema grant")
	}

	// quoteTableRef
	if got := quoteTableRef("core.events"); got != `"core"."events"` {
		t.Fatalf("quoteTableRef = %q", got)
	}

	// defaultACL helpers
	if p, err := defaultACLPlural("sequence"); err != nil || p != "SEQUENCES" {
		t.Fatalf("defaultACLPlural = %q, %v", p, err)
	}
	if ch, err := defaultACLObjChar("table"); err != nil || ch != "r" {
		t.Fatalf("defaultACLObjChar = %q, %v", ch, err)
	}
}
