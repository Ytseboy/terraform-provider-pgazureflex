package provider

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/testutil/mockazure"
)

func TestProviderSchemaAndRegistration(t *testing.T) {
	ctx := context.Background()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("failed to create protocol v6 server: %v", err)
	}

	schemaResp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema failed: %v", err)
	}
	for _, d := range schemaResp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("schema error diagnostic: %s: %s", d.Summary, d.Detail)
		}
	}

	expectedResources := []string{
		"pgazureflex_database",
		"pgazureflex_role",
		"pgazureflex_entra_role",
		"pgazureflex_entra_role_mapping",
		"pgazureflex_role_membership",
		"pgazureflex_schema",
		"pgazureflex_extension",
		"pgazureflex_grant",
		"pgazureflex_default_privileges",
		"pgazureflex_publication",
	}
	for _, name := range expectedResources {
		if _, ok := schemaResp.ResourceSchemas[name]; !ok {
			t.Errorf("missing expected resource schema %q", name)
		}
	}

	expectedDataSources := []string{
		"pgazureflex_server_info",
		"pgazureflex_entra_principals",
		"pgazureflex_databases",
		"pgazureflex_roles",
	}
	for _, name := range expectedDataSources {
		if _, ok := schemaResp.DataSourceSchemas[name]; !ok {
			t.Errorf("missing expected data source schema %q", name)
		}
	}
}

// TestAzureFlexibleServerEndToEnd runs a full end-to-end Protocol v6 lifecycle test against a live
// PostgreSQL server (configured via PGAZUREFLEX_TEST_HOST / PGHOST, PGPORT, PGUSER, PGPASSWORD).
// When run against the Docker test harness (test/azure_flex_sim.sql), it exercises non-superuser
// `azure_pg_admin` ownership impersonation, Microsoft Entra ID principals via `pgaadauth`,
// databases, roles, schemas, extensions, grants, default privileges, publications, and all 4 data sources.
func TestAzureFlexibleServerEndToEnd(t *testing.T) {
	host := os.Getenv("PGAZUREFLEX_TEST_HOST")
	if host == "" {
		t.Skip("set PGAZUREFLEX_TEST_HOST to run live PostgreSQL integration tests")
	}
	port := int64(5432)
	if p := os.Getenv("PGAZUREFLEX_TEST_PORT"); p != "" {
		if parsed, err := strconv.ParseInt(p, 10, 64); err == nil {
			port = parsed
		}
	}
	user := os.Getenv("PGAZUREFLEX_TEST_USER")
	if user == "" {
		user = "flexadmin"
	}
	password := os.Getenv("PGAZUREFLEX_TEST_PASSWORD")
	if password == "" {
		password = "flexadmin-secret"
	}
	sslmode := os.Getenv("PGAZUREFLEX_TEST_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	ctx := context.Background()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("failed to create provider server: %v", err)
	}

	schemaResp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema failed: %v", err)
	}

	// 1. Configure Provider
	provType := schemaResp.Provider.ValueType()
	provVals := nullObjectValues(provType)
	provVals["host"] = tftypes.NewValue(tftypes.String, host)
	provVals["port"] = tftypes.NewValue(tftypes.Number, port)
	provVals["database"] = tftypes.NewValue(tftypes.String, "postgres")
	provVals["username"] = tftypes.NewValue(tftypes.String, user)
	provVals["password"] = tftypes.NewValue(tftypes.String, password)
	provVals["auth_mode"] = tftypes.NewValue(tftypes.String, "password")
	provVals["sslmode"] = tftypes.NewValue(tftypes.String, sslmode)
	provVals["auto_grant_role_membership"] = tftypes.NewValue(tftypes.Bool, true)

	cfgDV, err := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, provVals))
	if err != nil {
		t.Fatalf("failed to encode provider config: %v", err)
	}
	cfgResp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &cfgDV})
	if err != nil {
		t.Fatalf("ConfigureProvider RPC failed: %v", err)
	}
	assertNoErrorDiags(t, "ConfigureProvider", cfgResp.Diagnostics)

	// Helper to run Plan + Apply for Create/Update/Delete on any resource via tfprotov6.
	applyResource := func(typeName string, priorVal tftypes.Value, configOverrides map[string]tftypes.Value) tftypes.Value {
		t.Helper()
		resSchema := schemaResp.ResourceSchemas[typeName]
		objType := resSchema.ValueType()

		var cfgVal tftypes.Value
		if configOverrides == nil {
			cfgVal = tftypes.NewValue(objType, nil) // Destroy
		} else {
			vals := nullObjectValues(objType)
			for k, v := range configOverrides {
				vals[k] = v
			}
			cfgVal = tftypes.NewValue(objType, vals)
		}

		if priorVal.Type() == nil {
			priorVal = tftypes.NewValue(objType, nil)
		}

		priorDV, err := tfprotov6.NewDynamicValue(objType, priorVal)
		if err != nil {
			t.Fatalf("%s encode prior: %v", typeName, err)
		}
		cfgDV, err := tfprotov6.NewDynamicValue(objType, cfgVal)
		if err != nil {
			t.Fatalf("%s encode config: %v", typeName, err)
		}

		// ProposedNewState mimics Terraform Core merging config onto prior (or null on destroy).
		proposedVal := cfgVal
		if configOverrides != nil && !priorVal.IsNull() {
			var pMap, cMap map[string]tftypes.Value
			_ = priorVal.As(&pMap)
			_ = cfgVal.As(&cMap)
			merged := make(map[string]tftypes.Value, len(cMap))
			for k, cv := range cMap {
				if cv.IsNull() && pMap[k].IsKnown() && !pMap[k].IsNull() {
					// Keep computed prior attributes only if not set in config
					if attr := findAttr(resSchema.Block, k); attr != nil && attr.Computed && !attr.Optional {
						merged[k] = pMap[k]
						continue
					}
				}
				merged[k] = cv
			}
			proposedVal = tftypes.NewValue(objType, merged)
		}
		proposedDV, err := tfprotov6.NewDynamicValue(objType, proposedVal)
		if err != nil {
			t.Fatalf("%s encode proposed: %v", typeName, err)
		}

		planResp, err := srv.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
			TypeName:         typeName,
			PriorState:       &priorDV,
			ProposedNewState: &proposedDV,
			Config:           &cfgDV,
		})
		if err != nil {
			t.Fatalf("%s PlanResourceChange RPC error: %v", typeName, err)
		}
		assertNoErrorDiags(t, typeName+" Plan", planResp.Diagnostics)

		applyResp, err := srv.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{
			TypeName:     typeName,
			PriorState:   &priorDV,
			PlannedState: planResp.PlannedState,
			Config:       &cfgDV,
		})
		if err != nil {
			t.Fatalf("%s ApplyResourceChange RPC error: %v", typeName, err)
		}
		assertNoErrorDiags(t, typeName+" Apply", applyResp.Diagnostics)

		newState, err := applyResp.NewState.Unmarshal(objType)
		if err != nil {
			t.Fatalf("%s unmarshal new state: %v", typeName, err)
		}
		return newState
	}

	readResource := func(typeName string, curVal tftypes.Value) tftypes.Value {
		t.Helper()
		objType := schemaResp.ResourceSchemas[typeName].ValueType()
		curDV, err := tfprotov6.NewDynamicValue(objType, curVal)
		if err != nil {
			t.Fatalf("%s encode state for read: %v", typeName, err)
		}
		resp, err := srv.ReadResource(ctx, &tfprotov6.ReadResourceRequest{
			TypeName:     typeName,
			CurrentState: &curDV,
		})
		if err != nil {
			t.Fatalf("%s ReadResource RPC error: %v", typeName, err)
		}
		assertNoErrorDiags(t, typeName+" Read", resp.Diagnostics)
		out, err := resp.NewState.Unmarshal(objType)
		if err != nil {
			t.Fatalf("%s unmarshal read state: %v", typeName, err)
		}
		return out
	}

	readDataSource := func(typeName string, configOverrides map[string]tftypes.Value) map[string]tftypes.Value {
		t.Helper()
		objType := schemaResp.DataSourceSchemas[typeName].ValueType()
		vals := nullObjectValues(objType)
		for k, v := range configOverrides {
			vals[k] = v
		}
		dv, err := tfprotov6.NewDynamicValue(objType, tftypes.NewValue(objType, vals))
		if err != nil {
			t.Fatalf("%s encode ds config: %v", typeName, err)
		}
		resp, err := srv.ReadDataSource(ctx, &tfprotov6.ReadDataSourceRequest{
			TypeName: typeName,
			Config:   &dv,
		})
		if err != nil {
			t.Fatalf("%s ReadDataSource RPC error: %v", typeName, err)
		}
		assertNoErrorDiags(t, typeName+" ReadDataSource", resp.Diagnostics)
		out, err := resp.State.Unmarshal(objType)
		if err != nil {
			t.Fatalf("%s unmarshal ds state: %v", typeName, err)
		}
		var m map[string]tftypes.Value
		if err := out.As(&m); err != nil {
			t.Fatalf("%s as map: %v", typeName, err)
		}
		return m
	}

	// 2. Verify data.pgazureflex_server_info detects Azure Flexible Server simulation properly!
	serverInfo := readDataSource("pgazureflex_server_info", nil)
	var isSuper, isAzureAdmin, isAzureFlex, hasPGAAD bool
	_ = serverInfo["is_superuser"].As(&isSuper)
	_ = serverInfo["is_azure_pg_admin"].As(&isAzureAdmin)
	_ = serverInfo["is_azure_flexible_server"].As(&isAzureFlex)
	_ = serverInfo["has_pgaadauth"].As(&hasPGAAD)
	if isSuper {
		t.Fatalf("expected non-superuser test admin (simulating Azure Flexible Server), got is_superuser=true")
	}
	if !isAzureAdmin || !isAzureFlex || !hasPGAAD {
		t.Fatalf("expected azure_pg_admin=%t, azure_flex=%t, has_pgaadauth=%t to all be true", isAzureAdmin, isAzureFlex, hasPGAAD)
	}
	// Verify allowed_extensions from custom `azure.extensions` GUC when pgaadauth_mock is loaded
	var allowedExts []tftypes.Value
	_ = serverInfo["allowed_extensions"].As(&allowedExts)
	if len(allowedExts) < 3 {
		t.Fatalf("expected >=3 allowed_extensions from azure.extensions GUC, got %d", len(allowedExts))
	}

	// 3. Create native group role + owner role
	groupRoleState := applyResource("pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyResource("pgazureflex_role", groupRoleState, nil)

	ownerRoleState := applyResource("pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "app_owner"),
		"login":            tftypes.NewValue(tftypes.Bool, true),
		"password":         tftypes.NewValue(tftypes.String, "Sup3rS3cret!"),
		"connection_limit": tftypes.NewValue(tftypes.Number, int64(20)),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"statement_timeout": tftypes.NewValue(tftypes.String, "30s"),
		}),
	})
	defer applyResource("pgazureflex_role", ownerRoleState, nil)

	// 4. Create Microsoft Entra ID principal (Managed Identity) via pgaadauth_create_principal_with_oid
	entraState := applyResource("pgazureflex_entra_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":           tftypes.NewValue(tftypes.String, "mi-orders-api"),
		"object_id":      tftypes.NewValue(tftypes.String, "11111111-2222-3333-4444-555555555555"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, false),
		"roles": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "app_readonly_group"),
		}),
		"drop_owned": tftypes.NewValue(tftypes.Bool, true),
	})
	defer applyResource("pgazureflex_entra_role", entraState, nil)

	// Verify Read + Update (connection_limit & parameters) on Managed Identity Entra role
	entraState = readResource("pgazureflex_entra_role", entraState)
	entraState = applyResource("pgazureflex_entra_role", entraState, map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "mi-orders-api"),
		"object_id":        tftypes.NewValue(tftypes.String, "11111111-2222-3333-4444-555555555555"),
		"principal_type":   tftypes.NewValue(tftypes.String, "service"),
		"is_admin":         tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":           tftypes.NewValue(tftypes.Bool, false),
		"connection_limit": tftypes.NewValue(tftypes.Number, int64(50)),
		"roles": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "app_readonly_group"),
		}),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"statement_timeout": tftypes.NewValue(tftypes.String, "15s"),
		}),
		"drop_owned": tftypes.NewValue(tftypes.Bool, true),
	})

	// Also create an Entra ID admin security group with MFA enforced
	entraAdminState := applyResource("pgazureflex_entra_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":           tftypes.NewValue(tftypes.String, "sg-pg-admins"),
		"object_id":      tftypes.NewValue(tftypes.String, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		"principal_type": tftypes.NewValue(tftypes.String, "group"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, true),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, true),
	})
	_ = readResource("pgazureflex_entra_role", entraAdminState)

	// Verify data.pgazureflex_entra_principals returns sg-pg-admins when admins_only = true
	entraList := readDataSource("pgazureflex_entra_principals", map[string]tftypes.Value{
		"admins_only": tftypes.NewValue(tftypes.Bool, true),
	})
	var principalSlice []tftypes.Value
	_ = entraList["principals"].As(&principalSlice)
	if len(principalSlice) != 1 {
		t.Fatalf("expected 1 admin Entra principal, got %d", len(principalSlice))
	}

	allEntraList := readDataSource("pgazureflex_entra_principals", map[string]tftypes.Value{
		"admins_only": tftypes.NewValue(tftypes.Bool, false),
	})
	var allPrincipalSlice []tftypes.Value
	_ = allEntraList["principals"].As(&allPrincipalSlice)
	if len(allPrincipalSlice) != 2 {
		t.Fatalf("expected 2 total Entra principals, got %d", len(allPrincipalSlice))
	}

	// 4b. Create a separate RBAC role and map the Entra principal `mi-orders-api` to it via
	//     `pgazureflex_role_membership` (decoupled Entra -> Postgres RBAC mapping with PG 16+ options).
	rwRoleState := applyResource("pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "app_readwrite_group"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyResource("pgazureflex_role", rwRoleState, nil)

	membershipState := applyResource("pgazureflex_role_membership", tftypes.Value{}, map[string]tftypes.Value{
		"role":                tftypes.NewValue(tftypes.String, "app_readwrite_group"),
		"member_role":         tftypes.NewValue(tftypes.String, "mi-orders-api"),
		"with_admin_option":   tftypes.NewValue(tftypes.Bool, false),
		"with_inherit_option": tftypes.NewValue(tftypes.Bool, true),
		"with_set_option":     tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyResource("pgazureflex_role_membership", membershipState, nil)
	membershipState = readResource("pgazureflex_role_membership", membershipState)

	// Update PG 16+ membership options in-place (enable SET option)
	membershipState = applyResource("pgazureflex_role_membership", membershipState, map[string]tftypes.Value{
		"role":                tftypes.NewValue(tftypes.String, "app_readwrite_group"),
		"member_role":         tftypes.NewValue(tftypes.String, "mi-orders-api"),
		"with_admin_option":   tftypes.NewValue(tftypes.Bool, false),
		"with_inherit_option": tftypes.NewValue(tftypes.Bool, true),
		"with_set_option":     tftypes.NewValue(tftypes.Bool, true),
	})

	// 5. Create Database owned by `app_owner` (exercises WithRoleMembership under non-superuser azure_pg_admin!)
	dbState := applyResource("pgazureflex_database", tftypes.Value{}, map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "orders_db"),
		"owner":            tftypes.NewValue(tftypes.String, "app_owner"),
		"connection_limit": tftypes.NewValue(tftypes.Number, int64(100)),
		"force_drop":       tftypes.NewValue(tftypes.Bool, true),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"work_mem": tftypes.NewValue(tftypes.String, "16MB"),
		}),
	})
	defer applyResource("pgazureflex_database", dbState, nil)
	dbState = readResource("pgazureflex_database", dbState)

	// 6. Create Schema owned by `app_owner` inside `orders_db`
	schemaState := applyResource("pgazureflex_schema", tftypes.Value{}, map[string]tftypes.Value{
		"database":             tftypes.NewValue(tftypes.String, "orders_db"),
		"name":                 tftypes.NewValue(tftypes.String, "core"),
		"owner":                tftypes.NewValue(tftypes.String, "app_owner"),
		"revoke_public_create": tftypes.NewValue(tftypes.Bool, true),
		"drop_cascade":         tftypes.NewValue(tftypes.Bool, true),
	})
	defer applyResource("pgazureflex_schema", schemaState, nil)
	schemaState = readResource("pgazureflex_schema", schemaState)

	// 7. Create Extension (pgcrypto) inside `orders_db`
	extState := applyResource("pgazureflex_extension", tftypes.Value{}, map[string]tftypes.Value{
		"database":     tftypes.NewValue(tftypes.String, "orders_db"),
		"name":         tftypes.NewValue(tftypes.String, "pgcrypto"),
		"schema":       tftypes.NewValue(tftypes.String, "core"),
		"drop_cascade": tftypes.NewValue(tftypes.Bool, true),
	})
	defer applyResource("pgazureflex_extension", extState, nil)
	extState = readResource("pgazureflex_extension", extState)

	// 8. Create Default Privileges FOR ROLE app_owner IN SCHEMA core TO app_readonly_group
	defPrivState := applyResource("pgazureflex_default_privileges", tftypes.Value{}, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "orders_db"),
		"owner":       tftypes.NewValue(tftypes.String, "app_owner"),
		"schema":      tftypes.NewValue(tftypes.String, "core"),
		"role":        tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"object_type": tftypes.NewValue(tftypes.String, "table"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "SELECT"),
		}),
	})
	defer applyResource("pgazureflex_default_privileges", defPrivState, nil)
	defPrivState = readResource("pgazureflex_default_privileges", defPrivState)

	// 9. Create Grants on Database and Schema
	dbGrantState := applyResource("pgazureflex_grant", tftypes.Value{}, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "orders_db"),
		"role":        tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"object_type": tftypes.NewValue(tftypes.String, "database"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "CONNECT"),
		}),
	})
	defer applyResource("pgazureflex_grant", dbGrantState, nil)
	dbGrantState = readResource("pgazureflex_grant", dbGrantState)

	schemaGrantState := applyResource("pgazureflex_grant", tftypes.Value{}, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "orders_db"),
		"role":        tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"object_type": tftypes.NewValue(tftypes.String, "schema"),
		"schema":      tftypes.NewValue(tftypes.String, "core"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "USAGE"),
		}),
	})
	defer applyResource("pgazureflex_grant", schemaGrantState, nil)
	schemaGrantState = readResource("pgazureflex_grant", schemaGrantState)

	// 10. Create a table as `app_owner` (confirming `flexadmin` did NOT retain leaked membership!)
	//     and test table-level grants + logical replication publications inside `orders_db`.
	rawClient, err := pgclient.NewClient(pgclient.Config{
		Host: host, Port: int(port), Database: "orders_db",
		Username: "app_owner", Password: "Sup3rS3cret!", SSLMode: sslmode,
	})
	if err != nil {
		t.Fatalf("rawClient init: %v", err)
	}
	defer rawClient.Close()
	ordersPool, err := rawClient.Pool(ctx, "orders_db")
	if err != nil {
		t.Fatalf("ordersPool connect: %v", err)
	}
	if _, err := ordersPool.Exec(ctx, `CREATE TABLE core.events (id serial primary key, payload jsonb)`); err != nil {
		t.Fatalf("create test table: %v", err)
	}

	tableGrantState := applyResource("pgazureflex_grant", tftypes.Value{}, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "orders_db"),
		"role":        tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"object_type": tftypes.NewValue(tftypes.String, "table"),
		"schema":      tftypes.NewValue(tftypes.String, "core"),
		"objects": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "events"),
		}),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "SELECT"),
		}),
	})
	defer applyResource("pgazureflex_grant", tableGrantState, nil)
	tableGrantState = readResource("pgazureflex_grant", tableGrantState)

	pubState := applyResource("pgazureflex_publication", tftypes.Value{}, map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "orders_db"),
		"name":     tftypes.NewValue(tftypes.String, "cdc_events"),
		"tables": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "core.events"),
		}),
		"publish_param": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "insert"),
			tftypes.NewValue(tftypes.String, "update"),
		}),
	})
	defer applyResource("pgazureflex_publication", pubState, nil)
	pubState = readResource("pgazureflex_publication", pubState)

	// Test in-place update on publication (add delete)
	pubState = applyResource("pgazureflex_publication", pubState, map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "orders_db"),
		"name":     tftypes.NewValue(tftypes.String, "cdc_events"),
		"tables": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "core.events"),
		}),
		"publish_param": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "insert"),
			tftypes.NewValue(tftypes.String, "update"),
			tftypes.NewValue(tftypes.String, "delete"),
		}),
	})

	// 11. Verify data.pgazureflex_databases and data.pgazureflex_roles
	dbsData := readDataSource("pgazureflex_databases", nil)
	var dbItems []tftypes.Value
	_ = dbsData["databases"].As(&dbItems)
	if len(dbItems) < 2 {
		t.Fatalf("expected at least 2 databases (postgres + orders_db), got %d", len(dbItems))
	}

	rolesData := readDataSource("pgazureflex_roles", nil)
	var roleItems []tftypes.Value
	_ = rolesData["roles"].As(&roleItems)
	if len(roleItems) < 3 {
		t.Fatalf("expected at least 3 non-system roles, got %d", len(roleItems))
	}

	// Verify out-of-band drift detection on table grant: revoke directly in SQL, then ReadResource
	if _, err := ordersPool.Exec(ctx, `REVOKE SELECT ON TABLE core.events FROM app_readonly_group`); err != nil {
		t.Fatalf("manual revoke for drift test failed: %v", err)
	}
	driftedGrant := readResource("pgazureflex_grant", tableGrantState)
	var driftedMap map[string]tftypes.Value
	_ = driftedGrant.As(&driftedMap)
	var driftedPrivs []tftypes.Value
	_ = driftedMap["privileges"].As(&driftedPrivs)
	if len(driftedPrivs) != 0 {
		t.Fatalf("expected drift detection to report 0 privileges after manual REVOKE, got %v", driftedPrivs)
	}
	// Re-apply to restore desired grant state cleanly before deferred destroy
	tableGrantState = applyResource("pgazureflex_grant", driftedGrant, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "orders_db"),
		"role":        tftypes.NewValue(tftypes.String, "app_readonly_group"),
		"object_type": tftypes.NewValue(tftypes.String, "table"),
		"schema":      tftypes.NewValue(tftypes.String, "core"),
		"objects": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "events"),
		}),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "SELECT"),
		}),
	})

	// Test ImportResourceState across importable resources
	importTests := []struct {
		typeName string
		id       string
	}{
		{"pgazureflex_database", "orders_db"},
		{"pgazureflex_role", "app_owner"},
		{"pgazureflex_entra_role", "mi-orders-api"},
		{"pgazureflex_role_membership", "app_readwrite_group:mi-orders-api"},
		{"pgazureflex_schema", "orders_db.core"},
		{"pgazureflex_extension", "orders_db.pgcrypto"},
		{"pgazureflex_publication", "orders_db.cdc_events"},
	}
	for _, it := range importTests {
		impResp, err := srv.ImportResourceState(ctx, &tfprotov6.ImportResourceStateRequest{
			TypeName: it.typeName,
			ID:       it.id,
		})
		if err != nil {
			t.Fatalf("ImportResourceState(%s, %q) RPC error: %v", it.typeName, it.id, err)
		}
		assertNoErrorDiags(t, "Import "+it.typeName, impResp.Diagnostics)
		if len(impResp.ImportedResources) != 1 {
			t.Fatalf("ImportResourceState(%s) returned %d resources, want 1", it.typeName, len(impResp.ImportedResources))
		}
		objType := schemaResp.ResourceSchemas[it.typeName].ValueType()
		importedVal, err := impResp.ImportedResources[0].State.Unmarshal(objType)
		if err != nil {
			t.Fatalf("unmarshal imported %s: %v", it.typeName, err)
		}
		_ = readResource(it.typeName, importedVal)
	}

	// Close rawClient before deferred DROP DATABASE runs
	rawClient.Close()
}

// TestEntraRoleMappingSecurityLabelEndToEnd tests `pgazureflex_entra_role_mapping` end-to-end
// against PostgreSQL 16 with the `pgaadauth_mock` security label provider loaded, verifying:
//   - Binding an Entra ID identity onto an existing NOLOGIN PostgreSQL role (auto-enabling LOGIN)
//   - Real `SECURITY LABEL FOR "pgaadauth"` persistence in `pg_shseclabel`
//   - In-place `object_id` rotation, `is_mfa` update, and `postgres_roles` diffing WITHOUT dropping the role
//   - `ImportResourceState` + `ReadResource`
//   - Non-destructive Destroy (`IS NULL` clears `pg_shseclabel`, leaving the underlying PG role intact)
func TestEntraRoleMappingSecurityLabelEndToEnd(t *testing.T) {
	host := os.Getenv("PGAZUREFLEX_TEST_HOST")
	if host == "" {
		t.Skip("set PGAZUREFLEX_TEST_HOST to run live PostgreSQL integration tests")
	}
	port := int64(5432)
	if p := os.Getenv("PGAZUREFLEX_TEST_PORT"); p != "" {
		if parsed, err := strconv.ParseInt(p, 10, 64); err == nil {
			port = parsed
		}
	}
	suUser := os.Getenv("PGAZUREFLEX_TEST_SUPERUSER")
	if suUser == "" {
		suUser = "postgres"
	}
	suPassword := os.Getenv("PGAZUREFLEX_TEST_SUPERUSER_PASSWORD")
	if suPassword == "" {
		suPassword = "postgres"
	}
	sslmode := os.Getenv("PGAZUREFLEX_TEST_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	ctx := context.Background()
	srv, schemaResp := configureTestProvider(t, nil, map[string]tftypes.Value{
		"host":      tftypes.NewValue(tftypes.String, host),
		"port":      tftypes.NewValue(tftypes.Number, port),
		"database":  tftypes.NewValue(tftypes.String, "postgres"),
		"username":  tftypes.NewValue(tftypes.String, suUser),
		"password":  tftypes.NewValue(tftypes.String, suPassword),
		"auth_mode": tftypes.NewValue(tftypes.String, "password"),
		"sslmode":   tftypes.NewValue(tftypes.String, sslmode),
	})

	// 1. Create two PostgreSQL RBAC group roles + one existing NOLOGIN service role
	roState := applyTestResource(t, srv, schemaResp, "pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "map_ro_group"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyTestResource(t, srv, schemaResp, "pgazureflex_role", roState, nil)

	rwState := applyTestResource(t, srv, schemaResp, "pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "map_rw_group"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyTestResource(t, srv, schemaResp, "pgazureflex_role", rwState, nil)

	svcRoleState := applyTestResource(t, srv, schemaResp, "pgazureflex_role", tftypes.Value{}, map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "svc_billing_legacy"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	})
	defer applyTestResource(t, srv, schemaResp, "pgazureflex_role", svcRoleState, nil)

	// 2. Bind Entra Managed Identity OID onto `svc_billing_legacy` (ensure_login=true auto-enables LOGIN)
	oid1 := "33333333-4444-5555-6666-777777777777"
	mappingState := applyTestResource(t, srv, schemaResp, "pgazureflex_entra_role_mapping", tftypes.Value{}, map[string]tftypes.Value{
		"role":           tftypes.NewValue(tftypes.String, "svc_billing_legacy"),
		"object_id":      tftypes.NewValue(tftypes.String, oid1),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, false),
		"ensure_login":   tftypes.NewValue(tftypes.Bool, true),
		"postgres_roles": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "map_ro_group"),
		}),
	})

	// Verify Read returns the exact security label from pg_shseclabel
	mappingState = readTestResource(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mappingState)
	var mMap map[string]tftypes.Value
	_ = mappingState.As(&mMap)
	var gotLabel string
	_ = mMap["security_label"].As(&gotLabel)
	wantLabel1 := "aadauth,oid=" + oid1 + ",type=service"
	if gotLabel != wantLabel1 {
		t.Fatalf("got security_label %q, want %q", gotLabel, wantLabel1)
	}

	// 3. In-place OID rotation + MFA enablement + postgres_roles swap (zero DROP ROLE!)
	oid2 := "88888888-9999-aaaa-bbbb-cccccccccccc"
	mappingState = applyTestResource(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mappingState, map[string]tftypes.Value{
		"role":           tftypes.NewValue(tftypes.String, "svc_billing_legacy"),
		"object_id":      tftypes.NewValue(tftypes.String, oid2),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, true),
		"ensure_login":   tftypes.NewValue(tftypes.Bool, true),
		"postgres_roles": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "map_rw_group"),
		}),
	})
	_ = mappingState.As(&mMap)
	_ = mMap["security_label"].As(&gotLabel)
	wantLabel2 := "aadauth,oid=" + oid2 + ",type=service,mfa"
	if gotLabel != wantLabel2 {
		t.Fatalf("after in-place rotation got security_label %q, want %q", gotLabel, wantLabel2)
	}

	// 4. Test ImportResourceState on pgazureflex_entra_role_mapping
	impResp, err := srv.ImportResourceState(ctx, &tfprotov6.ImportResourceStateRequest{
		TypeName: "pgazureflex_entra_role_mapping",
		ID:       "svc_billing_legacy",
	})
	if err != nil {
		t.Fatalf("ImportResourceState failed: %v", err)
	}
	assertNoErrorDiags(t, "Import pgazureflex_entra_role_mapping", impResp.Diagnostics)
	importedVal, _ := impResp.ImportedResources[0].State.Unmarshal(schemaResp.ResourceSchemas["pgazureflex_entra_role_mapping"].ValueType())
	_ = readTestResource(t, srv, schemaResp, "pgazureflex_entra_role_mapping", importedVal)

	// 5. Destroy mapping and confirm underlying role `svc_billing_legacy` STILL EXISTS while label is NULL!
	applyTestResource(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mappingState, nil)

	checkClient, err := pgclient.NewClient(pgclient.Config{
		Host: host, Port: int(port), Database: "postgres",
		Username: suUser, Password: suPassword, SSLMode: sslmode,
	})
	if err != nil {
		t.Fatalf("checkClient: %v", err)
	}
	defer checkClient.Close()
	pool, err := checkClient.Pool(ctx, "postgres")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}

	var roleStillExists bool
	var canLogin bool
	if err := pool.QueryRow(ctx, `SELECT true, rolcanlogin FROM pg_roles WHERE rolname = 'svc_billing_legacy'`).Scan(&roleStillExists, &canLogin); err != nil {
		t.Fatalf("expected underlying role svc_billing_legacy to survive mapping destroy: %v", err)
	}
	if !roleStillExists || !canLogin {
		t.Fatalf("expected roleStillExists=true & canLogin=true, got (%t, %t)", roleStillExists, canLogin)
	}

	lbl, _, err := checkClient.GetEntraSecurityLabel(ctx, "svc_billing_legacy")
	if err != nil {
		t.Fatalf("GetEntraSecurityLabel after destroy: %v", err)
	}
	if lbl != nil {
		t.Fatalf("expected pgaadauth security label to be cleared after destroy, still found %+v", lbl)
	}
}

// TestMockAzureEntraAuthEndToEnd boots a local Mock Azure Entra ID OAuth2 + IMDS HTTP server,
// configures the Terraform provider with `auth_mode = "azure_client_secret"` and
// `auth_mode = "azure_managed_identity"`, authenticates to a live PostgreSQL 16 server using
// the bearer token minted by the mock Azure API (injected via pgxpool.BeforeConnect), and
// executes real Terraform provider operations.
func TestMockAzureEntraAuthEndToEnd(t *testing.T) {
	host := os.Getenv("PGAZUREFLEX_TEST_HOST")
	if host == "" {
		t.Skip("set PGAZUREFLEX_TEST_HOST to run live PostgreSQL integration tests")
	}
	port := int64(5432)
	if p := os.Getenv("PGAZUREFLEX_TEST_PORT"); p != "" {
		if parsed, err := strconv.ParseInt(p, 10, 64); err == nil {
			port = parsed
		}
	}
	suUser := os.Getenv("PGAZUREFLEX_TEST_SUPERUSER")
	if suUser == "" {
		suUser = "postgres"
	}
	suPassword := os.Getenv("PGAZUREFLEX_TEST_SUPERUSER_PASSWORD")
	if suPassword == "" {
		suPassword = "postgres"
	}
	sslmode := os.Getenv("PGAZUREFLEX_TEST_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	ctx := context.Background()

	// Seed two PostgreSQL login roles whose passwords match the bearer tokens our Mock Azure API will mint.
	seedClient, err := pgclient.NewClient(pgclient.Config{
		Host: host, Port: int(port), Database: "postgres",
		Username: suUser, Password: suPassword, SSLMode: sslmode,
	})
	if err != nil {
		t.Fatalf("seedClient: %v", err)
	}
	defer seedClient.Close()
	seedPool, err := seedClient.Pool(ctx, "postgres")
	if err != nil {
		t.Fatalf("seedPool: %v", err)
	}

	_, err = seedPool.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sp_terraform_e2e') THEN
				CREATE ROLE sp_terraform_e2e LOGIN PASSWORD 'mock-sp-bearer-1' IN ROLE azure_pg_admin;
			ELSE
				ALTER ROLE sp_terraform_e2e WITH PASSWORD 'mock-sp-bearer-1';
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mi_terraform_e2e') THEN
				CREATE ROLE mi_terraform_e2e LOGIN PASSWORD 'mock-mi-bearer-imds-1' IN ROLE azure_pg_admin;
			ELSE
				ALTER ROLE mi_terraform_e2e WITH PASSWORD 'mock-mi-bearer-imds-1';
			END IF;
		END $$;
	`)
	if err != nil {
		t.Fatalf("failed to seed mock Entra test roles: %v", err)
	}
	t.Cleanup(func() {
		_, _ = seedPool.Exec(context.Background(), `DROP ROLE IF EXISTS sp_terraform_e2e`)
		_, _ = seedPool.Exec(context.Background(), `DROP ROLE IF EXISTS mi_terraform_e2e`)
	})

	t.Run("azure_client_secret end-to-end against mock Entra ID API + PostgreSQL 16", func(t *testing.T) {
		mock := mockazure.NewServer(t)
		mock.SetExpectedCredentials(
			"11111111-2222-3333-4444-555555555555",
			"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"ci-client-secret",
			pgclient.DefaultAzureOSSScope,
		)
		mock.SetTokenConfig("mock-sp-bearer", 1*time.Hour)

		srv, schemaResp := configureTestProvider(t, mock.Transport(), map[string]tftypes.Value{
			"host":                 tftypes.NewValue(tftypes.String, host),
			"port":                 tftypes.NewValue(tftypes.Number, port),
			"database":             tftypes.NewValue(tftypes.String, "postgres"),
			"username":             tftypes.NewValue(tftypes.String, "sp_terraform_e2e"),
			"auth_mode":            tftypes.NewValue(tftypes.String, "azure_client_secret"),
			"azure_tenant_id":      tftypes.NewValue(tftypes.String, "11111111-2222-3333-4444-555555555555"),
			"azure_client_id":      tftypes.NewValue(tftypes.String, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
			"azure_client_secret":  tftypes.NewValue(tftypes.String, "ci-client-secret"),
			"azure_authority_host": tftypes.NewValue(tftypes.String, mock.AuthorityHost()),
			"sslmode":              tftypes.NewValue(tftypes.String, sslmode),
		})

		info := readTestDataSource(t, srv, schemaResp, "pgazureflex_server_info", nil)
		var currentUser string
		_ = info["current_user"].As(&currentUser)
		if currentUser != "sp_terraform_e2e" {
			t.Fatalf("expected current_user=sp_terraform_e2e, got %q", currentUser)
		}
		if mock.OAuthTokenCalls() != 1 {
			t.Fatalf("expected 1 mock Entra OAuth2 token call, got %d", mock.OAuthTokenCalls())
		}
		if !strings.Contains(mock.LastScope(), pgclient.DefaultAzureOSSScope) {
			t.Fatalf("expected OSS RDBMS Entra scope, got %q", mock.LastScope())
		}
	})

	t.Run("azure_managed_identity end-to-end against mock IMDS API + PostgreSQL 16", func(t *testing.T) {
		mock := mockazure.NewServer(t)
		mock.SetExpectedCredentials("", "uami-app-999", "", "")
		mock.SetTokenConfig("mock-mi-bearer", 1*time.Hour)

		t.Setenv("IDENTITY_ENDPOINT", "")
		t.Setenv("IDENTITY_HEADER", "")
		t.Setenv("MSI_ENDPOINT", "")

		srv, schemaResp := configureTestProvider(t, mock.Transport(), map[string]tftypes.Value{
			"host":            tftypes.NewValue(tftypes.String, host),
			"port":            tftypes.NewValue(tftypes.Number, port),
			"database":        tftypes.NewValue(tftypes.String, "postgres"),
			"username":        tftypes.NewValue(tftypes.String, "mi_terraform_e2e"),
			"auth_mode":       tftypes.NewValue(tftypes.String, "azure_managed_identity"),
			"azure_client_id": tftypes.NewValue(tftypes.String, "uami-app-999"),
			"sslmode":         tftypes.NewValue(tftypes.String, sslmode),
		})

		info := readTestDataSource(t, srv, schemaResp, "pgazureflex_server_info", nil)
		var currentUser string
		_ = info["current_user"].As(&currentUser)
		if currentUser != "mi_terraform_e2e" {
			t.Fatalf("expected current_user=mi_terraform_e2e, got %q", currentUser)
		}
		if mock.IMDSTokenCalls() != 1 {
			t.Fatalf("expected 1 mock IMDS token call, got %d", mock.IMDSTokenCalls())
		}
		if mock.LastClientID() != "uami-app-999" {
			t.Fatalf("expected IMDS client_id=uami-app-999, got %q", mock.LastClientID())
		}
	})
}

func configureTestProvider(t *testing.T, transport policy.Transporter, overrides map[string]tftypes.Value) (tfprotov6.ProviderServer, *tfprotov6.GetProviderSchemaResponse) {
	t.Helper()
	ctx := context.Background()
	srv, err := providerserver.NewProtocol6WithError(NewWithAzureTransport("test", transport)())()
	if err != nil {
		t.Fatalf("failed to create provider server: %v", err)
	}
	schemaResp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema failed: %v", err)
	}
	provType := schemaResp.Provider.ValueType()
	vals := nullObjectValues(provType)
	for k, v := range overrides {
		vals[k] = v
	}
	cfgDV, err := tfprotov6.NewDynamicValue(provType, tftypes.NewValue(provType, vals))
	if err != nil {
		t.Fatalf("encode provider config: %v", err)
	}
	cfgResp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &cfgDV})
	if err != nil {
		t.Fatalf("ConfigureProvider RPC failed: %v", err)
	}
	assertNoErrorDiags(t, "ConfigureProvider", cfgResp.Diagnostics)
	return srv, schemaResp
}

func applyTestResource(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, priorVal tftypes.Value, configOverrides map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	ctx := context.Background()
	resSchema := schemaResp.ResourceSchemas[typeName]
	objType := resSchema.ValueType()

	var cfgVal tftypes.Value
	if configOverrides == nil {
		cfgVal = tftypes.NewValue(objType, nil)
	} else {
		vals := nullObjectValues(objType)
		for k, v := range configOverrides {
			vals[k] = v
		}
		cfgVal = tftypes.NewValue(objType, vals)
	}
	if priorVal.Type() == nil {
		priorVal = tftypes.NewValue(objType, nil)
	}

	priorDV, _ := tfprotov6.NewDynamicValue(objType, priorVal)
	cfgDV, _ := tfprotov6.NewDynamicValue(objType, cfgVal)

	proposedVal := cfgVal
	if configOverrides != nil && !priorVal.IsNull() {
		var pMap, cMap map[string]tftypes.Value
		_ = priorVal.As(&pMap)
		_ = cfgVal.As(&cMap)
		merged := make(map[string]tftypes.Value, len(cMap))
		for k, cv := range cMap {
			if cv.IsNull() && pMap[k].IsKnown() && !pMap[k].IsNull() {
				if attr := findAttr(resSchema.Block, k); attr != nil && attr.Computed && !attr.Optional {
					merged[k] = pMap[k]
					continue
				}
			}
			merged[k] = cv
		}
		proposedVal = tftypes.NewValue(objType, merged)
	}
	proposedDV, _ := tfprotov6.NewDynamicValue(objType, proposedVal)

	planResp, err := srv.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
		TypeName:         typeName,
		PriorState:       &priorDV,
		ProposedNewState: &proposedDV,
		Config:           &cfgDV,
	})
	if err != nil {
		t.Fatalf("%s Plan RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" Plan", planResp.Diagnostics)

	applyResp, err := srv.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{
		TypeName:     typeName,
		PriorState:   &priorDV,
		PlannedState: planResp.PlannedState,
		Config:       &cfgDV,
	})
	if err != nil {
		t.Fatalf("%s Apply RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" Apply", applyResp.Diagnostics)

	newState, err := applyResp.NewState.Unmarshal(objType)
	if err != nil {
		t.Fatalf("%s unmarshal new state: %v", typeName, err)
	}
	return newState
}

func readTestResource(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, curVal tftypes.Value) tftypes.Value {
	t.Helper()
	ctx := context.Background()
	objType := schemaResp.ResourceSchemas[typeName].ValueType()
	curDV, _ := tfprotov6.NewDynamicValue(objType, curVal)
	resp, err := srv.ReadResource(ctx, &tfprotov6.ReadResourceRequest{
		TypeName:     typeName,
		CurrentState: &curDV,
	})
	if err != nil {
		t.Fatalf("%s Read RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" Read", resp.Diagnostics)
	out, err := resp.NewState.Unmarshal(objType)
	if err != nil {
		t.Fatalf("%s unmarshal read state: %v", typeName, err)
	}
	return out
}

func readTestDataSource(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, configOverrides map[string]tftypes.Value) map[string]tftypes.Value {
	t.Helper()
	ctx := context.Background()
	objType := schemaResp.DataSourceSchemas[typeName].ValueType()
	vals := nullObjectValues(objType)
	for k, v := range configOverrides {
		vals[k] = v
	}
	dv, _ := tfprotov6.NewDynamicValue(objType, tftypes.NewValue(objType, vals))
	resp, err := srv.ReadDataSource(ctx, &tfprotov6.ReadDataSourceRequest{
		TypeName: typeName,
		Config:   &dv,
	})
	if err != nil {
		t.Fatalf("%s ReadDataSource RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" ReadDataSource", resp.Diagnostics)
	out, err := resp.State.Unmarshal(objType)
	if err != nil {
		t.Fatalf("%s unmarshal ds state: %v", typeName, err)
	}
	var m map[string]tftypes.Value
	_ = out.As(&m)
	return m
}

func nullObjectValues(t tftypes.Type) map[string]tftypes.Value {
	obj := t.(tftypes.Object)
	vals := make(map[string]tftypes.Value, len(obj.AttributeTypes))
	for k, attrType := range obj.AttributeTypes {
		vals[k] = tftypes.NewValue(attrType, nil)
	}
	return vals
}

func findAttr(block *tfprotov6.SchemaBlock, name string) *tfprotov6.SchemaAttribute {
	if block == nil {
		return nil
	}
	for _, a := range block.Attributes {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func assertNoErrorDiags(t *testing.T, op string, diags []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("%s returned error diagnostic: %s — %s", op, d.Summary, d.Detail)
		}
	}
}
