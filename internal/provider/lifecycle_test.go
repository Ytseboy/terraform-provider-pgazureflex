package provider

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

// TestLifecyclePlanIdempotencyImportDeleteEndToEnd rigorously verifies Terraform Core lifecycle
// contracts against live PostgreSQL 16 (with pgaadauth_mock + azure.extensions):
//  1. Strict zero-diff idempotency (`PlanResourceChange` after `Create` + `Read` returns
//     PlannedState == PriorState and RequiresReplace == empty, simulating real Terraform Core
//     ProposedNewState with UnknownValue for Computed attributes) across ALL 10 resources.
//  2. Plan accuracy: `RequiresReplace` fires for immutable attributes; in-place plans fire with
//     zero replacements for renames (`database`, `role`, `schema`, `publication`), `object_id`
//     rotation (`entra_role_mapping`), and PG 16+ options (`role_membership`).
//  3. Import + post-import zero-diff re-plan across all 8 importable resources, plus invalid
//     import ID error handling.
//  4. Explicit deletion verified in PostgreSQL catalogs, out-of-band external deletion detection
//     (`ReadResource` returns null state), and idempotent double-delete.
func TestLifecyclePlanIdempotencyImportDeleteEndToEnd(t *testing.T) {
	host := os.Getenv("PGAZUREFLEX_TEST_HOST")
	if host == "" {
		t.Skip("set PGAZUREFLEX_TEST_HOST to run live PostgreSQL lifecycle tests")
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

	verifyClient, err := pgclient.NewClient(pgclient.Config{
		Host: host, Port: int(port), Database: "postgres",
		Username: suUser, Password: suPassword, SSLMode: sslmode,
	})
	if err != nil {
		t.Fatalf("verifyClient: %v", err)
	}
	defer verifyClient.Close()
	pgPool, err := verifyClient.Pool(ctx, "postgres")
	if err != nil {
		t.Fatalf("pgPool: %v", err)
	}

	// --- 1. pgazureflex_role: Create, Idempotent Plan, In-Place Rename, Import, Re-Plan ---
	roleCfg := map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "lc_role_orig"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	}
	roleState := applyStrict(t, srv, schemaResp, "pgazureflex_role", tftypes.Value{}, roleCfg)
	roleState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_role", roleState, roleCfg)

	// In-place rename MUST NOT require replace
	roleRenamedCfg := map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	}
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_role", roleState, roleRenamedCfg, false)
	roleState = applyStrict(t, srv, schemaResp, "pgazureflex_role", roleState, roleRenamedCfg)
	roleState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_role", roleState, roleRenamedCfg)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_role", "lc_role_renamed", roleRenamedCfg)

	// Second group role for membership / mapping tests
	grpCfg := map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"login": tftypes.NewValue(tftypes.Bool, false),
	}
	grpState := applyStrict(t, srv, schemaResp, "pgazureflex_role", tftypes.Value{}, grpCfg)

	// --- 2. pgazureflex_entra_role: Create, Idempotent Plan, RequiresReplace check, Import ---
	entraCfg := map[string]tftypes.Value{
		"name":           tftypes.NewValue(tftypes.String, "lc_mi_principal"),
		"object_id":      tftypes.NewValue(tftypes.String, "12121212-3434-5656-7878-909090909090"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, false),
	}
	entraState := applyStrict(t, srv, schemaResp, "pgazureflex_entra_role", tftypes.Value{}, entraCfg)
	entraState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_entra_role", entraState, entraCfg)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_entra_role", "lc_mi_principal", entraCfg)
	// Changing name or object_id on pgazureflex_entra_role MUST require replace
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_entra_role", entraState, map[string]tftypes.Value{
		"name":           tftypes.NewValue(tftypes.String, "lc_mi_other"),
		"object_id":      tftypes.NewValue(tftypes.String, "12121212-3434-5656-7878-909090909090"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
	}, true)

	// --- 3. pgazureflex_entra_role_mapping: Create, Idempotent Plan, In-Place OID Rotation, RequiresReplace(role), Import ---
	mapCfg1 := map[string]tftypes.Value{
		"role":           tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"object_id":      tftypes.NewValue(tftypes.String, "aaaa1111-bbbb-2222-cccc-333333333333"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, false),
		"ensure_login":   tftypes.NewValue(tftypes.Bool, true),
	}
	mapState := applyStrict(t, srv, schemaResp, "pgazureflex_entra_role_mapping", tftypes.Value{}, mapCfg1)
	mapState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, mapCfg1)

	// Rotating object_id MUST plan IN-PLACE and compute the exact new security_label at plan time!
	mapCfg2 := map[string]tftypes.Value{
		"role":           tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"object_id":      tftypes.NewValue(tftypes.String, "dddd4444-eeee-5555-ffff-666666666666"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
		"is_admin":       tftypes.NewValue(tftypes.Bool, false),
		"is_mfa":         tftypes.NewValue(tftypes.Bool, true),
		"ensure_login":   tftypes.NewValue(tftypes.Bool, true),
	}
	plannedMap := assertPlanReplace(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, mapCfg2, false)
	var plannedMapFields map[string]tftypes.Value
	_ = plannedMap.As(&plannedMapFields)
	var plannedLabel string
	_ = plannedMapFields["security_label"].As(&plannedLabel)
	if plannedLabel != "aadauth,oid=dddd4444-eeee-5555-ffff-666666666666,type=service,mfa" {
		t.Fatalf("expected ModifyPlan to compute exact security_label at plan time, got %q", plannedLabel)
	}
	mapState = applyStrict(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, mapCfg2)
	mapState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, mapCfg2)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_entra_role_mapping", "lc_role_renamed", mapCfg2)
	// Changing target role MUST require replace
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, map[string]tftypes.Value{
		"role":           tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"object_id":      tftypes.NewValue(tftypes.String, "dddd4444-eeee-5555-ffff-666666666666"),
		"principal_type": tftypes.NewValue(tftypes.String, "service"),
	}, true)

	// --- 4. pgazureflex_role_membership: Create, Idempotent Plan, In-Place Option Update, RequiresReplace, Import ---
	memCfg := map[string]tftypes.Value{
		"role":                tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"member_role":         tftypes.NewValue(tftypes.String, "lc_mi_principal"),
		"with_admin_option":   tftypes.NewValue(tftypes.Bool, false),
		"with_inherit_option": tftypes.NewValue(tftypes.Bool, true),
		"with_set_option":     tftypes.NewValue(tftypes.Bool, false),
	}
	memState := applyStrict(t, srv, schemaResp, "pgazureflex_role_membership", tftypes.Value{}, memCfg)
	memState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_role_membership", memState, memCfg)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_role_membership", "lc_rbac_group:lc_mi_principal", memCfg)
	// Changing with_set_option is in-place; changing role requires replace
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_role_membership", memState, map[string]tftypes.Value{
		"role":                tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"member_role":         tftypes.NewValue(tftypes.String, "lc_mi_principal"),
		"with_admin_option":   tftypes.NewValue(tftypes.Bool, false),
		"with_inherit_option": tftypes.NewValue(tftypes.Bool, true),
		"with_set_option":     tftypes.NewValue(tftypes.Bool, true),
	}, false)
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_role_membership", memState, map[string]tftypes.Value{
		"role":        tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"member_role": tftypes.NewValue(tftypes.String, "lc_mi_principal"),
	}, true)

	// --- 5. pgazureflex_database: Create, Idempotent Plan, In-Place Rename, RequiresReplace(encoding), Import ---
	dbCfg1 := map[string]tftypes.Value{
		"name":       tftypes.NewValue(tftypes.String, "lc_db_orig"),
		"owner":      tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"force_drop": tftypes.NewValue(tftypes.Bool, true),
	}
	dbState := applyStrict(t, srv, schemaResp, "pgazureflex_database", tftypes.Value{}, dbCfg1)
	dbState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_database", dbState, dbCfg1)

	dbCfg2 := map[string]tftypes.Value{
		"name":       tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"owner":      tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"force_drop": tftypes.NewValue(tftypes.Bool, true),
	}
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_database", dbState, dbCfg2, false)
	dbState = applyStrict(t, srv, schemaResp, "pgazureflex_database", dbState, dbCfg2)
	dbState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_database", dbState, dbCfg2)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_database", "lc_db_renamed", map[string]tftypes.Value{
		"name":  tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"owner": tftypes.NewValue(tftypes.String, "lc_role_renamed"),
	})
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_database", dbState, map[string]tftypes.Value{
		"name":     tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"owner":    tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"encoding": tftypes.NewValue(tftypes.String, "SQL_ASCII"),
	}, true)

	// --- 6. pgazureflex_schema: Create, Idempotent Plan, In-Place Rename, RequiresReplace(database), Import ---
	scCfg1 := map[string]tftypes.Value{
		"database":     tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":         tftypes.NewValue(tftypes.String, "lc_schema_orig"),
		"owner":        tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"drop_cascade": tftypes.NewValue(tftypes.Bool, true),
	}
	scState := applyStrict(t, srv, schemaResp, "pgazureflex_schema", tftypes.Value{}, scCfg1)
	scState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_schema", scState, scCfg1)

	scCfg2 := map[string]tftypes.Value{
		"database":     tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":         tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"owner":        tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"drop_cascade": tftypes.NewValue(tftypes.Bool, true),
	}
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_schema", scState, scCfg2, false)
	scState = applyStrict(t, srv, schemaResp, "pgazureflex_schema", scState, scCfg2)
	scState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_schema", scState, scCfg2)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_schema", "lc_db_renamed.lc_schema_renamed", map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":     tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"owner":    tftypes.NewValue(tftypes.String, "lc_role_renamed"),
	})
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_schema", scState, map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "postgres"),
		"name":     tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
	}, true)

	// --- 7. pgazureflex_extension: Create, Idempotent Plan, RequiresReplace(name), Import ---
	extCfg := map[string]tftypes.Value{
		"database":     tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":         tftypes.NewValue(tftypes.String, "pgcrypto"),
		"schema":       tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"drop_cascade": tftypes.NewValue(tftypes.Bool, true),
	}
	extState := applyStrict(t, srv, schemaResp, "pgazureflex_extension", tftypes.Value{}, extCfg)
	extState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_extension", extState, extCfg)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_extension", "lc_db_renamed.pgcrypto", map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":     tftypes.NewValue(tftypes.String, "pgcrypto"),
		"schema":   tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
	})
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_extension", extState, map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":     tftypes.NewValue(tftypes.String, "uuid-ossp"),
	}, true)

	// --- 8. pgazureflex_grant: Create, Idempotent Plan, RequiresReplace(object_type) ---
	grantCfg := map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"role":        tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"object_type": tftypes.NewValue(tftypes.String, "schema"),
		"schema":      tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "USAGE"),
		}),
	}
	grantState := applyStrict(t, srv, schemaResp, "pgazureflex_grant", tftypes.Value{}, grantCfg)
	grantState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_grant", grantState, grantCfg)
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_grant", grantState, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"role":        tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"object_type": tftypes.NewValue(tftypes.String, "database"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "CONNECT"),
		}),
	}, true)

	// --- 9. pgazureflex_default_privileges: Create, Idempotent Plan, RequiresReplace(owner) ---
	defCfg := map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"owner":       tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"schema":      tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"role":        tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"object_type": tftypes.NewValue(tftypes.String, "table"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "SELECT"),
		}),
	}
	defState := applyStrict(t, srv, schemaResp, "pgazureflex_default_privileges", tftypes.Value{}, defCfg)
	defState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_default_privileges", defState, defCfg)
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_default_privileges", defState, map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"owner":       tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"schema":      tftypes.NewValue(tftypes.String, "lc_schema_renamed"),
		"role":        tftypes.NewValue(tftypes.String, "lc_rbac_group"),
		"object_type": tftypes.NewValue(tftypes.String, "table"),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "SELECT"),
		}),
	}, true)

	// --- 10. pgazureflex_publication: Create, Idempotent Plan, In-Place Rename, RequiresReplace(all_tables), Import ---
	pubCfg1 := map[string]tftypes.Value{
		"database":   tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":       tftypes.NewValue(tftypes.String, "lc_pub_orig"),
		"all_tables": tftypes.NewValue(tftypes.Bool, true),
		"publish_param": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "insert"),
			tftypes.NewValue(tftypes.String, "update"),
		}),
	}
	pubState := applyStrict(t, srv, schemaResp, "pgazureflex_publication", tftypes.Value{}, pubCfg1)
	pubState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_publication", pubState, pubCfg1)

	pubCfg2 := map[string]tftypes.Value{
		"database":   tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":       tftypes.NewValue(tftypes.String, "lc_pub_renamed"),
		"all_tables": tftypes.NewValue(tftypes.Bool, true),
		"publish_param": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "insert"),
			tftypes.NewValue(tftypes.String, "update"),
		}),
	}
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_publication", pubState, pubCfg2, false)
	pubState = applyStrict(t, srv, schemaResp, "pgazureflex_publication", pubState, pubCfg2)
	pubState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_publication", pubState, pubCfg2)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_publication", "lc_db_renamed.lc_pub_renamed", pubCfg2)
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_publication", pubState, map[string]tftypes.Value{
		"database":   tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"name":       tftypes.NewValue(tftypes.String, "lc_pub_renamed"),
		"all_tables": tftypes.NewValue(tftypes.Bool, false),
	}, true)

	// --- 10b. pgazureflex_database_config: non-destructive ownership transfer + PUBLIC revocation + parameters ---
	// Simulate an externally created database (like azurerm_postgresql_flexible_server_database)
	if _, err := pgPool.Exec(ctx, `CREATE DATABASE lc_ext_db`); err != nil {
		t.Fatalf("create external test db: %v", err)
	}
	defer func() {
		verifyClient.CloseDatabasePool("lc_ext_db")
		_, _ = pgPool.Exec(context.Background(), `DROP DATABASE IF EXISTS lc_ext_db WITH (FORCE)`)
	}()

	dbCfgResCfg := map[string]tftypes.Value{
		"database":             tftypes.NewValue(tftypes.String, "lc_ext_db"),
		"owner":                tftypes.NewValue(tftypes.String, "lc_role_renamed"),
		"revoke_public_access": tftypes.NewValue(tftypes.Bool, true),
		"connection_limit":     tftypes.NewValue(tftypes.Number, int64(50)),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"work_mem": tftypes.NewValue(tftypes.String, "8MB"),
		}),
	}
	dbCfgState := applyStrict(t, srv, schemaResp, "pgazureflex_database_config", tftypes.Value{}, dbCfgResCfg)
	dbCfgState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_database_config", dbCfgState, dbCfgResCfg)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_database_config", "lc_ext_db", dbCfgResCfg)

	// Verify PUBLIC has 0 privileges on lc_ext_db in pg_database ACL
	var extPubPrivs int
	_ = pgPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_database d
		CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
		WHERE d.datname = 'lc_ext_db' AND a.grantee = 0
	`).Scan(&extPubPrivs)
	if extPubPrivs != 0 {
		t.Fatalf("expected 0 PUBLIC privileges on lc_ext_db after revoke_public_access=true, got %d", extPubPrivs)
	}

	// --- 10c. pgazureflex_grant authoritative PUBLIC revocation (privileges = [] and authoritative = true) ---
	pubRevokeCfg := map[string]tftypes.Value{
		"database":    tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"role":        tftypes.NewValue(tftypes.String, "PUBLIC"),
		"object_type": tftypes.NewValue(tftypes.String, "database"),
		"privileges":  tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{}),
	}
	pubRevokeState := applyStrict(t, srv, schemaResp, "pgazureflex_grant", tftypes.Value{}, pubRevokeCfg)
	pubRevokeState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_grant", pubRevokeState, pubRevokeCfg)

	schemaAuthCfg := map[string]tftypes.Value{
		"database":      tftypes.NewValue(tftypes.String, "lc_db_renamed"),
		"role":          tftypes.NewValue(tftypes.String, "PUBLIC"),
		"object_type":   tftypes.NewValue(tftypes.String, "schema"),
		"schema":        tftypes.NewValue(tftypes.String, "public"),
		"authoritative": tftypes.NewValue(tftypes.Bool, true),
		"privileges": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "USAGE"),
		}),
	}
	schemaAuthState := applyStrict(t, srv, schemaResp, "pgazureflex_grant", tftypes.Value{}, schemaAuthCfg)
	schemaAuthState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_grant", schemaAuthState, schemaAuthCfg)

	// --- 10d. pgazureflex_role_database_parameters (standard + dotted extension GUC `pgaudit.log`) ---
	rdbParamsCfg1 := map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "lc_ext_db"),
		"role":     tftypes.NewValue(tftypes.String, "lc_mi_principal"),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"pgaudit.log":                   tftypes.NewValue(tftypes.String, "write, ddl, role"),
			"statement_timeout":             tftypes.NewValue(tftypes.String, "15s"),
			"default_transaction_read_only": tftypes.NewValue(tftypes.String, "on"),
		}),
	}
	rdbParamsState := applyStrict(t, srv, schemaResp, "pgazureflex_role_database_parameters", tftypes.Value{}, rdbParamsCfg1)
	rdbParamsState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_role_database_parameters", rdbParamsState, rdbParamsCfg1)
	assertImportAndIdempotentPlan(t, srv, schemaResp, "pgazureflex_role_database_parameters", "lc_ext_db:lc_mi_principal", rdbParamsCfg1)

	// Update role-in-database parameters in-place
	rdbParamsCfg2 := map[string]tftypes.Value{
		"database": tftypes.NewValue(tftypes.String, "lc_ext_db"),
		"role":     tftypes.NewValue(tftypes.String, "lc_mi_principal"),
		"parameters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"pgaudit.log":       tftypes.NewValue(tftypes.String, "write, ddl"),
			"statement_timeout": tftypes.NewValue(tftypes.String, "30s"),
		}),
	}
	assertPlanReplace(t, srv, schemaResp, "pgazureflex_role_database_parameters", rdbParamsState, rdbParamsCfg2, false)
	rdbParamsState = applyStrict(t, srv, schemaResp, "pgazureflex_role_database_parameters", rdbParamsState, rdbParamsCfg2)
	rdbParamsState = assertIdempotentPlan(t, srv, schemaResp, "pgazureflex_role_database_parameters", rdbParamsState, rdbParamsCfg2)

	// Destroy pgazureflex_role_database_parameters & pgazureflex_database_config:
	// Verify parameters reset AND external DB `lc_ext_db` SURVIVES non-destructive destroy!
	applyStrict(t, srv, schemaResp, "pgazureflex_role_database_parameters", rdbParamsState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_database_config", dbCfgState, nil)
	var extDBStillExists bool
	_ = pgPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'lc_ext_db')`).Scan(&extDBStillExists)
	if !extDBStillExists {
		t.Fatal("expected external database lc_ext_db to survive non-destructive pgazureflex_database_config destroy")
	}
	// Transfer lc_ext_db back to superuser before dropping lc_role_renamed at test end
	_, _ = pgPool.Exec(ctx, `ALTER DATABASE lc_ext_db OWNER TO postgres`)
	applyStrict(t, srv, schemaResp, "pgazureflex_grant", schemaAuthState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_grant", pubRevokeState, nil)

	// --- 11. Invalid Import ID Error Diagnostics ---
	invalidImports := []struct {
		typeName string
		badID    string
	}{
		{"pgazureflex_schema", "nodot"},
		{"pgazureflex_extension", "nodot"},
		{"pgazureflex_publication", "nodot"},
		{"pgazureflex_role_membership", "nocolon"},
	}
	for _, tc := range invalidImports {
		impResp, err := srv.ImportResourceState(ctx, &tfprotov6.ImportResourceStateRequest{
			TypeName: tc.typeName,
			ID:       tc.badID,
		})
		if err != nil {
			t.Fatalf("ImportResourceState(%s, %q) RPC error: %v", tc.typeName, tc.badID, err)
		}
		if len(impResp.Diagnostics) == 0 || impResp.Diagnostics[0].Severity != tfprotov6.DiagnosticSeverityError {
			t.Fatalf("expected error diagnostic for invalid import ID %q on %s", tc.badID, tc.typeName)
		}
	}

	// --- 12. Out-of-Band External Deletion Detection (`ReadResource` MUST return null state) ---
	lcPool, err := verifyClient.Pool(ctx, "lc_db_renamed")
	if err != nil {
		t.Fatalf("lcPool: %v", err)
	}
	if _, err := lcPool.Exec(ctx, `DROP PUBLICATION lc_pub_renamed`); err != nil {
		t.Fatalf("external DROP PUBLICATION: %v", err)
	}
	if afterDrop := readTestResource(t, srv, schemaResp, "pgazureflex_publication", pubState); !afterDrop.IsNull() {
		t.Fatalf("expected null state after out-of-band DROP PUBLICATION, got %v", afterDrop)
	}
	// Idempotent delete on an already-deleted publication MUST succeed with no error
	applyStrict(t, srv, schemaResp, "pgazureflex_publication", pubState, nil)

	if _, err := lcPool.Exec(ctx, `DROP EXTENSION pgcrypto CASCADE`); err != nil {
		t.Fatalf("external DROP EXTENSION: %v", err)
	}
	if afterDrop := readTestResource(t, srv, schemaResp, "pgazureflex_extension", extState); !afterDrop.IsNull() {
		t.Fatalf("expected null state after out-of-band DROP EXTENSION, got %v", afterDrop)
	}
	applyStrict(t, srv, schemaResp, "pgazureflex_extension", extState, nil)

	// --- 13. Explicit Destroy + Post-Delete PostgreSQL Catalog Verification ---
	applyStrict(t, srv, schemaResp, "pgazureflex_default_privileges", defState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_grant", grantState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_schema", scState, nil)

	var schemaExists bool
	_ = lcPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'lc_schema_renamed')`).Scan(&schemaExists)
	if schemaExists {
		t.Fatal("expected schema lc_schema_renamed to be deleted from pg_namespace")
	}

	// Close verifyClient's pool to lc_db_renamed before testing DB drop
	verifyClient.CloseDatabasePool("lc_db_renamed")
	applyStrict(t, srv, schemaResp, "pgazureflex_database", dbState, nil)

	var dbExists bool
	_ = pgPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'lc_db_renamed')`).Scan(&dbExists)
	if dbExists {
		t.Fatal("expected database lc_db_renamed to be deleted from pg_database")
	}

	applyStrict(t, srv, schemaResp, "pgazureflex_role_membership", memState, nil)
	var memCount int
	_ = pgPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_auth_members m
		JOIN pg_roles r ON r.oid = m.roleid
		JOIN pg_roles mem ON mem.oid = m.member
		WHERE r.rolname = 'lc_rbac_group' AND mem.rolname = 'lc_mi_principal'
	`).Scan(&memCount)
	if memCount != 0 {
		t.Fatalf("expected role membership to be deleted from pg_auth_members, got count=%d", memCount)
	}

	applyStrict(t, srv, schemaResp, "pgazureflex_entra_role_mapping", mapState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_entra_role", entraState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_role", grpState, nil)
	applyStrict(t, srv, schemaResp, "pgazureflex_role", roleState, nil)

	for _, droppedRole := range []string{"lc_mi_principal", "lc_rbac_group", "lc_role_renamed"} {
		var exists bool
		_ = pgPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, droppedRole).Scan(&exists)
		if exists {
			t.Fatalf("expected role %q to be deleted from pg_roles", droppedRole)
		}
	}
}

// buildStrictProposed mimics real Terraform Core: Computed-only attributes and unset
// Optional+Computed attributes are marked UnknownValue so plan modifiers (e.g.
// UseStateForUnknown and ModifyPlan) are genuinely exercised!
func buildStrictProposed(resSchema *tfprotov6.Schema, priorVal, cfgVal tftypes.Value) tftypes.Value {
	if cfgVal.IsNull() {
		return cfgVal
	}
	objType := resSchema.ValueType().(tftypes.Object)
	var cMap map[string]tftypes.Value
	_ = cfgVal.As(&cMap)

	proposed := make(map[string]tftypes.Value, len(cMap))
	for k, cv := range cMap {
		attr := findAttr(resSchema.Block, k)
		if attr != nil && attr.Computed && cv.IsNull() {
			proposed[k] = tftypes.NewValue(objType.AttributeTypes[k], tftypes.UnknownValue)
			continue
		}
		proposed[k] = cv
	}
	return tftypes.NewValue(objType, proposed)
}

func planStrict(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, priorVal tftypes.Value, configOverrides map[string]tftypes.Value) (tftypes.Value, []*tftypes.AttributePath) {
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

	proposedVal := buildStrictProposed(resSchema, priorVal, cfgVal)
	priorDV, _ := tfprotov6.NewDynamicValue(objType, priorVal)
	cfgDV, _ := tfprotov6.NewDynamicValue(objType, cfgVal)
	proposedDV, _ := tfprotov6.NewDynamicValue(objType, proposedVal)

	planResp, err := srv.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
		TypeName:         typeName,
		PriorState:       &priorDV,
		ProposedNewState: &proposedDV,
		Config:           &cfgDV,
	})
	if err != nil {
		t.Fatalf("%s PlanStrict RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" PlanStrict", planResp.Diagnostics)

	planned, err := planResp.PlannedState.Unmarshal(objType)
	if err != nil {
		t.Fatalf("%s unmarshal planned: %v", typeName, err)
	}
	return planned, planResp.RequiresReplace
}

func applyStrict(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, priorVal tftypes.Value, configOverrides map[string]tftypes.Value) tftypes.Value {
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

	planned, _ := planStrict(t, srv, schemaResp, typeName, priorVal, configOverrides)
	priorDV, _ := tfprotov6.NewDynamicValue(objType, priorVal)
	plannedDV, _ := tfprotov6.NewDynamicValue(objType, planned)
	cfgDV, _ := tfprotov6.NewDynamicValue(objType, cfgVal)

	applyResp, err := srv.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{
		TypeName:     typeName,
		PriorState:   &priorDV,
		PlannedState: &plannedDV,
		Config:       &cfgDV,
	})
	if err != nil {
		t.Fatalf("%s ApplyStrict RPC error: %v", typeName, err)
	}
	assertNoErrorDiags(t, typeName+" ApplyStrict", applyResp.Diagnostics)

	newState, err := applyResp.NewState.Unmarshal(objType)
	if err != nil {
		t.Fatalf("%s unmarshal new state: %v", typeName, err)
	}
	return newState
}

// assertIdempotentPlan performs ReadResource (refresh) followed by strict PlanResourceChange
// with the identical config, asserting zero diff (`PlannedState.Equal(PriorState)`) and no replace.
func assertIdempotentPlan(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, state tftypes.Value, cfg map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	refreshed := readTestResource(t, srv, schemaResp, typeName, state)
	planned, reqReplace := planStrict(t, srv, schemaResp, typeName, refreshed, cfg)
	if len(reqReplace) > 0 {
		t.Fatalf("%s idempotent re-plan unexpectedly requested replace: %v", typeName, reqReplace)
	}
	if !planned.Equal(refreshed) {
		t.Fatalf("%s is NOT idempotent on re-plan!\nRefreshed: %s\nPlanned:   %s", typeName, refreshed.String(), planned.String())
	}
	return refreshed
}

func assertPlanReplace(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName string, priorVal tftypes.Value, newCfg map[string]tftypes.Value, wantReplace bool) tftypes.Value {
	t.Helper()
	planned, reqReplace := planStrict(t, srv, schemaResp, typeName, priorVal, newCfg)
	gotReplace := len(reqReplace) > 0
	if gotReplace != wantReplace {
		t.Fatalf("%s plan RequiresReplace=%t (paths=%v), want %t", typeName, gotReplace, reqReplace, wantReplace)
	}
	return planned
}

func assertImportAndIdempotentPlan(t *testing.T, srv tfprotov6.ProviderServer, schemaResp *tfprotov6.GetProviderSchemaResponse, typeName, importID string, matchingCfg map[string]tftypes.Value) {
	t.Helper()
	ctx := context.Background()
	impResp, err := srv.ImportResourceState(ctx, &tfprotov6.ImportResourceStateRequest{
		TypeName: typeName,
		ID:       importID,
	})
	if err != nil {
		t.Fatalf("Import(%s, %q) RPC error: %v", typeName, importID, err)
	}
	assertNoErrorDiags(t, "Import "+typeName, impResp.Diagnostics)
	if len(impResp.ImportedResources) != 1 {
		t.Fatalf("Import(%s, %q) returned %d resources", typeName, importID, len(impResp.ImportedResources))
	}
	objType := schemaResp.ResourceSchemas[typeName].ValueType()
	importedVal, err := impResp.ImportedResources[0].State.Unmarshal(objType)
	if err != nil {
		t.Fatalf("unmarshal imported %s: %v", typeName, err)
	}
	// Refresh imported state via ReadResource, then assert zero-diff idempotent re-plan!
	assertIdempotentPlan(t, srv, schemaResp, typeName, importedVal, matchingCfg)
}
