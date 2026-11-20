# Architecture & Design: `terraform-provider-pgazureflex`

## 1. Motivation: Why an Azure Flexible Server–Focused PostgreSQL Provider?

Existing PostgreSQL Terraform providers (such as `cyrilgdn/postgresql`) were designed primarily around self-managed PostgreSQL with `SUPERUSER` password credentials and legacy Terraform SDKv2 / `lib/pq`. When used against **Azure Database for PostgreSQL - Flexible Server**, teams repeatedly hit six sharp operational issues:

1. **Microsoft Entra ID Token Expiry & Auth Complexity**: Azure Flexible Server expects short-lived OAuth2 JWTs scoped to `https://ossrdbms-aad.database.windows.net/.default` passed as the PostgreSQL password. Passing a static token from an external `az account get-access-token` script fails on long applies and breaks CI/CD portability.
2. **No Native `pgaadauth` Lifecycle Management**: Creating Entra ID Users, Security Groups, Managed Identities, and Service Principals requires invoking `pgaadauth_create_principal_with_oid` / `pgaadauth_create_principal` and inspecting `pgaadauth_list_principals(false)` rather than plain `CREATE ROLE`.
3. **Non-Superuser `azure_pg_admin` Ownership Friction (especially PostgreSQL 16+)**: On Azure Flexible Server, the server admin belongs to `azure_pg_admin` (not `SUPERUSER`). Statements such as `CREATE DATABASE ... OWNER TO app_owner`, `CREATE SCHEMA ... AUTHORIZATION app_owner`, `ALTER DEFAULT PRIVILEGES FOR ROLE app_owner`, and `REASSIGN OWNED BY` fail unless the admin holds membership (`WITH SET TRUE` on PG 16+) in the target role.
4. **Opaque `azure.extensions` Allowlist Failures**: Running `CREATE EXTENSION` fails unless the extension is first allow-listed in `azure.extensions` (and for some extensions, `shared_preload_libraries`).
5. **Concurrent Catalog Update Races (`XX000: tuple concurrently updated`)**: Terraform applies parallel grants and role updates concurrently, triggering transient PostgreSQL catalog lock/tuple errors.
6. **Provider-Held Sessions Blocking `DROP DATABASE`**: Connection pools targeting a database prevent `DROP DATABASE` unless explicitly evicted prior to drop and combined with `WITH (FORCE)` on PG 13+.

---

## 2. Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Terraform Core (Protocol v6)                                            │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│ internal/provider (Terraform Plugin Framework v1)                       │
│  ├── PGAzureFlexProvider (schema, env vars, Configure)                  │
│  ├── Resources (8):                                                     │
│  │     pgazureflex_database, pgazureflex_role, pgazureflex_entra_role,  │
│  │     pgazureflex_schema, pgazureflex_extension, pgazureflex_grant,    │
│  │     pgazureflex_default_privileges, pgazureflex_publication          │
│  └── Data Sources (4):                                                  │
│        pgazureflex_server_info, pgazureflex_entra_principals,           │
│        pgazureflex_databases, pgazureflex_roles                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│ internal/pgclient (pgx/v5 + Azure Identity SDK)                         │
│  ├── auth.go    : TokenProvider with 5m-skew cache + sovereign clouds   │
│  ├── config.go  : Validation, Azure hostname detection, TLS builder     │
│  ├── client.go  : Per-DB pgxpool manager, BeforeConnect token refresh,  │
│  │                server capability discovery, transient retry loop     │
│  ├── azure.go   : WithRoleMembership (serialized grant/revoke),         │
│  │                pgaadauth wrapper, azure.extensions diagnostics       │
│  └── sqlutil.go : pgx.Identifier quoting, literal escaping, ACL norms   │
└─────────────────────────────────────────────────────────────────────────┘
```

## 3. Key Design Decisions

### Dynamic Entra ID Authentication (`internal/pgclient/auth.go`, `client.go`)
- Uses `pgxpool.Config.BeforeConnect` so **every new physical TCP/TLS connection** fetches a fresh bearer token from `azureTokenProvider`.
- Tokens are cached in memory behind a mutex and refreshed automatically when within 5 minutes of `ExpiresOn`.
- Supports Public, US Government (`usgovernment`), and China (`china`) clouds with automatic scope selection.
- Defaults to `sslmode = "require"`, matching Azure Flexible Server's `require_secure_transport = ON`.

### `azure_pg_admin` Impersonation Safety (`internal/pgclient/azure.go`)
- `Client.WithRoleMembership(ctx, db, targetRole, fn)` inspects cached server capabilities:
  - If `IsSuperuser` or `targetRole == CurrentUser`, runs `fn` directly with zero overhead.
  - Otherwise acquires `Client.roleMu` (preventing parallel Terraform workers from revoking a temporary grant while another worker is using it), checks direct membership in `pg_auth_members`, temporarily grants `GRANT <targetRole> TO <currentUser> WITH SET TRUE` (PG 16+) or `GRANT <targetRole> TO <currentUser>`, executes `fn`, and revokes in `defer` only if it was temporarily granted.

### Private-VNet-Friendly Entra ID Roles & Role Mappings (`pgazureflex_entra_role`, `pgazureflex_entra_role_mapping`, `pgazureflex_role_membership`)
- **`pgazureflex_entra_role`**: When `object_id` is provided, calls `pgaadauth_create_principal_with_oid(name, object_id, principal_type, is_admin, is_mfa)`. Avoids outbound Microsoft Graph lookups (critical in private-endpoint / VNet-injected servers). State reads join `pgaadauth_list_principals(false)` with `pg_roles` and `pg_auth_members`.
- **`pgazureflex_entra_role_mapping`**: Uses Azure Flexible Server's native `SECURITY LABEL FOR "pgaadauth" ON ROLE "<role>" IS 'aadauth,oid=<oid>,type=<type>[,admin][,mfa]'` to bind an Entra ID identity onto an **existing** PostgreSQL role without owning the role's `CREATE`/`DROP` lifecycle. Supports zero-downtime password-to-Entra migrations, custom PostgreSQL role names, and **in-place `object_id` rotation**; on destroy, sets the security label to `NULL` without dropping the role or its owned objects.
- **`pgazureflex_role_membership`**: Manages standalone `GRANT <role> TO <member_role>` mappings (with PostgreSQL 16+ `ADMIN`, `INHERIT`, and `SET` options) so teams can map Entra ID groups/identities to PostgreSQL RBAC roles cleanly across decoupled Terraform modules.

### System Catalog ACL Readback (`pgazureflex_grant`, `pgazureflex_default_privileges`)
- Instead of assuming state matches config, `Read` queries PostgreSQL's real ACL catalogs via `aclexplode(COALESCE(acl, acldefault(...)))` and `pg_default_acl`, computing the privilege intersection across targeted objects so out-of-band revocations or grants are detected on the next `terraform plan`.

### Safe Destruction Semantics
- `pgazureflex_database`: Evicts any cached `pgxpool` for the target database (`CloseDatabasePool`) before issuing `DROP DATABASE`, and supports `force_drop = true` (`WITH (FORCE)` on PG 13+).
- `pgazureflex_role` & `pgazureflex_entra_role`: Support `reassign_owned_to` (`REASSIGN OWNED BY ... TO ...`) and `drop_owned` (`DROP OWNED BY ...`) wrapped in `WithRoleMembership` so role destruction succeeds cleanly even when the role created objects.
