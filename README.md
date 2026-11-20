# `terraform-provider-pgazureflex`

A modern **Terraform Plugin Framework (Protocol v6)** provider for PostgreSQL built on **`pgx/v5`** and the **Azure Identity SDK**, engineered specifically for **Azure Database for PostgreSQL - Flexible Server** (while remaining fully compatible with standard PostgreSQL 13–17).

## Highlights

- **Native Microsoft Entra ID Authentication**: `azure_default`, `azure_cli`, `azure_managed_identity`, `azure_client_secret`, `azure_workload_identity`, `access_token`, and `password` modes with automatic per-connection token refresh (`pgxpool.BeforeConnect`) and Azure Public / US Gov / China cloud support.
- **First-Class Entra ID Principal & Role Mapping**:
  - `pgazureflex_entra_role`: Private-VNet-safe Entra ID Users, Groups, Managed Identities, and Service Principals via `pgaadauth_create_principal_with_oid`.
  - `pgazureflex_entra_role_mapping`: In-place identity binding & OID rotation on existing PostgreSQL roles via `SECURITY LABEL FOR "pgaadauth"` (zero-downtime password → Entra migration, non-destructive destroy).
  - `pgazureflex_role_membership`: Decoupled Entra → PostgreSQL RBAC mappings with PostgreSQL 16+ `ADMIN`, `INHERIT`, and `SET` options.
- **Automatic PostgreSQL 16+ `azure_pg_admin` Role Impersonation**: Transparently handles temporary `WITH SET TRUE, INHERIT TRUE` membership (preserving pre-existing `ADMIN OPTION` rows) during ownership transfers, schemas, extensions, grants, default privileges, and `REASSIGN OWNED BY`.
- **Azure Extension Diagnostics**: Detects `azure.extensions` and `shared_preload_libraries` allowlist errors on `CREATE EXTENSION` and prints live server settings with remediation steps.
- **Formally Verified Core Invariants (Lean 4)**: Sorry-free, axiom-audited Lean 4 proofs covering SQL quoting breakout impossibility, `pgaadauth` security label bijection, PG 16+ `WithRoleMembership` non-leakage, ACL normalization/idempotency, and Terraform plan-modifier ordering.

---

## Documentation

### Provider & Guides
- [Provider Reference](docs/index.md) — Configuration attributes, auth modes, environment variables, TLS
- [Architecture & Design](docs/architecture.md) — Internal layers, connection pooling, `azure_pg_admin` mechanics
- [Guide: Microsoft Entra ID Authentication](docs/guides/azure-entra-id-authentication.md) — Workload Identity, Managed Identity, Private VNet, Sovereign Clouds
- [Guide: Production Multi-Tenant RBAC](docs/guides/production-multi-tenant-rbac.md) — 5-tier per-tenant RBAC, PG 16+ ownership, zero-downtime migration

### Resources (12)
| Resource | Documentation | Purpose |
|---|---|---|
| `pgazureflex_database` | [database.md](docs/resources/database.md) | Databases, ownership, in-place rename, `ALTER DATABASE SET`, `force_drop` |
| `pgazureflex_database_config` | [database_config.md](docs/resources/database_config.md) | Non-destructive ownership, `PUBLIC` hardening & parameters on `azurerm`-managed DBs |
| `pgazureflex_role` | [role.md](docs/resources/role.md) | Native login & `NOLOGIN` RBAC roles, parameters, `reassign_owned_to` / `drop_owned` |
| `pgazureflex_role_database_parameters` | [role_database_parameters.md](docs/resources/role_database_parameters.md) | Per-role, per-database parameters (`ALTER ROLE ... IN DATABASE ... SET`, e.g. `pgaudit.log`) |
| `pgazureflex_entra_role` | [entra_role.md](docs/resources/entra_role.md) | Microsoft Entra ID principals via `pgaadauth_create_principal_with_oid` |
| `pgazureflex_entra_role_mapping` | [entra_role_mapping.md](docs/resources/entra_role_mapping.md) | Bind Entra OID onto existing PG role via `SECURITY LABEL FOR "pgaadauth"` (in-place rotation) |
| `pgazureflex_role_membership` | [role_membership.md](docs/resources/role_membership.md) | Standalone `GRANT <role> TO <member_role>` with PG 16+ `ADMIN`/`INHERIT`/`SET` |
| `pgazureflex_schema` | [schema.md](docs/resources/schema.md) | Schemas, ownership, in-place rename, `revoke_public_create` |
| `pgazureflex_extension` | [extension.md](docs/resources/extension.md) | Extensions with Azure `azure.extensions` allowlist diagnostics |
| `pgazureflex_grant` | [grant.md](docs/resources/grant.md) | Declarative & authoritative (`privileges = []` / `authoritative = true`) grants with `aclexplode` drift detection |
| `pgazureflex_default_privileges` | [default_privileges.md](docs/resources/default_privileges.md) | `ALTER DEFAULT PRIVILEGES FOR ROLE ... IN SCHEMA ...` |
| `pgazureflex_publication` | [publication.md](docs/resources/publication.md) | Logical replication publications for CDC & migrations |

### Data Sources (4)
| Data Source | Documentation | Purpose |
|---|---|---|
| `pgazureflex_server_info` | [server_info.md](docs/data-sources/server_info.md) | Live PG version, `azure.extensions`, `shared_preload_libraries`, `pgaadauth`, TLS |
| `pgazureflex_entra_principals` | [entra_principals.md](docs/data-sources/entra_principals.md) | Lists Entra ID principals via `pgaadauth_list_principals` |
| `pgazureflex_databases` | [databases.md](docs/data-sources/databases.md) | Lists databases and settings |
| `pgazureflex_roles` | [roles.md](docs/data-sources/roles.md) | Lists roles and memberships |

### Examples
- [examples/azure-flexible-server-full/main.tf](examples/azure-flexible-server-full/main.tf) — Complete `azurerm_postgresql_flexible_server` + `pgazureflex` setup
- [examples/modules/pg-tenant-rbac/main.tf](examples/modules/pg-tenant-rbac/main.tf) — Reusable multi-tenant 5-tier RBAC module
- [examples/multi-tenant-rbac/main.tf](examples/multi-tenant-rbac/main.tf) — Multi-tenant production/UAT RBAC example using Managed Identities & Entra groups

---

## Building, Testing & Formal Verification

```bash
# Build provider binary
make build

# Run unit tests + Mock Azure Entra ID / IMDS API tests (-race)
make test

# Run full E2E integration tests against PostgreSQL 16 in Docker
# (non-superuser azure_pg_admin, pgaadauth C extension, Mock Azure APIs,
#  plan/idempotency/import/drift/deletion lifecycle verification)
make test-integration

# Run Lean 4 formal verification proofs (local lake or Docker Lean 4.16.0)
make verify-lean

# Install locally into ~/.terraform.d/plugins
make install
```
