---
page_title: "Provider: pgazureflex"
subcategory: ""
description: |-
  Terraform provider for PostgreSQL with first-class support for Azure Database for PostgreSQL - Flexible Server.
---

# `pgazureflex` Provider

The **`pgazureflex`** provider manages PostgreSQL databases, roles, Microsoft Entra ID principals, Entra-to-PostgreSQL role mappings, schemas, extensions, grants, default privileges, and logical replication publications. It is built on **Terraform Plugin Framework (Protocol v6)**, **`pgx/v5`**, and the **Azure Identity SDK**, specifically solving the operational realities of **Azure Database for PostgreSQL - Flexible Server** (while remaining fully compatible with standard PostgreSQL 13–17).

## Key Capabilities

- **Native Microsoft Entra ID Authentication**: Supports `azure_default`, `azure_cli`, `azure_managed_identity`, `azure_client_secret`, `azure_workload_identity`, `access_token`, and `password` modes across Azure Public, US Government, and China clouds. Tokens are cached and automatically refreshed inside `pgxpool.BeforeConnect`.
- **Private-VNet-Safe Entra ID Management**: `pgazureflex_entra_role` calls `pgaadauth_create_principal_with_oid` when `object_id` is provided, avoiding outbound Microsoft Graph calls. `pgazureflex_entra_role_mapping` uses `SECURITY LABEL FOR "pgaadauth"` for zero-downtime password → Entra migration and in-place `object_id` rotation.
- **Automatic PostgreSQL 16+ `azure_pg_admin` Impersonation**: Transparently grants and revokes temporary `WITH SET TRUE, INHERIT TRUE` membership (preserving pre-existing `ADMIN OPTION` rows) during ownership transfers, `CREATE SCHEMA AUTHORIZATION`, `CREATE EXTENSION`, `GRANT`/`REVOKE`, `ALTER DEFAULT PRIVILEGES FOR ROLE`, and `REASSIGN OWNED BY`.
- **Actionable Azure Extension Diagnostics**: Enriches `CREATE EXTENSION` allowlist errors with live `azure.extensions` and `shared_preload_libraries` settings.
- **Live System-Catalog Drift Detection**: Reads actual ACLs from `aclexplode(...)`, `pg_default_acl`, `pg_auth_members`, `pg_shseclabel`, and `pgaadauth_list_principals(false)`.

## Example Usage

### Microsoft Entra ID (Recommended for Azure Flexible Server)

```hcl
terraform {
  required_providers {
    pgazureflex = {
      source  = "registry.terraform.io/ytseboy/pgazureflex"
      version = "~> 0.1"
    }
  }
}

provider "pgazureflex" {
  host                       = "myserver.postgres.database.azure.com"
  port                       = 5432
  database                   = "postgres"
  username                   = "mi-terraform-runner"
  auth_mode                  = "azure_default"
  azure_tenant_id            = "00000000-0000-0000-0000-000000000000"
  sslmode                    = "verify-full"
  auto_grant_role_membership = true
}
```

### Password Authentication (Break-Glass / Standard PostgreSQL)

```hcl
provider "pgazureflex" {
  host      = "myserver.postgres.database.azure.com"
  username  = "pgadmin"
  password  = var.pg_password
  auth_mode = "password"
  sslmode   = "require"
}
```

## Schema

### Optional

- `host` (String) PostgreSQL server hostname (e.g. `myserver.postgres.database.azure.com`). Falls back to `PGHOST`. Required via config or env var.
- `port` (Number) PostgreSQL server port (`1`–`65535`). Falls back to `PGPORT`, defaults to `5432`.
- `database` (String) Default maintenance database for cluster-level operations. Falls back to `PGDATABASE`, defaults to `postgres`.
- `username` (String) PostgreSQL role or Microsoft Entra ID principal name. Falls back to `PGUSER`. Required via config or env var.
- `password` (String, Sensitive) PostgreSQL password when `auth_mode = "password"`. Falls back to `PGPASSWORD`.
- `auth_mode` (String) Authentication mode. Falls back to `PGAZUREFLEX_AUTH_MODE`, defaults to `password`. Valid values:
  - `password` — Standard PostgreSQL username/password.
  - `azure_default` — Azure SDK `DefaultAzureCredential` (Workload Identity, Managed Identity, Azure CLI, Env vars).
  - `azure_cli` — Local `az login` session via `AzureCLICredential`.
  - `azure_managed_identity` — System-assigned or User-assigned Managed Identity (`azure_client_id`).
  - `azure_client_secret` — Service Principal (`azure_tenant_id`, `azure_client_id`, `azure_client_secret`).
  - `azure_workload_identity` — AKS / Kubernetes OIDC federated Workload Identity.
  - `access_token` — Externally minted Entra ID OAuth2 bearer token (`azure_access_token`).
- `azure_tenant_id` (String) Microsoft Entra ID tenant ID. Falls back to `AZURE_TENANT_ID`.
- `azure_client_id` (String) Microsoft Entra ID application (client) ID or User-Assigned Managed Identity client ID. Falls back to `AZURE_CLIENT_ID`.
- `azure_client_secret` (String, Sensitive) Microsoft Entra ID client secret for `azure_client_secret` mode. Falls back to `AZURE_CLIENT_SECRET`.
- `azure_access_token` (String, Sensitive) Pre-acquired Entra ID bearer token for `access_token` mode. Falls back to `PGAZUREFLEX_ACCESS_TOKEN`.
- `azure_token_scope` (String) Custom OAuth2 token scope. Defaults automatically from `azure_cloud` (e.g. `https://ossrdbms-aad.database.windows.net/.default`). Falls back to `PGAZUREFLEX_TOKEN_SCOPE`.
- `azure_cloud` (String) Azure cloud environment: `public` (default), `usgovernment`, or `china`. Falls back to `PGAZUREFLEX_AZURE_CLOUD`.
- `azure_authority_host` (String) Optional custom Entra ID authority URL override (for sovereign proxies or local mock testing). Falls back to `AZURE_AUTHORITY_HOST`.
- `sslmode` (String) TLS verification mode: `disable`, `allow`, `prefer`, `require` (default), `verify-ca`, `verify-full`. Falls back to `PGSSLMODE`.
- `ssl_root_cert` (String) File path or inline PEM root CA bundle. Falls back to `PGSSLROOTCERT`.
- `ssl_cert` (String) File path or inline PEM client certificate for mTLS. Falls back to `PGSSLCERT`.
- `ssl_key` (String, Sensitive) File path or inline PEM client private key for mTLS. Falls back to `PGSSLKEY`.
- `connect_timeout` (Number) Connection timeout in seconds (`1`–`300`). Defaults to `15`.
- `max_connections` (Number) Maximum open connections per per-database pool (`1`–`100`). Defaults to `4`.
- `azure_flexible_server` (Boolean) Explicitly force Azure Flexible Server mode. Auto-detected when omitted (via hostname, `azure_pg_admin`, `pgaadauth`, or `azure.extensions`).
- `superuser` (Boolean) Override whether the connecting role has PostgreSQL `SUPERUSER`. Auto-detected when omitted.
- `auto_grant_role_membership` (Boolean) Automatically grant and revoke temporary `WITH SET TRUE, INHERIT TRUE` membership in target roles during ownership and default-privilege operations when running as non-superuser `azure_pg_admin`. Defaults to `true`.
