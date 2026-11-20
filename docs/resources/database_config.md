---
page_title: "pgazureflex_database_config Resource"
subcategory: "Resources"
description: |-
  Non-destructively configures ownership, PUBLIC privilege revocation, connection limits, and parameters on an existing PostgreSQL database (such as one created by azurerm_postgresql_flexible_server_database).
---

# `pgazureflex_database_config` (Resource)

Non-destructively configures an **existing** PostgreSQL database — ideal when `azurerm_postgresql_flexible_server_database` owns the ARM `CREATE`/`DROP` lifecycle and you want `pgazureflex` to manage in-PostgreSQL ownership, `PUBLIC` access hardening, `connection_limit`, and `ALTER DATABASE SET` parameters without two providers competing over database creation or deletion.

When transferring ownership (`ALTER DATABASE ... OWNER TO`), the provider automatically handles temporary `azure_pg_admin` role membership in **both** the current database owner (e.g. Azure's `administrator_login`) and the target `owner` role.

## Example Usage

```hcl
resource "azurerm_postgresql_flexible_server_database" "tenant" {
  name      = "tenant_alpha"
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "pgazureflex_database_config" "tenant" {
  database             = azurerm_postgresql_flexible_server_database.tenant.name
  owner                = pgazureflex_entra_role.tenant_owner.name
  revoke_public_access = true
  connection_limit     = 200

  parameters = {
    work_mem = "16MB"
    timezone = "UTC"
  }
}
```

## Schema

### Required

- `database` (String) Existing PostgreSQL database name. Forces replacement if changed.

### Optional

- `owner` (String) Desired PostgreSQL role or Entra ID principal that owns the database.
- `revoke_public_access` (Boolean) When `true`, executes `REVOKE ALL PRIVILEGES ON DATABASE <database> FROM PUBLIC` and detects drift if `PUBLIC` regains any database privilege (`CONNECT`, `TEMPORARY`, `CREATE`). Defaults to `false`.
- `connection_limit` (Number) Maximum concurrent connections allowed (`-1` for unlimited).
- `parameters` (Map of String) Database-level configuration parameters managed via `ALTER DATABASE ... SET` / `RESET`.

### Read-Only

- `id` (String) Resource identifier (matches `database`).

## Teardown Behavior

Destroying `pgazureflex_database_config` resets only managed `parameters`; it **never** drops the database or re-grants `PUBLIC` access.

## Import

```bash
terraform import pgazureflex_database_config.tenant tenant_alpha
```
