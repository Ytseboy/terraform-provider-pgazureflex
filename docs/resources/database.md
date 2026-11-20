---
page_title: "pgazureflex_database Resource"
subcategory: "Resources"
description: |-
  Manages a PostgreSQL database with azure_pg_admin ownership support, in-place rename, ALTER DATABASE SET parameters, and force_drop.
---

# `pgazureflex_database` (Resource)

Manages a PostgreSQL database. Automatically handles temporary `azure_pg_admin` role membership when assigning `owner` to another role on Azure Flexible Server, and evicts provider connection pools targeting the database prior to `DROP DATABASE`.

## Example Usage

```hcl
resource "pgazureflex_database" "orders" {
  name             = "orders"
  owner            = pgazureflex_role.orders_owner.name
  encoding         = "UTF8"
  connection_limit = 500
  force_drop       = false

  parameters = {
    work_mem = "16MB"
    timezone = "UTC"
  }
}
```

## Schema

### Required

- `name` (String) Database name. Updating this renames the database in-place via `ALTER DATABASE ... RENAME TO`.

### Optional

- `owner` (String) Role that owns the database. Defaults to the connecting user.
- `template` (String) Template database (e.g. `template0` or `template1`). Forces replacement if changed.
- `encoding` (String) Character set encoding (e.g. `UTF8`). Forces replacement if changed.
- `lc_collate` (String) Collation order (`LC_COLLATE`). Forces replacement if changed.
- `lc_ctype` (String) Character classification (`LC_CTYPE`). Forces replacement if changed.
- `tablespace_name` (String) Default tablespace name.
- `connection_limit` (Number) Maximum concurrent connections (`-1` for unlimited). Defaults to `-1`.
- `is_template` (Boolean) If `true`, database can be cloned by any user with `CREATEDB`. Defaults to `false`.
- `allow_connections` (Boolean) If `false`, no connections are permitted. Defaults to `true`.
- `force_drop` (Boolean) When `true`, terminates active connections via `DROP DATABASE ... WITH (FORCE)` (PG 13+) during destroy. Defaults to `false`.
- `parameters` (Map of String) Database-level configuration parameters managed via `ALTER DATABASE ... SET key = value` / `RESET key`.

### Read-Only

- `id` (String) Resource identifier (matches `name`).

## Import

```bash
terraform import pgazureflex_database.orders orders
```
