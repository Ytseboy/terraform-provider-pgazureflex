---
page_title: "pgazureflex_schema Resource"
subcategory: "Resources"
description: |-
  Manages a PostgreSQL schema inside a database with azure_pg_admin ownership support and optional PUBLIC hardening.
---

# `pgazureflex_schema` (Resource)

Manages a PostgreSQL schema inside a specific database. Automatically handles temporary `azure_pg_admin` role membership when assigning `owner` to another role on Azure Flexible Server.

## Example Usage

```hcl
resource "pgazureflex_schema" "core" {
  database             = pgazureflex_database.orders.name
  name                 = "core"
  owner                = pgazureflex_role.orders_owner.name
  revoke_public_create = true
  drop_cascade         = false
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `name` (String) Schema name. Updating this renames the schema in-place via `ALTER SCHEMA ... RENAME TO`.

### Optional

- `owner` (String) Role that owns the schema. Defaults to the connecting user.
- `if_not_exists` (Boolean) Emit `CREATE SCHEMA IF NOT EXISTS`. Defaults to `true`.
- `drop_cascade` (Boolean) Drop contained objects via `DROP SCHEMA ... CASCADE` on destroy. Defaults to `false`.
- `revoke_public_create` (Boolean) Execute `REVOKE CREATE ON SCHEMA <name> FROM PUBLIC`. Defaults to `false`.

### Read-Only

- `id` (String) Resource identifier in format `<database>.<name>`.

## Import

```bash
terraform import pgazureflex_schema.core orders.core
```
