---
page_title: "pgazureflex_extension Resource"
subcategory: "Resources"
description: |-
  Manages a PostgreSQL extension with Azure Flexible Server azure.extensions and shared_preload_libraries diagnostics.
---

# `pgazureflex_extension` (Resource)

Manages a PostgreSQL extension inside a target database. On Azure Flexible Server, automatically handles database-owner membership and enriches allowlist errors with live `azure.extensions` and `shared_preload_libraries` remediation diagnostics.

## Example Usage

```hcl
resource "pgazureflex_extension" "pgcrypto" {
  database = pgazureflex_database.orders.name
  name     = "pgcrypto"
  schema   = pgazureflex_schema.core.name
}

resource "pgazureflex_extension" "vector" {
  database = pgazureflex_database.orders.name
  name     = "vector"
  schema   = "public"
  cascade  = false
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `name` (String) Extension name (e.g. `pgcrypto`, `uuid-ossp`, `vector`, `postgis`, `pg_stat_statements`, `pgaudit`). Forces replacement if changed.

### Optional

- `schema` (String) Target schema. Updating moves the extension in-place via `ALTER EXTENSION ... SET SCHEMA`.
- `version` (String) Specific extension version. Updating upgrades via `ALTER EXTENSION ... UPDATE TO`.
- `cascade` (Boolean) Automatically install dependent extensions (`CREATE EXTENSION ... CASCADE`). Defaults to `false`.
- `drop_cascade` (Boolean) Drop dependent objects (`DROP EXTENSION ... CASCADE`) on destroy. Defaults to `false`.

### Read-Only

- `id` (String) Resource identifier in format `<database>.<name>`.

## Import

```bash
terraform import pgazureflex_extension.pgcrypto orders.pgcrypto
```
