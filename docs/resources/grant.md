---
page_title: "pgazureflex_grant Resource"
subcategory: "Resources"
description: |-
  Manages PostgreSQL privileges (GRANT / REVOKE) with live system-catalog drift detection via aclexplode.
---

# `pgazureflex_grant` (Resource)

Declaratively manages PostgreSQL privileges (`GRANT` / `REVOKE`) on databases, schemas, tables, sequences, functions, procedures, routines, and types. Reads live ACLs from PostgreSQL system catalogs (`aclexplode`) to detect out-of-band privilege drift.

## Example Usage

```hcl
resource "pgazureflex_grant" "db_connect" {
  database    = pgazureflex_database.orders.name
  role        = pgazureflex_role.orders_app_rw.name
  object_type = "database"
  privileges  = ["CONNECT"]
}

resource "pgazureflex_grant" "schema_usage" {
  database    = pgazureflex_database.orders.name
  role        = pgazureflex_role.orders_app_rw.name
  object_type = "schema"
  schema      = "core"
  privileges  = ["USAGE"]
}

resource "pgazureflex_grant" "specific_tables_ro" {
  database    = pgazureflex_database.orders.name
  role        = pgazureflex_role.orders_ro.name
  object_type = "table"
  schema      = "core"
  objects     = ["orders", "line_items"]
  privileges  = ["SELECT"]
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `role` (String) Target grantee role name (or `PUBLIC`). Forces replacement if changed.
- `object_type` (String) One of `database`, `schema`, `table`, `sequence`, `function`, `procedure`, `routine`, or `type`. Forces replacement if changed.
- `privileges` (Set of String) Set of PostgreSQL privileges to grant (`ALL` / `ALL PRIVILEGES` and `TEMP` are automatically normalized). Valid privileges by type:
  - `database`: `CONNECT`, `CREATE`, `TEMPORARY`
  - `schema`: `CREATE`, `USAGE`
  - `table`: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`
  - `sequence`: `USAGE`, `SELECT`, `UPDATE`
  - `function` / `procedure` / `routine`: `EXECUTE`
  - `type`: `USAGE`

### Optional

- `schema` (String) Target schema name. Required for all object types except `database`. Forces replacement if changed.
- `objects` (Set of String) Specific object names inside `schema`. Required for `type`; cannot be set for `database` or `schema`. If omitted for `table`/`sequence`/`function`/`procedure`/`routine`, grants apply to `ALL <OBJECTS> IN SCHEMA`. Function/procedure names may include argument signatures (e.g. `calc_total(integer)`). Forces replacement if changed.
- `with_grant_option` (Boolean) Include `WITH GRANT OPTION`. Defaults to `false`.

### Read-Only

- `id` (String) Deterministic composite resource identifier.
