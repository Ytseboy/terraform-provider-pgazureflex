---
page_title: "pgazureflex_default_privileges Resource"
subcategory: "Resources"
description: |-
  Manages PostgreSQL ALTER DEFAULT PRIVILEGES entries with automatic azure_pg_admin FOR ROLE membership handling.
---

# `pgazureflex_default_privileges` (Resource)

Manages PostgreSQL `ALTER DEFAULT PRIVILEGES FOR ROLE <owner> [IN SCHEMA <schema>] GRANT ... TO <role>` entries. Automatically wraps `FOR ROLE <owner>` in temporary `azure_pg_admin` role membership on Azure Flexible Server and reads live state directly from `pg_default_acl`.

## Example Usage

```hcl
resource "pgazureflex_default_privileges" "future_tables_rw" {
  database    = pgazureflex_database.orders.name
  owner       = pgazureflex_role.orders_owner.name
  schema      = "core"
  role        = pgazureflex_role.orders_app_rw.name
  object_type = "table"
  privileges  = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}

resource "pgazureflex_default_privileges" "future_sequences_rw" {
  database    = pgazureflex_database.orders.name
  owner       = pgazureflex_role.orders_owner.name
  schema      = "core"
  role        = pgazureflex_role.orders_app_rw.name
  object_type = "sequence"
  privileges  = ["USAGE", "SELECT", "UPDATE"]
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `owner` (String) Role whose future created objects receive these default privileges (`FOR ROLE <owner>`). Forces replacement if changed.
- `role` (String) Grantee role name (or `PUBLIC`). Forces replacement if changed.
- `object_type` (String) One of `table`, `sequence`, `function`, `type`, or `schema`. Forces replacement if changed.
- `privileges` (Set of String) Set of default privileges to grant.

### Optional

- `schema` (String) Optional schema scope (`IN SCHEMA <schema>`). Omit to apply database-wide for `owner`. Forces replacement if changed.
- `with_grant_option` (Boolean) Include `WITH GRANT OPTION`. Defaults to `false`.

### Read-Only

- `id` (String) Deterministic composite resource identifier.
