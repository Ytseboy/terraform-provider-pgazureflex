---
page_title: "pgazureflex_role_database_parameters Resource"
subcategory: "Resources"
description: |-
  Manages PostgreSQL role-in-database parameters (ALTER ROLE <role> IN DATABASE <database> SET <param> = <value>) via pg_db_role_setting.
---

# `pgazureflex_role_database_parameters` (Resource)

Manages PostgreSQL role-in-database configuration parameters (`ALTER ROLE <role> IN DATABASE <database> SET <param> = <value>`), backed by `pg_db_role_setting`.

Supports both standard PostgreSQL GUCs (`statement_timeout`, `default_transaction_read_only`, `search_path`) and dot-qualified extension GUCs (such as `pgaudit.log = "write, ddl, role"` for per-database auditing of specific Entra ID groups or roles).

## Example Usage

```hcl
resource "pgazureflex_role_database_parameters" "consultants_audit" {
  database = "tenant_alpha"
  role     = pgazureflex_entra_role.consultants_group.name

  parameters = {
    "pgaudit.log"       = "write, ddl, role"
    "statement_timeout" = "30s"
  }
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `role` (String) Target PostgreSQL role or Entra ID principal name. Forces replacement if changed.
- `parameters` (Map of String) Map of parameter names to values applied specifically when `role` connects to `database`.

### Read-Only

- `id` (String) Resource identifier in format `<database>:<role>`.

## Import

```bash
terraform import pgazureflex_role_database_parameters.consultants_audit tenant_alpha:sg-consultants
```
