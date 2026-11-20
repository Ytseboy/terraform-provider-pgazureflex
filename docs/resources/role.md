---
page_title: "pgazureflex_role Resource"
subcategory: "Resources"
description: |-
  Manages a native PostgreSQL role (login user or NOLOGIN RBAC group role).
---

# `pgazureflex_role` (Resource)

Manages a native PostgreSQL role (either a `NOLOGIN` RBAC group role or a password-authenticated `LOGIN` role). For Microsoft Entra ID identities on Azure Flexible Server, prefer `pgazureflex_entra_role` or `pgazureflex_entra_role_mapping`.

## Example Usage

```hcl
resource "pgazureflex_role" "orders_rw" {
  name  = "orders_rw"
  login = false
}

resource "pgazureflex_role" "migration_user" {
  name              = "orders_migrator_svc"
  login             = true
  password          = var.migration_password
  connection_limit  = 10
  roles             = [pgazureflex_role.orders_rw.name]
  reassign_owned_to = "orders_owner"

  parameters = {
    statement_timeout = "120s"
  }
}
```

## Schema

### Required

- `name` (String) PostgreSQL role name. Updating this renames the role in-place via `ALTER ROLE ... RENAME TO`.

### Optional

- `login` (Boolean) Whether the role can log in (`LOGIN` / `NOLOGIN`). Defaults to `false`.
- `superuser` (Boolean) Whether the role is a PostgreSQL `SUPERUSER`. Defaults to `false`. Rejected cleanly on non-superuser servers (use `roles = ["azure_pg_admin"]` instead).
- `create_db` (Boolean) Grant `CREATEDB`. Defaults to `false`.
- `create_role` (Boolean) Grant `CREATEROLE`. Defaults to `false`.
- `inherit` (Boolean) Grant `INHERIT`. Defaults to `true`.
- `replication` (Boolean) Grant `REPLICATION`. Defaults to `false`.
- `bypass_rls` (Boolean) Grant `BYPASSRLS`. Defaults to `false`.
- `connection_limit` (Number) Maximum concurrent connections (`-1` for unlimited). Defaults to `-1`.
- `valid_until` (String) Password expiration timestamp (RFC3339 or `infinity`).
- `password` (String, Sensitive) Role password. Applied on creation and whenever changed in configuration.
- `roles` (Set of String) Group roles granted to this role. For decoupled cross-module management, prefer `pgazureflex_role_membership`.
- `parameters` (Map of String) Role-level PostgreSQL settings (`ALTER ROLE ... SET key = value`).
- `reassign_owned_to` (String) Role to execute `REASSIGN OWNED BY <name> TO <target>` against before dropping this role.
- `drop_owned` (Boolean) Run `DROP OWNED BY <name>` before dropping this role. Defaults to `false`.

### Read-Only

- `id` (String) Resource identifier (matches `name`).

## Import

```bash
terraform import pgazureflex_role.orders_rw orders_rw
```
