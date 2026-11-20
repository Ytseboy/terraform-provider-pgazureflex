---
page_title: "pgazureflex_role_membership Resource"
subcategory: "Resources"
description: |-
  Manages a standalone PostgreSQL role membership (GRANT <role> TO <member_role>) with PostgreSQL 16+ ADMIN, INHERIT, and SET options.
---

# `pgazureflex_role_membership` (Resource)

Manages a single standalone `GRANT <role> TO <member_role>` binding. Ideal for declaratively mapping Microsoft Entra ID principals (`pgazureflex_entra_role`) to PostgreSQL RBAC roles (`pgazureflex_role`) in a decoupled IAM layer without coupling role lifecycles.

Supports PostgreSQL 16+ granular `WITH ADMIN`, `WITH INHERIT`, and `WITH SET` options with live `pg_auth_members` drift detection.

## Example Usage

```hcl
# Runtime app identity: inherits DML privileges, cannot SET ROLE
resource "pgazureflex_role_membership" "app_rw_binding" {
  role                = pgazureflex_role.orders_app_rw.name
  member_role         = pgazureflex_entra_role.orders_api_mi.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = false
}

# Migration identity: allowed to `SET ROLE orders_owner` for consistent DDL ownership
resource "pgazureflex_role_membership" "migrator_to_owner" {
  role                = pgazureflex_role.orders_owner.name
  member_role         = pgazureflex_role.orders_migrator.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = true
}
```

## Schema

### Required

- `role` (String) Target PostgreSQL RBAC role being granted. Forces replacement if changed.
- `member_role` (String) Grantee role receiving membership (e.g. an Entra principal name or another PG role). Forces replacement if changed.

### Optional

- `with_admin_option` (Boolean) Allow `member_role` to grant `role` to others (`WITH ADMIN`). Defaults to `false`.
- `with_inherit_option` (Boolean) PostgreSQL 16+: automatically inherit privileges of `role` (`WITH INHERIT`). Defaults to `true`.
- `with_set_option` (Boolean) PostgreSQL 16+: allow `SET ROLE <role>` (`WITH SET`). Defaults to `true`.

### Read-Only

- `id` (String) Resource identifier in format `<role>:<member_role>`.

## Import

```bash
terraform import pgazureflex_role_membership.app_rw_binding orders_app_rw:mi-orders-api-prod
```
