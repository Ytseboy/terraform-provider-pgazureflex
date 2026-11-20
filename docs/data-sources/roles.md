---
page_title: "pgazureflex_roles Data Source"
subcategory: "Data Sources"
description: |-
  Lists PostgreSQL roles, attributes, and role memberships.
---

# `pgazureflex_roles` (Data Source)

Lists PostgreSQL roles along with their attributes and direct role memberships (`pg_auth_members`).

## Example Usage

```hcl
data "pgazureflex_roles" "non_system" {
  include_system = false
}

output "role_memberships" {
  value = { for r in data.pgazureflex_roles.non_system.roles : r.name => r.member_of }
}
```

## Schema

### Optional

- `include_system` (Boolean) Include built-in `pg_*` and Azure internal (`azuresu`, `replication`) roles. Defaults to `false`.

### Read-Only

- `id` (String) Configured PostgreSQL host.
- `roles` (List of Object):
  - `name` (String)
  - `login` (Boolean)
  - `superuser` (Boolean)
  - `create_db` (Boolean)
  - `create_role` (Boolean)
  - `inherit` (Boolean)
  - `replication` (Boolean)
  - `bypass_rls` (Boolean)
  - `connection_limit` (Number)
  - `member_of` (List of String)
