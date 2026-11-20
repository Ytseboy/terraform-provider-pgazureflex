---
page_title: "pgazureflex_entra_principals Data Source"
subcategory: "Data Sources"
description: |-
  Lists Microsoft Entra ID principals registered in Azure Flexible Server via pgaadauth_list_principals.
---

# `pgazureflex_entra_principals` (Data Source)

Lists Microsoft Entra ID Users, Groups, Managed Identities, and Service Principals registered in Azure Flexible Server via `pgaadauth_list_principals(false)`.

## Example Usage

```hcl
data "pgazureflex_entra_principals" "admins" {
  admins_only = true
}

output "entra_admin_names" {
  value = [for p in data.pgazureflex_entra_principals.admins.principals : p.name]
}
```

## Schema

### Optional

- `admins_only` (Boolean) If `true`, return only principals that hold `azure_pg_admin`. Defaults to `false`.

### Read-Only

- `id` (String) Configured PostgreSQL host.
- `principals` (List of Object) Registered Entra ID principals:
  - `name` (String) PostgreSQL role name.
  - `object_id` (String) Microsoft Entra ID Object ID (UUID).
  - `principal_type` (String) `user`, `group`, or `service`.
  - `is_admin` (Boolean) Whether the principal holds `azure_pg_admin`.
  - `is_mfa` (Boolean) Whether Entra MFA is enforced.
