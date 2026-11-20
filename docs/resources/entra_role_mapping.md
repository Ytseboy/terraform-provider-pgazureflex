---
page_title: "pgazureflex_entra_role_mapping Resource"
subcategory: "Resources"
description: |-
  Maps a Microsoft Entra ID identity onto an existing PostgreSQL role via SECURITY LABEL FOR "pgaadauth" with in-place OID rotation and non-destructive teardown.
---

# `pgazureflex_entra_role_mapping` (Resource)

Maps a Microsoft Entra ID identity (`object_id`, `principal_type`, `is_admin`, `is_mfa`) onto an **existing** PostgreSQL role using Azure Flexible Server's native `pgaadauth` security label:

```sql
SECURITY LABEL FOR "pgaadauth" ON ROLE "<role>"
  IS 'aadauth,oid=<object_id>,type=<user|group|service>[,admin][,mfa]';
```

### When to Use `pgazureflex_entra_role_mapping` vs. `pgazureflex_entra_role`
- Use **`pgazureflex_entra_role_mapping`** when you want to **migrate an existing PostgreSQL role** from password auth to Entra ID without dropping it or losing object ownership, map an Entra identity to a **custom PostgreSQL role name**, or **rotate `object_id` in-place** (e.g., recreating a Managed Identity).
- On destroy, executes `SECURITY LABEL FOR "pgaadauth" ON ROLE "<role>" IS NULL` and revokes only the roles in `postgres_roles`, leaving the underlying PostgreSQL role and its owned objects intact.

## Example Usage

```hcl
resource "pgazureflex_entra_role_mapping" "billing_worker" {
  role           = pgazureflex_role.legacy_worker.name
  object_id      = azurerm_user_assigned_identity.worker.principal_id
  principal_type = "service"
  is_admin       = false
  is_mfa         = false
  ensure_login   = true
  postgres_roles = ["orders_app_rw"]
}
```

## Schema

### Required

- `role` (String) Existing PostgreSQL role name to bind. Forces replacement if changed.
- `object_id` (String) Microsoft Entra ID Object ID (UUID). **Updates in-place** without dropping the PostgreSQL role.

### Optional

- `principal_type` (String) Entra ID principal type: `user` (default), `group`, or `service`. Updates in-place.
- `is_admin` (Boolean) Include `,admin` in the security label and grant `azure_pg_admin`. Defaults to `false`.
- `is_mfa` (Boolean) Include `,mfa` in the security label to enforce Entra ID MFA. Defaults to `false`.
- `ensure_login` (Boolean) Automatically runs `ALTER ROLE <role> WITH LOGIN` if the target role is currently `NOLOGIN`. Defaults to `true`.
- `postgres_roles` (Set of String) Optional set of PostgreSQL RBAC group roles granted to the mapped role (diffed and revoked cleanly without touching unrelated memberships).

### Read-Only

- `id` (String) Resource identifier (matches `role`).
- `security_label` (String) Canonical `pgaadauth` security label computed at plan time and verified against `pg_shseclabel` (e.g. `aadauth,oid=...,type=service`).

## Import

```bash
terraform import pgazureflex_entra_role_mapping.billing_worker svc_orders_worker
```
