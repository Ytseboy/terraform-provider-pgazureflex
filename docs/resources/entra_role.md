---
page_title: "pgazureflex_entra_role Resource"
subcategory: "Resources"
description: |-
  Manages a Microsoft Entra ID principal (User, Group, Managed Identity, or Service Principal) in Azure Flexible Server via pgaadauth.
---

# `pgazureflex_entra_role` (Resource)

Manages the full lifecycle (`pgaadauth_create_principal_with_oid` / `pgaadauth_create_principal` → `DROP ROLE`) of a Microsoft Entra ID principal in **Azure Database for PostgreSQL - Flexible Server**.

When `object_id` is provided (strongly recommended), the provider calls `pgaadauth_create_principal_with_oid`, which works reliably inside Private VNet / air-gapped servers without requiring Microsoft Graph lookups from PostgreSQL.

## Example Usage

```hcl
resource "pgazureflex_entra_role" "orders_api_mi" {
  name             = "mi-orders-api-prod"
  object_id        = "11111111-2222-3333-4444-555555555555"
  principal_type   = "service"
  is_admin         = false
  connection_limit = 100

  parameters = {
    statement_timeout                   = "30s"
    idle_in_transaction_session_timeout = "30s"
  }
}

resource "pgazureflex_entra_role" "analysts_group" {
  name           = "sg-data-analysts"
  object_id      = "22222222-3333-4444-5555-666666666666"
  principal_type = "group"
  is_admin       = false
  is_mfa         = true
}
```

## Schema

### Required

- `name` (String) PostgreSQL role name mapped to the Entra ID principal. Forces replacement if changed.

### Optional

- `object_id` (String) Microsoft Entra ID Object ID (UUID) — for Managed Identities, use `principal_id` (Object ID), not `client_id`. Forces replacement if changed.
- `principal_type` (String) Principal type: `user` (default), `group`, or `service` (Managed Identities and Service Principals). Forces replacement if changed.
- `is_admin` (Boolean) When `true`, grants `azure_pg_admin` membership. Can be updated in-place. Defaults to `false`.
- `is_mfa` (Boolean) Enforce Microsoft Entra ID Multi-Factor Authentication. Forces replacement if changed. Defaults to `false`.
- `connection_limit` (Number) Maximum concurrent connections (`-1` for unlimited). Defaults to `-1`.
- `create_db` (Boolean) Grant `CREATEDB`. Defaults to `false`.
- `create_role` (Boolean) Grant `CREATEROLE`. Defaults to `false`.
- `inherit` (Boolean) Grant `INHERIT`. Defaults to `true`.
- `bypass_rls` (Boolean) Grant `BYPASSRLS`. Defaults to `false`.
- `roles` (Set of String) Additional PostgreSQL roles granted to this principal (control `azure_pg_admin` via `is_admin` instead).
- `parameters` (Map of String) Role-level PostgreSQL settings (`ALTER ROLE ... SET key = value`).
- `reassign_owned_to` (String) Role to reassign owned objects to before dropping.
- `drop_owned` (Boolean) Run `DROP OWNED BY` before dropping. Defaults to `false`.

### Read-Only

- `id` (String) Resource identifier (matches `name`).

## Import

```bash
terraform import pgazureflex_entra_role.orders_api_mi mi-orders-api-prod
```
