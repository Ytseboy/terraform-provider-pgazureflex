---
page_title: "Guide: Production Multi-Tenant RBAC on Azure Flexible Server"
subcategory: "Guides"
description: |-
  Designing least-privilege multi-tenant PostgreSQL roles, PostgreSQL 16+ azure_pg_admin workflows, and zero-downtime Entra migrations.
---

# Production Multi-Tenant RBAC Guide

On a shared Azure Database for PostgreSQL Flexible Server hosting multiple customer or service databases, follow a 5-tier NOLOGIN RBAC pattern per database and bind Microsoft Entra ID principals cleanly via `pgazureflex_role_membership` or `pgazureflex_entra_role_mapping`.

## 5-Tier Per-Database Role Model

| Role | Login | Purpose | PostgreSQL 16+ Membership |
|---|---|---|---|
| `<db>_owner` | `NOLOGIN` | Owns the database, schemas, and all DDL objects | Target of `SET ROLE` from migrator |
| `<db>_migrator` | `NOLOGIN` | Granted to CI/migration Managed Identity | `INHERIT TRUE, SET TRUE` into `<db>_owner` |
| `<db>_app_rw` | `NOLOGIN` | Runtime DML (`SELECT, INSERT, UPDATE, DELETE` + sequences) | `INHERIT TRUE, SET FALSE` |
| `<db>_agent_rw` | `NOLOGIN` | Background worker DML with separate `connection_limit` & `statement_timeout` | `INHERIT TRUE, SET FALSE` |
| `<db>_ro` | `NOLOGIN` | Read-only (`SELECT`) for support/analytics Entra groups (`is_mfa = true`) | `INHERIT TRUE, SET FALSE` |

### Why Separate `owner` and `migrator`?
When multiple engineers or CI pipelines run schema migrations directly as their own login roles, tables end up owned by different roles and `ALTER DEFAULT PRIVILEGES` breaks. Giving the migration identity `with_set_option = true` into `<db>_owner` lets migrations execute `SET ROLE <db>_owner;` so every table/sequence is owned consistently and automatically inherits `pgazureflex_default_privileges`.

## How `pgazureflex` Handles PostgreSQL 16+ `azure_pg_admin`

On Azure Flexible Server, server administrators are members of `azure_pg_admin`, **not** `SUPERUSER`. In PostgreSQL 16+, creating a role only grants `ADMIN OPTION` with `SET FALSE, INHERIT FALSE` to the creator — causing `CREATE DATABASE ... OWNER TO`, `CREATE SCHEMA ... AUTHORIZATION`, and `ALTER DEFAULT PRIVILEGES FOR ROLE` to fail with `SQLSTATE 42501`.

With `auto_grant_role_membership = true` (default), `pgazureflex` automatically:
1. Checks `pg_auth_members` (`set_option`, `inherit_option`).
2. Grants temporary `WITH SET TRUE, INHERIT TRUE` serialized behind an internal mutex.
3. Executes the DDL operation.
4. Revokes **only** the temporary options it added (`REVOKE SET OPTION` / `REVOKE INHERIT OPTION`), strictly preserving pre-existing `ADMIN OPTION` rows and leaving zero leaked privileges.

## Zero-Downtime Password → Entra ID Migration

If a production database already has a legacy PostgreSQL role owning tables (`legacy_app`), do **not** drop and recreate it with `pgazureflex_entra_role`. Instead, use `pgazureflex_entra_role_mapping`:

```hcl
resource "pgazureflex_entra_role_mapping" "migrate_legacy_app" {
  role           = "legacy_app"
  object_id      = azurerm_user_assigned_identity.app.principal_id
  principal_type = "service"
  ensure_login   = true
  postgres_roles = ["orders_app_rw"]
}
```

This applies `SECURITY LABEL FOR "pgaadauth" ON ROLE "legacy_app" IS 'aadauth,oid=...,type=service'` in-place. Rotating `object_id` later updates the label in-place with zero downtime, and destroying the mapping runs `IS NULL` without dropping `legacy_app` or its tables.

See complete runnable examples in:
- [examples/modules/pg-tenant-rbac/main.tf](../../examples/modules/pg-tenant-rbac/main.tf)
- [examples/multi-tenant-rbac/main.tf](../../examples/multi-tenant-rbac/main.tf)
- [examples/azure-flexible-server-full/main.tf](../../examples/azure-flexible-server-full/main.tf)
