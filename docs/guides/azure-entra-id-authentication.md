---
page_title: "Guide: Microsoft Entra ID Authentication"
subcategory: "Guides"
description: |-
  Configuring Microsoft Entra ID authentication, token refresh, sovereign clouds, and Private VNet deployments.
---

# Microsoft Entra ID Authentication Guide

Azure Database for PostgreSQL Flexible Server authenticates Microsoft Entra ID principals by accepting a short-lived OAuth2 JWT scoped to `https://ossrdbms-aad.database.windows.net/.default` as the PostgreSQL connection password over TLS.

`pgazureflex` acquires, caches, and proactively refreshes tokens (5 minutes before expiry) inside `pgxpool.Config.BeforeConnect` on every new physical connection.

## Choosing an `auth_mode`

| Environment | Recommended `auth_mode` | Required Attributes |
|---|---|---|
| AKS / Kubernetes Pod with Workload Identity | `azure_workload_identity` or `azure_default` | `username`, `azure_tenant_id`, `azure_client_id` (or pod env vars) |
| Azure VM / Container Apps / App Service | `azure_managed_identity` | `username` (+ `azure_client_id` for User-Assigned MI) |
| Local developer over VPN (`az login`) | `azure_cli` or `azure_default` | `username`, `azure_tenant_id` |
| GitHub Actions / Azure DevOps (SP secret) | `azure_client_secret` | `username`, `azure_tenant_id`, `azure_client_id`, `azure_client_secret` |
| GitHub Actions / OIDC external token | `access_token` | `username`, `azure_access_token` |

> **Important**: `username` must match the **PostgreSQL role name** registered in `pgaadauth` (e.g., an Entra admin group name like `sg-pg-admins` or a Managed Identity name like `mi-terraform-runner`), **not** the client ID UUID.

## Private VNet / `publicNetworkAccess = Disabled`

When your Azure Flexible Server is deployed into a private VNet without outbound internet access:

1. Run Terraform from a runner inside the VNet (e.g., AKS Workload Identity pod, self-hosted runner VM, or VPN-connected developer workstation).
2. Always set `object_id` (`principalId` of the Managed Identity, User, or Entra Security Group) on `pgazureflex_entra_role` and `pgazureflex_entra_role_mapping`. This invokes `pgaadauth_create_principal_with_oid(...)` / `SECURITY LABEL FOR "pgaadauth"`, requiring **zero** outbound Microsoft Graph calls from PostgreSQL.

## Sovereign Clouds

Set `azure_cloud` to automatically select the right Entra ID authority and PostgreSQL OAuth2 scope:

| `azure_cloud` | Automatic Token Scope |
|---|---|
| `public` (default) | `https://ossrdbms-aad.database.windows.net/.default` |
| `usgovernment` | `https://ossrdbms-aad.database.usgovcloudapi.net/.default` |
| `china` | `https://ossrdbms-aad.database.chinacloudapi.cn/.default` |

## TLS / Certificate Verification

Azure Flexible Server enforces `require_secure_transport = on` by default. `pgazureflex` defaults to `sslmode = "require"`. For production, prefer `sslmode = "verify-full"` (optionally supplying Microsoft's DigiCert Global Root G2 / Microsoft RSA Root CA via `ssl_root_cert` if not present in the OS trust store).
