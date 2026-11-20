---
page_title: "pgazureflex_server_info Data Source"
subcategory: "Data Sources"
description: |-
  Inspects live PostgreSQL and Azure Flexible Server capabilities, azure.extensions, shared_preload_libraries, pgaadauth, and TLS status.
---

# `pgazureflex_server_info` (Data Source)

Reads live server version, privilege level, TLS cipher/protocol, and Azure Flexible Server capabilities (`azure.extensions`, `shared_preload_libraries`, `pgaadauth` availability).

## Example Usage

```hcl
data "pgazureflex_server_info" "this" {}

output "pg_capabilities" {
  value = {
    version            = data.pgazureflex_server_info.this.version_string
    is_azure_flex      = data.pgazureflex_server_info.this.is_azure_flexible_server
    allowed_extensions = data.pgazureflex_server_info.this.allowed_extensions
    tls                = data.pgazureflex_server_info.this.ssl_version
  }
}
```

## Schema

### Read-Only

- `id` (String) Configured PostgreSQL host.
- `version_num` (Number) Numeric PostgreSQL server version (e.g. `160004`).
- `version_string` (String) Full output of `SELECT version()`.
- `current_user` (String) Authenticated PostgreSQL role name.
- `is_superuser` (Boolean) Whether `current_user` has `SUPERUSER`.
- `is_azure_pg_admin` (Boolean) Whether `current_user` is a member of `azure_pg_admin`.
- `is_azure_flexible_server` (Boolean) Whether the server is detected as Azure Database for PostgreSQL Flexible Server.
- `has_pgaadauth` (Boolean) Whether `pgaadauth` Entra ID functions are available.
- `allowed_extensions` (List of String) Extensions listed in the `azure.extensions` server parameter.
- `shared_preload_libraries` (List of String) Libraries listed in `shared_preload_libraries`.
- `ssl_in_use` (Boolean) Whether the current connection is TLS-encrypted.
- `ssl_version` (String) Negotiated TLS version (e.g. `TLSv1.3`).
- `ssl_cipher` (String) Negotiated TLS cipher suite.
