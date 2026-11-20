terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    pgazureflex = {
      source  = "registry.terraform.io/ytseboy/pgazureflex"
      version = "~> 0.1"
    }
  }
}

provider "azurerm" {
  features {}
}

# 1. Provision Azure Database for PostgreSQL Flexible Server with Entra ID enabled
#    and allow-listed extensions.
resource "azurerm_resource_group" "db" {
  name     = "rg-orders-pg-prod"
  location = "eastus2"
}

resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "pg-orders-prod-01"
  resource_group_name    = azurerm_resource_group.db.name
  location               = azurerm_resource_group.db.location
  version                = "16"
  sku_name               = "GP_Standard_D2ds_v5"
  storage_mb             = 65536
  administrator_login    = "pgadmin"
  administrator_password = var.pg_admin_password

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = true
    tenant_id                     = var.azure_tenant_id
  }
}

resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "PGCRYPTO,UUID-OSSP,VECTOR,PG_STAT_STATEMENTS"
}

resource "azurerm_postgresql_flexible_server_configuration" "wal_level" {
  name      = "wal_level"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "logical"
}

# 2. Configure the pgazureflex provider using Microsoft Entra ID (DefaultAzureCredential)
#    with automatic TLS (`sslmode = "require"`) and automatic `azure_pg_admin` role
#    impersonation (`auto_grant_role_membership = true`).
provider "pgazureflex" {
  host                       = azurerm_postgresql_flexible_server.main.fqdn
  port                       = 5432
  database                   = "postgres"
  username                   = var.entra_admin_principal_name
  auth_mode                  = "azure_default" # or azure_managed_identity / azure_workload_identity / azure_cli
  azure_tenant_id            = var.azure_tenant_id
  sslmode                    = "verify-full"
  auto_grant_role_membership = true
}

# 3. Inspect live Flexible Server capabilities & allow-listed extensions
data "pgazureflex_server_info" "this" {}

# 4. Create logical NOLOGIN group roles for RBAC separation
resource "pgazureflex_role" "orders_owner" {
  name  = "orders_owner"
  login = false
}

resource "pgazureflex_role" "orders_rw" {
  name  = "orders_rw"
  login = false
}

resource "pgazureflex_role" "orders_ro" {
  name  = "orders_ro"
  login = false
}

# 5. Register Microsoft Entra ID identities via `pgaadauth_create_principal_with_oid`
#    (No outbound Microsoft Graph lookup required — works cleanly in private VNets!)
resource "pgazureflex_entra_role" "orders_api_mi" {
  name             = "mi-orders-api-prod"
  object_id        = var.orders_api_managed_identity_oid
  principal_type   = "service"
  is_admin         = false
  connection_limit = 100
  roles            = [pgazureflex_role.orders_rw.name]

  parameters = {
    statement_timeout                   = "30s"
    idle_in_transaction_session_timeout = "60s"
  }

  reassign_owned_to = pgazureflex_role.orders_owner.name
}

resource "pgazureflex_entra_role" "analytics_group" {
  name           = "sg-data-analysts"
  object_id      = var.analysts_entra_group_oid
  principal_type = "group"
  is_admin       = false
  is_mfa         = true
}

# 5b. Entra-to-Postgres Role Mappings:
#     (A) Decoupled RBAC mapping: grant PostgreSQL group role `orders_ro` to Entra group `sg-data-analysts`
resource "pgazureflex_role_membership" "analysts_orders_ro" {
  role                = pgazureflex_role.orders_ro.name
  member_role         = pgazureflex_entra_role.analytics_group.name
  with_inherit_option = true
  with_set_option     = false
}

#     (B) Identity binding via `SECURITY LABEL FOR "pgaadauth"`:
#         Bind an Entra Managed Identity directly onto an existing PostgreSQL role
#         (supports zero-downtime password -> Entra migration and in-place OID rotation!)
resource "pgazureflex_role" "legacy_worker" {
  name  = "svc_orders_worker"
  login = true
}

resource "pgazureflex_entra_role_mapping" "legacy_worker_mi" {
  role           = pgazureflex_role.legacy_worker.name
  object_id      = var.orders_worker_managed_identity_oid
  principal_type = "service"
  is_admin       = false
  ensure_login   = true
  postgres_roles = [pgazureflex_role.orders_rw.name]
}

# 6. Provision application database owned by `orders_owner`
#    (Provider automatically manages temporary `azure_pg_admin` -> `orders_owner` membership!)
resource "pgazureflex_database" "orders" {
  name             = "orders"
  owner            = pgazureflex_role.orders_owner.name
  connection_limit = 500
  force_drop       = false

  parameters = {
    work_mem = "16MB"
    timezone = "UTC"
  }
}

# 7. Provision dedicated schema & install allow-listed Azure extensions
resource "pgazureflex_schema" "core" {
  database             = pgazureflex_database.orders.name
  name                 = "core"
  owner                = pgazureflex_role.orders_owner.name
  revoke_public_create = true
}

resource "pgazureflex_extension" "pgcrypto" {
  database = pgazureflex_database.orders.name
  name     = "pgcrypto"
  schema   = pgazureflex_schema.core.name
}

resource "pgazureflex_extension" "vector" {
  database = pgazureflex_database.orders.name
  name     = "vector"
  schema   = pgazureflex_schema.core.name
}

# 8. Least-privilege grants + Default Privileges for future migrations
resource "pgazureflex_grant" "db_connect_rw" {
  database    = pgazureflex_database.orders.name
  role        = pgazureflex_role.orders_rw.name
  object_type = "database"
  privileges  = ["CONNECT"]
}

resource "pgazureflex_grant" "schema_usage_rw" {
  database    = pgazureflex_database.orders.name
  role        = pgazureflex_role.orders_rw.name
  object_type = "schema"
  schema      = pgazureflex_schema.core.name
  privileges  = ["USAGE"]
}

resource "pgazureflex_default_privileges" "future_tables_rw" {
  database    = pgazureflex_database.orders.name
  owner       = pgazureflex_role.orders_owner.name
  schema      = pgazureflex_schema.core.name
  role        = pgazureflex_role.orders_rw.name
  object_type = "table"
  privileges  = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}

resource "pgazureflex_default_privileges" "future_tables_ro" {
  database    = pgazureflex_database.orders.name
  owner       = pgazureflex_role.orders_owner.name
  schema      = pgazureflex_schema.core.name
  role        = pgazureflex_role.orders_ro.name
  object_type = "table"
  privileges  = ["SELECT"]
}

# 9. Logical replication publication for downstream CDC
resource "pgazureflex_publication" "cdc" {
  database      = pgazureflex_database.orders.name
  name          = "orders_cdc_pub"
  all_tables    = true
  publish_param = ["insert", "update", "delete"]
}

variable "azure_tenant_id" { type = string }
variable "entra_admin_principal_name" { type = string }
variable "orders_api_managed_identity_oid" { type = string }
variable "orders_worker_managed_identity_oid" { type = string }
variable "analysts_entra_group_oid" { type = string }
variable "pg_admin_password" {
  type      = string
  sensitive = true
}

output "server_capabilities" {
  value = {
    version            = data.pgazureflex_server_info.this.version_string
    is_azure_flex      = data.pgazureflex_server_info.this.is_azure_flexible_server
    allowed_extensions = data.pgazureflex_server_info.this.allowed_extensions
    tls_version        = data.pgazureflex_server_info.this.ssl_version
  }
}
