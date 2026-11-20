# Example: Multi-tenant Production & UAT PostgreSQL RBAC on Azure Flexible Server
# Demonstrates the 3-identity-per-tenant pattern (migrator, app, agent) + MFA read-only group.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    pgazureflex = {
      source  = "registry.terraform.io/ytseboy/pgazureflex"
      version = "~> 0.1"
    }
  }
}

provider "pgazureflex" {
  host                       = "contoso-pg-prod.postgres.database.azure.com"
  port                       = 5432
  database                   = "postgres"
  username                   = "sg-pg-prod-admins"
  auth_mode                  = "azure_default" # Workload Identity in CI or azure_cli over VPN
  azure_tenant_id            = "00000000-0000-0000-0000-000000000000"
  sslmode                    = "verify-full"
  auto_grant_role_membership = true
}

module "tenant_alpha_prod_rbac" {
  source   = "../modules/pg-tenant-rbac"
  database = "tenant_alpha_prod"
  schemas  = ["public"]

  migrator_identity = {
    name              = "mi-tenant-alpha-prod"
    object_id         = "11111111-1111-1111-1111-111111111111"
    connection_limit  = 10
    statement_timeout = "300s"
  }

  app_identity = {
    name              = "mi-tenant-alpha-prod-app"
    object_id         = "22222222-2222-2222-2222-222222222222"
    connection_limit  = 100
    statement_timeout = "30s"
  }

  agent_identity = {
    name              = "mi-tenant-alpha-prod-agent"
    object_id         = "33333333-3333-3333-3333-333333333333"
    connection_limit  = 30
    statement_timeout = "120s"
  }

  readonly_entra_groups = {
    "sg-support-readers" = {
      object_id = "44444444-4444-4444-4444-444444444444"
      is_mfa    = true
    }
  }
}

module "tenant_alpha_uat_rbac" {
  source   = "../modules/pg-tenant-rbac"
  database = "tenant_alpha_uat"
  schemas  = ["public"]

  migrator_identity = {
    name              = "mi-tenant-alpha-uat"
    object_id         = "55555555-5555-5555-5555-555555555555"
    connection_limit  = 10
    statement_timeout = "300s"
  }

  app_identity = {
    name              = "mi-tenant-alpha-uat-app"
    object_id         = "66666666-6666-6666-6666-666666666666"
    connection_limit  = 50
    statement_timeout = "30s"
  }

  agent_identity = {
    name              = "mi-tenant-alpha-uat-agent"
    object_id         = "77777777-7777-7777-7777-777777777777"
    connection_limit  = 20
    statement_timeout = "120s"
  }
}

# Optional: Zero-downtime binding for a pre-existing PostgreSQL role that already owns tables:
#
# resource "pgazureflex_entra_role_mapping" "legacy_app_binding" {
#   role           = "legacy_app"
#   object_id      = "22222222-2222-2222-2222-222222222222"
#   principal_type = "service"
#   ensure_login   = true
#   postgres_roles = ["tenant_alpha_prod_app_rw"]
# }
