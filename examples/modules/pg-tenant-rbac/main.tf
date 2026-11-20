# Reusable multi-tenant PostgreSQL RBAC module for Azure Flexible Server (`pgazureflex`).
# Encapsulates a 3-identity-per-tenant least-privilege pattern:
#   - `<tenant>`       -> `<db>_migrator` (may `SET ROLE <db>_owner` for consistent DDL ownership)
#   - `<tenant>-app`   -> `<db>_app_rw`   (runtime DML only, INHERIT, no SET, no DDL)
#   - `<tenant>-agent` -> `<db>_agent_rw` (background worker DML + isolated connection/timeout caps)
#   - optional RO groups -> `<db>_ro`     (read-only, MFA-enforced Entra groups)

variable "database" {
  type        = string
  description = "Target tenant database name (e.g. tenant_alpha_prod, tenant_alpha_uat)."
}

variable "schemas" {
  type        = set(string)
  default     = ["public"]
  description = "Schemas inside `database` covered by RBAC grants & default privileges."
}

variable "migrator_identity" {
  type = object({
    name              = string
    object_id         = string
    connection_limit  = optional(number, 10)
    statement_timeout = optional(string, "300s")
  })
}

variable "app_identity" {
  type = object({
    name              = string
    object_id         = string
    connection_limit  = optional(number, 100)
    statement_timeout = optional(string, "30s")
  })
}

variable "agent_identity" {
  type = object({
    name              = string
    object_id         = string
    connection_limit  = optional(number, 30)
    statement_timeout = optional(string, "120s")
  })
}

variable "readonly_entra_groups" {
  type = map(object({
    object_id        = string
    is_mfa           = optional(bool, true)
    connection_limit = optional(number, 15)
  }))
  default = {}
}

# 1. Per-tenant NOLOGIN RBAC group roles
resource "pgazureflex_role" "owner" {
  name  = "${var.database}_owner"
  login = false
}

resource "pgazureflex_role" "migrator" {
  name  = "${var.database}_migrator"
  login = false
}

resource "pgazureflex_role" "app_rw" {
  name  = "${var.database}_app_rw"
  login = false
}

resource "pgazureflex_role" "agent_rw" {
  name  = "${var.database}_agent_rw"
  login = false
}

resource "pgazureflex_role" "ro" {
  name  = "${var.database}_ro"
  login = false
}

# Migrator may `SET ROLE <db>_owner` so all migrations create objects owned consistently by `<db>_owner`
resource "pgazureflex_role_membership" "migrator_to_owner" {
  role                = pgazureflex_role.owner.name
  member_role         = pgazureflex_role.migrator.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = true
}

# 2. Database CONNECT grants (tenant-isolated — no cross-DB access)
locals {
  connect_roles = {
    owner    = pgazureflex_role.owner.name
    migrator = pgazureflex_role.migrator.name
    app_rw   = pgazureflex_role.app_rw.name
    agent_rw = pgazureflex_role.agent_rw.name
    ro       = pgazureflex_role.ro.name
  }
}

resource "pgazureflex_grant" "db_connect" {
  for_each    = local.connect_roles
  database    = var.database
  role        = each.value
  object_type = "database"
  privileges  = ["CONNECT"]
}

# 3. Schema grants + Default Privileges for future objects created by `<db>_owner`
resource "pgazureflex_grant" "schema_usage_app" {
  for_each    = var.schemas
  database    = var.database
  role        = pgazureflex_role.app_rw.name
  object_type = "schema"
  schema      = each.value
  privileges  = ["USAGE"]
}

resource "pgazureflex_grant" "schema_usage_agent" {
  for_each    = var.schemas
  database    = var.database
  role        = pgazureflex_role.agent_rw.name
  object_type = "schema"
  schema      = each.value
  privileges  = ["USAGE"]
}

resource "pgazureflex_grant" "schema_usage_ro" {
  for_each    = var.schemas
  database    = var.database
  role        = pgazureflex_role.ro.name
  object_type = "schema"
  schema      = each.value
  privileges  = ["USAGE"]
}

resource "pgazureflex_default_privileges" "tables_app_rw" {
  for_each    = var.schemas
  database    = var.database
  owner       = pgazureflex_role.owner.name
  schema      = each.value
  role        = pgazureflex_role.app_rw.name
  object_type = "table"
  privileges  = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}

resource "pgazureflex_default_privileges" "sequences_app_rw" {
  for_each    = var.schemas
  database    = var.database
  owner       = pgazureflex_role.owner.name
  schema      = each.value
  role        = pgazureflex_role.app_rw.name
  object_type = "sequence"
  privileges  = ["USAGE", "SELECT", "UPDATE"]
}

resource "pgazureflex_default_privileges" "tables_agent_rw" {
  for_each    = var.schemas
  database    = var.database
  owner       = pgazureflex_role.owner.name
  schema      = each.value
  role        = pgazureflex_role.agent_rw.name
  object_type = "table"
  privileges  = ["SELECT", "INSERT", "UPDATE", "DELETE"]
}

resource "pgazureflex_default_privileges" "sequences_agent_rw" {
  for_each    = var.schemas
  database    = var.database
  owner       = pgazureflex_role.owner.name
  schema      = each.value
  role        = pgazureflex_role.agent_rw.name
  object_type = "sequence"
  privileges  = ["USAGE", "SELECT", "UPDATE"]
}

resource "pgazureflex_default_privileges" "tables_ro" {
  for_each    = var.schemas
  database    = var.database
  owner       = pgazureflex_role.owner.name
  schema      = each.value
  role        = pgazureflex_role.ro.name
  object_type = "table"
  privileges  = ["SELECT"]
}

# 4. Entra Managed Identities (always by `object_id` for Private VNet compatibility!)
resource "pgazureflex_entra_role" "migrator_mi" {
  name             = var.migrator_identity.name
  object_id        = var.migrator_identity.object_id
  principal_type   = "service"
  is_admin         = false
  connection_limit = var.migrator_identity.connection_limit

  parameters = {
    statement_timeout                   = var.migrator_identity.statement_timeout
    idle_in_transaction_session_timeout = "60s"
  }
}

resource "pgazureflex_entra_role" "app_mi" {
  name             = var.app_identity.name
  object_id        = var.app_identity.object_id
  principal_type   = "service"
  is_admin         = false
  connection_limit = var.app_identity.connection_limit

  parameters = {
    statement_timeout                   = var.app_identity.statement_timeout
    idle_in_transaction_session_timeout = "30s"
  }
}

resource "pgazureflex_entra_role" "agent_mi" {
  name             = var.agent_identity.name
  object_id        = var.agent_identity.object_id
  principal_type   = "service"
  is_admin         = false
  connection_limit = var.agent_identity.connection_limit

  parameters = {
    statement_timeout                   = var.agent_identity.statement_timeout
    idle_in_transaction_session_timeout = "60s"
  }
}

# 5. Decoupled Entra -> PostgreSQL RBAC mappings (PG 16+ INHERIT / SET options)
resource "pgazureflex_role_membership" "migrator_binding" {
  role                = pgazureflex_role.migrator.name
  member_role         = pgazureflex_entra_role.migrator_mi.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = true
}

resource "pgazureflex_role_membership" "app_binding" {
  role                = pgazureflex_role.app_rw.name
  member_role         = pgazureflex_entra_role.app_mi.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = false
}

resource "pgazureflex_role_membership" "agent_binding" {
  role                = pgazureflex_role.agent_rw.name
  member_role         = pgazureflex_entra_role.agent_mi.name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = false
}

# Optional read-only Entra Security Groups (MFA enforced)
resource "pgazureflex_entra_role" "ro_groups" {
  for_each         = var.readonly_entra_groups
  name             = each.key
  object_id        = each.value.object_id
  principal_type   = "group"
  is_admin         = false
  is_mfa           = each.value.is_mfa
  connection_limit = each.value.connection_limit

  parameters = {
    statement_timeout = "30s"
  }
}

resource "pgazureflex_role_membership" "ro_group_bindings" {
  for_each            = var.readonly_entra_groups
  role                = pgazureflex_role.ro.name
  member_role         = pgazureflex_entra_role.ro_groups[each.key].name
  with_admin_option   = false
  with_inherit_option = true
  with_set_option     = false
}
