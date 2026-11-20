---
page_title: "pgazureflex_publication Resource"
subcategory: "Resources"
description: |-
  Manages a PostgreSQL logical replication publication (CREATE PUBLICATION) for CDC and zero-downtime migrations.
---

# `pgazureflex_publication` (Resource)

Manages a PostgreSQL logical replication publication (`CREATE PUBLICATION`). Useful on Azure Flexible Server (with `wal_level = logical`) for Debezium/CDC pipelines and zero-downtime migrations.

## Example Usage

```hcl
resource "pgazureflex_publication" "cdc_all" {
  database      = pgazureflex_database.orders.name
  name          = "orders_cdc_pub"
  all_tables    = true
  publish_param = ["insert", "update", "delete"]
}

resource "pgazureflex_publication" "cdc_events" {
  database      = pgazureflex_database.orders.name
  name          = "events_only_pub"
  all_tables    = false
  tables        = ["core.events", "core.audit_log"]
  publish_param = ["insert", "update"]
}
```

## Schema

### Required

- `database` (String) Target database name. Forces replacement if changed.
- `name` (String) Publication name. Updating this renames the publication in-place via `ALTER PUBLICATION ... RENAME TO`.

### Optional

- `owner` (String) Role that owns the publication.
- `all_tables` (Boolean) Publish changes for all tables in the database (`FOR ALL TABLES`). Forces replacement if changed. Defaults to `false`.
- `tables` (Set of String) Qualified `schema.table` names included in the publication (ignored when `all_tables = true`). Supports in-place updates.
- `publish_param` (Set of String) DML operations to publish: subset of `insert`, `update`, `delete`, `truncate`. Defaults to all four.
- `drop_cascade` (Boolean) Drop dependent objects via `DROP PUBLICATION ... CASCADE` on destroy. Defaults to `false`.

### Read-Only

- `id` (String) Resource identifier in format `<database>.<name>`.

## Import

```bash
terraform import pgazureflex_publication.cdc_all orders.orders_cdc_pub
```
