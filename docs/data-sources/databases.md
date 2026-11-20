---
page_title: "pgazureflex_databases Data Source"
subcategory: "Data Sources"
description: |-
  Lists databases present on the PostgreSQL server.
---

# `pgazureflex_databases` (Data Source)

Lists databases present on the PostgreSQL server along with owner, encoding, collation, and connection settings.

## Example Usage

```hcl
data "pgazureflex_databases" "all" {
  include_templates = false
}

output "database_names" {
  value = [for d in data.pgazureflex_databases.all.databases : d.name]
}
```

## Schema

### Optional

- `include_templates` (Boolean) Include template databases (`template0`, `template1`). Defaults to `false`.

### Read-Only

- `id` (String) Configured PostgreSQL host.
- `databases` (List of Object):
  - `name` (String)
  - `owner` (String)
  - `encoding` (String)
  - `lc_collate` (String)
  - `lc_ctype` (String)
  - `connection_limit` (Number)
  - `is_template` (Boolean)
  - `allow_connections` (Boolean)
