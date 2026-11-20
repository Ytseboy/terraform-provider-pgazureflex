package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource              = &GrantResource{}
	_ resource.ResourceWithConfigure = &GrantResource{}
)

type GrantResource struct {
	client *pgclient.Client
}

type grantModel struct {
	ID              types.String `tfsdk:"id"`
	Database        types.String `tfsdk:"database"`
	Role            types.String `tfsdk:"role"`
	ObjectType      types.String `tfsdk:"object_type"`
	Schema          types.String `tfsdk:"schema"`
	Objects         types.Set    `tfsdk:"objects"`
	Privileges      types.Set    `tfsdk:"privileges"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
	Authoritative   types.Bool   `tfsdk:"authoritative"`
}

func NewGrantResource() resource.Resource {
	return &GrantResource{}
}

func (r *GrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func (r *GrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages PostgreSQL privileges (`GRANT` / `REVOKE`) on databases, schemas, tables, sequences, functions, procedures, routines, or types, with real system-catalog drift detection.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Deterministic resource identifier.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"database": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Target database name.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Target role name (or `PUBLIC`).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"object_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "PostgreSQL object type: `database`, `schema`, `table`, `sequence`, `function`, `procedure`, `routine`, or `type`.",
				Validators: []validator.String{
					stringvalidator.OneOf("database", "schema", "table", "sequence", "function", "procedure", "routine", "type"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"schema": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target schema name. Required for all object types except `database`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"objects": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Specific object names inside `schema`. If omitted for `table`, `sequence`, `function`, `procedure`, or `routine`, grants apply to `ALL <OBJECTS> IN SCHEMA`.",
				PlanModifiers:       []planmodifier.Set{setplanmodifier.RequiresReplace()},
			},
			"privileges": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Set of PostgreSQL privileges to grant (e.g. `[\"SELECT\", \"INSERT\"]`, `[\"USAGE\"]`, `[\"CONNECT\"]`, or `[\"ALL\"]`). Pass `[]` (empty set) to explicitly `REVOKE ALL PRIVILEGES` (ideal for hardening `role = \"PUBLIC\"` on databases or the `public` schema).",
			},
			"with_grant_option": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the grantee may re-grant these privileges to others (`WITH GRANT OPTION`).",
			},
			"authoritative": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, revokes any privileges for `object_type` that are not listed in `privileges` (e.g. setting `role = \"PUBLIC\"`, `object_type = \"schema\"`, `schema = \"public\"`, `privileges = [\"USAGE\"]`, `authoritative = true` revokes `CREATE` while keeping `USAGE`). Automatically implied when `privileges = []`.",
			},
		},
	}
}

func (r *GrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *GrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateGrantModel(ctx, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Invalid Grant Configuration", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyGrant(ctx, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Apply Grant", err.Error())
		return
	}

	objects := setToStringSlice(ctx, plan.Objects, &resp.Diagnostics)
	plan.ID = types.StringValue(computeGrantID(plan.Database.ValueString(), plan.Role.ValueString(), plan.ObjectType.ValueString(), plan.Schema.ValueString(), objects))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := state.Database.ValueString()
	role := state.Role.ValueString()
	objType := state.ObjectType.ValueString()
	schemaName := state.Schema.ValueString()
	objects := setToStringSlice(ctx, state.Objects, &resp.Diagnostics)
	plannedPrivs := setToStringSlice(ctx, state.Privileges, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		if pgclient.IsInvalidCatalogName(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	// Ensure role exists (unless PUBLIC).
	if !strings.EqualFold(role, "PUBLIC") {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			resp.Diagnostics.AddError("Failed to Check Role Existence", err.Error())
			return
		}
		if !exists {
			resp.State.RemoveResource(ctx)
			return
		}
	}

	actualPrivs, actualGrantable, foundObjects, err := readGrantedPrivileges(ctx, pool, db, role, objType, schemaName, objects)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Read Grants", err.Error())
		return
	}

	if !foundObjects {
		// If targeting a specific database/schema that no longer exists, remove resource from state.
		if objType == "database" || objType == "schema" || len(objects) > 0 {
			resp.State.RemoveResource(ctx)
			return
		}
		// For ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA when the schema has 0 objects yet,
		// keep state as-is so empty schemas do not perpetually diff.
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	// Compare normalized planned privileges vs actual granted privileges.
	normPlanned := pgclient.NormalizePrivileges(objType, plannedPrivs)
	normActual := pgclient.NormalizePrivileges(objType, actualPrivs)
	if !pgclient.EqualStringSets(normPlanned, normActual) {
		state.Privileges = stringSliceToSet(ctx, normActual, &resp.Diagnostics)
	}
	if len(normActual) > 0 {
		state.WithGrantOption = types.BoolValue(actualGrantable)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *GrantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Revoke all previously managed privileges first, then grant the new desired set.
	if err := r.revokeAllManaged(ctx, &state, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Revoke Previous Privileges", err.Error())
		return
	}
	if err := r.applyGrant(ctx, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Apply Updated Grant", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.revokeAllManaged(ctx, &state, &resp.Diagnostics); err != nil {
		if pgclient.IsInvalidCatalogName(err) || pgclient.IsUndefinedObject(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Revoke Privileges", err.Error())
		return
	}
}

func (r *GrantResource) applyGrant(ctx context.Context, m *grantModel, diags *diag.Diagnostics) error {
	db := m.Database.ValueString()
	objType := m.ObjectType.ValueString()

	privs := pgclient.NormalizePrivileges(objType, setToStringSlice(ctx, m.Privileges, diags))
	if diags.HasError() {
		return nil
	}

	objects := setToStringSlice(ctx, m.Objects, diags)
	if diags.HasError() {
		return nil
	}

	targetClause, err := buildGrantTargetClause(db, objType, m.Schema.ValueString(), objects)
	if err != nil {
		return err
	}

	grantee := formatGrantee(m.Role.ValueString())

	return r.client.WithDatabaseOwnerMembership(ctx, db, func(pool *pgxpool.Pool) error {
		// Empty privilege set: authoritatively REVOKE ALL PRIVILEGES (e.g. hardening PUBLIC).
		if len(privs) == 0 {
			revokeSQL := fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s FROM %s", targetClause, grantee)
			return pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, revokeSQL)
				return execErr
			})
		}

		// Authoritative mode: revoke any valid privilege for object_type not in desired privs.
		if m.Authoritative.ValueBool() {
			desiredSet := make(map[string]bool, len(privs))
			for _, p := range privs {
				desiredSet[p] = true
			}
			var toRevoke []string
			for _, vp := range pgclient.ValidPrivilegesByObjectType[objType] {
				if !desiredSet[vp] {
					toRevoke = append(toRevoke, vp)
				}
			}
			if len(toRevoke) > 0 {
				revokeSQL := fmt.Sprintf("REVOKE %s ON %s FROM %s", strings.Join(toRevoke, ", "), targetClause, grantee)
				if err := pgclient.RetryTransient(ctx, func() error {
					_, execErr := pool.Exec(ctx, revokeSQL)
					return execErr
				}); err != nil {
					return err
				}
			}
		}

		sql := fmt.Sprintf("GRANT %s ON %s TO %s", strings.Join(privs, ", "), targetClause, grantee)
		if m.WithGrantOption.ValueBool() {
			sql += " WITH GRANT OPTION"
		}
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, sql)
			return execErr
		})
	})
}

func (r *GrantResource) revokeAllManaged(ctx context.Context, m *grantModel, diags *diag.Diagnostics) error {
	db := m.Database.ValueString()

	privs := pgclient.NormalizePrivileges(m.ObjectType.ValueString(), setToStringSlice(ctx, m.Privileges, diags))
	if diags.HasError() || len(privs) == 0 {
		return nil
	}

	objects := setToStringSlice(ctx, m.Objects, diags)
	if diags.HasError() {
		return nil
	}

	targetClause, err := buildGrantTargetClause(db, m.ObjectType.ValueString(), m.Schema.ValueString(), objects)
	if err != nil {
		return err
	}

	grantee := formatGrantee(m.Role.ValueString())
	sql := fmt.Sprintf("REVOKE %s ON %s FROM %s", strings.Join(privs, ", "), targetClause, grantee)

	return r.client.WithDatabaseOwnerMembership(ctx, db, func(pool *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, sql)
			return execErr
		})
	})
}

func validateGrantModel(ctx context.Context, m *grantModel, diags *diag.Diagnostics) error {
	objType := m.ObjectType.ValueString()
	schemaName := m.Schema.ValueString()
	objects := setToStringSlice(ctx, m.Objects, diags)

	if objType != "database" && schemaName == "" {
		return fmt.Errorf("`schema` is required when `object_type` is %q", objType)
	}
	if objType == "type" && len(objects) == 0 {
		return fmt.Errorf("`objects` must be specified when `object_type` is \"type\"")
	}
	if (objType == "database" || objType == "schema") && len(objects) > 0 {
		return fmt.Errorf("`objects` cannot be set when `object_type` is %q", objType)
	}

	valid := make(map[string]bool)
	for _, p := range pgclient.ValidPrivilegesByObjectType[objType] {
		valid[p] = true
	}
	for _, p := range pgclient.NormalizePrivileges(objType, setToStringSlice(ctx, m.Privileges, diags)) {
		if !valid[p] {
			return fmt.Errorf("privilege %q is not valid for object_type %q (valid: %v)", p, objType, pgclient.ValidPrivilegesByObjectType[objType])
		}
	}
	return nil
}

func formatGrantee(role string) string {
	if strings.EqualFold(role, "PUBLIC") {
		return "PUBLIC"
	}
	return pgclient.QuoteIdent(role)
}

func formatQualifiedObject(schemaName, obj string, allowSignature bool) string {
	if allowSignature {
		if paren := strings.IndexByte(obj, '('); paren > 0 {
			fnName := strings.TrimSpace(obj[:paren])
			sig := obj[paren:]
			return pgclient.QuoteIdent(schemaName) + "." + pgclient.QuoteIdent(fnName) + sig
		}
	}
	return pgclient.QuoteQualifiedIdent(schemaName, obj)
}

func buildGrantTargetClause(db, objType, schemaName string, objects []string) (string, error) {
	switch objType {
	case "database":
		return "DATABASE " + pgclient.QuoteIdent(db), nil
	case "schema":
		return "SCHEMA " + pgclient.QuoteIdent(schemaName), nil
	case "table":
		if len(objects) == 0 {
			return "ALL TABLES IN SCHEMA " + pgclient.QuoteIdent(schemaName), nil
		}
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, false)
		}
		return "TABLE " + strings.Join(quoted, ", "), nil
	case "sequence":
		if len(objects) == 0 {
			return "ALL SEQUENCES IN SCHEMA " + pgclient.QuoteIdent(schemaName), nil
		}
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, false)
		}
		return "SEQUENCE " + strings.Join(quoted, ", "), nil
	case "function":
		if len(objects) == 0 {
			return "ALL FUNCTIONS IN SCHEMA " + pgclient.QuoteIdent(schemaName), nil
		}
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, true)
		}
		return "FUNCTION " + strings.Join(quoted, ", "), nil
	case "procedure":
		if len(objects) == 0 {
			return "ALL PROCEDURES IN SCHEMA " + pgclient.QuoteIdent(schemaName), nil
		}
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, true)
		}
		return "PROCEDURE " + strings.Join(quoted, ", "), nil
	case "routine":
		if len(objects) == 0 {
			return "ALL ROUTINES IN SCHEMA " + pgclient.QuoteIdent(schemaName), nil
		}
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, true)
		}
		return "ROUTINE " + strings.Join(quoted, ", "), nil
	case "type":
		quoted := make([]string, len(objects))
		for i, o := range objects {
			quoted[i] = formatQualifiedObject(schemaName, o, false)
		}
		return "TYPE " + strings.Join(quoted, ", "), nil
	default:
		return "", fmt.Errorf("unsupported object_type %q", objType)
	}
}

func computeGrantID(db, role, objType, schemaName string, objects []string) string {
	sorted := append([]string(nil), objects...)
	sort.Strings(sorted)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s", db, role, objType, schemaName, strings.Join(sorted, ","))
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s.%s.%s.%s", db, role, objType, hex.EncodeToString(sum[:6]))
}

// readGrantedPrivileges inspects PostgreSQL system catalog ACLs and returns the intersection of
// privileges held by role across the targeted object(s).
func readGrantedPrivileges(ctx context.Context, pool *pgxpool.Pool, db, role, objType, schemaName string, objects []string) ([]string, bool, bool, error) {
	isPublic := strings.EqualFold(role, "PUBLIC")

	var query string
	var args []any

	granteeMatch := "a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $2)"
	if isPublic {
		granteeMatch = "a.grantee = 0"
	}

	switch objType {
	case "database":
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, db).Scan(&exists); err != nil || !exists {
			return nil, false, false, err
		}
		query = fmt.Sprintf(`
			SELECT d.datname, a.privilege_type, a.is_grantable
			FROM pg_database d
			CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
			WHERE d.datname = $1 AND %s
		`, granteeMatch)
		if isPublic {
			args = []any{db}
		} else {
			args = []any{db, role}
		}
		return collectIntersectionPrivileges(ctx, pool, query, args, 1)

	case "schema":
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schemaName).Scan(&exists); err != nil || !exists {
			return nil, false, false, err
		}
		query = fmt.Sprintf(`
			SELECT n.nspname, a.privilege_type, a.is_grantable
			FROM pg_namespace n
			CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
			WHERE n.nspname = $1 AND %s
		`, granteeMatch)
		if isPublic {
			args = []any{schemaName}
		} else {
			args = []any{schemaName, role}
		}
		return collectIntersectionPrivileges(ctx, pool, query, args, 1)

	case "table", "sequence":
		relKinds := []string{"r", "p", "v", "m", "f"}
		if objType == "sequence" {
			relKinds = []string{"S"}
		}

		var totalCount int
		if len(objects) > 0 {
			err := pool.QueryRow(ctx, `
				SELECT count(*)
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = $1 AND c.relkind = ANY($2) AND c.relname = ANY($3)
			`, schemaName, relKinds, objects).Scan(&totalCount)
			if err != nil || totalCount == 0 {
				return nil, false, false, err
			}
			if isPublic {
				query = `
					SELECT c.relname, a.privilege_type, a.is_grantable
					FROM pg_class c
					JOIN pg_namespace n ON n.oid = c.relnamespace
					CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
					WHERE n.nspname = $1 AND c.relkind = ANY($2) AND c.relname = ANY($3) AND a.grantee = 0
				`
				args = []any{schemaName, relKinds, objects}
			} else {
				query = `
					SELECT c.relname, a.privilege_type, a.is_grantable
					FROM pg_class c
					JOIN pg_namespace n ON n.oid = c.relnamespace
					CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
					WHERE n.nspname = $1 AND c.relkind = ANY($2) AND c.relname = ANY($3)
					  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $4)
				`
				args = []any{schemaName, relKinds, objects, role}
			}
			return collectIntersectionPrivileges(ctx, pool, query, args, totalCount)
		}

		err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relkind = ANY($2)
		`, schemaName, relKinds).Scan(&totalCount)
		if err != nil || totalCount == 0 {
			return nil, false, false, err
		}
		if isPublic {
			query = `
				SELECT c.relname, a.privilege_type, a.is_grantable
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
				WHERE n.nspname = $1 AND c.relkind = ANY($2) AND a.grantee = 0
			`
			args = []any{schemaName, relKinds}
		} else {
			query = `
				SELECT c.relname, a.privilege_type, a.is_grantable
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
				WHERE n.nspname = $1 AND c.relkind = ANY($2)
				  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $3)
			`
			args = []any{schemaName, relKinds, role}
		}
		return collectIntersectionPrivileges(ctx, pool, query, args, totalCount)

	case "function", "procedure", "routine":
		proKinds := []string{"f", "p"}
		if objType == "function" {
			proKinds = []string{"f"}
		} else if objType == "procedure" {
			proKinds = []string{"p"}
		}
		var totalCount int
		err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_proc p
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = $1 AND p.prokind = ANY($2)
		`, schemaName, proKinds).Scan(&totalCount)
		if err != nil || totalCount == 0 {
			return nil, false, false, err
		}
		if isPublic {
			query = `
				SELECT p.oid::text, a.privilege_type, a.is_grantable
				FROM pg_proc p
				JOIN pg_namespace n ON n.oid = p.pronamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
				WHERE n.nspname = $1 AND p.prokind = ANY($2) AND a.grantee = 0
			`
			args = []any{schemaName, proKinds}
		} else {
			query = `
				SELECT p.oid::text, a.privilege_type, a.is_grantable
				FROM pg_proc p
				JOIN pg_namespace n ON n.oid = p.pronamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
				WHERE n.nspname = $1 AND p.prokind = ANY($2)
				  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $3)
			`
			args = []any{schemaName, proKinds, role}
		}
		return collectIntersectionPrivileges(ctx, pool, query, args, totalCount)

	case "type":
		var totalCount int
		err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_type t
			JOIN pg_namespace n ON n.oid = t.typnamespace
			WHERE n.nspname = $1 AND t.typname = ANY($2)
		`, schemaName, objects).Scan(&totalCount)
		if err != nil || totalCount == 0 {
			return nil, false, false, err
		}
		if isPublic {
			query = `
				SELECT t.typname, a.privilege_type, a.is_grantable
				FROM pg_type t
				JOIN pg_namespace n ON n.oid = t.typnamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(t.typacl, acldefault('T', t.typowner))) a
				WHERE n.nspname = $1 AND t.typname = ANY($2) AND a.grantee = 0
			`
			args = []any{schemaName, objects}
		} else {
			query = `
				SELECT t.typname, a.privilege_type, a.is_grantable
				FROM pg_type t
				JOIN pg_namespace n ON n.oid = t.typnamespace
				CROSS JOIN LATERAL aclexplode(COALESCE(t.typacl, acldefault('T', t.typowner))) a
				WHERE n.nspname = $1 AND t.typname = ANY($2)
				  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $3)
			`
			args = []any{schemaName, objects, role}
		}
		return collectIntersectionPrivileges(ctx, pool, query, args, totalCount)
	}

	return nil, false, false, fmt.Errorf("unsupported object_type %q", objType)
}

func collectIntersectionPrivileges(ctx context.Context, pool *pgxpool.Pool, query string, args []any, expectedObjects int) ([]string, bool, bool, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, false, false, err
	}
	defer rows.Close()

	privCounts := make(map[string]int)
	grantableCounts := make(map[string]int)

	for rows.Next() {
		var objKey, priv string
		var grantable bool
		if err := rows.Scan(&objKey, &priv, &grantable); err != nil {
			return nil, false, false, err
		}
		priv = strings.ToUpper(priv)
		privCounts[priv]++
		if grantable {
			grantableCounts[priv]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, false, err
	}

	var result []string
	allGrantable := true
	for p, count := range privCounts {
		if count >= expectedObjects {
			result = append(result, p)
			if grantableCounts[p] < expectedObjects {
				allGrantable = false
			}
		}
	}
	sort.Strings(result)
	if len(result) == 0 {
		allGrantable = false
	}
	return result, allGrantable, true, nil
}
