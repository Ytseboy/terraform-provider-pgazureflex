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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource              = &DefaultPrivilegesResource{}
	_ resource.ResourceWithConfigure = &DefaultPrivilegesResource{}
)

type DefaultPrivilegesResource struct {
	client *pgclient.Client
}

type defaultPrivilegesModel struct {
	ID              types.String `tfsdk:"id"`
	Database        types.String `tfsdk:"database"`
	Owner           types.String `tfsdk:"owner"`
	Schema          types.String `tfsdk:"schema"`
	Role            types.String `tfsdk:"role"`
	ObjectType      types.String `tfsdk:"object_type"`
	Privileges      types.Set    `tfsdk:"privileges"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func NewDefaultPrivilegesResource() resource.Resource {
	return &DefaultPrivilegesResource{}
}

func (r *DefaultPrivilegesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_default_privileges"
}

func (r *DefaultPrivilegesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages PostgreSQL `ALTER DEFAULT PRIVILEGES` entries (`pg_default_acl`). Automatically handles temporary `azure_pg_admin` role membership for `FOR ROLE <owner>` on Azure Flexible Server.",
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
			"owner": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Role whose future created objects will receive these default privileges (`FOR ROLE <owner>`).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"schema": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional schema scope (`IN SCHEMA <schema>`). Omit to apply cluster/database-wide for `owner`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Grantee role name (or `PUBLIC`).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"object_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Object type: `table`, `sequence`, `function`, `type`, or `schema`.",
				Validators: []validator.String{
					stringvalidator.OneOf("table", "sequence", "function", "type", "schema"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"privileges": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Set of default privileges to grant.",
			},
			"with_grant_option": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to include `WITH GRANT OPTION`.",
			},
		},
	}
}

func (r *DefaultPrivilegesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *DefaultPrivilegesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan defaultPrivilegesModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyDefaultPrivileges(ctx, &plan, false, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Apply Default Privileges", err.Error())
		return
	}

	raw := fmt.Sprintf("%s|%s|%s|%s|%s",
		plan.Database.ValueString(),
		plan.Owner.ValueString(),
		plan.Schema.ValueString(),
		plan.Role.ValueString(),
		plan.ObjectType.ValueString(),
	)
	sum := sha256.Sum256([]byte(raw))
	plan.ID = types.StringValue(fmt.Sprintf("%s.%s.%s.%s",
		plan.Database.ValueString(),
		plan.Owner.ValueString(),
		plan.ObjectType.ValueString(),
		hex.EncodeToString(sum[:6]),
	))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DefaultPrivilegesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state defaultPrivilegesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := state.Database.ValueString()
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		if pgclient.IsInvalidCatalogName(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	objChar, err := defaultACLObjChar(state.ObjectType.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Object Type", err.Error())
		return
	}

	owner := state.Owner.ValueString()
	role := state.Role.ValueString()
	schemaName := state.Schema.ValueString()
	isPublic := strings.EqualFold(role, "PUBLIC")

	var rowsQuery string
	var args []any

	if schemaName == "" {
		if isPublic {
			rowsQuery = `
				SELECT a.privilege_type, a.is_grantable
				FROM pg_default_acl d
				JOIN pg_roles o ON o.oid = d.defaclrole
				CROSS JOIN LATERAL aclexplode(d.defaclacl) a
				WHERE o.rolname = $1 AND d.defaclnamespace = 0 AND d.defaclobjtype = $2 AND a.grantee = 0
			`
			args = []any{owner, objChar}
		} else {
			rowsQuery = `
				SELECT a.privilege_type, a.is_grantable
				FROM pg_default_acl d
				JOIN pg_roles o ON o.oid = d.defaclrole
				CROSS JOIN LATERAL aclexplode(d.defaclacl) a
				WHERE o.rolname = $1 AND d.defaclnamespace = 0 AND d.defaclobjtype = $2
				  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $3)
			`
			args = []any{owner, objChar, role}
		}
	} else {
		if isPublic {
			rowsQuery = `
				SELECT a.privilege_type, a.is_grantable
				FROM pg_default_acl d
				JOIN pg_roles o ON o.oid = d.defaclrole
				JOIN pg_namespace n ON n.oid = d.defaclnamespace
				CROSS JOIN LATERAL aclexplode(d.defaclacl) a
				WHERE o.rolname = $1 AND n.nspname = $2 AND d.defaclobjtype = $3 AND a.grantee = 0
			`
			args = []any{owner, schemaName, objChar}
		} else {
			rowsQuery = `
				SELECT a.privilege_type, a.is_grantable
				FROM pg_default_acl d
				JOIN pg_roles o ON o.oid = d.defaclrole
				JOIN pg_namespace n ON n.oid = d.defaclnamespace
				CROSS JOIN LATERAL aclexplode(d.defaclacl) a
				WHERE o.rolname = $1 AND n.nspname = $2 AND d.defaclobjtype = $3
				  AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $4)
			`
			args = []any{owner, schemaName, objChar, role}
		}
	}

	rows, err := pool.Query(ctx, rowsQuery, args...)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Query pg_default_acl", err.Error())
		return
	}
	defer rows.Close()

	var actual []string
	allGrantable := true
	for rows.Next() {
		var priv string
		var grantable bool
		if err := rows.Scan(&priv, &grantable); err != nil {
			resp.Diagnostics.AddError("Failed to Scan pg_default_acl", err.Error())
			return
		}
		actual = append(actual, strings.ToUpper(priv))
		if !grantable {
			allGrantable = false
		}
	}
	if err := rows.Err(); err != nil {
		resp.Diagnostics.AddError("Failed to Read pg_default_acl", err.Error())
		return
	}

	if len(actual) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	sort.Strings(actual)
	planned := pgclient.NormalizePrivileges(state.ObjectType.ValueString(), setToStringSlice(ctx, state.Privileges, &resp.Diagnostics))
	if !pgclient.EqualStringSets(planned, actual) {
		state.Privileges = stringSliceToSet(ctx, actual, &resp.Diagnostics)
	}
	state.WithGrantOption = types.BoolValue(allGrantable)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DefaultPrivilegesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state defaultPrivilegesModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyDefaultPrivileges(ctx, &state, true, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Revoke Old Default Privileges", err.Error())
		return
	}
	if err := r.applyDefaultPrivileges(ctx, &plan, false, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Grant Updated Default Privileges", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DefaultPrivilegesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state defaultPrivilegesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyDefaultPrivileges(ctx, &state, true, &resp.Diagnostics); err != nil {
		if pgclient.IsInvalidCatalogName(err) || pgclient.IsUndefinedObject(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Revoke Default Privileges", err.Error())
		return
	}
}

func (r *DefaultPrivilegesResource) applyDefaultPrivileges(ctx context.Context, m *defaultPrivilegesModel, revoke bool, diags *diag.Diagnostics) error {
	db := m.Database.ValueString()
	owner := m.Owner.ValueString()
	schemaName := m.Schema.ValueString()
	objType := m.ObjectType.ValueString()
	privs := pgclient.NormalizePrivileges(objType, setToStringSlice(ctx, m.Privileges, diags))
	if diags.HasError() || len(privs) == 0 {
		return nil
	}

	plural, err := defaultACLPlural(objType)
	if err != nil {
		return err
	}

	stmt := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s", pgclient.QuoteIdent(owner))
	if schemaName != "" {
		stmt += " IN SCHEMA " + pgclient.QuoteIdent(schemaName)
	}

	grantee := formatGrantee(m.Role.ValueString())
	if revoke {
		stmt += fmt.Sprintf(" REVOKE %s ON %s FROM %s", strings.Join(privs, ", "), plural, grantee)
	} else {
		stmt += fmt.Sprintf(" GRANT %s ON %s TO %s", strings.Join(privs, ", "), plural, grantee)
		if m.WithGrantOption.ValueBool() {
			stmt += " WITH GRANT OPTION"
		}
	}

	return r.client.WithRoleMembership(ctx, db, owner, func(pool *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, stmt)
			return execErr
		})
	})
}

func defaultACLPlural(objType string) (string, error) {
	switch objType {
	case "table":
		return "TABLES", nil
	case "sequence":
		return "SEQUENCES", nil
	case "function":
		return "FUNCTIONS", nil
	case "type":
		return "TYPES", nil
	case "schema":
		return "SCHEMAS", nil
	default:
		return "", fmt.Errorf("unsupported default privileges object_type %q", objType)
	}
}

func defaultACLObjChar(objType string) (string, error) {
	switch objType {
	case "table":
		return "r", nil
	case "sequence":
		return "S", nil
	case "function":
		return "f", nil
	case "type":
		return "T", nil
	case "schema":
		return "n", nil
	default:
		return "", fmt.Errorf("unsupported default privileges object_type %q", objType)
	}
}
