package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &RoleResource{}
	_ resource.ResourceWithConfigure   = &RoleResource{}
	_ resource.ResourceWithImportState = &RoleResource{}
	_ resource.ResourceWithModifyPlan  = &RoleResource{}
)

type RoleResource struct {
	client *pgclient.Client
}

type roleModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Login           types.Bool   `tfsdk:"login"`
	Superuser       types.Bool   `tfsdk:"superuser"`
	CreateDB        types.Bool   `tfsdk:"create_db"`
	CreateRole      types.Bool   `tfsdk:"create_role"`
	Inherit         types.Bool   `tfsdk:"inherit"`
	Replication     types.Bool   `tfsdk:"replication"`
	BypassRLS       types.Bool   `tfsdk:"bypass_rls"`
	ConnectionLimit types.Int64  `tfsdk:"connection_limit"`
	ValidUntil      types.String `tfsdk:"valid_until"`
	Password        types.String `tfsdk:"password"`
	Roles           types.Set    `tfsdk:"roles"`
	Parameters      types.Map    `tfsdk:"parameters"`
	ReassignOwnedTo types.String `tfsdk:"reassign_owned_to"`
	DropOwned       types.Bool   `tfsdk:"drop_owned"`
}

func NewRoleResource() resource.Resource {
	return &RoleResource{}
}

func (r *RoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *RoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a native PostgreSQL role (login user or NOLOGIN group role). For Microsoft Entra ID identities on Azure Flexible Server, prefer `pgazureflex_entra_role`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier (matches role `name`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the PostgreSQL role. Renaming updates in-place via `ALTER ROLE ... RENAME TO`.",
			},
			"login": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role can log in (`LOGIN` / `NOLOGIN`).",
			},
			"superuser": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role is a PostgreSQL superuser. Note: Azure Flexible Server does not allow granting `SUPERUSER`; use `roles = [\"azure_pg_admin\"]` instead.",
			},
			"create_db": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role can create databases (`CREATEDB`).",
			},
			"create_role": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role can create other roles (`CREATEROLE`).",
			},
			"inherit": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the role inherits privileges of roles it is a member of (`INHERIT`).",
			},
			"replication": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role can initiate streaming or logical replication (`REPLICATION`).",
			},
			"bypass_rls": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the role bypasses row-level security policies (`BYPASSRLS`).",
			},
			"connection_limit": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(-1),
				MarkdownDescription: "Maximum concurrent connections (`-1` for unlimited).",
			},
			"valid_until": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Password expiration timestamp (RFC3339 or `infinity`).",
			},
			"password": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Role password. Applied on create and whenever changed in configuration.",
			},
			"roles": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Set of group roles to grant to this role.",
			},
			"parameters": schema.MapAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Role-level PostgreSQL parameters applied via `ALTER ROLE ... SET key = value` (e.g. `search_path`, `statement_timeout`).",
			},
			"reassign_owned_to": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Role to reassign owned objects to (`REASSIGN OWNED BY`) prior to dropping this role.",
			},
			"drop_owned": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, runs `DROP OWNED BY` before dropping this role.",
			},
		},
	}
}

func (r *RoleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *RoleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Name.IsUnknown() && !plan.Name.IsNull() {
		plan.ID = plan.Name
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

func (r *RoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	caps, err := r.client.Capabilities(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Inspect Server Capabilities", err.Error())
		return
	}

	if plan.Superuser.ValueBool() && !caps.IsSuperuser {
		resp.Diagnostics.AddError(
			"SUPERUSER Not Permitted on Non-Superuser Server",
			"Azure Database for PostgreSQL Flexible Server does not allow granting SUPERUSER. Set `superuser = false` and optionally include `\"azure_pg_admin\"` in `roles`.",
		)
		return
	}

	roleName := plan.Name.ValueString()
	opts := buildRoleAttributeClauses(&plan, caps, true)
	createSQL := fmt.Sprintf("CREATE ROLE %s WITH %s", pgclient.QuoteIdent(roleName), strings.Join(opts, " "))

	if err := pgclient.RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, createSQL)
		return execErr
	}); err != nil {
		resp.Diagnostics.AddError("Failed to Create Role", fmt.Sprintf("Error creating role %q: %v", roleName, err))
		return
	}

	if !plan.Roles.IsNull() && !plan.Roles.IsUnknown() {
		desiredRoles := setToStringSlice(ctx, plan.Roles, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncRoleMemberships(ctx, pool, roleName, desiredRoles, nil); err != nil {
			resp.Diagnostics.AddError("Failed to Grant Role Memberships", err.Error())
			return
		}
	}

	if !plan.Parameters.IsNull() && !plan.Parameters.IsUnknown() {
		desiredParams := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncEntityParameters(ctx, pool, "ROLE", roleName, desiredParams, nil); err != nil {
			resp.Diagnostics.AddError("Failed to Set Role Parameters", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, roleName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleName := state.Name.ValueString()
	if roleName == "" {
		roleName = state.ID.ValueString()
	}

	err := r.readIntoModel(ctx, roleName, &state, &resp.Diagnostics)
	if err != nil {
		if err == pgx.ErrNoRows {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}
	caps, err := r.client.Capabilities(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Inspect Server Capabilities", err.Error())
		return
	}

	currentName := state.Name.ValueString()
	targetName := plan.Name.ValueString()

	if currentName != targetName {
		sql := fmt.Sprintf("ALTER ROLE %s RENAME TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(targetName))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Rename Role", err.Error())
			return
		}
		currentName = targetName
	}

	passwordChanged := !plan.Password.Equal(state.Password)
	opts := buildRoleAttributeClauses(&plan, caps, passwordChanged)
	alterSQL := fmt.Sprintf("ALTER ROLE %s WITH %s", pgclient.QuoteIdent(currentName), strings.Join(opts, " "))
	if err := pgclient.RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, alterSQL)
		return execErr
	}); err != nil {
		resp.Diagnostics.AddError("Failed to Update Role", err.Error())
		return
	}

	if !plan.Roles.Equal(state.Roles) {
		desiredRoles := setToStringSlice(ctx, plan.Roles, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncRoleMemberships(ctx, pool, currentName, desiredRoles, nil); err != nil {
			resp.Diagnostics.AddError("Failed to Update Role Memberships", err.Error())
			return
		}
	}

	if !plan.Parameters.Equal(state.Parameters) {
		curParams := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
		desParams := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncEntityParameters(ctx, pool, "ROLE", currentName, desParams, curParams); err != nil {
			resp.Diagnostics.AddError("Failed to Update Role Parameters", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, currentName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reassignTo := ""
	if !state.ReassignOwnedTo.IsNull() {
		reassignTo = state.ReassignOwnedTo.ValueString()
	}

	if err := r.client.DropRoleWithCleanup(ctx, state.Name.ValueString(), reassignTo, state.DropOwned.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Failed to Drop Role", err.Error())
		return
	}
}

func (r *RoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func buildRoleAttributeClauses(m *roleModel, caps pgclient.ServerCapabilities, includePassword bool) []string {
	var opts []string

	if m.Login.ValueBool() {
		opts = append(opts, "LOGIN")
	} else {
		opts = append(opts, "NOLOGIN")
	}

	// Only emit SUPERUSER/NOSUPERUSER when actually superuser (Azure PG rejects even NOSUPERUSER on some configs for non-superusers).
	if caps.IsSuperuser {
		if m.Superuser.ValueBool() {
			opts = append(opts, "SUPERUSER")
		} else {
			opts = append(opts, "NOSUPERUSER")
		}
	}

	if m.CreateDB.ValueBool() {
		opts = append(opts, "CREATEDB")
	} else {
		opts = append(opts, "NOCREATEDB")
	}

	if m.CreateRole.ValueBool() {
		opts = append(opts, "CREATEROLE")
	} else {
		opts = append(opts, "NOCREATEROLE")
	}

	if m.Inherit.ValueBool() {
		opts = append(opts, "INHERIT")
	} else {
		opts = append(opts, "NOINHERIT")
	}

	// Only emit REPLICATION / BYPASSRLS when requested true or when superuser.
	// On PostgreSQL 16+, non-superusers (even with CREATEROLE) receive SQLSTATE 42501
	// if NOREPLICATION or NOBYPASSRLS is passed unconditionally.
	if m.Replication.ValueBool() {
		opts = append(opts, "REPLICATION")
	} else if caps.IsSuperuser {
		opts = append(opts, "NOREPLICATION")
	}

	if m.BypassRLS.ValueBool() {
		opts = append(opts, "BYPASSRLS")
	} else if caps.IsSuperuser {
		opts = append(opts, "NOBYPASSRLS")
	}

	opts = append(opts, fmt.Sprintf("CONNECTION LIMIT %d", m.ConnectionLimit.ValueInt64()))

	if !m.ValidUntil.IsNull() && !m.ValidUntil.IsUnknown() && m.ValidUntil.ValueString() != "" {
		opts = append(opts, "VALID UNTIL "+pgclient.QuoteLiteral(m.ValidUntil.ValueString()))
	}

	if includePassword && !m.Password.IsNull() && !m.Password.IsUnknown() {
		if m.Password.ValueString() == "" {
			opts = append(opts, "PASSWORD NULL")
		} else {
			opts = append(opts, "PASSWORD "+pgclient.QuoteLiteral(m.Password.ValueString()))
		}
	}

	return opts
}

func (r *RoleResource) readIntoModel(ctx context.Context, roleName string, model *roleModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	var (
		rolSuper       bool
		rolInherit     bool
		rolCreateRole  bool
		rolCreateDB    bool
		rolCanLogin    bool
		rolReplication bool
		rolBypassRLS   bool
		rolConnLimit   int64
		rolValidUntil  *time.Time
		rolConfig      []string
	)

	err = pool.QueryRow(ctx, `
		SELECT
			rolsuper,
			rolinherit,
			rolcreaterole,
			rolcreatedb,
			rolcanlogin,
			rolreplication,
			rolbypassrls,
			rolconnlimit,
			rolvaliduntil,
			COALESCE(rolconfig, ARRAY[]::text[])
		FROM pg_roles
		WHERE rolname = $1
	`, roleName).Scan(
		&rolSuper,
		&rolInherit,
		&rolCreateRole,
		&rolCreateDB,
		&rolCanLogin,
		&rolReplication,
		&rolBypassRLS,
		&rolConnLimit,
		&rolValidUntil,
		&rolConfig,
	)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(roleName)
	model.Name = types.StringValue(roleName)
	model.Superuser = types.BoolValue(rolSuper)
	model.Inherit = types.BoolValue(rolInherit)
	model.CreateRole = types.BoolValue(rolCreateRole)
	model.CreateDB = types.BoolValue(rolCreateDB)
	model.Login = types.BoolValue(rolCanLogin)
	model.Replication = types.BoolValue(rolReplication)
	model.BypassRLS = types.BoolValue(rolBypassRLS)
	model.ConnectionLimit = types.Int64Value(rolConnLimit)
	if model.DropOwned.IsNull() || model.DropOwned.IsUnknown() {
		model.DropOwned = types.BoolValue(false)
	}

	if rolValidUntil != nil && !model.ValidUntil.IsNull() {
		// Preserve user's timestamp string if it refers to the same instant to prevent formatting churn.
		if parsed, parseErr := time.Parse(time.RFC3339, model.ValidUntil.ValueString()); parseErr != nil || !parsed.Equal(*rolValidUntil) {
			model.ValidUntil = types.StringValue(rolValidUntil.UTC().Format(time.RFC3339))
		}
	} else if rolValidUntil == nil && !model.ValidUntil.IsNull() && strings.ToLower(model.ValidUntil.ValueString()) != "infinity" {
		model.ValidUntil = types.StringNull()
	}

	memberships, err := readRoleMemberships(ctx, pool, roleName, nil)
	if err != nil {
		return err
	}
	if len(memberships) > 0 || !model.Roles.IsNull() {
		model.Roles = stringSliceToSet(ctx, memberships, diags)
	}

	parsedParams := parsePGConfigArray(rolConfig)
	if len(parsedParams) > 0 || !model.Parameters.IsNull() {
		model.Parameters = stringMapToTFMap(ctx, parsedParams, diags)
	}

	return nil
}
