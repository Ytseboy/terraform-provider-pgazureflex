package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &EntraRoleResource{}
	_ resource.ResourceWithConfigure   = &EntraRoleResource{}
	_ resource.ResourceWithImportState = &EntraRoleResource{}
)

// EntraRoleResource manages Microsoft Entra ID principals (users, groups, managed identities,
// and service principals) in Azure Database for PostgreSQL Flexible Server via pgaadauth.
type EntraRoleResource struct {
	client *pgclient.Client
}

type entraRoleModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	ObjectID        types.String `tfsdk:"object_id"`
	PrincipalType   types.String `tfsdk:"principal_type"`
	IsAdmin         types.Bool   `tfsdk:"is_admin"`
	IsMFA           types.Bool   `tfsdk:"is_mfa"`
	ConnectionLimit types.Int64  `tfsdk:"connection_limit"`
	CreateDB        types.Bool   `tfsdk:"create_db"`
	CreateRole      types.Bool   `tfsdk:"create_role"`
	Inherit         types.Bool   `tfsdk:"inherit"`
	BypassRLS       types.Bool   `tfsdk:"bypass_rls"`
	Roles           types.Set    `tfsdk:"roles"`
	Parameters      types.Map    `tfsdk:"parameters"`
	ReassignOwnedTo types.String `tfsdk:"reassign_owned_to"`
	DropOwned       types.Bool   `tfsdk:"drop_owned"`
}

func NewEntraRoleResource() resource.Resource {
	return &EntraRoleResource{}
}

func (r *EntraRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entra_role"
}

func (r *EntraRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Microsoft Entra ID principal (User, Group, Managed Identity, or Service Principal) in **Azure Database for PostgreSQL - Flexible Server** via `pgaadauth`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier (matches the PostgreSQL role `name`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "PostgreSQL role name mapped to the Entra ID principal (e.g. UPN, Managed Identity name, or custom alias when `object_id` is supplied).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"object_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Microsoft Entra ID Object ID (UUID). Strongly recommended for IaC and private-network Flexible Servers because it uses `pgaadauth_create_principal_with_oid` with no outbound Microsoft Graph lookup.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(uuidRegex, "must be a valid Entra ID Object ID UUID"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"principal_type": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("user"),
				MarkdownDescription: "Entra ID principal type: `user`, `group`, or `service` (used for Managed Identities and Service Principals).",
				Validators: []validator.String{
					stringvalidator.OneOf("user", "group", "service"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"is_admin": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, grants `azure_pg_admin` membership to the Entra ID principal.",
			},
			"is_mfa": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, enforces Entra ID Multi-Factor Authentication for this principal.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"connection_limit": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(-1),
				MarkdownDescription: "Maximum concurrent connections (`-1` for unlimited).",
			},
			"create_db": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the principal can create databases (`CREATEDB`).",
			},
			"create_role": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the principal can create roles (`CREATEROLE`).",
			},
			"inherit": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the principal inherits privileges from roles it belongs to (`INHERIT`).",
			},
			"bypass_rls": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the principal bypasses row-level security (`BYPASSRLS`).",
			},
			"roles": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Additional PostgreSQL roles granted to this Entra principal (do not include `azure_pg_admin`; control it with `is_admin`).",
			},
			"parameters": schema.MapAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Role-level PostgreSQL parameters applied via `ALTER ROLE ... SET key = value`.",
			},
			"reassign_owned_to": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Role to reassign owned objects to prior to dropping this Entra role.",
			},
			"drop_owned": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, runs `DROP OWNED BY` before dropping this Entra role.",
			},
		},
	}
}

func (r *EntraRoleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *EntraRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan entraRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleName := plan.Name.ValueString()
	objectID := ""
	if !plan.ObjectID.IsNull() && !plan.ObjectID.IsUnknown() {
		objectID = plan.ObjectID.ValueString()
	}

	if err := r.client.CreateEntraPrincipal(
		ctx,
		roleName,
		objectID,
		plan.PrincipalType.ValueString(),
		plan.IsAdmin.ValueBool(),
		plan.IsMFA.ValueBool(),
	); err != nil {
		resp.Diagnostics.AddError("Failed to Create Microsoft Entra ID Principal", err.Error())
		return
	}

	if err := r.applyExtraRoleAttributes(ctx, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Configure Entra ID Role Attributes", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, roleName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Entra ID Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *EntraRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state entraRoleModel
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
		resp.Diagnostics.AddError("Failed to Read Entra ID Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *EntraRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state entraRoleModel
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

	roleName := plan.Name.ValueString()

	// Toggle azure_pg_admin membership if is_admin changed.
	if plan.IsAdmin.ValueBool() != state.IsAdmin.ValueBool() {
		var sql string
		if plan.IsAdmin.ValueBool() {
			sql = fmt.Sprintf("GRANT %s TO %s", pgclient.QuoteIdent("azure_pg_admin"), pgclient.QuoteIdent(roleName))
		} else {
			sql = fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent("azure_pg_admin"), pgclient.QuoteIdent(roleName))
		}
		err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, sql)
			return execErr
		})
		// On PostgreSQL 16+, if azure_pg_admin held reverse membership in roleName,
		// GRANT azure_pg_admin TO roleName returns SQLSTATE 0LP01 (circular membership).
		// Revoke the reverse membership and retry cleanly.
		if err != nil && plan.IsAdmin.ValueBool() && pgclient.PgErrorCode(err) == "0LP01" {
			_, _ = pool.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent(roleName), pgclient.QuoteIdent("azure_pg_admin")))
			err = pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, sql)
				return execErr
			})
		}
		if err != nil {
			resp.Diagnostics.AddError("Failed to Update azure_pg_admin Membership", err.Error())
			return
		}
	}

	if err := r.applyExtraRoleAttributes(ctx, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Update Entra ID Role Attributes", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Parameters.Equal(state.Parameters) {
		curParams := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
		desParams := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncEntityParameters(ctx, pool, "ROLE", roleName, desParams, curParams); err != nil {
			resp.Diagnostics.AddError("Failed to Update Entra ID Role Parameters", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, roleName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Entra ID Role", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *EntraRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state entraRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reassignTo := ""
	if !state.ReassignOwnedTo.IsNull() {
		reassignTo = state.ReassignOwnedTo.ValueString()
	}

	if err := r.client.DropRoleWithCleanup(ctx, state.Name.ValueString(), reassignTo, state.DropOwned.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Failed to Drop Entra ID Role", err.Error())
		return
	}
}

func (r *EntraRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func (r *EntraRoleResource) applyExtraRoleAttributes(ctx context.Context, m *entraRoleModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}
	caps, err := r.client.Capabilities(ctx)
	if err != nil {
		return err
	}

	roleName := m.Name.ValueString()
	needsAlter := m.CreateDB.ValueBool() ||
		m.CreateRole.ValueBool() ||
		!m.Inherit.ValueBool() ||
		m.BypassRLS.ValueBool() ||
		m.ConnectionLimit.ValueInt64() != -1

	if needsAlter {
		var opts []string
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
		if m.BypassRLS.ValueBool() {
			opts = append(opts, "BYPASSRLS")
		} else if caps.IsSuperuser {
			opts = append(opts, "NOBYPASSRLS")
		}
		opts = append(opts, fmt.Sprintf("CONNECTION LIMIT %d", m.ConnectionLimit.ValueInt64()))

		alterSQL := fmt.Sprintf("ALTER ROLE %s WITH %s", pgclient.QuoteIdent(roleName), strings.Join(opts, " "))
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, alterSQL)
			return execErr
		}); err != nil {
			return err
		}
	}

	if !m.Roles.IsNull() && !m.Roles.IsUnknown() {
		desiredRoles := setToStringSlice(ctx, m.Roles, diags)
		if diags.HasError() {
			return nil
		}
		exclude := map[string]bool{"azure_pg_admin": true}
		if err := syncRoleMemberships(ctx, pool, roleName, desiredRoles, exclude); err != nil {
			return err
		}
	}

	if !m.Parameters.IsNull() && !m.Parameters.IsUnknown() {
		desiredParams := mapToStringMap(ctx, m.Parameters, diags)
		if diags.HasError() {
			return nil
		}
		if err := syncEntityParameters(ctx, pool, "ROLE", roleName, desiredParams, nil); err != nil {
			return err
		}
	}

	return nil
}

func (r *EntraRoleResource) readIntoModel(ctx context.Context, roleName string, model *entraRoleModel, diags *diag.Diagnostics) error {
	principal, err := r.client.GetEntraPrincipal(ctx, roleName)
	if err != nil {
		return err
	}
	if principal == nil {
		return pgx.ErrNoRows
	}

	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	var (
		rolInherit    bool
		rolCreateRole bool
		rolCreateDB   bool
		rolBypassRLS  bool
		rolConnLimit  int64
		rolConfig     []string
	)

	err = pool.QueryRow(ctx, `
		SELECT
			rolinherit,
			rolcreaterole,
			rolcreatedb,
			rolbypassrls,
			rolconnlimit,
			COALESCE(rolconfig, ARRAY[]::text[])
		FROM pg_roles
		WHERE rolname = $1
	`, roleName).Scan(
		&rolInherit,
		&rolCreateRole,
		&rolCreateDB,
		&rolBypassRLS,
		&rolConnLimit,
		&rolConfig,
	)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(roleName)
	model.Name = types.StringValue(roleName)
	model.ObjectID = types.StringValue(principal.ObjectID)
	model.PrincipalType = types.StringValue(principal.PrincipalType)
	model.IsAdmin = types.BoolValue(principal.IsAdmin)
	model.IsMFA = types.BoolValue(principal.IsMFA)
	model.Inherit = types.BoolValue(rolInherit)
	model.CreateRole = types.BoolValue(rolCreateRole)
	model.CreateDB = types.BoolValue(rolCreateDB)
	model.BypassRLS = types.BoolValue(rolBypassRLS)
	model.ConnectionLimit = types.Int64Value(rolConnLimit)
	if model.DropOwned.IsNull() || model.DropOwned.IsUnknown() {
		model.DropOwned = types.BoolValue(false)
	}

	exclude := map[string]bool{"azure_pg_admin": true}
	memberships, err := readRoleMemberships(ctx, pool, roleName, exclude)
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
