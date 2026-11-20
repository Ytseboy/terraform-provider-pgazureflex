package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &RoleMembershipResource{}
	_ resource.ResourceWithConfigure   = &RoleMembershipResource{}
	_ resource.ResourceWithImportState = &RoleMembershipResource{}
)

// RoleMembershipResource manages a single `GRANT <role> TO <member_role>` relationship.
// Ideal for declaratively mapping Microsoft Entra ID principals (Users, Security Groups,
// Managed Identities) to PostgreSQL RBAC roles in a decoupled IAM layer.
type RoleMembershipResource struct {
	client *pgclient.Client
}

type roleMembershipModel struct {
	ID                types.String `tfsdk:"id"`
	Role              types.String `tfsdk:"role"`
	MemberRole        types.String `tfsdk:"member_role"`
	WithAdminOption   types.Bool   `tfsdk:"with_admin_option"`
	WithInheritOption types.Bool   `tfsdk:"with_inherit_option"`
	WithSetOption     types.Bool   `tfsdk:"with_set_option"`
}

func NewRoleMembershipResource() resource.Resource {
	return &RoleMembershipResource{}
}

func (r *RoleMembershipResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_membership"
}

func (r *RoleMembershipResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a standalone PostgreSQL role membership (`GRANT <role> TO <member_role>`). Ideal for declaratively mapping Microsoft Entra ID principals (`pgazureflex_entra_role`) to PostgreSQL RBAC roles (`pgazureflex_role`) across separate Terraform modules, with full PostgreSQL 16+ `ADMIN`, `INHERIT`, and `SET` option support.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier in format `<role>:<member_role>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Target PostgreSQL role being granted (e.g. an RBAC group role like `orders_rw` or `orders_ro`).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"member_role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Grantee role receiving membership (e.g. a Microsoft Entra ID user, group, or Managed Identity role name).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"with_admin_option": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether `member_role` can grant `role` to other roles (`WITH ADMIN OPTION`).",
			},
			"with_inherit_option": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "PostgreSQL 16+: whether `member_role` automatically inherits privileges of `role` (`WITH INHERIT TRUE/FALSE`). Ignored on PostgreSQL <16.",
			},
			"with_set_option": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "PostgreSQL 16+: whether `member_role` may execute `SET ROLE <role>` (`WITH SET TRUE/FALSE`). Ignored on PostgreSQL <16.",
			},
		},
	}
}

func (r *RoleMembershipResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *RoleMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyGrant(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Grant Role Membership", err.Error())
		return
	}

	if err := r.readIntoModel(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Role Membership", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	found, err := r.readIntoModelCheck(ctx, &state)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Read Role Membership", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RoleMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleMembershipModel
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

	role := plan.Role.ValueString()
	member := plan.MemberRole.ValueString()

	// Revoke options that changed from true -> false before applying the new GRANT.
	if state.WithAdminOption.ValueBool() && !plan.WithAdminOption.ValueBool() {
		if _, err := pool.Exec(ctx, fmt.Sprintf("REVOKE ADMIN OPTION FOR %s FROM %s", pgclient.QuoteIdent(role), pgclient.QuoteIdent(member))); err != nil {
			resp.Diagnostics.AddError("Failed to Revoke ADMIN OPTION", err.Error())
			return
		}
	}
	if caps.VersionNum >= 160000 {
		if state.WithInheritOption.ValueBool() && !plan.WithInheritOption.ValueBool() {
			if _, err := pool.Exec(ctx, fmt.Sprintf("REVOKE INHERIT OPTION FOR %s FROM %s", pgclient.QuoteIdent(role), pgclient.QuoteIdent(member))); err != nil {
				resp.Diagnostics.AddError("Failed to Revoke INHERIT OPTION", err.Error())
				return
			}
		}
		if state.WithSetOption.ValueBool() && !plan.WithSetOption.ValueBool() {
			if _, err := pool.Exec(ctx, fmt.Sprintf("REVOKE SET OPTION FOR %s FROM %s", pgclient.QuoteIdent(role), pgclient.QuoteIdent(member))); err != nil {
				resp.Diagnostics.AddError("Failed to Revoke SET OPTION", err.Error())
				return
			}
		}
	}

	if err := r.applyGrant(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Update Role Membership", err.Error())
		return
	}

	if err := r.readIntoModel(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Role Membership", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	sql := fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent(state.Role.ValueString()), pgclient.QuoteIdent(state.MemberRole.ValueString()))
	if err := pgclient.RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	}); err != nil {
		if pgclient.IsUndefinedObject(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Revoke Role Membership", err.Error())
		return
	}
}

func (r *RoleMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("Expected import ID in format '<role>:<member_role>', got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member_role"), parts[1])...)
}

func (r *RoleMembershipResource) applyGrant(ctx context.Context, m *roleMembershipModel) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}
	caps, err := r.client.Capabilities(ctx)
	if err != nil {
		return err
	}

	role := m.Role.ValueString()
	member := m.MemberRole.ValueString()

	var sql string
	if caps.VersionNum >= 160000 {
		sql = fmt.Sprintf(
			"GRANT %s TO %s WITH ADMIN %t, INHERIT %t, SET %t",
			pgclient.QuoteIdent(role),
			pgclient.QuoteIdent(member),
			m.WithAdminOption.ValueBool(),
			m.WithInheritOption.ValueBool(),
			m.WithSetOption.ValueBool(),
		)
	} else {
		sql = fmt.Sprintf("GRANT %s TO %s", pgclient.QuoteIdent(role), pgclient.QuoteIdent(member))
		if m.WithAdminOption.ValueBool() {
			sql += " WITH ADMIN OPTION"
		}
	}

	return pgclient.RetryTransient(ctx, func() error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	})
}

func (r *RoleMembershipResource) readIntoModel(ctx context.Context, m *roleMembershipModel) error {
	found, err := r.readIntoModelCheck(ctx, m)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("role membership %q -> %q not found", m.Role.ValueString(), m.MemberRole.ValueString())
	}
	return nil
}

func (r *RoleMembershipResource) readIntoModelCheck(ctx context.Context, m *roleMembershipModel) (bool, error) {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return false, err
	}
	caps, err := r.client.Capabilities(ctx)
	if err != nil {
		return false, err
	}

	role := m.Role.ValueString()
	member := m.MemberRole.ValueString()

	var (
		count      int
		adminOpt   bool
		inheritOpt bool
		setOpt     bool
	)

	if caps.VersionNum >= 160000 {
		err = pool.QueryRow(ctx, `
			SELECT
				COUNT(*),
				COALESCE(bool_or(m.admin_option), false),
				COALESCE(bool_or(m.inherit_option), false),
				COALESCE(bool_or(m.set_option), false)
			FROM pg_auth_members m
			JOIN pg_roles r ON r.oid = m.roleid
			JOIN pg_roles mem ON mem.oid = m.member
			WHERE r.rolname = $1 AND mem.rolname = $2
		`, role, member).Scan(&count, &adminOpt, &inheritOpt, &setOpt)
	} else {
		err = pool.QueryRow(ctx, `
			SELECT
				COUNT(*),
				COALESCE(bool_or(m.admin_option), false)
			FROM pg_auth_members m
			JOIN pg_roles r ON r.oid = m.roleid
			JOIN pg_roles mem ON mem.oid = m.member
			WHERE r.rolname = $1 AND mem.rolname = $2
		`, role, member).Scan(&count, &adminOpt)
		inheritOpt = true
		setOpt = true
	}
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}

	m.ID = types.StringValue(fmt.Sprintf("%s:%s", role, member))
	m.WithAdminOption = types.BoolValue(adminOpt)
	m.WithInheritOption = types.BoolValue(inheritOpt)
	m.WithSetOption = types.BoolValue(setOpt)
	return true, nil
}
