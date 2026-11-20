package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &EntraRoleMappingResource{}
	_ resource.ResourceWithConfigure   = &EntraRoleMappingResource{}
	_ resource.ResourceWithImportState = &EntraRoleMappingResource{}
	_ resource.ResourceWithModifyPlan  = &EntraRoleMappingResource{}
)

// EntraRoleMappingResource maps a Microsoft Entra ID identity (User, Group, Managed Identity,
// or Service Principal) onto an existing PostgreSQL role using Azure Flexible Server's native
// `SECURITY LABEL FOR "pgaadauth" ON ROLE` mechanism, and optionally manages PostgreSQL RBAC
// role memberships for that mapped role.
type EntraRoleMappingResource struct {
	client *pgclient.Client
}

type entraRoleMappingModel struct {
	ID            types.String `tfsdk:"id"`
	Role          types.String `tfsdk:"role"`
	ObjectID      types.String `tfsdk:"object_id"`
	PrincipalType types.String `tfsdk:"principal_type"`
	IsAdmin       types.Bool   `tfsdk:"is_admin"`
	IsMFA         types.Bool   `tfsdk:"is_mfa"`
	EnsureLogin   types.Bool   `tfsdk:"ensure_login"`
	PostgresRoles types.Set    `tfsdk:"postgres_roles"`
	SecurityLabel types.String `tfsdk:"security_label"`
}

func NewEntraRoleMappingResource() resource.Resource {
	return &EntraRoleMappingResource{}
}

func (r *EntraRoleMappingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entra_role_mapping"
}

func (r *EntraRoleMappingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Maps a Microsoft Entra ID identity (`object_id`, `principal_type`) to an **existing** PostgreSQL role using Azure Flexible Server's `SECURITY LABEL FOR \"pgaadauth\" ON ROLE`. Supports zero-downtime migration from password roles to Entra ID, custom PostgreSQL role names, and **in-place `object_id` rotation** without dropping the role or its owned objects.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier (matches the target PostgreSQL `role`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Existing PostgreSQL role name to bind to the Microsoft Entra ID identity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"object_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Microsoft Entra ID Object ID (UUID) of the User, Security Group, Managed Identity, or Service Principal. Updating this rotates the mapping **in-place** without dropping the PostgreSQL role.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(uuidRegex, "must be a valid Entra ID Object ID UUID"),
				},
			},
			"principal_type": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("user"),
				MarkdownDescription: "Microsoft Entra ID principal type: `user`, `group`, or `service` (Managed Identities and Service Principals).",
				Validators: []validator.String{
					stringvalidator.OneOf("user", "group", "service"),
				},
			},
			"is_admin": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, includes `,admin` in the `pgaadauth` security label and grants `azure_pg_admin` membership to the mapped role.",
			},
			"is_mfa": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, includes `,mfa` in the `pgaadauth` security label to require Entra ID MFA.",
			},
			"ensure_login": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "When `true`, automatically ensures the target PostgreSQL role has `LOGIN` enabled so Entra ID tokens can authenticate as it.",
			},
			"postgres_roles": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Optional set of PostgreSQL RBAC group roles to grant to the mapped role (e.g. `[\"orders_rw\", \"analytics_ro\"]`). Revoked when removed from this set or when the mapping is destroyed.",
			},
			"security_label": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Rendered `pgaadauth` security label applied to the PostgreSQL role (e.g. `aadauth,oid=...,type=service`).",
			},
		},
	}
}

func (r *EntraRoleMappingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *EntraRoleMappingResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip destroy plans.
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan entraRoleMappingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.ObjectID.IsUnknown() && !plan.ObjectID.IsNull() &&
		!plan.PrincipalType.IsUnknown() && !plan.PrincipalType.IsNull() &&
		!plan.IsAdmin.IsUnknown() && !plan.IsMFA.IsUnknown() {
		if label, err := pgclient.FormatPGAADAuthSecurityLabel(
			plan.ObjectID.ValueString(),
			plan.PrincipalType.ValueString(),
			plan.IsAdmin.ValueBool(),
			plan.IsMFA.ValueBool(),
		); err == nil {
			plan.SecurityLabel = types.StringValue(label)
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		}
	}
}

func (r *EntraRoleMappingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan entraRoleMappingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyMapping(ctx, &plan, nil, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Create Entra Role Mapping", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, plan.Role.ValueString(), &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Entra Role Mapping", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *EntraRoleMappingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state entraRoleMappingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleName := state.Role.ValueString()
	if roleName == "" {
		roleName = state.ID.ValueString()
	}

	found, err := r.readIntoModelCheck(ctx, roleName, &state, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Read Entra Role Mapping", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *EntraRoleMappingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state entraRoleMappingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyMapping(ctx, &plan, &state, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Update Entra Role Mapping", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, plan.Role.ValueString(), &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Entra Role Mapping", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *EntraRoleMappingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state entraRoleMappingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	roleName := state.Role.ValueString()
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	// 1. Remove the pgaadauth security label (leaving the PostgreSQL role and its objects intact).
	if err := r.client.ClearEntraSecurityLabel(ctx, roleName); err != nil {
		resp.Diagnostics.AddError("Failed to Clear Entra Security Label", err.Error())
		return
	}

	// 2. Revoke azure_pg_admin if this mapping granted it.
	if state.IsAdmin.ValueBool() {
		_, _ = pool.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent("azure_pg_admin"), pgclient.QuoteIdent(roleName)))
	}

	// 3. Revoke only the postgres_roles that this mapping managed.
	managedRoles := setToStringSlice(ctx, state.PostgresRoles, &resp.Diagnostics)
	for _, pgRole := range managedRoles {
		if pgRole == "azure_pg_admin" {
			continue
		}
		_, _ = pool.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent(pgRole), pgclient.QuoteIdent(roleName)))
	}
}

func (r *EntraRoleMappingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), req.ID)...)
}

func (r *EntraRoleMappingResource) applyMapping(ctx context.Context, plan, prior *entraRoleMappingModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	roleName := plan.Role.ValueString()

	if plan.EnsureLogin.ValueBool() {
		var canLogin bool
		err := pool.QueryRow(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname = $1`, roleName).Scan(&canLogin)
		if err != nil {
			return fmt.Errorf("target PostgreSQL role %q does not exist or cannot be queried: %w", roleName, err)
		}
		if !canLogin {
			if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH LOGIN", pgclient.QuoteIdent(roleName))); err != nil {
				return fmt.Errorf("failed to enable LOGIN on role %q: %w", roleName, err)
			}
		}
	}

	label, err := r.client.SetEntraSecurityLabel(
		ctx,
		roleName,
		plan.ObjectID.ValueString(),
		plan.PrincipalType.ValueString(),
		plan.IsAdmin.ValueBool(),
		plan.IsMFA.ValueBool(),
	)
	if err != nil {
		return err
	}
	plan.SecurityLabel = types.StringValue(label)

	// Sync azure_pg_admin membership according to is_admin.
	wasAdmin := prior != nil && prior.IsAdmin.ValueBool()
	wantAdmin := plan.IsAdmin.ValueBool()
	if wantAdmin && !wasAdmin {
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", pgclient.QuoteIdent("azure_pg_admin"), pgclient.QuoteIdent(roleName)))
			return execErr
		}); err != nil {
			return fmt.Errorf("failed to GRANT azure_pg_admin to %q: %w", roleName, err)
		}
	} else if !wantAdmin && wasAdmin {
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent("azure_pg_admin"), pgclient.QuoteIdent(roleName)))
			return execErr
		}); err != nil {
			return fmt.Errorf("failed to REVOKE azure_pg_admin from %q: %w", roleName, err)
		}
	}

	// Diff only the managed postgres_roles so we don't disturb unrelated role memberships.
	var prevRoles []string
	if prior != nil && !prior.PostgresRoles.IsNull() {
		prevRoles = setToStringSlice(ctx, prior.PostgresRoles, diags)
	}
	var desiredRoles []string
	if !plan.PostgresRoles.IsNull() && !plan.PostgresRoles.IsUnknown() {
		desiredRoles = setToStringSlice(ctx, plan.PostgresRoles, diags)
	}
	if diags.HasError() {
		return nil
	}

	prevSet := make(map[string]bool, len(prevRoles))
	for _, rName := range prevRoles {
		prevSet[rName] = true
	}
	desSet := make(map[string]bool, len(desiredRoles))
	for _, rName := range desiredRoles {
		if rName == "azure_pg_admin" {
			continue
		}
		desSet[rName] = true
	}

	for rName := range desSet {
		if !prevSet[rName] {
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", pgclient.QuoteIdent(rName), pgclient.QuoteIdent(roleName)))
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to GRANT PostgreSQL role %q to Entra-mapped role %q: %w", rName, roleName, err)
			}
		}
	}
	for rName := range prevSet {
		if !desSet[rName] && rName != "azure_pg_admin" {
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgclient.QuoteIdent(rName), pgclient.QuoteIdent(roleName)))
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to REVOKE PostgreSQL role %q from Entra-mapped role %q: %w", rName, roleName, err)
			}
		}
	}

	return nil
}

func (r *EntraRoleMappingResource) readIntoModel(ctx context.Context, roleName string, model *entraRoleMappingModel, diags *diag.Diagnostics) error {
	found, err := r.readIntoModelCheck(ctx, roleName, model, diags)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("pgaadauth security label mapping for role %q was not found after write", roleName)
	}
	return nil
}

func (r *EntraRoleMappingResource) readIntoModelCheck(ctx context.Context, roleName string, model *entraRoleMappingModel, diags *diag.Diagnostics) (bool, error) {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return false, err
	}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, roleName).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}

	parsed, rawLabel, err := r.client.GetEntraSecurityLabel(ctx, roleName)
	if err != nil {
		return false, err
	}
	if parsed == nil {
		return false, nil
	}

	model.ID = types.StringValue(roleName)
	model.Role = types.StringValue(roleName)
	model.ObjectID = types.StringValue(parsed.ObjectID)
	model.PrincipalType = types.StringValue(parsed.PrincipalType)
	model.IsAdmin = types.BoolValue(parsed.IsAdmin)
	model.IsMFA = types.BoolValue(parsed.IsMFA)
	model.SecurityLabel = types.StringValue(rawLabel)
	if model.EnsureLogin.IsNull() || model.EnsureLogin.IsUnknown() {
		model.EnsureLogin = types.BoolValue(true)
	}

	// If postgres_roles is being managed, check which of the tracked roles are currently granted.
	if !model.PostgresRoles.IsNull() && !model.PostgresRoles.IsUnknown() {
		actualMemberships, err := readRoleMemberships(ctx, pool, roleName, map[string]bool{"azure_pg_admin": true})
		if err != nil {
			return false, err
		}
		actualSet := make(map[string]bool, len(actualMemberships))
		for _, m := range actualMemberships {
			actualSet[m] = true
		}
		tracked := setToStringSlice(ctx, model.PostgresRoles, diags)
		var stillGranted []string
		for _, t := range tracked {
			if actualSet[t] {
				stillGranted = append(stillGranted, t)
			}
		}
		model.PostgresRoles = stringSliceToSet(ctx, stillGranted, diags)
	}

	return true, nil
}
