package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &RoleDatabaseParametersResource{}
	_ resource.ResourceWithConfigure   = &RoleDatabaseParametersResource{}
	_ resource.ResourceWithImportState = &RoleDatabaseParametersResource{}
)

// RoleDatabaseParametersResource manages PostgreSQL role-in-database configuration parameters
// via `ALTER ROLE <role> IN DATABASE <database> SET <param> = <value>` (backed by `pg_db_role_setting`).
// Ideal for per-database audit settings (e.g. `pgaudit.log = "write, ddl, role"`), per-database
// `search_path`, `statement_timeout`, or `default_transaction_read_only`.
type RoleDatabaseParametersResource struct {
	client *pgclient.Client
}

type roleDatabaseParametersModel struct {
	ID         types.String `tfsdk:"id"`
	Database   types.String `tfsdk:"database"`
	Role       types.String `tfsdk:"role"`
	Parameters types.Map    `tfsdk:"parameters"`
}

func NewRoleDatabaseParametersResource() resource.Resource {
	return &RoleDatabaseParametersResource{}
}

func (r *RoleDatabaseParametersResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_database_parameters"
}

func (r *RoleDatabaseParametersResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages role-in-database PostgreSQL parameters (`ALTER ROLE <role> IN DATABASE <database> SET <param> = <value>`), stored in `pg_db_role_setting`. Supports standard GUCs (`statement_timeout`, `search_path`, `default_transaction_read_only`) and dot-qualified extension GUCs (e.g. `pgaudit.log = \"write, ddl, role\"`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier in format `<database>:<role>`.",
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
				MarkdownDescription: "Target PostgreSQL role or Entra ID principal name.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"parameters": schema.MapAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map of PostgreSQL parameter names to values applied specifically when `role` connects to `database`.",
			},
		},
	}
}

func (r *RoleDatabaseParametersResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *RoleDatabaseParametersResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleDatabaseParametersModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	role := plan.Role.ValueString()
	desired := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.syncRoleDBParameters(ctx, db, role, desired, nil); err != nil {
		resp.Diagnostics.AddError("Failed to Set Role-in-Database Parameters", err.Error())
		return
	}

	if err := r.readIntoModel(ctx, db, role, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Role-in-Database Parameters", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleDatabaseParametersResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleDatabaseParametersModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := state.Database.ValueString()
	role := state.Role.ValueString()
	found, err := r.readIntoModelCheck(ctx, db, role, &state, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Read Role-in-Database Parameters", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RoleDatabaseParametersResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleDatabaseParametersModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	role := plan.Role.ValueString()
	cur := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
	des := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.syncRoleDBParameters(ctx, db, role, des, cur); err != nil {
		resp.Diagnostics.AddError("Failed to Update Role-in-Database Parameters", err.Error())
		return
	}

	if err := r.readIntoModel(ctx, db, role, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Role-in-Database Parameters", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RoleDatabaseParametersResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleDatabaseParametersModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cur := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.syncRoleDBParameters(ctx, state.Database.ValueString(), state.Role.ValueString(), nil, cur); err != nil {
		if pgclient.IsUndefinedObject(err) || pgclient.IsInvalidCatalogName(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Reset Role-in-Database Parameters", err.Error())
		return
	}
}

func (r *RoleDatabaseParametersResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("Expected import ID in format '<database>:<role>', got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), parts[1])...)
}

func (r *RoleDatabaseParametersResource) syncRoleDBParameters(ctx context.Context, db, role string, desired, current map[string]string) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	for k := range current {
		if _, keep := desired[k]; !keep {
			sql := fmt.Sprintf("ALTER ROLE %s IN DATABASE %s RESET %s",
				pgclient.QuoteIdent(role),
				pgclient.QuoteIdent(db),
				quoteParameterName(k),
			)
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := pool.Exec(ctx, sql)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to RESET %q for role %q in database %q: %w", k, role, db, err)
			}
		}
	}

	for k, v := range desired {
		if curVal, exists := current[k]; exists && curVal == v {
			continue
		}
		sql := fmt.Sprintf("ALTER ROLE %s IN DATABASE %s SET %s = %s",
			pgclient.QuoteIdent(role),
			pgclient.QuoteIdent(db),
			quoteParameterName(k),
			pgclient.QuoteLiteral(v),
		)
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, sql)
			return execErr
		}); err != nil {
			return fmt.Errorf("failed to SET %q=%q for role %q in database %q: %w", k, v, role, db, err)
		}
	}
	return nil
}

func (r *RoleDatabaseParametersResource) readIntoModel(ctx context.Context, db, role string, model *roleDatabaseParametersModel, diags *diag.Diagnostics) error {
	found, err := r.readIntoModelCheck(ctx, db, role, model, diags)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("role-in-database parameters for %q in %q not found", role, db)
	}
	return nil
}

func (r *RoleDatabaseParametersResource) readIntoModelCheck(ctx context.Context, db, role string, model *roleDatabaseParametersModel, diags *diag.Diagnostics) (bool, error) {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return false, err
	}

	var setConfig []string
	err = pool.QueryRow(ctx, `
		SELECT COALESCE(s.setconfig, ARRAY[]::text[])
		FROM pg_database d
		JOIN pg_roles r ON r.rolname = $2
		LEFT JOIN pg_db_role_setting s ON s.setdatabase = d.oid AND s.setrole = r.oid
		WHERE d.datname = $1
	`, db, role).Scan(&setConfig)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	parsed := parsePGConfigArray(setConfig)
	if len(parsed) == 0 {
		// If the user explicitly configured an empty map, keep it; otherwise treat absent settings as removed.
		if !model.Parameters.IsNull() && !model.Parameters.IsUnknown() {
			tracked := mapToStringMap(ctx, model.Parameters, diags)
			if len(tracked) == 0 {
				model.ID = types.StringValue(fmt.Sprintf("%s:%s", db, role))
				model.Parameters = stringMapToTFMap(ctx, parsed, diags)
				return true, nil
			}
		}
		return false, nil
	}

	model.ID = types.StringValue(fmt.Sprintf("%s:%s", db, role))
	model.Database = types.StringValue(db)
	model.Role = types.StringValue(role)
	model.Parameters = stringMapToTFMap(ctx, parsed, diags)
	return true, nil
}
