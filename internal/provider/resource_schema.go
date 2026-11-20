package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &SchemaResource{}
	_ resource.ResourceWithConfigure   = &SchemaResource{}
	_ resource.ResourceWithImportState = &SchemaResource{}
	_ resource.ResourceWithModifyPlan  = &SchemaResource{}
)

type SchemaResource struct {
	client *pgclient.Client
}

type schemaModel struct {
	ID                 types.String `tfsdk:"id"`
	Database           types.String `tfsdk:"database"`
	Name               types.String `tfsdk:"name"`
	Owner              types.String `tfsdk:"owner"`
	IfNotExists        types.Bool   `tfsdk:"if_not_exists"`
	DropCascade        types.Bool   `tfsdk:"drop_cascade"`
	RevokePublicCreate types.Bool   `tfsdk:"revoke_public_create"`
}

func NewSchemaResource() resource.Resource {
	return &SchemaResource{}
}

func (r *SchemaResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_schema"
}

func (r *SchemaResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a PostgreSQL schema inside a specific database. Handles `azure_pg_admin` ownership authorization automatically on Azure Flexible Server.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier in format `<database>.<name>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"database": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Target database name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Schema name. Renaming updates in-place via `ALTER SCHEMA ... RENAME TO`.",
			},
			"owner": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Role that owns the schema. Defaults to the connecting user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"if_not_exists": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Use `CREATE SCHEMA IF NOT EXISTS` on creation.",
			},
			"drop_cascade": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, drops contained objects via `DROP SCHEMA ... CASCADE` on destroy.",
			},
			"revoke_public_create": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, executes `REVOKE CREATE ON SCHEMA <name> FROM PUBLIC` (useful for hardening schemas on PG 14 or explicit compliance).",
			},
		},
	}
}

func (r *SchemaResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *SchemaResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan schemaModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Database.IsUnknown() && !plan.Database.IsNull() && !plan.Name.IsUnknown() && !plan.Name.IsNull() {
		plan.ID = types.StringValue(fmt.Sprintf("%s.%s", plan.Database.ValueString(), plan.Name.ValueString()))
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

func (r *SchemaResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan schemaModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	name := plan.Name.ValueString()
	owner := ""
	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() {
		owner = plan.Owner.ValueString()
	}

	createSQL := "CREATE SCHEMA "
	if plan.IfNotExists.ValueBool() {
		createSQL += "IF NOT EXISTS "
	}
	createSQL += pgclient.QuoteIdent(name)
	if owner != "" {
		createSQL += " AUTHORIZATION " + pgclient.QuoteIdent(owner)
	}

	err := r.client.WithRoleMembership(ctx, db, owner, func(pool *pgxpool.Pool) error {
		if err := pgclient.RetryTransient(ctx, func() error {
			_, execErr := pool.Exec(ctx, createSQL)
			return execErr
		}); err != nil {
			return err
		}
		if plan.RevokePublicCreate.ValueBool() {
			revokeSQL := fmt.Sprintf("REVOKE CREATE ON SCHEMA %s FROM PUBLIC", pgclient.QuoteIdent(name))
			if _, execErr := pool.Exec(ctx, revokeSQL); execErr != nil {
				return execErr
			}
		}
		return nil
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to Create Schema", fmt.Sprintf("Error creating schema %q in database %q: %v", name, db, err))
		return
	}

	if err := r.readIntoModel(ctx, db, name, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Schema", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SchemaResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state schemaModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := state.Database.ValueString()
	name := state.Name.ValueString()
	if err := r.readIntoModel(ctx, db, name, &state); err != nil {
		if err == pgx.ErrNoRows || pgclient.IsInvalidCatalogName(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Schema", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SchemaResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state schemaModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	currentName := state.Name.ValueString()
	targetName := plan.Name.ValueString()
	if currentName != targetName {
		sql := fmt.Sprintf("ALTER SCHEMA %s RENAME TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(targetName))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Rename Schema", err.Error())
			return
		}
		currentName = targetName
	}

	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() && plan.Owner.ValueString() != state.Owner.ValueString() {
		newOwner := plan.Owner.ValueString()
		err := r.client.WithRoleMembership(ctx, db, newOwner, func(p *pgxpool.Pool) error {
			sql := fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(newOwner))
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
		if err != nil {
			resp.Diagnostics.AddError("Failed to Update Schema Owner", err.Error())
			return
		}
	}

	if plan.RevokePublicCreate.ValueBool() && !state.RevokePublicCreate.ValueBool() {
		sql := fmt.Sprintf("REVOKE CREATE ON SCHEMA %s FROM PUBLIC", pgclient.QuoteIdent(currentName))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Revoke PUBLIC CREATE on Schema", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, db, currentName, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Schema", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SchemaResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state schemaModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dropSQL := fmt.Sprintf("DROP SCHEMA IF EXISTS %s", pgclient.QuoteIdent(state.Name.ValueString()))
	if state.DropCascade.ValueBool() {
		dropSQL += " CASCADE"
	}
	if err := r.client.WithDatabaseOwnerMembership(ctx, state.Database.ValueString(), func(p *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := p.Exec(ctx, dropSQL)
			return execErr
		})
	}); err != nil {
		if pgclient.IsInvalidCatalogName(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Drop Schema", err.Error())
		return
	}
}

func (r *SchemaResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	db, name, err := splitTwoPartID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), db)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func (r *SchemaResource) readIntoModel(ctx context.Context, db, name string, model *schemaModel) error {
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		return err
	}

	var owner string
	err = pool.QueryRow(ctx, `
		SELECT pg_get_userbyid(nspowner)
		FROM pg_namespace
		WHERE nspname = $1
	`, name).Scan(&owner)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(fmt.Sprintf("%s.%s", db, name))
	model.Database = types.StringValue(db)
	model.Name = types.StringValue(name)
	model.Owner = types.StringValue(owner)
	if model.IfNotExists.IsNull() || model.IfNotExists.IsUnknown() {
		model.IfNotExists = types.BoolValue(true)
	}
	if model.DropCascade.IsNull() || model.DropCascade.IsUnknown() {
		model.DropCascade = types.BoolValue(false)
	}
	if model.RevokePublicCreate.IsNull() || model.RevokePublicCreate.IsUnknown() {
		model.RevokePublicCreate = types.BoolValue(false)
	}
	return nil
}
