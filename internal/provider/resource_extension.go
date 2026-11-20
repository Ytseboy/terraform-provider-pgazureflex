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
	_ resource.Resource                = &ExtensionResource{}
	_ resource.ResourceWithConfigure   = &ExtensionResource{}
	_ resource.ResourceWithImportState = &ExtensionResource{}
)

type ExtensionResource struct {
	client *pgclient.Client
}

type extensionModel struct {
	ID          types.String `tfsdk:"id"`
	Database    types.String `tfsdk:"database"`
	Name        types.String `tfsdk:"name"`
	Schema      types.String `tfsdk:"schema"`
	Version     types.String `tfsdk:"version"`
	Cascade     types.Bool   `tfsdk:"cascade"`
	DropCascade types.Bool   `tfsdk:"drop_cascade"`
}

func NewExtensionResource() resource.Resource {
	return &ExtensionResource{}
}

func (r *ExtensionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_extension"
}

func (r *ExtensionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a PostgreSQL extension inside a database. On Azure Flexible Server, enriches allowlist errors with current `azure.extensions` and `shared_preload_libraries` diagnostics.",
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
				MarkdownDescription: "Target database where the extension is installed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Extension name (e.g. `pgcrypto`, `uuid-ossp`, `vector`, `postgis`, `pg_stat_statements`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"schema": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Schema in which to install the extension's objects.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"version": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Version of the extension to install or upgrade to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cascade": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Automatically install dependent extensions via `CREATE EXTENSION ... CASCADE`.",
			},
			"drop_cascade": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Drop dependent objects via `DROP EXTENSION ... CASCADE` on destroy.",
			},
		},
	}
}

func (r *ExtensionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *ExtensionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan extensionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	name := plan.Name.ValueString()

	sql := fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s", pgclient.QuoteIdent(name))
	if !plan.Schema.IsNull() && !plan.Schema.IsUnknown() && plan.Schema.ValueString() != "" {
		sql += " SCHEMA " + pgclient.QuoteIdent(plan.Schema.ValueString())
	}
	if !plan.Version.IsNull() && !plan.Version.IsUnknown() && plan.Version.ValueString() != "" {
		sql += " VERSION " + pgclient.QuoteLiteral(plan.Version.ValueString())
	}
	if plan.Cascade.ValueBool() {
		sql += " CASCADE"
	}

	if err := r.client.WithDatabaseOwnerMembership(ctx, db, func(p *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
	}); err != nil {
		enriched := r.client.DiagnoseAzureExtensionError(ctx, name, err)
		resp.Diagnostics.AddError("Failed to Create Extension", enriched.Error())
		return
	}

	if err := r.readIntoModel(ctx, db, name, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Extension", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ExtensionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state extensionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, state.Database.ValueString(), state.Name.ValueString(), &state); err != nil {
		if err == pgx.ErrNoRows || pgclient.IsInvalidCatalogName(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Extension", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ExtensionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state extensionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	name := plan.Name.ValueString()
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	if !plan.Schema.IsNull() && !plan.Schema.IsUnknown() && plan.Schema.ValueString() != state.Schema.ValueString() {
		sql := fmt.Sprintf("ALTER EXTENSION %s SET SCHEMA %s", pgclient.QuoteIdent(name), pgclient.QuoteIdent(plan.Schema.ValueString()))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Move Extension Schema", err.Error())
			return
		}
	}

	if !plan.Version.IsNull() && !plan.Version.IsUnknown() && plan.Version.ValueString() != state.Version.ValueString() {
		sql := fmt.Sprintf("ALTER EXTENSION %s UPDATE TO %s", pgclient.QuoteIdent(name), pgclient.QuoteLiteral(plan.Version.ValueString()))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Update Extension Version", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, db, name, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Extension", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ExtensionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state extensionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sql := fmt.Sprintf("DROP EXTENSION IF EXISTS %s", pgclient.QuoteIdent(state.Name.ValueString()))
	if state.DropCascade.ValueBool() {
		sql += " CASCADE"
	}
	if err := r.client.WithDatabaseOwnerMembership(ctx, state.Database.ValueString(), func(p *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
	}); err != nil {
		if pgclient.IsInvalidCatalogName(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Drop Extension", err.Error())
		return
	}
}

func (r *ExtensionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	db, name, err := splitTwoPartID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), db)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func (r *ExtensionResource) readIntoModel(ctx context.Context, db, name string, model *extensionModel) error {
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		return err
	}

	var extSchema, extVersion string
	err = pool.QueryRow(ctx, `
		SELECT n.nspname, e.extversion
		FROM pg_extension e
		JOIN pg_namespace n ON n.oid = e.extnamespace
		WHERE e.extname = $1
	`, name).Scan(&extSchema, &extVersion)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(fmt.Sprintf("%s.%s", db, name))
	model.Database = types.StringValue(db)
	model.Name = types.StringValue(name)
	model.Schema = types.StringValue(extSchema)
	model.Version = types.StringValue(extVersion)
	if model.Cascade.IsNull() || model.Cascade.IsUnknown() {
		model.Cascade = types.BoolValue(false)
	}
	if model.DropCascade.IsNull() || model.DropCascade.IsUnknown() {
		model.DropCascade = types.BoolValue(false)
	}
	return nil
}
