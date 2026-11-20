package provider

import (
	"context"
	"fmt"
	"strings"

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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &DatabaseResource{}
	_ resource.ResourceWithConfigure   = &DatabaseResource{}
	_ resource.ResourceWithImportState = &DatabaseResource{}
	_ resource.ResourceWithModifyPlan  = &DatabaseResource{}
)

type DatabaseResource struct {
	client *pgclient.Client
}

type databaseModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Owner            types.String `tfsdk:"owner"`
	Template         types.String `tfsdk:"template"`
	Encoding         types.String `tfsdk:"encoding"`
	LCCollate        types.String `tfsdk:"lc_collate"`
	LCCtype          types.String `tfsdk:"lc_ctype"`
	TablespaceName   types.String `tfsdk:"tablespace_name"`
	ConnectionLimit  types.Int64  `tfsdk:"connection_limit"`
	IsTemplate       types.Bool   `tfsdk:"is_template"`
	AllowConnections types.Bool   `tfsdk:"allow_connections"`
	ForceDrop        types.Bool   `tfsdk:"force_drop"`
	Parameters       types.Map    `tfsdk:"parameters"`
}

func NewDatabaseResource() resource.Resource {
	return &DatabaseResource{}
}

func (r *DatabaseResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_database"
}

func (r *DatabaseResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a PostgreSQL database. Automatically handles `azure_pg_admin` ownership assignment on Azure Flexible Server and closes provider pools before dropping.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier (matches database `name`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the database. Changing this renames the database in-place via `ALTER DATABASE ... RENAME TO`.",
			},
			"owner": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Role that owns the database. Defaults to the connecting user.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"template": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Template database from which to create the database (e.g. `template0` or `template1`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encoding": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Character set encoding (e.g. `UTF8`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"lc_collate": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Collation order (`LC_COLLATE`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"lc_ctype": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Character classification (`LC_CTYPE`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"tablespace_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Default tablespace for the database.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"connection_limit": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(-1),
				MarkdownDescription: "Maximum concurrent connections allowed (`-1` for unlimited).",
			},
			"is_template": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If `true`, this database can be cloned by any user with `CREATEDB`.",
			},
			"allow_connections": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "If `false`, no one can connect to this database.",
			},
			"force_drop": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, terminates active sessions via `DROP DATABASE ... WITH (FORCE)` (PostgreSQL 13+) during destroy.",
			},
			"parameters": schema.MapAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Database-level configuration parameters set via `ALTER DATABASE ... SET key = value`.",
			},
		},
	}
}

func (r *DatabaseResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *DatabaseResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan databaseModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Name.IsUnknown() && !plan.Name.IsNull() {
		plan.ID = plan.Name
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

func (r *DatabaseResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databaseModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dbName := plan.Name.ValueString()
	owner := ""
	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() {
		owner = plan.Owner.ValueString()
	}

	var opts []string
	if owner != "" {
		opts = append(opts, "OWNER = "+pgclient.QuoteIdent(owner))
	}
	if !plan.Template.IsNull() && !plan.Template.IsUnknown() && plan.Template.ValueString() != "" {
		opts = append(opts, "TEMPLATE = "+pgclient.QuoteIdent(plan.Template.ValueString()))
	}
	if !plan.Encoding.IsNull() && !plan.Encoding.IsUnknown() && plan.Encoding.ValueString() != "" {
		opts = append(opts, "ENCODING = "+pgclient.QuoteLiteral(plan.Encoding.ValueString()))
	}
	if !plan.LCCollate.IsNull() && !plan.LCCollate.IsUnknown() && plan.LCCollate.ValueString() != "" {
		opts = append(opts, "LC_COLLATE = "+pgclient.QuoteLiteral(plan.LCCollate.ValueString()))
	}
	if !plan.LCCtype.IsNull() && !plan.LCCtype.IsUnknown() && plan.LCCtype.ValueString() != "" {
		opts = append(opts, "LC_CTYPE = "+pgclient.QuoteLiteral(plan.LCCtype.ValueString()))
	}
	if !plan.TablespaceName.IsNull() && !plan.TablespaceName.IsUnknown() && plan.TablespaceName.ValueString() != "" {
		opts = append(opts, "TABLESPACE = "+pgclient.QuoteIdent(plan.TablespaceName.ValueString()))
	}
	if !plan.ConnectionLimit.IsNull() && !plan.ConnectionLimit.IsUnknown() {
		opts = append(opts, fmt.Sprintf("CONNECTION LIMIT = %d", plan.ConnectionLimit.ValueInt64()))
	}
	if !plan.IsTemplate.IsNull() && !plan.IsUnknownBool(plan.IsTemplate) {
		opts = append(opts, fmt.Sprintf("IS_TEMPLATE = %t", plan.IsTemplate.ValueBool()))
	}
	if !plan.AllowConnections.IsNull() && !plan.AllowConnections.IsUnknown() {
		opts = append(opts, fmt.Sprintf("ALLOW_CONNECTIONS = %t", plan.AllowConnections.ValueBool()))
	}

	createSQL := fmt.Sprintf("CREATE DATABASE %s", pgclient.QuoteIdent(dbName))
	if len(opts) > 0 {
		createSQL += " WITH " + strings.Join(opts, " ")
	}

	err := r.client.WithRoleMembership(ctx, "", owner, func(pool *pgxpool.Pool) error {
		_, execErr := pool.Exec(ctx, createSQL)
		return execErr
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to Create Database", fmt.Sprintf("Error creating database %q: %v", dbName, err))
		return
	}

	if !plan.Parameters.IsNull() && !plan.Parameters.IsUnknown() {
		desiredParams := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := r.client.WithRoleMembership(ctx, "", owner, func(p *pgxpool.Pool) error {
			return syncEntityParameters(ctx, p, "DATABASE", dbName, desiredParams, nil)
		}); err != nil {
			resp.Diagnostics.AddError("Failed to Set Database Parameters", err.Error())
			return
		}
	}

	// Read back authoritative database metadata.
	if err := r.readIntoModel(ctx, dbName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Database", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (m *databaseModel) IsUnknownBool(v types.Bool) bool {
	return v.IsUnknown()
}

func (r *DatabaseResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databaseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dbName := state.Name.ValueString()
	if dbName == "" {
		dbName = state.ID.ValueString()
	}

	err := r.readIntoModel(ctx, dbName, &state, &resp.Diagnostics)
	if err != nil {
		if err == pgx.ErrNoRows {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Database", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DatabaseResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state databaseModel
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

	currentName := state.Name.ValueString()
	targetName := plan.Name.ValueString()

	if currentName != targetName {
		r.client.CloseDatabasePool(currentName)
		renameSQL := fmt.Sprintf("ALTER DATABASE %s RENAME TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(targetName))
		if _, err := pool.Exec(ctx, renameSQL); err != nil {
			resp.Diagnostics.AddError("Failed to Rename Database", err.Error())
			return
		}
		currentName = targetName
	}

	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() && plan.Owner.ValueString() != state.Owner.ValueString() {
		newOwner := plan.Owner.ValueString()
		err := r.client.WithRoleMembership(ctx, "", newOwner, func(p *pgxpool.Pool) error {
			sql := fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(newOwner))
			_, execErr := p.Exec(ctx, sql)
			return execErr
		})
		if err != nil {
			resp.Diagnostics.AddError("Failed to Update Database Owner", err.Error())
			return
		}
	}

	if !plan.TablespaceName.IsNull() && !plan.TablespaceName.IsUnknown() && plan.TablespaceName.ValueString() != state.TablespaceName.ValueString() {
		sql := fmt.Sprintf("ALTER DATABASE %s SET TABLESPACE %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(plan.TablespaceName.ValueString()))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Update Database Tablespace", err.Error())
			return
		}
	}

	var alterOpts []string
	if plan.ConnectionLimit.ValueInt64() != state.ConnectionLimit.ValueInt64() {
		alterOpts = append(alterOpts, fmt.Sprintf("CONNECTION LIMIT %d", plan.ConnectionLimit.ValueInt64()))
	}
	if plan.IsTemplate.ValueBool() != state.IsTemplate.ValueBool() {
		alterOpts = append(alterOpts, fmt.Sprintf("IS_TEMPLATE %t", plan.IsTemplate.ValueBool()))
	}
	if plan.AllowConnections.ValueBool() != state.AllowConnections.ValueBool() {
		alterOpts = append(alterOpts, fmt.Sprintf("ALLOW_CONNECTIONS %t", plan.AllowConnections.ValueBool()))
	}
	if len(alterOpts) > 0 {
		sql := fmt.Sprintf("ALTER DATABASE %s WITH %s", pgclient.QuoteIdent(currentName), strings.Join(alterOpts, " "))
		if _, err := pool.Exec(ctx, sql); err != nil {
			resp.Diagnostics.AddError("Failed to Update Database Options", err.Error())
			return
		}
	}

	if !plan.Parameters.Equal(state.Parameters) {
		curParams := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
		desParams := mapToStringMap(ctx, plan.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := syncEntityParameters(ctx, pool, "DATABASE", currentName, desParams, curParams); err != nil {
			resp.Diagnostics.AddError("Failed to Update Database Parameters", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, currentName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Database", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DatabaseResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databaseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dbName := state.Name.ValueString()
	// Close any cached provider pool targeting this database before attempting DROP DATABASE.
	r.client.CloseDatabasePool(dbName)

	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	// If database is marked as template, unmark it before dropping.
	if state.IsTemplate.ValueBool() {
		_, _ = pool.Exec(ctx, fmt.Sprintf("ALTER DATABASE %s WITH IS_TEMPLATE false", pgclient.QuoteIdent(dbName)))
	}

	caps, _ := r.client.Capabilities(ctx)
	dropSQL := fmt.Sprintf("DROP DATABASE IF EXISTS %s", pgclient.QuoteIdent(dbName))
	if state.ForceDrop.ValueBool() {
		if caps.VersionNum >= 130000 {
			dropSQL += " WITH (FORCE)"
		} else {
			_, _ = pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		}
	}

	owner := state.Owner.ValueString()
	if err := r.client.WithRoleMembership(ctx, "", owner, func(p *pgxpool.Pool) error {
		return pgclient.RetryTransient(ctx, func() error {
			_, execErr := p.Exec(ctx, dropSQL)
			return execErr
		})
	}); err != nil {
		resp.Diagnostics.AddError("Failed to Drop Database", fmt.Sprintf("Error dropping database %q: %v", dbName, err))
		return
	}
}

func (r *DatabaseResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func (r *DatabaseResource) readIntoModel(ctx context.Context, dbName string, model *databaseModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	var (
		owner            string
		encoding         string
		lcCollate        string
		lcCtype          string
		tablespace       string
		connLimit        int64
		isTemplate       bool
		allowConnections bool
		setConfig        []string
	)

	err = pool.QueryRow(ctx, `
		SELECT
			pg_get_userbyid(d.datdba),
			pg_encoding_to_char(d.encoding),
			d.datcollate,
			d.datctype,
			t.spcname,
			d.datconnlimit,
			d.datistemplate,
			d.datallowconn,
			COALESCE(s.setconfig, ARRAY[]::text[])
		FROM pg_database d
		JOIN pg_tablespace t ON t.oid = d.dattablespace
		LEFT JOIN pg_db_role_setting s ON s.setdatabase = d.oid AND s.setrole = 0
		WHERE d.datname = $1
	`, dbName).Scan(
		&owner,
		&encoding,
		&lcCollate,
		&lcCtype,
		&tablespace,
		&connLimit,
		&isTemplate,
		&allowConnections,
		&setConfig,
	)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(dbName)
	model.Name = types.StringValue(dbName)
	model.Owner = types.StringValue(owner)
	if model.Template.IsNull() || model.Template.IsUnknown() {
		model.Template = types.StringValue("template1")
	}
	model.Encoding = types.StringValue(encoding)
	model.LCCollate = types.StringValue(lcCollate)
	model.LCCtype = types.StringValue(lcCtype)
	model.TablespaceName = types.StringValue(tablespace)
	model.ConnectionLimit = types.Int64Value(connLimit)
	model.IsTemplate = types.BoolValue(isTemplate)
	model.AllowConnections = types.BoolValue(allowConnections)
	if model.ForceDrop.IsNull() || model.ForceDrop.IsUnknown() {
		model.ForceDrop = types.BoolValue(false)
	}

	parsedParams := parsePGConfigArray(setConfig)
	if len(parsedParams) > 0 || !model.Parameters.IsNull() {
		model.Parameters = stringMapToTFMap(ctx, parsedParams, diags)
	}

	return nil
}
