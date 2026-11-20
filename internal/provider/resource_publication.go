package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &PublicationResource{}
	_ resource.ResourceWithConfigure   = &PublicationResource{}
	_ resource.ResourceWithImportState = &PublicationResource{}
	_ resource.ResourceWithModifyPlan  = &PublicationResource{}
)

type PublicationResource struct {
	client *pgclient.Client
}

type publicationModel struct {
	ID           types.String `tfsdk:"id"`
	Database     types.String `tfsdk:"database"`
	Name         types.String `tfsdk:"name"`
	Owner        types.String `tfsdk:"owner"`
	AllTables    types.Bool   `tfsdk:"all_tables"`
	Tables       types.Set    `tfsdk:"tables"`
	PublishParam types.Set    `tfsdk:"publish_param"`
	DropCascade  types.Bool   `tfsdk:"drop_cascade"`
}

func NewPublicationResource() resource.Resource {
	return &PublicationResource{}
}

func (r *PublicationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_publication"
}

func (r *PublicationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a PostgreSQL logical replication publication (`CREATE PUBLICATION`). Useful for Azure Flexible Server CDC, Debezium, and zero-downtime migrations.",
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
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Publication name. Supports in-place rename.",
			},
			"owner": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Role that owns the publication.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"all_tables": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If `true`, publishes changes for all tables in the database (`FOR ALL TABLES`).",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"tables": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Set of `schema.table` names included in the publication (ignored when `all_tables = true`).",
			},
			"publish_param": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "DML operations to publish: subset of `insert`, `update`, `delete`, `truncate`. Defaults to all four.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf("insert", "update", "delete", "truncate")),
				},
			},
			"drop_cascade": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Drop dependent objects via `DROP PUBLICATION ... CASCADE` on destroy.",
			},
		},
	}
}

func (r *PublicationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *PublicationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan publicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Database.IsUnknown() && !plan.Database.IsNull() && !plan.Name.IsUnknown() && !plan.Name.IsNull() {
		plan.ID = types.StringValue(fmt.Sprintf("%s.%s", plan.Database.ValueString(), plan.Name.ValueString()))
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}

func (r *PublicationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan publicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	name := plan.Name.ValueString()

	sql := fmt.Sprintf("CREATE PUBLICATION %s", pgclient.QuoteIdent(name))
	if plan.AllTables.ValueBool() {
		sql += " FOR ALL TABLES"
	} else {
		tables := setToStringSlice(ctx, plan.Tables, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(tables) > 0 {
			quoted := make([]string, len(tables))
			for i, t := range tables {
				quoted[i] = quoteTableRef(t)
			}
			sql += " FOR TABLE " + strings.Join(quoted, ", ")
		}
	}

	if !plan.PublishParam.IsNull() && !plan.PublishParam.IsUnknown() {
		params := setToStringSlice(ctx, plan.PublishParam, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		sql += fmt.Sprintf(" WITH (publish = %s)", pgclient.QuoteLiteral(strings.Join(params, ", ")))
	}

	if err := r.client.WithDatabaseOwnerMembership(ctx, db, func(p *pgxpool.Pool) error {
		_, execErr := p.Exec(ctx, sql)
		return execErr
	}); err != nil {
		resp.Diagnostics.AddError("Failed to Create Publication", err.Error())
		return
	}

	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() && plan.Owner.ValueString() != "" {
		owner := plan.Owner.ValueString()
		if err := r.client.WithRoleMembership(ctx, db, owner, func(p *pgxpool.Pool) error {
			_, execErr := p.Exec(ctx, fmt.Sprintf("ALTER PUBLICATION %s OWNER TO %s", pgclient.QuoteIdent(name), pgclient.QuoteIdent(owner)))
			return execErr
		}); err != nil {
			resp.Diagnostics.AddError("Failed to Set Publication Owner", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, db, name, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Created Publication", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PublicationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state publicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, state.Database.ValueString(), state.Name.ValueString(), &state, &resp.Diagnostics); err != nil {
		if err == pgx.ErrNoRows || pgclient.IsInvalidCatalogName(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Publication", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PublicationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state publicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	db := plan.Database.ValueString()
	currentName := state.Name.ValueString()
	targetName := plan.Name.ValueString()

	if err := r.client.WithDatabaseOwnerMembership(ctx, db, func(pool *pgxpool.Pool) error {
		if currentName != targetName {
			if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER PUBLICATION %s RENAME TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(targetName))); err != nil {
				return fmt.Errorf("failed to rename publication: %w", err)
			}
			currentName = targetName
		}

		if !plan.AllTables.ValueBool() && !plan.Tables.Equal(state.Tables) {
			tables := setToStringSlice(ctx, plan.Tables, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return nil
			}
			if len(tables) == 0 {
				oldTables := setToStringSlice(ctx, state.Tables, &resp.Diagnostics)
				if len(oldTables) > 0 {
					quoted := make([]string, len(oldTables))
					for i, t := range oldTables {
						quoted[i] = quoteTableRef(t)
					}
					if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER PUBLICATION %s DROP TABLE %s", pgclient.QuoteIdent(currentName), strings.Join(quoted, ", "))); err != nil {
						return fmt.Errorf("failed to clear publication tables: %w", err)
					}
				}
			} else {
				quoted := make([]string, len(tables))
				for i, t := range tables {
					quoted[i] = quoteTableRef(t)
				}
				if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER PUBLICATION %s SET TABLE %s", pgclient.QuoteIdent(currentName), strings.Join(quoted, ", "))); err != nil {
					return fmt.Errorf("failed to update publication tables: %w", err)
				}
			}
		}

		if !plan.PublishParam.IsNull() && !plan.PublishParam.IsUnknown() && !plan.PublishParam.Equal(state.PublishParam) {
			params := setToStringSlice(ctx, plan.PublishParam, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return nil
			}
			sql := fmt.Sprintf("ALTER PUBLICATION %s SET (publish = %s)", pgclient.QuoteIdent(currentName), pgclient.QuoteLiteral(strings.Join(params, ", ")))
			if _, err := pool.Exec(ctx, sql); err != nil {
				return fmt.Errorf("failed to update publication parameters: %w", err)
			}
		}
		return nil
	}); err != nil {
		resp.Diagnostics.AddError("Failed to Update Publication", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() && plan.Owner.ValueString() != state.Owner.ValueString() {
		owner := plan.Owner.ValueString()
		if err := r.client.WithRoleMembership(ctx, db, owner, func(p *pgxpool.Pool) error {
			_, execErr := p.Exec(ctx, fmt.Sprintf("ALTER PUBLICATION %s OWNER TO %s", pgclient.QuoteIdent(currentName), pgclient.QuoteIdent(owner)))
			return execErr
		}); err != nil {
			resp.Diagnostics.AddError("Failed to Update Publication Owner", err.Error())
			return
		}
	}

	if err := r.readIntoModel(ctx, db, currentName, &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Publication", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PublicationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state publicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sql := fmt.Sprintf("DROP PUBLICATION IF EXISTS %s", pgclient.QuoteIdent(state.Name.ValueString()))
	if state.DropCascade.ValueBool() {
		sql += " CASCADE"
	}
	if err := r.client.WithDatabaseOwnerMembership(ctx, state.Database.ValueString(), func(p *pgxpool.Pool) error {
		_, execErr := p.Exec(ctx, sql)
		return execErr
	}); err != nil {
		if pgclient.IsInvalidCatalogName(err) {
			return
		}
		resp.Diagnostics.AddError("Failed to Drop Publication", err.Error())
		return
	}
}

func (r *PublicationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	db, name, err := splitTwoPartID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), db)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func (r *PublicationResource) readIntoModel(ctx context.Context, db, name string, model *publicationModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, db)
	if err != nil {
		return err
	}

	var (
		owner       string
		allTables   bool
		pubInsert   bool
		pubUpdate   bool
		pubDelete   bool
		pubTruncate bool
	)

	err = pool.QueryRow(ctx, `
		SELECT
			pg_get_userbyid(pubowner),
			puballtables,
			pubinsert,
			pubupdate,
			pubdelete,
			pubtruncate
		FROM pg_publication
		WHERE pubname = $1
	`, name).Scan(&owner, &allTables, &pubInsert, &pubUpdate, &pubDelete, &pubTruncate)
	if err != nil {
		return err
	}

	var params []string
	if pubInsert {
		params = append(params, "insert")
	}
	if pubUpdate {
		params = append(params, "update")
	}
	if pubDelete {
		params = append(params, "delete")
	}
	if pubTruncate {
		params = append(params, "truncate")
	}
	sort.Strings(params)

	model.ID = types.StringValue(fmt.Sprintf("%s.%s", db, name))
	model.Database = types.StringValue(db)
	model.Name = types.StringValue(name)
	model.Owner = types.StringValue(owner)
	model.AllTables = types.BoolValue(allTables)
	model.PublishParam = stringSliceToSet(ctx, params, diags)
	if model.DropCascade.IsNull() || model.DropCascade.IsUnknown() {
		model.DropCascade = types.BoolValue(false)
	}

	if !allTables {
		rows, err := pool.Query(ctx, `
			SELECT schemaname || '.' || tablename
			FROM pg_publication_tables
			WHERE pubname = $1
			ORDER BY schemaname, tablename
		`, name)
		if err != nil {
			return err
		}
		defer rows.Close()
		var tables []string
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err != nil {
				return err
			}
			tables = append(tables, t)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(tables) > 0 || !model.Tables.IsNull() {
			model.Tables = stringSliceToSet(ctx, tables, diags)
		}
	}

	return nil
}

func quoteTableRef(ref string) string {
	parts := strings.SplitN(ref, ".", 2)
	if len(parts) == 2 {
		return pgclient.QuoteQualifiedIdent(parts[0], parts[1])
	}
	return pgclient.QuoteIdent(ref)
}
