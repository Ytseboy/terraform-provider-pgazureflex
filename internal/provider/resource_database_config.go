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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ resource.Resource                = &DatabaseConfigResource{}
	_ resource.ResourceWithConfigure   = &DatabaseConfigResource{}
	_ resource.ResourceWithImportState = &DatabaseConfigResource{}
)

// DatabaseConfigResource non-destructively configures an existing PostgreSQL database
// (such as one created via `azurerm_postgresql_flexible_server_database`): transferring
// ownership (`ALTER DATABASE ... OWNER TO`), revoking `PUBLIC` database privileges
// (`REVOKE ALL PRIVILEGES ON DATABASE ... FROM PUBLIC`), setting `connection_limit`, and
// managing `ALTER DATABASE ... SET` parameters — without owning `CREATE`/`DROP DATABASE`.
type DatabaseConfigResource struct {
	client *pgclient.Client
}

type databaseConfigModel struct {
	ID                 types.String `tfsdk:"id"`
	Database           types.String `tfsdk:"database"`
	Owner              types.String `tfsdk:"owner"`
	RevokePublicAccess types.Bool   `tfsdk:"revoke_public_access"`
	ConnectionLimit    types.Int64  `tfsdk:"connection_limit"`
	Parameters         types.Map    `tfsdk:"parameters"`
}

func NewDatabaseConfigResource() resource.Resource {
	return &DatabaseConfigResource{}
}

func (r *DatabaseConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_database_config"
}

func (r *DatabaseConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Non-destructively configures an **existing** PostgreSQL database (for example, one provisioned by `azurerm_postgresql_flexible_server_database`). Manages database ownership (`ALTER DATABASE ... OWNER TO` with automatic `azure_pg_admin` multi-role impersonation across both current and target owners), `PUBLIC` privilege revocation, `connection_limit`, and database-level `ALTER DATABASE SET` parameters without owning `CREATE`/`DROP DATABASE`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier (matches `database`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"database": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Existing PostgreSQL database name to configure.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"owner": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Desired PostgreSQL role or Entra ID principal that owns the database. Automatically handles temporary membership in both the current database owner and target owner under `azure_pg_admin`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"revoke_public_access": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, runs `REVOKE ALL PRIVILEGES ON DATABASE <database> FROM PUBLIC` and detects drift if `PUBLIC` regains any database privilege (`CONNECT`, `TEMPORARY`, `CREATE`).",
			},
			"connection_limit": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Maximum concurrent connections allowed on the database (`-1` for unlimited).",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"parameters": schema.MapAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Database-level configuration parameters managed via `ALTER DATABASE ... SET key = value` / `RESET key`.",
			},
		},
	}
}

func (r *DatabaseConfigResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *DatabaseConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databaseConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyConfig(ctx, &plan, nil, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Configure Database", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, plan.Database.ValueString(), &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Database Configuration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DatabaseConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databaseConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dbName := state.Database.ValueString()
	if dbName == "" {
		dbName = state.ID.ValueString()
	}

	err := r.readIntoModel(ctx, dbName, &state, &resp.Diagnostics)
	if err != nil {
		if err == pgx.ErrNoRows {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to Read Database Configuration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DatabaseConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state databaseConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyConfig(ctx, &plan, &state, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Update Database Configuration", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readIntoModel(ctx, plan.Database.ValueString(), &plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to Read Updated Database Configuration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DatabaseConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databaseConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Non-destructive teardown: reset only managed database parameters; NEVER drop the database
	// or re-grant PUBLIC access.
	if !state.Parameters.IsNull() && !state.Parameters.IsUnknown() {
		curParams := mapToStringMap(ctx, state.Parameters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() || len(curParams) == 0 {
			return
		}
		dbName := state.Database.ValueString()
		owner := state.Owner.ValueString()
		if err := r.client.WithRoleMembership(ctx, "", owner, func(p *pgxpool.Pool) error {
			return syncEntityParameters(ctx, p, "DATABASE", dbName, nil, curParams)
		}); err != nil && !pgclient.IsInvalidCatalogName(err) {
			resp.Diagnostics.AddError("Failed to Reset Database Parameters on Destroy", err.Error())
			return
		}
	}
}

func (r *DatabaseConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("database"), req.ID)...)
}

func (r *DatabaseConfigResource) applyConfig(ctx context.Context, plan, prior *databaseConfigModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	dbName := plan.Database.ValueString()

	var currentOwner string
	if err := pool.QueryRow(ctx, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1`, dbName).Scan(&currentOwner); err != nil {
		return fmt.Errorf("database %q does not exist or cannot be queried: %w", dbName, err)
	}

	targetOwner := currentOwner
	if !plan.Owner.IsNull() && !plan.Owner.IsUnknown() && plan.Owner.ValueString() != "" {
		targetOwner = plan.Owner.ValueString()
	}

	rolesNeeded := []string{currentOwner}
	if !strings.EqualFold(targetOwner, currentOwner) {
		rolesNeeded = append(rolesNeeded, targetOwner)
	}

	return r.client.WithRoleMemberships(ctx, "", rolesNeeded, func(p *pgxpool.Pool) error {
		// 1. Revoke PUBLIC database privileges while holding current owner's privileges.
		if plan.RevokePublicAccess.ValueBool() {
			revokeSQL := fmt.Sprintf("REVOKE ALL PRIVILEGES ON DATABASE %s FROM PUBLIC", pgclient.QuoteIdent(dbName))
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := p.Exec(ctx, revokeSQL)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to revoke PUBLIC privileges on database %q: %w", dbName, err)
			}
		}

		// 2. Update connection_limit if explicitly set.
		if !plan.ConnectionLimit.IsNull() && !plan.ConnectionLimit.IsUnknown() {
			sql := fmt.Sprintf("ALTER DATABASE %s WITH CONNECTION LIMIT %d", pgclient.QuoteIdent(dbName), plan.ConnectionLimit.ValueInt64())
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := p.Exec(ctx, sql)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to set connection_limit on database %q: %w", dbName, err)
			}
		}

		// 3. Sync ALTER DATABASE ... SET parameters if configured or changed.
		if !plan.Parameters.IsNull() && !plan.Parameters.IsUnknown() || (prior != nil && !prior.Parameters.IsNull()) {
			var curParams map[string]string
			if prior != nil && !prior.Parameters.IsNull() {
				curParams = mapToStringMap(ctx, prior.Parameters, diags)
			}
			desParams := mapToStringMap(ctx, plan.Parameters, diags)
			if diags.HasError() {
				return nil
			}
			if err := syncEntityParameters(ctx, p, "DATABASE", dbName, desParams, curParams); err != nil {
				return err
			}
		}

		// 4. Transfer ownership last (from currentOwner -> targetOwner).
		if !strings.EqualFold(targetOwner, currentOwner) {
			ownerSQL := fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", pgclient.QuoteIdent(dbName), pgclient.QuoteIdent(targetOwner))
			if err := pgclient.RetryTransient(ctx, func() error {
				_, execErr := p.Exec(ctx, ownerSQL)
				return execErr
			}); err != nil {
				return fmt.Errorf("failed to transfer ownership of database %q from %q to %q: %w", dbName, currentOwner, targetOwner, err)
			}
		}

		return nil
	})
}

func (r *DatabaseConfigResource) readIntoModel(ctx context.Context, dbName string, model *databaseConfigModel, diags *diag.Diagnostics) error {
	pool, err := r.client.Pool(ctx, "")
	if err != nil {
		return err
	}

	var (
		owner           string
		connLimit       int64
		setConfig       []string
		publicPrivCount int
	)

	err = pool.QueryRow(ctx, `
		SELECT
			pg_get_userbyid(d.datdba),
			d.datconnlimit,
			COALESCE(s.setconfig, ARRAY[]::text[]),
			(
				SELECT COUNT(*)
				FROM aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
				WHERE a.grantee = 0
			)
		FROM pg_database d
		LEFT JOIN pg_db_role_setting s ON s.setdatabase = d.oid AND s.setrole = 0
		WHERE d.datname = $1
	`, dbName).Scan(&owner, &connLimit, &setConfig, &publicPrivCount)
	if err != nil {
		return err
	}

	model.ID = types.StringValue(dbName)
	model.Database = types.StringValue(dbName)
	model.Owner = types.StringValue(owner)
	model.ConnectionLimit = types.Int64Value(connLimit)
	// When revoke_public_access is enabled (or during import), reflect real catalog PUBLIC ACL state.
	if model.RevokePublicAccess.IsNull() || model.RevokePublicAccess.IsUnknown() || model.RevokePublicAccess.ValueBool() {
		model.RevokePublicAccess = types.BoolValue(publicPrivCount == 0)
	}

	parsedParams := parsePGConfigArray(setConfig)
	if len(parsedParams) > 0 || !model.Parameters.IsNull() {
		model.Parameters = stringMapToTFMap(ctx, parsedParams, diags)
	}
	return nil
}
