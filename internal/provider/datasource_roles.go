package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ datasource.DataSource              = &RolesDataSource{}
	_ datasource.DataSourceWithConfigure = &RolesDataSource{}
)

type RolesDataSource struct {
	client *pgclient.Client
}

type rolesDataModel struct {
	ID            types.String    `tfsdk:"id"`
	IncludeSystem types.Bool      `tfsdk:"include_system"`
	Roles         []roleItemModel `tfsdk:"roles"`
}

type roleItemModel struct {
	Name            types.String `tfsdk:"name"`
	Login           types.Bool   `tfsdk:"login"`
	Superuser       types.Bool   `tfsdk:"superuser"`
	CreateDB        types.Bool   `tfsdk:"create_db"`
	CreateRole      types.Bool   `tfsdk:"create_role"`
	Inherit         types.Bool   `tfsdk:"inherit"`
	Replication     types.Bool   `tfsdk:"replication"`
	BypassRLS       types.Bool   `tfsdk:"bypass_rls"`
	ConnectionLimit types.Int64  `tfsdk:"connection_limit"`
	MemberOf        types.List   `tfsdk:"member_of"`
}

func NewRolesDataSource() datasource.DataSource {
	return &RolesDataSource{}
}

func (d *RolesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roles"
}

func (d *RolesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists PostgreSQL roles and their attributes/memberships.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"include_system": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Include PostgreSQL built-in `pg_*` and Azure internal `azuresu` roles. Defaults to `false`.",
			},
			"roles": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":             schema.StringAttribute{Computed: true},
						"login":            schema.BoolAttribute{Computed: true},
						"superuser":        schema.BoolAttribute{Computed: true},
						"create_db":        schema.BoolAttribute{Computed: true},
						"create_role":      schema.BoolAttribute{Computed: true},
						"inherit":          schema.BoolAttribute{Computed: true},
						"replication":      schema.BoolAttribute{Computed: true},
						"bypass_rls":       schema.BoolAttribute{Computed: true},
						"connection_limit": schema.Int64Attribute{Computed: true},
						"member_of":        schema.ListAttribute{Computed: true, ElementType: types.StringType},
					},
				},
			},
		},
	}
}

func (d *RolesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *RolesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config rolesDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := d.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	includeSystem := !config.IncludeSystem.IsNull() && config.IncludeSystem.ValueBool()
	rows, err := pool.Query(ctx, `
		SELECT
			r.rolname,
			r.rolcanlogin,
			r.rolsuper,
			r.rolcreatedb,
			r.rolcreaterole,
			r.rolinherit,
			r.rolreplication,
			r.rolbypassrls,
			r.rolconnlimit,
			COALESCE(ARRAY(
				SELECT g.rolname
				FROM pg_auth_members m
				JOIN pg_roles g ON g.oid = m.roleid
				WHERE m.member = r.oid
				ORDER BY g.rolname
			), ARRAY[]::text[])
		FROM pg_roles r
		WHERE ($1 OR (r.rolname NOT LIKE 'pg\_%' ESCAPE '\' AND r.rolname NOT IN ('azuresu', 'replication')))
		ORDER BY r.rolname
	`, includeSystem)
	if err != nil {
		resp.Diagnostics.AddError("Failed to List Roles", err.Error())
		return
	}
	defer rows.Close()

	var items []roleItemModel
	for rows.Next() {
		var (
			name                                                        string
			login, superuser, createDB, createRole, inherit, repl, brls bool
			connLimit                                                   int64
			memberOf                                                    []string
		)
		if err := rows.Scan(&name, &login, &superuser, &createDB, &createRole, &inherit, &repl, &brls, &connLimit, &memberOf); err != nil {
			resp.Diagnostics.AddError("Failed to Scan Role Row", err.Error())
			return
		}
		items = append(items, roleItemModel{
			Name:            types.StringValue(name),
			Login:           types.BoolValue(login),
			Superuser:       types.BoolValue(superuser),
			CreateDB:        types.BoolValue(createDB),
			CreateRole:      types.BoolValue(createRole),
			Inherit:         types.BoolValue(inherit),
			Replication:     types.BoolValue(repl),
			BypassRLS:       types.BoolValue(brls),
			ConnectionLimit: types.Int64Value(connLimit),
			MemberOf:        stringSliceToList(ctx, memberOf, &resp.Diagnostics),
		})
	}
	if err := rows.Err(); err != nil {
		resp.Diagnostics.AddError("Failed to Read Roles", err.Error())
		return
	}

	config.ID = types.StringValue(d.client.Config().Host)
	config.Roles = items
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
