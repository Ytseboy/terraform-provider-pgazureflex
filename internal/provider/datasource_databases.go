package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ datasource.DataSource              = &DatabasesDataSource{}
	_ datasource.DataSourceWithConfigure = &DatabasesDataSource{}
)

type DatabasesDataSource struct {
	client *pgclient.Client
}

type databasesDataModel struct {
	ID               types.String        `tfsdk:"id"`
	IncludeTemplates types.Bool          `tfsdk:"include_templates"`
	Databases        []databaseItemModel `tfsdk:"databases"`
}

type databaseItemModel struct {
	Name             types.String `tfsdk:"name"`
	Owner            types.String `tfsdk:"owner"`
	Encoding         types.String `tfsdk:"encoding"`
	LCCollate        types.String `tfsdk:"lc_collate"`
	LCCtype          types.String `tfsdk:"lc_ctype"`
	ConnectionLimit  types.Int64  `tfsdk:"connection_limit"`
	IsTemplate       types.Bool   `tfsdk:"is_template"`
	AllowConnections types.Bool   `tfsdk:"allow_connections"`
}

func NewDatabasesDataSource() datasource.DataSource {
	return &DatabasesDataSource{}
}

func (d *DatabasesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_databases"
}

func (d *DatabasesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists databases present on the PostgreSQL server.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"include_templates": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Include template databases (`template0`, `template1`, etc.). Defaults to `false`.",
			},
			"databases": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":              schema.StringAttribute{Computed: true},
						"owner":             schema.StringAttribute{Computed: true},
						"encoding":          schema.StringAttribute{Computed: true},
						"lc_collate":        schema.StringAttribute{Computed: true},
						"lc_ctype":          schema.StringAttribute{Computed: true},
						"connection_limit":  schema.Int64Attribute{Computed: true},
						"is_template":       schema.BoolAttribute{Computed: true},
						"allow_connections": schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *DatabasesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *DatabasesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config databasesDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pool, err := d.client.Pool(ctx, "")
	if err != nil {
		resp.Diagnostics.AddError("Database Connection Error", err.Error())
		return
	}

	includeTemplates := !config.IncludeTemplates.IsNull() && config.IncludeTemplates.ValueBool()
	rows, err := pool.Query(ctx, `
		SELECT
			d.datname,
			pg_get_userbyid(d.datdba),
			pg_encoding_to_char(d.encoding),
			d.datcollate,
			d.datctype,
			d.datconnlimit,
			d.datistemplate,
			d.datallowconn
		FROM pg_database d
		WHERE ($1 OR NOT d.datistemplate)
		ORDER BY d.datname
	`, includeTemplates)
	if err != nil {
		resp.Diagnostics.AddError("Failed to List Databases", err.Error())
		return
	}
	defer rows.Close()

	var items []databaseItemModel
	for rows.Next() {
		var (
			name, owner, enc, collate, ctype string
			connLimit                        int64
			isTpl, allowConn                 bool
		)
		if err := rows.Scan(&name, &owner, &enc, &collate, &ctype, &connLimit, &isTpl, &allowConn); err != nil {
			resp.Diagnostics.AddError("Failed to Scan Database Row", err.Error())
			return
		}
		items = append(items, databaseItemModel{
			Name:             types.StringValue(name),
			Owner:            types.StringValue(owner),
			Encoding:         types.StringValue(enc),
			LCCollate:        types.StringValue(collate),
			LCCtype:          types.StringValue(ctype),
			ConnectionLimit:  types.Int64Value(connLimit),
			IsTemplate:       types.BoolValue(isTpl),
			AllowConnections: types.BoolValue(allowConn),
		})
	}
	if err := rows.Err(); err != nil {
		resp.Diagnostics.AddError("Failed to Read Databases", err.Error())
		return
	}

	config.ID = types.StringValue(d.client.Config().Host)
	config.Databases = items
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
