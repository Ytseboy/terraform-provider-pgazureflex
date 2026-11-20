package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ datasource.DataSource              = &ServerInfoDataSource{}
	_ datasource.DataSourceWithConfigure = &ServerInfoDataSource{}
)

type ServerInfoDataSource struct {
	client *pgclient.Client
}

type serverInfoModel struct {
	ID                     types.String `tfsdk:"id"`
	VersionNum             types.Int64  `tfsdk:"version_num"`
	VersionString          types.String `tfsdk:"version_string"`
	CurrentUser            types.String `tfsdk:"current_user"`
	IsSuperuser            types.Bool   `tfsdk:"is_superuser"`
	IsAzurePGAdmin         types.Bool   `tfsdk:"is_azure_pg_admin"`
	IsAzureFlexibleServer  types.Bool   `tfsdk:"is_azure_flexible_server"`
	HasPGAADAuth           types.Bool   `tfsdk:"has_pgaadauth"`
	AllowedExtensions      types.List   `tfsdk:"allowed_extensions"`
	SharedPreloadLibraries types.List   `tfsdk:"shared_preload_libraries"`
	SSLInUse               types.Bool   `tfsdk:"ssl_in_use"`
	SSLVersion             types.String `tfsdk:"ssl_version"`
	SSLCipher              types.String `tfsdk:"ssl_cipher"`
}

func NewServerInfoDataSource() datasource.DataSource {
	return &ServerInfoDataSource{}
}

func (d *ServerInfoDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_server_info"
}

func (d *ServerInfoDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Inspects live PostgreSQL and Azure Database for PostgreSQL Flexible Server capabilities, including `azure.extensions`, `shared_preload_libraries`, `pgaadauth` availability, TLS status, and caller role privileges.",
		Attributes: map[string]schema.Attribute{
			"id":                       schema.StringAttribute{Computed: true},
			"version_num":              schema.Int64Attribute{Computed: true, MarkdownDescription: "Numeric PostgreSQL version (e.g. `160004`)."},
			"version_string":           schema.StringAttribute{Computed: true, MarkdownDescription: "Full output of `version()`."},
			"current_user":             schema.StringAttribute{Computed: true, MarkdownDescription: "Authenticated PostgreSQL role name."},
			"is_superuser":             schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the connecting user has `SUPERUSER`."},
			"is_azure_pg_admin":        schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the connecting user is a member of `azure_pg_admin`."},
			"is_azure_flexible_server": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the target server is detected as Azure Database for PostgreSQL Flexible Server."},
			"has_pgaadauth":            schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether `pgaadauth` Microsoft Entra ID functions are available on the server."},
			"allowed_extensions":       schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Extensions allow-listed via the `azure.extensions` server parameter."},
			"shared_preload_libraries": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Libraries configured in `shared_preload_libraries`."},
			"ssl_in_use":               schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the current connection uses TLS."},
			"ssl_version":              schema.StringAttribute{Computed: true, MarkdownDescription: "Negotiated TLS protocol version (e.g. `TLSv1.3`)."},
			"ssl_cipher":               schema.StringAttribute{Computed: true, MarkdownDescription: "Negotiated TLS cipher suite."},
		},
	}
}

func (d *ServerInfoDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *ServerInfoDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	caps, err := d.client.RefreshCapabilities(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Query Server Info", err.Error())
		return
	}

	cfg := d.client.Config()
	state := serverInfoModel{
		ID:                     types.StringValue(cfg.Host),
		VersionNum:             types.Int64Value(int64(caps.VersionNum)),
		VersionString:          types.StringValue(caps.VersionString),
		CurrentUser:            types.StringValue(caps.CurrentUser),
		IsSuperuser:            types.BoolValue(caps.IsSuperuser),
		IsAzurePGAdmin:         types.BoolValue(caps.IsAzurePGAdmin),
		IsAzureFlexibleServer:  types.BoolValue(caps.IsAzureFlexibleServer),
		HasPGAADAuth:           types.BoolValue(caps.HasPGAADAuth),
		AllowedExtensions:      stringSliceToList(ctx, caps.AllowedExtensions, &resp.Diagnostics),
		SharedPreloadLibraries: stringSliceToList(ctx, caps.SharedPreloadLibraries, &resp.Diagnostics),
		SSLInUse:               types.BoolValue(caps.SSLInUse),
		SSLVersion:             types.StringValue(caps.SSLVersion),
		SSLCipher:              types.StringValue(caps.SSLCipher),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
