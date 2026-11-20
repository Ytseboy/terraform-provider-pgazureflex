package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var (
	_ datasource.DataSource              = &EntraPrincipalsDataSource{}
	_ datasource.DataSourceWithConfigure = &EntraPrincipalsDataSource{}
)

type EntraPrincipalsDataSource struct {
	client *pgclient.Client
}

type entraPrincipalsModel struct {
	ID         types.String              `tfsdk:"id"`
	AdminsOnly types.Bool                `tfsdk:"admins_only"`
	Principals []entraPrincipalItemModel `tfsdk:"principals"`
}

type entraPrincipalItemModel struct {
	Name          types.String `tfsdk:"name"`
	ObjectID      types.String `tfsdk:"object_id"`
	PrincipalType types.String `tfsdk:"principal_type"`
	IsAdmin       types.Bool   `tfsdk:"is_admin"`
	IsMFA         types.Bool   `tfsdk:"is_mfa"`
}

func NewEntraPrincipalsDataSource() datasource.DataSource {
	return &EntraPrincipalsDataSource{}
}

func (d *EntraPrincipalsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entra_principals"
}

func (d *EntraPrincipalsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists Microsoft Entra ID principals registered in Azure Database for PostgreSQL Flexible Server via `pgaadauth_list_principals`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"admins_only": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "If `true`, returns only principals with `azure_pg_admin` privileges.",
			},
			"principals": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Microsoft Entra ID principals configured on the server.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":           schema.StringAttribute{Computed: true},
						"object_id":      schema.StringAttribute{Computed: true},
						"principal_type": schema.StringAttribute{Computed: true},
						"is_admin":       schema.BoolAttribute{Computed: true},
						"is_mfa":         schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *EntraPrincipalsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *EntraPrincipalsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config entraPrincipalsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principals, err := d.client.ListEntraPrincipals(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to List Entra ID Principals", err.Error())
		return
	}

	adminsOnly := !config.AdminsOnly.IsNull() && config.AdminsOnly.ValueBool()
	items := make([]entraPrincipalItemModel, 0, len(principals))
	for _, p := range principals {
		if adminsOnly && !p.IsAdmin {
			continue
		}
		items = append(items, entraPrincipalItemModel{
			Name:          types.StringValue(p.RoleName),
			ObjectID:      types.StringValue(p.ObjectID),
			PrincipalType: types.StringValue(p.PrincipalType),
			IsAdmin:       types.BoolValue(p.IsAdmin),
			IsMFA:         types.BoolValue(p.IsMFA),
		})
	}

	config.ID = types.StringValue(d.client.Config().Host)
	config.Principals = items
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
