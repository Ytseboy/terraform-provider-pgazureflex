package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
)

var _ provider.Provider = &PGAzureFlexProvider{}

// PGAzureFlexProvider implements the Terraform Plugin Framework Provider for PostgreSQL
// with first-class support for Azure Database for PostgreSQL Flexible Server.
type PGAzureFlexProvider struct {
	version        string
	azureTransport policy.Transporter
}

type providerModel struct {
	Host                    types.String `tfsdk:"host"`
	Port                    types.Int64  `tfsdk:"port"`
	Database                types.String `tfsdk:"database"`
	Username                types.String `tfsdk:"username"`
	Password                types.String `tfsdk:"password"`
	AuthMode                types.String `tfsdk:"auth_mode"`
	AzureTenantID           types.String `tfsdk:"azure_tenant_id"`
	AzureClientID           types.String `tfsdk:"azure_client_id"`
	AzureClientSecret       types.String `tfsdk:"azure_client_secret"`
	AzureAccessToken        types.String `tfsdk:"azure_access_token"`
	AzureTokenScope         types.String `tfsdk:"azure_token_scope"`
	AzureCloud              types.String `tfsdk:"azure_cloud"`
	AzureAuthorityHost      types.String `tfsdk:"azure_authority_host"`
	SSLMode                 types.String `tfsdk:"sslmode"`
	SSLRootCert             types.String `tfsdk:"ssl_root_cert"`
	SSLCert                 types.String `tfsdk:"ssl_cert"`
	SSLKey                  types.String `tfsdk:"ssl_key"`
	ConnectTimeout          types.Int64  `tfsdk:"connect_timeout"`
	MaxConnections          types.Int64  `tfsdk:"max_connections"`
	AzureFlexibleServer     types.Bool   `tfsdk:"azure_flexible_server"`
	Superuser               types.Bool   `tfsdk:"superuser"`
	AutoGrantRoleMembership types.Bool   `tfsdk:"auto_grant_role_membership"`
}

// New returns a constructor function for the pgazureflex provider.
func New(version string) func() provider.Provider {
	return NewWithAzureTransport(version, nil)
}

// NewWithAzureTransport returns a provider constructor with an injected Azure HTTP transporter
// (used for testing against mock Entra ID / IMDS servers or custom enterprise HTTP proxies).
func NewWithAzureTransport(version string, transport policy.Transporter) func() provider.Provider {
	return func() provider.Provider {
		return &PGAzureFlexProvider{
			version:        version,
			azureTransport: transport,
		}
	}
}

func (p *PGAzureFlexProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pgazureflex"
	resp.Version = p.version
}

func (p *PGAzureFlexProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Terraform provider for PostgreSQL with first-class support for **Azure Database for PostgreSQL - Flexible Server** (Microsoft Entra ID authentication, `pgaadauth` principal management, `azure_pg_admin` ownership workflows, and `azure.extensions` diagnostics).",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "PostgreSQL server hostname (e.g. `myserver.postgres.database.azure.com`). Falls back to `PGHOST`.",
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "PostgreSQL server port. Defaults to `5432` or `PGPORT`.",
				Validators:          []validator.Int64{int64validator.Between(1, 65535)},
			},
			"database": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Default maintenance database name to connect to. Defaults to `postgres` or `PGDATABASE`.",
			},
			"username": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "PostgreSQL username or Microsoft Entra ID principal name. Falls back to `PGUSER`.",
			},
			"password": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "PostgreSQL password when `auth_mode = \"password\"`. Falls back to `PGPASSWORD`.",
			},
			"auth_mode": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Authentication mode: `password`, `azure_default`, `azure_cli`, `azure_managed_identity`, `azure_client_secret`, `azure_workload_identity`, or `access_token`. Falls back to `PGAZUREFLEX_AUTH_MODE`, defaulting to `password`.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						string(pgclient.AuthModePassword),
						string(pgclient.AuthModeAzureDefault),
						string(pgclient.AuthModeAzureCLI),
						string(pgclient.AuthModeAzureManagedIdentity),
						string(pgclient.AuthModeAzureClientSecret),
						string(pgclient.AuthModeAzureWorkloadIdentity),
						string(pgclient.AuthModeAccessToken),
					),
				},
			},
			"azure_tenant_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Microsoft Entra ID tenant ID. Falls back to `AZURE_TENANT_ID`.",
			},
			"azure_client_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Microsoft Entra ID application (client) ID or User-Assigned Managed Identity client ID. Falls back to `AZURE_CLIENT_ID`.",
			},
			"azure_client_secret": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Microsoft Entra ID client secret for `azure_client_secret` mode. Falls back to `AZURE_CLIENT_SECRET`.",
			},
			"azure_access_token": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Pre-acquired Microsoft Entra ID OAuth2 bearer token for `access_token` mode. Falls back to `PGAZUREFLEX_ACCESS_TOKEN`.",
			},
			"azure_token_scope": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "OAuth2 token scope override. Defaults automatically based on `azure_cloud` (e.g. `https://ossrdbms-aad.database.windows.net/.default`).",
			},
			"azure_cloud": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure cloud environment: `public`, `usgovernment`, or `china`. Falls back to `PGAZUREFLEX_AZURE_CLOUD`, defaulting to `public`.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						string(pgclient.AzureCloudPublic),
						string(pgclient.AzureCloudUSGovernment),
						string(pgclient.AzureCloudChina),
					),
				},
			},
			"azure_authority_host": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional custom Microsoft Entra ID authority URL override (e.g. sovereign cloud proxy or local test mock). Falls back to `AZURE_AUTHORITY_HOST`.",
			},
			"sslmode": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "PostgreSQL TLS mode (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`). Falls back to `PGSSLMODE`, defaulting to `require` (matching Azure Flexible Server).",
				Validators: []validator.String{
					stringvalidator.OneOf("disable", "allow", "prefer", "require", "verify-ca", "verify-full"),
				},
			},
			"ssl_root_cert": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to a PEM CA bundle or inline PEM content used to verify the server certificate. Falls back to `PGSSLROOTCERT`.",
			},
			"ssl_cert": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to a client certificate file or inline PEM content. Falls back to `PGSSLCERT`.",
			},
			"ssl_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Path to a client private key file or inline PEM content. Falls back to `PGSSLKEY`.",
			},
			"connect_timeout": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Connection timeout in seconds. Defaults to `15`.",
				Validators:          []validator.Int64{int64validator.Between(1, 300)},
			},
			"max_connections": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Maximum open connections per database pool. Defaults to `4`.",
				Validators:          []validator.Int64{int64validator.Between(1, 100)},
			},
			"azure_flexible_server": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Explicitly force Azure Flexible Server mode. When omitted, the provider auto-detects Azure Flexible Server via hostname, `azure_pg_admin`, `pgaadauth`, and `azure.extensions`.",
			},
			"superuser": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Explicitly override whether the connecting role has PostgreSQL SUPERUSER privileges. Auto-detected when omitted.",
			},
			"auto_grant_role_membership": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "When running as a non-superuser (such as `azure_pg_admin`), automatically grant and revoke temporary membership in target roles during ownership and `ALTER DEFAULT PRIVILEGES` operations. Defaults to `true`.",
			},
		},
	}
}

func (p *PGAzureFlexProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Host.IsUnknown() || data.Username.IsUnknown() || data.Password.IsUnknown() ||
		data.AuthMode.IsUnknown() || data.AzureAccessToken.IsUnknown() || data.AzureClientSecret.IsUnknown() {
		resp.Diagnostics.AddError(
			"Unknown Provider Configuration Value",
			"The provider cannot be configured while connection or credential attributes are unknown. Apply upstream resources first or pass known values.",
		)
		return
	}

	cfg := pgclient.Config{
		Host:                    stringWithEnv(data.Host, "PGHOST"),
		Database:                stringWithEnv(data.Database, "PGDATABASE"),
		Username:                stringWithEnv(data.Username, "PGUSER"),
		Password:                stringWithEnv(data.Password, "PGPASSWORD"),
		AuthMode:                pgclient.AuthMode(stringWithEnv(data.AuthMode, "PGAZUREFLEX_AUTH_MODE")),
		AzureTenantID:           stringWithEnv(data.AzureTenantID, "AZURE_TENANT_ID"),
		AzureClientID:           stringWithEnv(data.AzureClientID, "AZURE_CLIENT_ID"),
		AzureClientSecret:       stringWithEnv(data.AzureClientSecret, "AZURE_CLIENT_SECRET"),
		AzureAccessToken:        stringWithEnv(data.AzureAccessToken, "PGAZUREFLEX_ACCESS_TOKEN"),
		AzureTokenScope:         stringWithEnv(data.AzureTokenScope, "PGAZUREFLEX_TOKEN_SCOPE"),
		AzureCloud:              pgclient.AzureCloud(stringWithEnv(data.AzureCloud, "PGAZUREFLEX_AZURE_CLOUD")),
		AzureAuthorityHost:      stringWithEnv(data.AzureAuthorityHost, "AZURE_AUTHORITY_HOST"),
		AzureTransport:          p.azureTransport,
		SSLMode:                 stringWithEnv(data.SSLMode, "PGSSLMODE"),
		SSLRootCert:             stringWithEnv(data.SSLRootCert, "PGSSLROOTCERT"),
		SSLCert:                 stringWithEnv(data.SSLCert, "PGSSLCERT"),
		SSLKey:                  stringWithEnv(data.SSLKey, "PGSSLKEY"),
		AutoGrantRoleMembership: true,
	}

	if !data.Port.IsNull() {
		cfg.Port = int(data.Port.ValueInt64())
	} else if envPort := strings.TrimSpace(os.Getenv("PGPORT")); envPort != "" {
		portNum, err := strconv.Atoi(envPort)
		if err != nil {
			resp.Diagnostics.AddError("Invalid PGPORT Environment Variable", fmt.Sprintf("PGPORT=%q is not a valid integer: %v", envPort, err))
			return
		}
		cfg.Port = portNum
	}

	if !data.ConnectTimeout.IsNull() {
		cfg.ConnectTimeout = time.Duration(data.ConnectTimeout.ValueInt64()) * time.Second
	}
	if !data.MaxConnections.IsNull() {
		cfg.MaxConnections = int32(data.MaxConnections.ValueInt64())
	}
	if !data.AzureFlexibleServer.IsNull() {
		v := data.AzureFlexibleServer.ValueBool()
		cfg.AzureFlexibleServer = &v
	}
	if !data.Superuser.IsNull() {
		v := data.Superuser.ValueBool()
		cfg.Superuser = &v
	}
	if !data.AutoGrantRoleMembership.IsNull() {
		cfg.AutoGrantRoleMembership = data.AutoGrantRoleMembership.ValueBool()
	}

	client, err := pgclient.NewClient(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Provider Configuration", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *PGAzureFlexProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewDatabaseResource,
		NewDatabaseConfigResource,
		NewRoleResource,
		NewRoleDatabaseParametersResource,
		NewEntraRoleResource,
		NewEntraRoleMappingResource,
		NewRoleMembershipResource,
		NewSchemaResource,
		NewExtensionResource,
		NewGrantResource,
		NewDefaultPrivilegesResource,
		NewPublicationResource,
	}
}

func (p *PGAzureFlexProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewServerInfoDataSource,
		NewEntraPrincipalsDataSource,
		NewDatabasesDataSource,
		NewRolesDataSource,
	}
}

func stringWithEnv(attr types.String, envKey string) string {
	if !attr.IsNull() && !attr.IsUnknown() {
		return attr.ValueString()
	}
	return os.Getenv(envKey)
}
