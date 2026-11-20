package pgclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// PasswordProvider returns the password or bearer token to use for a new PostgreSQL connection.
type PasswordProvider interface {
	GetPassword(ctx context.Context) (string, error)
}

type staticPasswordProvider struct {
	secret string
}

func (s *staticPasswordProvider) GetPassword(_ context.Context) (string, error) {
	return s.secret, nil
}

// azureTokenProvider wraps an Azure TokenCredential and caches tokens until shortly before expiry.
// Azure Database for PostgreSQL Flexible Server validates Entra ID tokens at connection time,
// so refreshing cached tokens inside pgxpool's BeforeConnect hook keeps long-running Terraform
// operations resilient across token lifetimes.
type azureTokenProvider struct {
	cred  azcore.TokenCredential
	scope string

	mu        sync.Mutex
	token     string
	expiresOn time.Time
}

const tokenRefreshSkew = 5 * time.Minute

func (a *azureTokenProvider) GetPassword(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Add(tokenRefreshSkew).Before(a.expiresOn) {
		return a.token, nil
	}

	tk, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{a.scope},
	})
	if err != nil {
		return "", fmt.Errorf("failed to acquire Microsoft Entra ID token for scope %q: %w", a.scope, err)
	}

	a.token = tk.Token
	a.expiresOn = tk.ExpiresOn
	return a.token, nil
}

func azureCloudConfig(cfg Config) cloud.Configuration {
	if cfg.AzureAuthorityHost != "" {
		return cloud.Configuration{
			ActiveDirectoryAuthorityHost: cfg.AzureAuthorityHost,
		}
	}
	switch cfg.AzureCloud {
	case AzureCloudUSGovernment:
		return cloud.AzureGovernment
	case AzureCloudChina:
		return cloud.AzureChina
	default:
		return cloud.AzurePublic
	}
}

// NewPasswordProvider builds the appropriate PasswordProvider for the Config's AuthMode.
func NewPasswordProvider(cfg Config) (PasswordProvider, error) {
	switch cfg.AuthMode {
	case AuthModePassword:
		return &staticPasswordProvider{secret: cfg.Password}, nil
	case AuthModeAccessToken:
		return &staticPasswordProvider{secret: cfg.AzureAccessToken}, nil
	}

	clientOpts := azcore.ClientOptions{
		Cloud:     azureCloudConfig(cfg),
		Transport: cfg.AzureTransport,
	}
	var (
		cred azcore.TokenCredential
		err  error
	)

	switch cfg.AuthMode {
	case AuthModeAzureDefault:
		opts := &azidentity.DefaultAzureCredentialOptions{
			ClientOptions: clientOpts,
			TenantID:      cfg.AzureTenantID,
		}
		cred, err = azidentity.NewDefaultAzureCredential(opts)
	case AuthModeAzureCLI:
		opts := &azidentity.AzureCLICredentialOptions{
			TenantID: cfg.AzureTenantID,
		}
		cred, err = azidentity.NewAzureCLICredential(opts)
	case AuthModeAzureManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{
			ClientOptions: clientOpts,
		}
		if cfg.AzureClientID != "" {
			opts.ID = azidentity.ClientID(cfg.AzureClientID)
		}
		cred, err = azidentity.NewManagedIdentityCredential(opts)
	case AuthModeAzureClientSecret:
		opts := &azidentity.ClientSecretCredentialOptions{
			ClientOptions: clientOpts,
		}
		if cfg.AzureAuthorityHost != "" {
			// Allow non-HTTPS or custom authority host in local tests / sovereign proxies.
			opts.DisableInstanceDiscovery = true
		}
		cred, err = azidentity.NewClientSecretCredential(cfg.AzureTenantID, cfg.AzureClientID, cfg.AzureClientSecret, opts)
	case AuthModeAzureWorkloadIdentity:
		opts := &azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: clientOpts,
			TenantID:      cfg.AzureTenantID,
			ClientID:      cfg.AzureClientID,
		}
		cred, err = azidentity.NewWorkloadIdentityCredential(opts)
	default:
		return nil, fmt.Errorf("unsupported auth_mode %q", cfg.AuthMode)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize Azure credential (%s): %w", cfg.AuthMode, err)
	}

	return &azureTokenProvider{
		cred:  cred,
		scope: cfg.AzureTokenScope,
	}, nil
}
