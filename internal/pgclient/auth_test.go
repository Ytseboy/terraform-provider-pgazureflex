package pgclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/pgclient"
	"github.com/Ytseboy/terraform-provider-pgazureflex/internal/testutil/mockazure"
)

func TestAzureClientSecretAuthAndTokenCachingWithMockAPI(t *testing.T) {
	mock := mockazure.NewServer(t)
	mock.SetExpectedCredentials(
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
		"super-secret-value",
		pgclient.DefaultAzureOSSScope,
	)
	mock.SetTokenConfig("entra-sp-token", 1*time.Hour)

	cfg := pgclient.Config{
		Host:               "flex-test.postgres.database.azure.com",
		Username:           "sp-terraform",
		AuthMode:           pgclient.AuthModeAzureClientSecret,
		AzureTenantID:      "11111111-1111-1111-1111-111111111111",
		AzureClientID:      "22222222-2222-2222-2222-222222222222",
		AzureClientSecret:  "super-secret-value",
		AzureAuthorityHost: mock.AuthorityHost(),
		AzureTransport:     mock.Transport(),
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate failed: %v", err)
	}

	pw, err := pgclient.NewPasswordProvider(cfg)
	if err != nil {
		t.Fatalf("NewPasswordProvider failed: %v", err)
	}

	ctx := context.Background()
	tok1, err := pw.GetPassword(ctx)
	if err != nil {
		t.Fatalf("first GetPassword failed: %v", err)
	}
	if tok1 != "entra-sp-token-1" {
		t.Fatalf("got token %q, want %q", tok1, "entra-sp-token-1")
	}
	if mock.OAuthTokenCalls() != 1 {
		t.Fatalf("expected 1 OAuth token call, got %d", mock.OAuthTokenCalls())
	}

	// Second call should hit the in-memory token cache (no additional HTTP call).
	tok2, err := pw.GetPassword(ctx)
	if err != nil {
		t.Fatalf("second GetPassword failed: %v", err)
	}
	if tok2 != tok1 {
		t.Fatalf("expected cached token %q, got %q", tok1, tok2)
	}
	if mock.OAuthTokenCalls() != 1 {
		t.Fatalf("expected cached token (still 1 OAuth call), got %d", mock.OAuthTokenCalls())
	}
}

func TestAzureTokenRefreshWhenNearExpiryWithMockAPI(t *testing.T) {
	mock := mockazure.NewServer(t)
	// Return a short-lived token (60s < 5m refresh skew) so our provider proactively refreshes.
	mock.SetTokenConfig("short-lived-jwt", 60*time.Second)

	cfg := pgclient.Config{
		Host:               "flex-test.postgres.database.azure.com",
		Username:           "sp-terraform",
		AuthMode:           pgclient.AuthModeAzureClientSecret,
		AzureTenantID:      "11111111-1111-1111-1111-111111111111",
		AzureClientID:      "22222222-2222-2222-2222-222222222222",
		AzureClientSecret:  "secret",
		AzureAuthorityHost: mock.AuthorityHost(),
		AzureTransport:     mock.Transport(),
	}
	cfg.ApplyDefaults()

	pw, err := pgclient.NewPasswordProvider(cfg)
	if err != nil {
		t.Fatalf("NewPasswordProvider failed: %v", err)
	}

	ctx := context.Background()
	tok1, err := pw.GetPassword(ctx)
	if err != nil {
		t.Fatalf("first GetPassword failed: %v", err)
	}
	tok2, err := pw.GetPassword(ctx)
	if err != nil {
		t.Fatalf("second GetPassword failed: %v", err)
	}

	if tok1 == tok2 {
		t.Fatalf("expected token refresh on second call for near-expiry token, both returned %q", tok1)
	}
	if mock.OAuthTokenCalls() < 2 {
		t.Fatalf("expected at least 2 token calls, got %d", mock.OAuthTokenCalls())
	}
}

func TestAzureManagedIdentityAuthWithMockIMDS(t *testing.T) {
	mock := mockazure.NewServer(t)
	mock.SetExpectedCredentials("", "uami-client-id-123", "", "")
	mock.SetTokenConfig("uami-jwt", 1*time.Hour)

	// Wire App Service / Container Apps MSI env vars OR IMDS transport cleanly.
	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IDENTITY_HEADER", "")
	t.Setenv("MSI_ENDPOINT", "")

	cfg := pgclient.Config{
		Host:           "flex-prod.postgres.database.azure.com",
		Username:       "mi-orders-api",
		AuthMode:       pgclient.AuthModeAzureManagedIdentity,
		AzureClientID:  "uami-client-id-123",
		AzureTransport: mock.Transport(),
	}
	cfg.ApplyDefaults()

	pw, err := pgclient.NewPasswordProvider(cfg)
	if err != nil {
		t.Fatalf("NewPasswordProvider(IMDS) failed: %v", err)
	}

	tok, err := pw.GetPassword(context.Background())
	if err != nil {
		t.Fatalf("GetPassword(IMDS) failed: %v", err)
	}
	if !strings.HasPrefix(tok, "uami-jwt-imds-") {
		t.Fatalf("unexpected IMDS token %q", tok)
	}
	if mock.IMDSTokenCalls() != 1 {
		t.Fatalf("expected 1 IMDS call, got %d", mock.IMDSTokenCalls())
	}
	if mock.LastClientID() != "uami-client-id-123" {
		t.Fatalf("expected user-assigned client_id %q, got %q", "uami-client-id-123", mock.LastClientID())
	}
	if mock.LastResource() != "https://ossrdbms-aad.database.windows.net" {
		t.Fatalf("unexpected IMDS resource %q", mock.LastResource())
	}
}

func TestAzureAuthErrorSurfacedFromMockAPI(t *testing.T) {
	mock := mockazure.NewServer(t)
	mock.SetFailure(401, "invalid_client", "AADSTS7000215: Invalid client secret provided.")

	cfg := pgclient.Config{
		Host:               "flex-test.postgres.database.azure.com",
		Username:           "sp-terraform",
		AuthMode:           pgclient.AuthModeAzureClientSecret,
		AzureTenantID:      "11111111-1111-1111-1111-111111111111",
		AzureClientID:      "22222222-2222-2222-2222-222222222222",
		AzureClientSecret:  "wrong-secret",
		AzureAuthorityHost: mock.AuthorityHost(),
		AzureTransport:     mock.Transport(),
	}
	cfg.ApplyDefaults()

	pw, err := pgclient.NewPasswordProvider(cfg)
	if err != nil {
		t.Fatalf("NewPasswordProvider failed: %v", err)
	}

	_, err = pw.GetPassword(context.Background())
	if err == nil {
		t.Fatal("expected authentication error from mock Entra ID server, got nil")
	}
	if !strings.Contains(err.Error(), "AADSTS7000215") && !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("expected Entra error details in message, got: %v", err)
	}
}

func TestBuildTLSConfigModesAndInlinePEM(t *testing.T) {
	certPEM, keyPEM := generateTestSelfSignedCert(t)

	// disable -> nil tls.Config
	cfgDisable := pgclient.Config{Host: "db.local", Username: "u", SSLMode: "disable"}
	cfgDisable.ApplyDefaults()
	tlsDisable, err := cfgDisable.BuildTLSConfig()
	if err != nil || tlsDisable != nil {
		t.Fatalf("disable: got (%v, %v), want (nil, nil)", tlsDisable, err)
	}

	// verify-full with inline Root CA + client cert/key
	cfgFull := pgclient.Config{
		Host:        "myflex.postgres.database.azure.com",
		Username:    "u",
		SSLMode:     "verify-full",
		SSLRootCert: certPEM,
		SSLCert:     certPEM,
		SSLKey:      keyPEM,
	}
	cfgFull.ApplyDefaults()
	tlsFull, err := cfgFull.BuildTLSConfig()
	if err != nil {
		t.Fatalf("verify-full BuildTLSConfig failed: %v", err)
	}
	if tlsFull.InsecureSkipVerify {
		t.Fatal("verify-full must not set InsecureSkipVerify")
	}
	if tlsFull.ServerName != "myflex.postgres.database.azure.com" {
		t.Fatalf("ServerName = %q", tlsFull.ServerName)
	}
	if len(tlsFull.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(tlsFull.Certificates))
	}

	// verify-ca sets VerifyConnection
	cfgCA := pgclient.Config{
		Host:        "myflex.postgres.database.azure.com",
		Username:    "u",
		SSLMode:     "verify-ca",
		SSLRootCert: certPEM,
	}
	cfgCA.ApplyDefaults()
	tlsCA, err := cfgCA.BuildTLSConfig()
	if err != nil || tlsCA.VerifyConnection == nil {
		t.Fatalf("verify-ca should configure VerifyConnection, err=%v", err)
	}
}

func TestRetryTransientBehavior(t *testing.T) {
	attempts := 0
	err := pgclient.RetryTransient(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected retry to succeed on attempt 3, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}

	// Non-retryable permission error should fail immediately without retrying.
	nonRetryAttempts := 0
	permErr := &pgconn.PgError{Code: "42501", Message: "permission denied"}
	err = pgclient.RetryTransient(context.Background(), func() error {
		nonRetryAttempts++
		return permErr
	})
	if !errors.Is(err, permErr) || nonRetryAttempts != 1 {
		t.Fatalf("expected immediate failure (1 attempt) for 42501, got attempts=%d err=%v", nonRetryAttempts, err)
	}
}

func generateTestSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "myflex.postgres.database.azure.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}
