package mockazure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Server is a local mock Microsoft Entra ID (OAuth2 v2 + OIDC discovery) and
// Azure Instance Metadata Service (IMDS / Managed Identity) HTTP server for
// deterministic unit and end-to-end testing without hitting live Azure endpoints.
type Server struct {
	httpServer *httptest.Server

	mu              sync.Mutex
	expectedClient  string
	expectedSecret  string
	expectedTenant  string
	expectedScope   string
	tokenPrefix     string
	tokenTTL        time.Duration
	failStatus      int
	failBody        string
	oauthTokenCalls int
	imdsTokenCalls  int
	lastClientID    string
	lastScope       string
	lastResource    string
	lastIssuedToken string
}

// NewServer starts a TLS-enabled mock Azure Entra ID + IMDS server (TLS is required by MSAL / azidentity
// for Entra ID authority URLs) and registers t.Cleanup to shut it down.
func NewServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		tokenPrefix: "mock-entra-jwt",
		tokenTTL:    1 * time.Hour,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	// MSAL requires HTTPS for ActiveDirectoryAuthorityHost; httptest.NewTLSServer provides a valid local TLS server
	// whose client/transport is wired directly into azcore.ClientOptions.Transport.
	s.httpServer = httptest.NewTLSServer(mux)
	t.Cleanup(s.httpServer.Close)
	return s
}

// AuthorityHost returns the base HTTPS URL for AzureAuthorityHost (with trailing slash).
func (s *Server) AuthorityHost() string {
	return s.httpServer.URL + "/"
}

// URL returns the raw server URL (without trailing slash).
func (s *Server) URL() string {
	return s.httpServer.URL
}

// Transport returns an azcore policy.Transporter that trusts the mock server's TLS cert
// and transparently redirects Azure IMDS (`169.254.169.254`) requests to this mock server.
func (s *Server) Transport() policy.Transporter {
	targetURL, _ := url.Parse(s.httpServer.URL)
	baseClient := s.httpServer.Client()
	return &redirectTransport{
		base:      baseClient,
		targetURL: targetURL,
	}
}

type redirectTransport struct {
	base      *http.Client
	targetURL *url.URL
}

func (rt *redirectTransport) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	// Redirect IMDS (169.254.169.254) or any Azure authority request to our local httptest server.
	if clone.URL.Host == "169.254.169.254" || clone.URL.Host == rt.targetURL.Host {
		clone.URL.Scheme = rt.targetURL.Scheme
		clone.URL.Host = rt.targetURL.Host
	}
	return rt.base.Do(clone)
}

func (s *Server) SetExpectedCredentials(tenantID, clientID, clientSecret, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectedTenant = tenantID
	s.expectedClient = clientID
	s.expectedSecret = clientSecret
	s.expectedScope = scope
}

func (s *Server) SetTokenConfig(prefix string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenPrefix = prefix
	s.tokenTTL = ttl
}

func (s *Server) SetFailure(status int, errorCode, description string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failStatus = status
	body, _ := json.Marshal(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
	s.failBody = string(body)
}

func (s *Server) ClearFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failStatus = 0
	s.failBody = ""
}

func (s *Server) OAuthTokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.oauthTokenCalls
}

func (s *Server) IMDSTokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imdsTokenCalls
}

func (s *Server) LastIssuedToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastIssuedToken
}

func (s *Server) LastScope() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastScope
}

func (s *Server) LastResource() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastResource
}

func (s *Server) LastClientID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastClientID
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/.well-known/openid-configuration"):
		s.handleOIDCDiscovery(w, r)
	case strings.HasSuffix(path, "/oauth2/v2.0/token"):
		s.handleOAuth2Token(w, r)
	case path == "/metadata/identity/oauth2/token" || path == "/msi/token":
		s.handleIMDSToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	// Path format: /{tenant}/v2.0/.well-known/openid-configuration
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	tenant := strings.SplitN(trimmed, "/", 2)[0]
	base := s.httpServer.URL

	resp := map[string]any{
		"issuer":                 fmt.Sprintf("%s/%s/v2.0", base, tenant),
		"token_endpoint":         fmt.Sprintf("%s/%s/oauth2/v2.0/token", base, tenant),
		"authorization_endpoint": fmt.Sprintf("%s/%s/oauth2/v2.0/authorize", base, tenant),
		"jwks_uri":               fmt.Sprintf("%s/%s/discovery/v2.0/keys", base, tenant),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleOAuth2Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.failStatus)
		_, _ = w.Write([]byte(s.failBody))
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	tenant := strings.SplitN(trimmed, "/", 2)[0]
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	if s.expectedTenant != "" && tenant != s.expectedTenant {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("unexpected tenant %q", tenant))
		return
	}
	if s.expectedClient != "" && clientID != s.expectedClient {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", fmt.Sprintf("unexpected client_id %q", clientID))
		return
	}
	if s.expectedSecret != "" && clientSecret != s.expectedSecret {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client_secret")
		return
	}
	if s.expectedScope != "" && !strings.Contains(scope, s.expectedScope) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", fmt.Sprintf("unexpected scope %q", scope))
		return
	}

	s.oauthTokenCalls++
	s.lastClientID = clientID
	s.lastScope = scope
	token := fmt.Sprintf("%s-%d", s.tokenPrefix, s.oauthTokenCalls)
	s.lastIssuedToken = token

	ttlSec := int(s.tokenTTL.Seconds())
	if ttlSec <= 0 {
		ttlSec = 60
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token_type":   "Bearer",
		"expires_in":   ttlSec,
		"access_token": token,
	})
}

func (s *Server) handleIMDSToken(w http.ResponseWriter, r *http.Request) {
	// Standard Azure IMDS requires Metadata: true (App Service MSI uses X-IDENTITY-HEADER).
	if r.URL.Path == "/metadata/identity/oauth2/token" && r.Header.Get("Metadata") != "true" {
		http.Error(w, `{"error":"missing Metadata: true header"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.failStatus)
		_, _ = w.Write([]byte(s.failBody))
		return
	}

	q := r.URL.Query()
	resource := q.Get("resource")
	clientID := q.Get("client_id")
	if s.expectedClient != "" && clientID != s.expectedClient {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("unexpected managed identity client_id %q", clientID))
		return
	}

	s.imdsTokenCalls++
	s.lastResource = resource
	s.lastClientID = clientID
	token := fmt.Sprintf("%s-imds-%d", s.tokenPrefix, s.imdsTokenCalls)
	s.lastIssuedToken = token

	expiresOn := time.Now().Add(s.tokenTTL)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"expires_in":   strconv.Itoa(int(s.tokenTTL.Seconds())),
		"expires_on":   strconv.FormatInt(expiresOn.Unix(), 10),
		"resource":     resource,
		"token_type":   "Bearer",
	})
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
