package gateway

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/exchange"
	"github.com/shivendra25/agent-sso/internal/jwt"
	"github.com/shivendra25/agent-sso/internal/registry"
)

// mockMCPServer simulates an MCP server that accepts Bearer tokens
// and returns data. It records the Authorization header it receives.
func mockMCPServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var receivedAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/v1/prs/42" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pr":42,"title":"test PR","state":"open"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &receivedAuthHeader
}

func setupGateway(t *testing.T, mcpServerURL string) (*Gateway, *jwt.Signer, *crypto.KeyPair) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair("gateway-test-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer := jwt.NewSigner(kp)

	policy := &exchange.MockPolicyEvaluator{AllowAll: true}
	exchanger := exchange.NewExchanger(
		jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public}),
		signer,
		policy,
		"https://aidp.test",
		5*time.Minute,
	)

	reg := registry.NewMemoryRegistry()
	reg.Register(&registry.MCPServer{
		TenantID:       "tnt_test",
		ServerAlias:    "github",
		ServerURL:      mcpServerURL,
		AuthServer:     "https://aidp.test",
		RequiredScopes: []string{"github:read"},
		RFC9728Enabled: false,
	})

	logger := slog.New(slog.NewJSONHandler(&dummyWriter{}, nil))
	gw := New(DefaultConfig(), exchanger, reg, jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public}), logger)
	return gw, signer, kp
}

type dummyWriter struct{}

func (d *dummyWriter) Write(p []byte) (int, error) { return len(p), nil }

func mintGatewayAIT(t *testing.T, signer *jwt.Signer) string {
	t.Helper()
	now := time.Now()
	claims := &jwt.AITClaims{
		Issuer:   "https://aidp.test",
		Subject:  "a:test-agent-001",
		Audience: "https://aidp.test/oauth/token",
		Exp:      now.Add(15 * time.Minute).Unix(),
		Iat:      now.Unix(),
		Nbf:      now.Unix(),
		JTI:      "ait_" + uuid.NewString(),
		ClientID: "test-client",
		Scope:    jwt.ScopeAgentAttest + " " + jwt.ScopeToolsExchange,
		Act:      &jwt.ActorClaim{Sub: "oidc:okta:user-001", Iss: "https://test.okta.com"},
		TenantID: "tnt_test",
	}
	token, err := signer.SignAIT(claims)
	if err != nil {
		t.Fatalf("SignAIT: %v", err)
	}
	return token
}

func TestCallSuccess(t *testing.T) {
	mcpSrv, receivedAuth := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)

	ait := mintGatewayAIT(t, signer)

	resp, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		SessionID:   "ses_test",
		ServerAlias: "github",
		Path:        "v1/prs/42",
		Method:      "GET",
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["title"] != "test PR" {
		t.Errorf("title = %v, want test PR", body["title"])
	}

	// Verify the MCP server received a Bearer token
	if !strings.HasPrefix(*receivedAuth, "Bearer ") {
		t.Errorf("MCP server received Auth header: %q, expected Bearer prefix", *receivedAuth)
	}
	if *receivedAuth == "Bearer "+ait {
		t.Error("MCP server received the AIT directly — should have received a JIT, not the AIT")
	}
}

func TestCallNoAIT(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, _, _ := setupGateway(t, mcpSrv.URL)

	_, err := gw.Call(context.Background(), &CallRequest{
		SessionID:   "ses_test",
		ServerAlias: "github",
	})
	if err == nil {
		t.Fatal("expected error for missing AIT")
	}
}

func TestCallNoSession(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	_, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		ServerAlias: "github",
	})
	if err == nil {
		t.Fatal("expected error for missing session")
	}
}

func TestCallUnknownServer(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	_, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		SessionID:   "ses_test",
		ServerAlias: "unknown-server",
	})
	if err == nil {
		t.Fatal("expected error for unknown server")
	}
}

func TestCallResponseStripsAuthHeaders(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	resp, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		SessionID:   "ses_test",
		ServerAlias: "github",
		Path:        "v1/prs/42",
		Method:      "GET",
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	// The mock server sends WWW-Authenticate — gateway should strip it
	for k := range resp.Headers {
		if strings.ToLower(k) == "www-authenticate" {
			t.Error("WWW-Authenticate header should have been stripped")
		}
	}
}

func TestCallDoesNotAllowAuthorizationOverride(t *testing.T) {
	var receivedAuth string
	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer mcpSrv.Close()

	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	_, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		SessionID:   "ses_test",
		ServerAlias: "github",
		Method:      "GET",
		Headers:     map[string]string{"Authorization": "Bearer stolen-token"},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	// The caller tried to override Authorization — gateway should ignore it
	if receivedAuth == "Bearer stolen-token" {
		t.Error("gateway allowed caller to override Authorization header")
	}
	if !strings.HasPrefix(receivedAuth, "Bearer ") {
		t.Error("gateway did not inject a Bearer token")
	}
}

func TestCallInvalidAIT(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, _, _ := setupGateway(t, mcpSrv.URL)

	_, err := gw.Call(context.Background(), &CallRequest{
		AIT:         "garbage.token.here",
		SessionID:   "ses_test",
		ServerAlias: "github",
	})
	if err == nil {
		t.Fatal("expected error for invalid AIT")
	}
}

func TestCallResponseBodyDoesNotContainToken(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	resp, err := gw.Call(context.Background(), &CallRequest{
		AIT:         ait,
		SessionID:   "ses_test",
		ServerAlias: "github",
		Path:        "v1/prs/42",
		Method:      "GET",
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	// The response body should not contain the AIT or any JWT-like string
	bodyStr := string(resp.Body)
	if strings.Contains(bodyStr, ait) {
		t.Error("response body contains the AIT — credential leakage")
	}
	if strings.Contains(bodyStr, "Bearer ") {
		t.Error("response body contains 'Bearer ' — possible credential leakage")
	}
}

func TestTokenCache(t *testing.T) {
	cache := NewTokenCache(5 * time.Minute)

	if _, ok := cache.Get("missing"); ok {
		t.Error("expected miss for missing key")
	}

	cache.Set("key1", "token1")
	val, ok := cache.Get("key1")
	if !ok {
		t.Fatal("expected hit after Set")
	}
	if val != "token1" {
		t.Errorf("Get = %q, want token1", val)
	}

	cache.Clear()
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected miss after Clear")
	}
}

func TestTokenCacheExpiry(t *testing.T) {
	cache := NewTokenCache(10 * time.Millisecond)
	cache.Set("key1", "token1")

	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected miss after expiry")
	}
}

func TestServeHTTPHealthz(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, _, _ := setupGateway(t, mcpSrv.URL)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestServeHTTPWrongMethod(t *testing.T) {
	mcpSrv, _ := mockMCPServer(t)
	gw, _, _ := setupGateway(t, mcpSrv.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/call/github/prs", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestServeHTTPCallSuccess(t *testing.T) {
	mcpSrv, receivedAuth := mockMCPServer(t)
	gw, signer, _ := setupGateway(t, mcpSrv.URL)
	ait := mintGatewayAIT(t, signer)

	req := httptest.NewRequest(http.MethodPost, "/v1/call/github/v1/prs/42", strings.NewReader(`{}`))
	req.Header.Set("X-AIT", ait)
	req.Header.Set("X-Session", "ses_http")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if !strings.HasPrefix(*receivedAuth, "Bearer ") {
		t.Error("MCP server did not receive a Bearer token")
	}
}
