package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

func newTestServer(t *testing.T) (*Server, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair("test-server-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := Config{
		Issuer: "https://aidp.test",
		Addr:   ":0",
	}
	logger := slog.New(slog.NewJSONHandler(&dummyWriter{}, nil))
	srv := New(cfg, kp, logger)
	return srv, kp
}

type dummyWriter struct{}

func (d *dummyWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
	if body["issuer"] != "https://aidp.test" {
		t.Errorf("issuer = %q, want https://aidp.test", body["issuer"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rec.Header().Get("Content-Type"))
	}

	var jwks crypto.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "EC" {
		t.Errorf("Kty = %q, want EC", jwks.Keys[0].Kty)
	}
	if jwks.Keys[0].Crv != "P-256" {
		t.Errorf("Crv = %q, want P-256", jwks.Keys[0].Crv)
	}
	if jwks.Keys[0].Alg != "ES256" {
		t.Errorf("Alg = %q, want ES256", jwks.Keys[0].Alg)
	}
}

func TestASMetadataEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var meta ASMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal ASMetadata: %v", err)
	}
	if meta.Issuer != "https://aidp.test" {
		t.Errorf("Issuer = %q, want https://aidp.test", meta.Issuer)
	}
	if meta.TokenEndpoint != "https://aidp.test/oauth/token" {
		t.Errorf("TokenEndpoint = %q", meta.TokenEndpoint)
	}
	if meta.JwksURI != "https://aidp.test/.well-known/jwks.json" {
		t.Errorf("JwksURI = %q", meta.JwksURI)
	}
	if len(meta.GrantTypesSupported) != 1 {
		t.Fatalf("GrantTypesSupported has %d entries, want 1", len(meta.GrantTypesSupported))
	}
	if meta.GrantTypesSupported[0] != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("GrantTypesSupported[0] = %q, want token-exchange", meta.GrantTypesSupported[0])
	}
	if !contains(meta.ScopesSupported, "agent:attest") {
		t.Error("ScopesSupported missing agent:attest")
	}
}

func TestRoutedoesNotLeakTokenInURI(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json?access_token=secret123", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "secret123") {
		t.Error("token from query string leaked into response body")
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
