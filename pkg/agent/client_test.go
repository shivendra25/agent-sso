package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAttestSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attest" {
			http.NotFound(w, r)
			return
		}
		var req AttestRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.SignedAttestation == "" || req.OIDCIDToken == "" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AttestResponse{
			AIT:          "test-ait-jwt",
			ExpiresAt:    time.Now().Add(15 * time.Minute).Unix(),
			IssuedAt:     time.Now().Unix(),
			JTI:          "ait_001",
			AgentID:      "a:test-agent-001",
			PrincipalSub: "user-001",
		})
	}))
	defer srv.Close()

	client := New(Config{
		AIdPURL:  srv.URL,
		TenantID: "tnt_test",
	})

	resp, err := client.Attest(context.Background(), "attestation-doc", "oidc-id-token", "okta")
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if resp.AIT != "test-ait-jwt" {
		t.Errorf("AIT = %q, want test-ait-jwt", resp.AIT)
	}
	if resp.AgentID != "a:test-agent-001" {
		t.Errorf("AgentID = %q", resp.AgentID)
	}
}

func TestAttestMissingConfig(t *testing.T) {
	client := New(Config{})
	_, err := client.Attest(context.Background(), "att", "token", "okta")
	if err == nil {
		t.Fatal("expected error for missing AIdPURL")
	}
}

func TestAttestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_attestation"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := New(Config{AIdPURL: srv.URL, TenantID: "tnt_test"})
	_, err := client.Attest(context.Background(), "bad-att", "bad-token", "okta")
	if err == nil {
		t.Fatal("expected error for server 401")
	}
}

func TestCallSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/call/") {
			http.NotFound(w, r)
			return
		}
		ait := r.Header.Get("X-AIT")
		if ait == "" {
			http.Error(w, `{"error":"ait_required"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"response from MCP server"}`))
	}))
	defer srv.Close()

	client := New(Config{
		GatewayURL: srv.URL,
		TenantID:   "tnt_test",
	})

	result, err := client.Call(context.Background(), "test-ait", "github", "v1/prs/42", "GET", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(result.Body), "response from MCP server") {
		t.Errorf("Body = %s", result.Body)
	}
}

func TestCallNoGateway(t *testing.T) {
	client := New(Config{TenantID: "tnt_test"})
	_, err := client.Call(context.Background(), "ait", "github", "path", "GET", nil)
	if err == nil {
		t.Fatal("expected error for missing gateway URL")
	}
}

func TestCallJSONSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok","count":42}`))
	}))
	defer srv.Close()

	client := New(Config{GatewayURL: srv.URL, TenantID: "tnt_test"})

	var response struct {
		Result string `json:"result"`
		Count  int    `json:"count"`
	}
	err := client.CallJSON(context.Background(), "ait", "github", "v1/query", map[string]string{"q": "test"}, &response)
	if err != nil {
		t.Fatalf("CallJSON: %v", err)
	}
	if response.Result != "ok" {
		t.Errorf("Result = %q", response.Result)
	}
	if response.Count != 42 {
		t.Errorf("Count = %d, want 42", response.Count)
	}
}

func TestCallJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"denied"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	client := New(Config{GatewayURL: srv.URL, TenantID: "tnt_test"})

	err := client.CallJSON(context.Background(), "ait", "github", "v1/query", nil, nil)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestGetJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"test","alg":"ES256","x":"abc","y":"def"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := New(Config{AIdPURL: srv.URL})
	data, err := client.GetJWKS(context.Background())
	if err != nil {
		t.Fatalf("GetJWKS: %v", err)
	}
	if !strings.Contains(string(data), "jwks") && !strings.Contains(string(data), "keys") {
		t.Errorf("JWKS response = %s", data)
	}
}

func TestGetASMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"issuer":"https://aidp.test","token_endpoint":"https://aidp.test/oauth/token"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := New(Config{AIdPURL: srv.URL})
	data, err := client.GetASMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetASMetadata: %v", err)
	}
	if !strings.Contains(string(data), "issuer") {
		t.Errorf("metadata response = %s", data)
	}
}

func TestDefaultTimeout(t *testing.T) {
	client := New(Config{})
	if client.httpClient.Timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s", client.httpClient.Timeout)
	}
}
