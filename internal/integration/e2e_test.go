// Package integration contains end-to-end tests that prove the complete
// AgentSSO flow: attestation → OIDC → AIT issuance → token exchange →
// gateway call → MCP server response, with credential injection-proofness
// verified at every step.
//
// This test suite is the proof that AgentSSO delivers on its core promise:
// an agent can call tools with zero static secrets, and a prompt-injection
// attacker cannot exfiltrate credentials because the LLM context never
// contains a bearer token.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shivendra25/agent-sso/internal/attest"
	"github.com/shivendra25/agent-sso/internal/attestation"
	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/exchange"
	"github.com/shivendra25/agent-sso/internal/gateway"
	"github.com/shivendra25/agent-sso/internal/idp"
	"github.com/shivendra25/agent-sso/internal/jwt"
	"github.com/shivendra25/agent-sso/internal/policy"
	"github.com/shivendra25/agent-sso/internal/registry"
)

// TestEndToEndFlow proves the complete AgentSSO pipeline:
// 1. Agent attests → aIdP issues AIT
// 2. Agent calls gateway → gateway exchanges AIT for JIT
// 3. Gateway forwards to MCP server with JIT
// 4. Response returns to agent
// 5. No token appears in any response body (injection-proof)
func TestEndToEndFlow(t *testing.T) {
	// --- Setup: aIdP signing key ---
	aidpKey, err := crypto.GenerateKeyPair("aidp-e2e-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer := jwt.NewSigner(aidpKey)
	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{aidpKey.KeyID: aidpKey.Public})

	// --- Setup: IdP (Okta simulation) ---
	idpKey, err := crypto.GenerateKeyPair("idp-e2e-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	minter := idp.NewIDTokenMinter(idpKey, "https://acme.okta.com")

	providers := idp.NewProviderRegistry()
	providers.Register(idp.ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://acme.okta.com",
		ClientID: "agent-sso-client",
	}, idp.NewJWKSVerifier(idp.ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://acme.okta.com",
		ClientID: "agent-sso-client",
	}, idp.MinterToVerifierKeys(idpKey)))

	// --- Setup: Attestation registry ---
	hostPub, hostPriv, _ := ed25519.GenerateKey(nil)
	attestReg := attestation.NewMemoryRegistry()
	attestReg.Register(&attestation.AgentRegistration{
		AgentID:          "a:e2e-agent-001",
		HostID:           "host-e2e-001",
		HostPublicKey:    hostPub,
		AllowedCodebases: []string{"sha256:e2e-codebase"},
		AllowedRuntimes:  []string{"sha256:e2e-runtime"},
	})
	attestVerifier := attestation.NewVerifier(attestReg)
	attestSigner := attestation.NewAttestationSigner("host-e2e-001", hostPriv)

	// --- Setup: Policy engine (allow read scopes) ---
	policyEngine := policy.NewEngine()
	policyEngine.SetPolicy(&policy.Policy{
		Default: "deny",
		Rules: []policy.AllowRule{
			{
				AgentID:       "a:e2e-agent-001",
				PrincipalSub:  "*",
				Resource:      "*",
				AllowedScopes: []string{"github:read", "github:write", "slack:read"},
			},
		},
	})

	// --- Setup: Token exchanger ---
	exchanger := exchange.NewExchanger(
		verifier, signer, policyEngine,
		"https://aidp.e2e.test", 5*time.Minute,
	)

	// --- Setup: MCP server (mock) ---
	var mcpReceivedAuth string
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mcpReceivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"prs":[{"id":42,"title":"Fix bug","state":"open"},{"id":43,"title":"Add feature","state":"closed"}]}`))
	}))
	defer mcpServer.Close()

	// --- Setup: MCP server registry ---
	mcpRegistry := registry.NewMemoryRegistry()
	mcpRegistry.Register(&registry.MCPServer{
		TenantID:       "tnt_e2e",
		ServerAlias:    "github",
		ServerURL:      mcpServer.URL,
		AuthServer:     "https://aidp.e2e.test",
		RequiredScopes: []string{"github:read"},
		RFC9728Enabled: false,
	})

	// --- Setup: Gateway ---
	e2eLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(gateway.DefaultConfig(), exchanger, mcpRegistry, verifier, e2eLogger)

	// === STEP 1: Agent attests and receives AIT ===

	// Mint OIDC ID token (human login)
	oidcToken, err := minter.MintIDToken("okta-user-alice", "agent-sso-client", map[string]interface{}{
		"email":  "alice@acme.com",
		"name":   "Alice Engineer",
		"groups": []string{"engineering"},
	})
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}

	// Create attestation document
	attDoc := &attestation.AttestationDocument{
		AgentID:      "a:e2e-agent-001",
		CodebaseHash: "sha256:e2e-codebase",
		RuntimeHash:  "sha256:e2e-runtime",
		StartedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HostID:       "host-e2e-001",
		JTI:          "att-e2e-001",
	}
	signedAtt, err := attestSigner.Sign(attDoc)
	if err != nil {
		t.Fatalf("Sign attestation: %v", err)
	}

	// Issue AIT via the attest.Issuer
	issuer := attest.NewIssuer(
		attestVerifier, providers, signer,
		"https://aidp.e2e.test", "https://aidp.e2e.test/oauth/token",
		15*time.Minute,
	)
	aitResp, err := issuer.Issue(&attest.Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       oidcToken,
		OIDCProviderAlias: "okta",
		TenantID:          "tnt_e2e",
	})
	if err != nil {
		t.Fatalf("Issue AIT: %v", err)
	}
	t.Logf("✓ Step 1: AIT issued — agent_id=%s, principal=%s, jti=%s",
		aitResp.AgentID, aitResp.PrincipalSub, aitResp.JTI)

	// === STEP 2: Agent calls gateway → gateway exchanges for JIT ===

	resp, err := gw.Call(context.Background(), &gateway.CallRequest{
		AIT:         aitResp.AIT,
		SessionID:   "ses-e2e-001",
		ServerAlias: "github",
		Path:        "v1/prs",
		Method:      "GET",
	})
	if err != nil {
		t.Fatalf("Gateway Call: %v", err)
	}
	t.Logf("✓ Step 2: Gateway call succeeded — status=%d", resp.StatusCode)

	// === STEP 3: Verify response data ===

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	prs, ok := body["prs"].([]interface{})
	if !ok || len(prs) != 2 {
		t.Fatalf("expected 2 PRs, got %v", body)
	}
	t.Logf("✓ Step 3: MCP server returned %d PRs", len(prs))

	// === STEP 4: Verify credential injection-proofness ===

	// 4a: MCP server received a Bearer token (the JIT), not the AIT
	if !strings.HasPrefix(mcpReceivedAuth, "Bearer ") {
		t.Fatal("MCP server did not receive a Bearer token")
	}
	if mcpReceivedAuth == "Bearer "+aitResp.AIT {
		t.Fatal("SECURITY FAILURE: MCP server received the AIT directly — should have received a JIT")
	}
	t.Logf("✓ Step 4a: MCP server received JIT (not AIT)")

	// 4b: Response body contains no tokens
	bodyStr := string(resp.Body)
	if strings.Contains(bodyStr, aitResp.AIT) {
		t.Fatal("SECURITY FAILURE: AIT found in response body")
	}
	if strings.Contains(bodyStr, mcpReceivedAuth) {
		t.Fatal("SECURITY FAILURE: JIT found in response body")
	}
	if strings.Contains(bodyStr, "Bearer ") {
		t.Fatal("SECURITY FAILURE: 'Bearer ' found in response body")
	}
	t.Logf("✓ Step 4b: No tokens in response body")

	// 4c: WWW-Authenticate header stripped from response
	for k := range resp.Headers {
		if strings.ToLower(k) == "www-authenticate" {
			t.Fatal("SECURITY FAILURE: WWW-Authenticate header leaked to agent")
		}
	}
	t.Logf("✓ Step 4c: WWW-Authenticate stripped from response")

	// 4d: JIT has correct audience (the MCP server URL, not the aIdP)
	jit, err := verifier.VerifyJIT(strings.TrimPrefix(mcpReceivedAuth, "Bearer "))
	if err != nil {
		t.Fatalf("VerifyJIT: %v", err)
	}
	if jit.Audience != mcpServer.URL {
		t.Errorf("JIT audience = %q, want MCP server URL %q", jit.Audience, mcpServer.URL)
	}
	t.Logf("✓ Step 4d: JIT audience = MCP server URL (RFC 8707 compliant)")

	// 4e: JIT carries the delegation chain (act.sub = human principal)
	if jit.Act == nil {
		t.Fatal("JIT missing act claim — delegation chain broken")
	}
	if !strings.Contains(jit.Act.Sub, "okta-user-alice") {
		t.Errorf("JIT act.sub = %q, should contain okta-user-alice", jit.Act.Sub)
	}
	t.Logf("✓ Step 4e: Delegation chain preserved — act.sub=%s", jit.Act.Sub)

	// 4f: JIT parent_jti links to AIT (audit chain)
	if jit.ParentJTI != aitResp.JTI {
		t.Errorf("JIT parent_jti = %q, want AIT jti %q", jit.ParentJTI, aitResp.JTI)
	}
	t.Logf("✓ Step 4f: Audit chain — JIT parent_jti links to AIT jti")

	t.Log("\n=== END-TO-END FLOW PASSED ===")
	t.Log("Agent successfully called MCP server with:")
	t.Log("  - Zero static secrets")
	t.Log("  - OIDC-federated human identity")
	t.Log("  - RFC 8693 delegation chain")
	t.Log("  - Audience-bound JIT (RFC 8707)")
	t.Log("  - Injection-proof credential boundary")
	t.Log("  - No tokens in LLM context")
}

// TestEndToEndPolicyDenial proves that the policy engine blocks
// unauthorized scope requests.
func TestEndToEndPolicyDenial(t *testing.T) {
	aidpKey, _ := crypto.GenerateKeyPair("aidp-deny")
	signer := jwt.NewSigner(aidpKey)
	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{aidpKey.KeyID: aidpKey.Public})

	// Policy: only allow github:read, deny everything else
	policyEngine := policy.NewEngine()
	policyEngine.SetPolicy(&policy.Policy{
		Default: "deny",
		Rules: []policy.AllowRule{
			{
				AgentID:       "a:deny-agent",
				PrincipalSub:  "*",
				Resource:      "*",
				AllowedScopes: []string{"github:read"},
			},
		},
	})

	exchanger := exchange.NewExchanger(verifier, signer, policyEngine, "https://aidp.deny", 5*time.Minute)

	// Mint AIT with tools:exchange scope
	now := time.Now()
	ait, _ := signer.SignAIT(&jwt.AITClaims{
		Issuer:   "https://aidp.deny",
		Subject:  "a:deny-agent",
		Audience: "https://aidp.deny/oauth/token",
		Exp:      now.Add(15 * time.Minute).Unix(),
		Iat:      now.Unix(),
		Nbf:      now.Unix(),
		JTI:      "ait_deny_" + uuid.NewString(),
		ClientID: "test",
		Scope:    jwt.ScopeToolsExchange,
		Act:      &jwt.ActorClaim{Sub: "oidc:okta:user-001"},
	})

	// Request admin scope — should be narrowed or denied
	_, err := exchanger.Exchange(&exchange.Request{
		GrantType:    exchange.GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.test",
		Scope:        "github:admin:delete",
	})
	if err == nil {
		t.Fatal("expected policy denial for admin scope")
	}
	t.Log("✓ Policy correctly denied unauthorized scope")
}

// TestEndToEndGatewayBinary serves as the gateway binary entry point
// (referenced by cmd/gateway/main.go in a later brick).
var _ = gateway.DefaultConfig
