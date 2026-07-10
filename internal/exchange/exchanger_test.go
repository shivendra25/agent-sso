package exchange

import (
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/jwt"
)

func newTestExchanger(t *testing.T, policy PolicyEvaluator) (*Exchanger, *jwt.Signer, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair("exchange-test-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer := jwt.NewSigner(kp)
	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public})

	issuerURL := "https://aidp.test"
	exchanger := NewExchanger(verifier, signer, policy, issuerURL, 5*time.Minute)
	return exchanger, signer, kp
}

func mintTestAIT(t *testing.T, signer *jwt.Signer, issuerURL string, scopes string, act *jwt.ActorClaim) string {
	t.Helper()
	now := time.Now()
	claims := &jwt.AITClaims{
		Issuer:         issuerURL,
		Subject:        "a:test-agent-001",
		Audience:       issuerURL + "/oauth/token",
		Exp:            now.Add(15 * time.Minute).Unix(),
		Iat:            now.Unix(),
		Nbf:            now.Unix(),
		JTI:            "ait_" + uuid.NewString(),
		ClientID:       "test-client",
		Scope:          scopes,
		Act:            act,
		CodebaseHash:   "sha256:abc",
		RuntimeHash:    "sha256:def",
		SessionID:      "ses_test",
		AttestationJTI: "att_test",
		TenantID:       "tnt_test",
	}
	token, err := signer.SignAIT(claims)
	if err != nil {
		t.Fatalf("SignAIT: %v", err)
	}
	return token
}

func TestExchangeSuccess(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeAgentAttest+" "+jwt.ScopeToolsExchange,
		&jwt.ActorClaim{Sub: "oidc:okta:user-001", Iss: "https://test.okta.com"})

	resp, err := exchanger.Exchange(&Request{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     ait,
		SubjectTokenType: TokenTypeAccessToken,
		Resource:         "https://mcp.github.example.com",
		Scope:            "github:prs:read",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("AccessToken is empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.Scope != "github:prs:read" {
		t.Errorf("Scope = %q, want github:prs:read", resp.Scope)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", resp.ExpiresIn)
	}
}

func TestExchangeJITCorrectClaims(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, kp := newTestExchanger(t, policy)
	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public})

	act := &jwt.ActorClaim{Sub: "oidc:okta:user-001", Iss: "https://test.okta.com", DelegationID: "del_test"}
	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeAgentAttest+" "+jwt.ScopeToolsExchange, act)

	resp, _ := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read github:prs:write",
	})

	jit, err := verifier.VerifyJIT(resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyJIT: %v", err)
	}
	if jit.Audience != "https://mcp.github.example.com" {
		t.Errorf("Audience = %q", jit.Audience)
	}
	if jit.Issuer != "https://aidp.test" {
		t.Errorf("Issuer = %q", jit.Issuer)
	}
	if jit.Subject != "a:test-agent-001" {
		t.Errorf("Subject = %q", jit.Subject)
	}
	if jit.Scope != "github:prs:read github:prs:write" {
		t.Errorf("Scope = %q", jit.Scope)
	}
	if jit.Act == nil || jit.Act.Sub != "oidc:okta:user-001" {
		t.Error("Act delegation chain not preserved")
	}
	if jit.ParentJTI == "" {
		t.Error("ParentJTI is empty")
	}
	if jit.TenantID != "tnt_test" {
		t.Errorf("TenantID = %q", jit.TenantID)
	}
}

func TestExchangeScopeNarrowing(t *testing.T) {
	policy := &MockPolicyEvaluator{
		AllowedScopes: []string{"github:prs:read"}, // only read allowed
	}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	resp, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read github:prs:write github:repos:admin",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Scope != "github:prs:read" {
		t.Errorf("Scope = %q, want github:prs:read (narrowed)", resp.Scope)
	}
}

func TestExchangePolicyDenyAll(t *testing.T) {
	policy := &MockPolicyEvaluator{DenyError: errors.New("no permissions")}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected policy denial error")
	}
}

func TestExchangePolicyNarrowsToEmpty(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowedScopes: []string{}}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected empty scope error")
	}
}

func TestExchangeWrongGrantType(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, _, _ := newTestExchanger(t, policy)

	_, err := exchanger.Exchange(&Request{
		GrantType: "authorization_code",
	})
	if err == nil {
		t.Fatal("expected wrong grant type error")
	}
}

func TestExchangeMissingResource(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected missing resource error")
	}
}

func TestExchangeMissingScope(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
	})
	if err == nil {
		t.Fatal("expected missing scope error")
	}
}

func TestExchangeInvalidAIT(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, _, _ := newTestExchanger(t, policy)

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: "garbage.token.here",
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected AIT verification error")
	}
}

func TestExchangeAITMissingExchangeScope(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeAgentAttest, // missing tools:exchange
		&jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected error for AIT without tools:exchange scope")
	}
}

func TestExchangeExpiredAIT(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	now := time.Now()
	claims := &jwt.AITClaims{
		Issuer:   "https://aidp.test",
		Subject:  "a:test-agent-001",
		Audience: "https://aidp.test/oauth/token",
		Exp:      now.Add(-1 * time.Minute).Unix(), // expired
		Iat:      now.Add(-16 * time.Minute).Unix(),
		Nbf:      now.Add(-16 * time.Minute).Unix(),
		JTI:      "ait_expired",
		ClientID: "test-client",
		Scope:    jwt.ScopeToolsExchange,
		Act:      &jwt.ActorClaim{Sub: "oidc:okta:user-001"},
	}
	ait, _ := signer.SignAIT(claims)

	_, err := exchanger.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected expired AIT error")
	}
}

func TestExchangeWrongAudience(t *testing.T) {
	policy := &MockPolicyEvaluator{AllowAll: true}
	exchanger, signer, _ := newTestExchanger(t, policy)

	ait := mintTestAIT(t, signer, "https://aidp.test",
		jwt.ScopeToolsExchange, &jwt.ActorClaim{Sub: "oidc:okta:user-001"})

	// Use a different issuer URL for the exchanger
	exchangerWrongIssuer := NewExchanger(
		exchanger.verifier, exchanger.signer, policy,
		"https://wrong.issuer", 5*time.Minute,
	)

	_, err := exchangerWrongIssuer.Exchange(&Request{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: ait,
		Resource:     "https://mcp.github.example.com",
		Scope:        "github:prs:read",
	})
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestIsValidResourceURI(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		{"https://mcp.example.com", true},
		{"https://mcp.example.com/path", true},
		{"https://mcp.example.com:8443", true},
		{"https://localhost:3000/mcp", true},
		{"http://mcp.example.com", false},       // non-https
		{"mcp.example.com", false},              // no scheme
		{"https://mcp.example.com#frag", false}, // has fragment
		{"", false},                             // empty
		{"https://", false},                     // no host
		{"https://mcp.example.com:abc", false},  // non-numeric port
	}
	for _, tt := range tests {
		got := isValidResourceURI(tt.uri)
		if got != tt.want {
			t.Errorf("isValidResourceURI(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}
