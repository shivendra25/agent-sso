package attest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/shivendra25/agent-sso/internal/attestation"
	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/idp"
	"github.com/shivendra25/agent-sso/internal/jwt"
)

func newTestIssuer(t *testing.T) (*Issuer, *idp.IDTokenMinter, *attestation.AttestationSigner) {
	t.Helper()

	// aIdP signing key
	kp, err := crypto.GenerateKeyPair("aidp-test-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer := jwt.NewSigner(kp)

	// IdP key for minting OIDC ID tokens
	idpKey, err := crypto.GenerateKeyPair("idp-test-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	minter := idp.NewIDTokenMinter(idpKey, "https://test.okta.com")

	// OIDC provider registry
	providers := idp.NewProviderRegistry()
	providers.Register(idp.ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "test-client-id",
	}, idp.NewJWKSVerifier(idp.ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "test-client-id",
	}, idp.MinterToVerifierKeys(idpKey)))

	// Attestation registry + verifier
	_, hostPriv, _ := ed25519.GenerateKey(nil)
	hostPub, _, _ := ed25519.GenerateKey(nil)
	_ = hostPriv
	// We need the same key for signing and verifying
	hostPub2, hostPriv2, _ := ed25519.GenerateKey(nil)
	attestRegistry := attestation.NewMemoryRegistry()
	attestRegistry.Register(&attestation.AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    hostPub2,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:def456"},
	})
	attestVerifier := attestation.NewVerifier(attestRegistry)
	attestSigner := attestation.NewAttestationSigner("host-001", hostPriv2)
	_ = hostPub

	issuer := NewIssuer(
		attestVerifier,
		providers,
		signer,
		"https://aidp.test",
		"https://aidp.test/oauth/token",
		15*time.Minute,
	)
	return issuer, minter, attestSigner
}

func TestIssueSuccess(t *testing.T) {
	issuer, minter, attestSigner := newTestIssuer(t)

	// Mint a valid OIDC ID token
	idToken, err := minter.MintIDToken("user-okta-001", "test-client-id", map[string]interface{}{
		"email": "alice@example.com",
		"name":  "Alice",
	})
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}

	// Create a valid attestation document
	doc := &attestation.AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HostID:       "host-001",
		JTI:          "att-test-001",
	}
	signedAtt, err := attestSigner.Sign(doc)
	if err != nil {
		t.Fatalf("Sign attestation: %v", err)
	}

	// Issue AIT
	resp, err := issuer.Issue(&Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       idToken,
		OIDCProviderAlias: "okta",
		TenantID:          "tnt_test",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.AIT == "" {
		t.Fatal("AIT is empty")
	}
	if resp.AgentID != "a:test-agent-001" {
		t.Errorf("AgentID = %q, want a:test-agent-001", resp.AgentID)
	}
	if resp.PrincipalSub != "user-okta-001" {
		t.Errorf("PrincipalSub = %q, want user-okta-001", resp.PrincipalSub)
	}
	if resp.JTI == "" {
		t.Error("JTI is empty")
	}
	if resp.ExpiresAt <= resp.IssuedAt {
		t.Error("ExpiresAt should be after IssuedAt")
	}

	// Verify the AIT is parseable and has correct claims
	// (decode without signature check — just validate claims structure)
	parts := splitJWT(resp.AIT)
	if len(parts) != 3 {
		t.Fatal("AIT is not a valid JWT (3 parts)")
	}
}

func TestIssueMissingAttestation(t *testing.T) {
	issuer, _, _ := newTestIssuer(t)
	_, err := issuer.Issue(&Request{
		OIDCIDToken:       "some-token",
		OIDCProviderAlias: "okta",
	})
	if err == nil {
		t.Fatal("expected error for missing attestation")
	}
}

func TestIssueMissingIDToken(t *testing.T) {
	issuer, _, _ := newTestIssuer(t)
	_, err := issuer.Issue(&Request{
		SignedAttestation: "some-att",
	})
	if err == nil {
		t.Fatal("expected error for missing ID token")
	}
}

func TestIssueInvalidAttestation(t *testing.T) {
	issuer, _, _ := newTestIssuer(t)
	_, err := issuer.Issue(&Request{
		SignedAttestation: "garbage",
		OIDCIDToken:       "some-token",
		OIDCProviderAlias: "okta",
	})
	if err == nil {
		t.Fatal("expected error for invalid attestation")
	}
}

func TestIssueInvalidIDToken(t *testing.T) {
	issuer, _, attestSigner := newTestIssuer(t)

	doc := &attestation.AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HostID:       "host-001",
		JTI:          "att-test-002",
	}
	signedAtt, _ := attestSigner.Sign(doc)

	_, err := issuer.Issue(&Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       "invalid-id-token",
		OIDCProviderAlias: "okta",
	})
	if err == nil {
		t.Fatal("expected error for invalid ID token")
	}
}

func TestIssueUnknownProvider(t *testing.T) {
	issuer, minter, attestSigner := newTestIssuer(t)

	idToken, _ := minter.MintIDToken("user-001", "test-client-id", nil)

	doc := &attestation.AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HostID:       "host-001",
		JTI:          "att-test-003",
	}
	signedAtt, _ := attestSigner.Sign(doc)

	_, err := issuer.Issue(&Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       idToken,
		OIDCProviderAlias: "unknown-provider",
	})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestIssueAttestationExpired(t *testing.T) {
	issuer, minter, attestSigner := newTestIssuer(t)

	idToken, _ := minter.MintIDToken("user-001", "test-client-id", nil)

	doc := &attestation.AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    time.Now().Add(-20 * time.Minute),
		ExpiresAt:    time.Now().Add(-5 * time.Minute), // expired
		HostID:       "host-001",
		JTI:          "att-test-004",
	}
	signedAtt, _ := attestSigner.Sign(doc)

	_, err := issuer.Issue(&Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       idToken,
		OIDCProviderAlias: "okta",
	})
	if err == nil {
		t.Fatal("expected error for expired attestation")
	}
}

func TestIssueAITCorrectClaims(t *testing.T) {
	issuer, minter, attestSigner := newTestIssuer(t)
	kp, _ := crypto.GenerateKeyPair("verify-key")
	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public})

	// Replace issuer's signer with one whose key we can verify with
	issuer.jwtSigner = jwt.NewSigner(kp)

	idToken, _ := minter.MintIDToken("user-claims-001", "test-client-id", map[string]interface{}{
		"email": "bob@example.com",
	})

	doc := &attestation.AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HostID:       "host-001",
		JTI:          "att-claims-001",
	}
	signedAtt, _ := attestSigner.Sign(doc)

	resp, err := issuer.Issue(&Request{
		SignedAttestation: signedAtt,
		OIDCIDToken:       idToken,
		OIDCProviderAlias: "okta",
		TenantID:          "tnt_claims",
		SessionID:         "ses_custom",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	ait, err := verifier.VerifyAIT(resp.AIT)
	if err != nil {
		t.Fatalf("VerifyAIT: %v", err)
	}
	if ait.Subject != "a:test-agent-001" {
		t.Errorf("Subject = %q", ait.Subject)
	}
	if ait.Audience != "https://aidp.test/oauth/token" {
		t.Errorf("Audience = %q", ait.Audience)
	}
	if ait.Issuer != "https://aidp.test" {
		t.Errorf("Issuer = %q", ait.Issuer)
	}
	if ait.CodebaseHash != "sha256:abc123" {
		t.Errorf("CodebaseHash = %q", ait.CodebaseHash)
	}
	if ait.RuntimeHash != "sha256:def456" {
		t.Errorf("RuntimeHash = %q", ait.RuntimeHash)
	}
	if ait.TenantID != "tnt_claims" {
		t.Errorf("TenantID = %q", ait.TenantID)
	}
	if ait.SessionID != "ses_custom" {
		t.Errorf("SessionID = %q", ait.SessionID)
	}
	if ait.AttestationJTI != "att-claims-001" {
		t.Errorf("AttestationJTI = %q", ait.AttestationJTI)
	}
	if ait.Act == nil {
		t.Fatal("Act claim is nil")
	}
	if ait.Act.Sub != "oidc:okta:user-claims-001" {
		t.Errorf("Act.Sub = %q, want oidc:okta:user-claims-001", ait.Act.Sub)
	}
	if !ait.HasScope(jwt.ScopeAgentAttest) {
		t.Error("missing agent:attest scope")
	}
	if !ait.HasScope(jwt.ScopeToolsExchange) {
		t.Error("missing tools:exchange scope")
	}
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
