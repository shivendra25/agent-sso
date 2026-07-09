package jwt

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

func testClaims(issuer, audience string, exp time.Time) *AITClaims {
	now := time.Now().Unix()
	return &AITClaims{
		Issuer:   issuer,
		Subject:  "a:test-agent-id",
		Audience: audience,
		Exp:      exp.Unix(),
		Iat:      now,
		Nbf:      now,
		JTI:      "test-jti-001",
		ClientID: "test-client",
		Scope:    "agent:attest tools:exchange",
		Act: &ActorClaim{
			Sub:          "oidc:okta:test-principal",
			Iss:          "https://test.okta.com",
			DelegationID: "del_test",
		},
		CodebaseHash:   "sha256:abc123",
		RuntimeHash:    "sha256:def456",
		SessionID:      "ses_test",
		AttestationJTI: "att_test",
		TenantID:       "tnt_test",
	}
}

func TestAITSignAndVerify(t *testing.T) {
	kp, err := crypto.GenerateKeyPair("test-sign-1")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signer := NewSigner(kp)
	claims := testClaims("https://aidp.test", "https://aidp.test/oauth/token", time.Now().Add(15*time.Minute))

	token, err := signer.SignAIT(claims)
	if err != nil {
		t.Fatalf("SignAIT: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	verifier := NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{
		kp.KeyID: kp.Public,
	})

	parsed, err := verifier.VerifyAIT(token)
	if err != nil {
		t.Fatalf("VerifyAIT: %v", err)
	}
	if parsed.Subject != claims.Subject {
		t.Errorf("Subject = %q, want %q", parsed.Subject, claims.Subject)
	}
	if parsed.Act == nil {
		t.Fatal("Act claim is nil after round-trip")
	}
	if parsed.Act.Sub != claims.Act.Sub {
		t.Errorf("Act.Sub = %q, want %q", parsed.Act.Sub, claims.Act.Sub)
	}
	if parsed.JTI != claims.JTI {
		t.Errorf("JTI = %q, want %q", parsed.JTI, claims.JTI)
	}
}

func TestAITVerificationWrongKey(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair("key-1")
	kp2, _ := crypto.GenerateKeyPair("key-2")

	signer := NewSigner(kp1)
	claims := testClaims("https://aidp.test", "https://aidp.test/oauth/token", time.Now().Add(15*time.Minute))
	token, _ := signer.SignAIT(claims)

	verifier := NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{
		kp2.KeyID: kp2.Public, // wrong key
	})
	if _, err := verifier.VerifyAIT(token); err == nil {
		t.Error("expected error verifying with wrong key (unknown kid should fail)")
	}
}

func TestAITValidationExpired(t *testing.T) {
	claims := testClaims("https://aidp.test", "https://aidp.test/oauth/token", time.Now().Add(-1*time.Minute))
	if err := claims.Validate("https://aidp.test", "https://aidp.test/oauth/token"); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestAITValidationNotYetValid(t *testing.T) {
	now := time.Now()
	claims := &AITClaims{
		Issuer:   "https://aidp.test",
		Audience: "https://aidp.test/oauth/token",
		Exp:      now.Add(10 * time.Minute).Unix(),
		Iat:      now.Unix(),
		Nbf:      now.Add(5 * time.Minute).Unix(),
		Act:      &ActorClaim{Sub: "test"},
	}
	if err := claims.Validate("https://aidp.test", "https://aidp.test/oauth/token"); err == nil {
		t.Error("expected error for not-yet-valid token")
	}
}

func TestAITValidationWrongAudience(t *testing.T) {
	claims := testClaims("https://aidp.test", "https://wrong", time.Now().Add(15*time.Minute))
	err := claims.Validate("https://aidp.test", "https://aidp.test/oauth/token")
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestAITValidationWrongIssuer(t *testing.T) {
	claims := testClaims("https://wrong", "https://aidp.test/oauth/token", time.Now().Add(15*time.Minute))
	err := claims.Validate("https://aidp.test", "https://aidp.test/oauth/token")
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestAITValidationMissingAct(t *testing.T) {
	claims := &AITClaims{
		Issuer:   "https://aidp.test",
		Audience: "https://aidp.test/oauth/token",
		Exp:      time.Now().Add(15 * time.Minute).Unix(),
		Iat:      time.Now().Unix(),
		Nbf:      time.Now().Unix(),
		Act:      nil,
	}
	err := claims.Validate("https://aidp.test", "https://aidp.test/oauth/token")
	if err == nil {
		t.Fatal("expected error for missing act claim")
	}
}

func TestHasScope(t *testing.T) {
	claims := &AITClaims{Scope: "agent:attest tools:exchange"}
	if !claims.HasScope("agent:attest") {
		t.Error("expected agent:attest scope")
	}
	if !claims.HasScope("tools:exchange") {
		t.Error("expected tools:exchange scope")
	}
	if claims.HasScope("admin") {
		t.Error("did not expect admin scope")
	}
}

func TestJITSignAndVerify(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("jit-key")
	signer := NewSigner(kp)

	jit := &JITClaims{
		Issuer:    "https://aidp.test",
		Subject:   "a:test-agent",
		Audience:  "https://mcp.github.test",
		Exp:       time.Now().Add(5 * time.Minute).Unix(),
		Iat:       time.Now().Unix(),
		JTI:       "jit-001",
		ClientID:  "test-client",
		Scope:     "github:prs:read",
		Act:       &ActorClaim{Sub: "oidc:okta:human"},
		SessionID: "ses_test",
		TenantID:  "tnt_test",
		ParentJTI: "ait-jti-001",
	}

	token, err := signer.SignJIT(jit)
	if err != nil {
		t.Fatalf("SignJIT: %v", err)
	}

	verifier := NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{
		kp.KeyID: kp.Public,
	})
	parsed, err := verifier.VerifyJIT(token)
	if err != nil {
		t.Fatalf("VerifyJIT: %v", err)
	}
	if parsed.Audience != "https://mcp.github.test" {
		t.Errorf("Audience = %q, want https://mcp.github.test", parsed.Audience)
	}
	if parsed.ParentJTI != "ait-jti-001" {
		t.Errorf("ParentJTI = %q, want ait-jti-001", parsed.ParentJTI)
	}
}

func TestInvalidTokenFormat(t *testing.T) {
	verifier := NewVerifier(nil)
	if _, err := verifier.VerifyAIT("not.a.valid.jwt.extra"); err == nil {
		t.Error("expected error for invalid token format")
	}
	if _, err := verifier.VerifyAIT(""); err == nil {
		t.Error("expected error for empty token")
	}
}
