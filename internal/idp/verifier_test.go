package idp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

func TestJWKSVerifierValidToken(t *testing.T) {
	kp, err := crypto.GenerateKeyPair("idp-test-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	realmIssuer := "https://test.okta.com"
	clientID := "test-client-id"
	minter := NewIDTokenMinter(kp, realmIssuer)
	verifier := NewJWKSVerifier(ProviderConfig{
		Alias:    "okta",
		Issuer:   realmIssuer,
		ClientID: clientID,
	}, MinterToVerifierKeys(kp))

	token, err := minter.MintIDToken("user-001", clientID, map[string]interface{}{
		"email":  "alice@example.com",
		"name":   "Alice Engineer",
		"groups": []string{"engineering", "admins"},
	})
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}

	principal, err := verifier.VerifyIDToken(token)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if principal.Subject != "user-001" {
		t.Errorf("Subject = %q, want user-001", principal.Subject)
	}
	if principal.Issuer != realmIssuer {
		t.Errorf("Issuer = %q, want %q", principal.Issuer, realmIssuer)
	}
	if principal.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", principal.Email)
	}
	if principal.Name != "Alice Engineer" {
		t.Errorf("Name = %q, want Alice Engineer", principal.Name)
	}
	if len(principal.Groups) != 2 {
		t.Fatalf("Groups len = %d, want 2", len(principal.Groups))
	}
	if principal.IsExpired() {
		t.Error("principal should not be expired")
	}
}

func TestJWKSVerifierWrongIssuer(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("idp-key")
	minter := NewIDTokenMinter(kp, "https://wrong.okta.com")
	verifier := NewJWKSVerifier(ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "test-client",
	}, MinterToVerifierKeys(kp))

	token, _ := minter.MintIDToken("user-001", "test-client", nil)
	_, err := verifier.VerifyIDToken(token)
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestJWKSVerifierWrongAudience(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("idp-key")
	minter := NewIDTokenMinter(kp, "https://test.okta.com")
	verifier := NewJWKSVerifier(ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "expected-client",
	}, MinterToVerifierKeys(kp))

	token, _ := minter.MintIDToken("user-001", "wrong-client", nil)
	_, err := verifier.VerifyIDToken(token)
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestJWKSVerifierExpiredToken(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("idp-key")
	issuer := "https://test.okta.com"
	clientID := "test-client"
	verifier := NewJWKSVerifier(ProviderConfig{
		Alias:    "okta",
		Issuer:   issuer,
		ClientID: clientID,
	}, MinterToVerifierKeys(kp))

	now := time.Now()
	header := oidcHeader{Alg: "ES256", Typ: "JWT", Kid: string(kp.KeyID)}
	claims := map[string]interface{}{
		"iss": issuer,
		"sub": "user-001",
		"aud": []string{clientID},
		"exp": now.Add(-1 * time.Hour).Unix(), // expired
		"iat": now.Add(-2 * time.Hour).Unix(),
	}
	headerJSON, _ := encodeJSON(header)
	claimsJSON, _ := encodeJSON(claims)
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	sig := signES256(kp, signingInput)
	token := signingInput + "." + b64(sig)

	_, err := verifier.VerifyIDToken(token)
	if err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestJWKSVerifierInvalidSignature(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair("real-key")
	kp2, _ := crypto.GenerateKeyPair("wrong-key")
	minter := NewIDTokenMinter(kp1, "https://test.okta.com")
	verifier := NewJWKSVerifier(ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "test-client",
	}, MinterToVerifierKeys(kp2)) // wrong key

	token, _ := minter.MintIDToken("user-001", "test-client", nil)
	_, err := verifier.VerifyIDToken(token)
	if err == nil {
		t.Fatal("expected invalid signature error")
	}
}

func TestStaticVerifier(t *testing.T) {
	sv := NewStaticVerifier()
	p := &Principal{
		Subject:       "user-001",
		Issuer:        "https://test.okta.com",
		EstablishedAt: time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	sv.AddToken("test-token-123", p)

	result, err := sv.VerifyIDToken("test-token-123")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if result.Subject != "user-001" {
		t.Errorf("Subject = %q, want user-001", result.Subject)
	}

	_, err = sv.VerifyIDToken("unknown-token")
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestStaticVerifierExpiredPrincipal(t *testing.T) {
	sv := NewStaticVerifier()
	p := &Principal{
		Subject:       "user-001",
		EstablishedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // expired
	}
	sv.AddToken("expired-token", p)

	_, err := sv.VerifyIDToken("expired-token")
	if err == nil {
		t.Fatal("expected expired principal error")
	}
}

func TestProviderRegistry(t *testing.T) {
	reg := NewProviderRegistry()
	sv := NewStaticVerifier()
	p := &Principal{
		Subject:       "user-001",
		EstablishedAt: time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	sv.AddToken("token-okta", p)

	reg.Register(ProviderConfig{
		Alias:    "okta",
		Issuer:   "https://test.okta.com",
		ClientID: "test-client",
	}, sv)

	_, err := reg.VerifyTokenForProvider("unknown", "token-okta")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}

	result, err := reg.VerifyTokenForProvider("okta", "token-okta")
	if err != nil {
		t.Fatalf("VerifyTokenForProvider: %v", err)
	}
	if result.Subject != "user-001" {
		t.Errorf("Subject = %q, want user-001", result.Subject)
	}
}

func TestActorSubject(t *testing.T) {
	p := &Principal{Subject: "00u8f4jk2l", Issuer: "https://acme.okta.com"}
	got := p.ActorSubject("okta")
	want := "oidc:okta:00u8f4jk2l"
	if got != want {
		t.Errorf("ActorSubject = %q, want %q", got, want)
	}
}

func TestPrincipalIsExpired(t *testing.T) {
	p := &Principal{
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	if !p.IsExpired() {
		t.Error("expected expired")
	}
	p2 := &Principal{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if p2.IsExpired() {
		t.Error("expected not expired")
	}
}

// helpers

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func encodeJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func signES256(kp *crypto.KeyPair, signingInput string) []byte {
	sig, err := ecdsa.SignASN1(rand.Reader, kp.Private, crypto.HashSHA256([]byte(signingInput)))
	if err != nil {
		panic(err)
	}
	return sig
}
