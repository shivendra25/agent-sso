package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair("test-key-1")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.KeyID != KeyID("test-key-1") {
		t.Errorf("KeyID = %q, want %q", kp.KeyID, "test-key-1")
	}
	if kp.Private == nil {
		t.Fatal("Private key is nil")
	}
	if kp.Public == nil {
		t.Fatal("Public key is nil")
	}
	if !kp.IsActive() {
		t.Error("freshly generated key should be active")
	}
}

func TestKeyPairJWK(t *testing.T) {
	kp, err := GenerateKeyPair("2026-07-10-key-1")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	jwk := kp.ToJWK()
	if jwk.Kty != "EC" {
		t.Errorf("Kty = %q, want EC", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("Crv = %q, want P-256", jwk.Crv)
	}
	if jwk.Kid != "2026-07-10-key-1" {
		t.Errorf("Kid = %q, want 2026-07-10-key-1", jwk.Kid)
	}
	if jwk.Alg != "ES256" {
		t.Errorf("Alg = %q, want ES256", jwk.Alg)
	}
	if jwk.X == "" || jwk.Y == "" {
		t.Error("X or Y coordinate is empty")
	}

	// Verify coords are valid base64url
	if _, err := base64.RawURLEncoding.DecodeString(jwk.X); err != nil {
		t.Errorf("X is not valid base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(jwk.Y); err != nil {
		t.Errorf("Y is not valid base64url: %v", err)
	}
}

func TestJWKRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair("roundtrip-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	jwk := kp.ToJWK()
	pub, err := ParsePublicKeyFromJWK(jwk.Kty, jwk.Crv, jwk.X, jwk.Y)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromJWK: %v", err)
	}

	// Verify the reconstructed key matches the original
	if pub.X.Cmp(kp.Public.X) != 0 || pub.Y.Cmp(kp.Public.Y) != 0 {
		t.Error("reconstructed public key does not match original")
	}
}

func TestParsePublicKeyFromJWKInvalidType(t *testing.T) {
	_, err := ParsePublicKeyFromJWK("RSA", "P-256", "x", "y")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestParsePublicKeyFromJWKInvalidCoords(t *testing.T) {
	_, err := ParsePublicKeyFromJWK("EC", "P-256", "!!!not-base64!!!", "y")
	if err == nil {
		t.Error("expected error for invalid base64 coordinates")
	}
}

func TestPEMEncoding(t *testing.T) {
	kp, err := GenerateKeyPair("pem-key")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pemBytes, err := kp.EncodePrivateKeyToPEM()
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("PEM output is empty")
	}
}

func TestJWKSStructure(t *testing.T) {
	kp1, _ := GenerateKeyPair("key-1")
	kp2, _ := GenerateKeyPair("key-2")

	jwks := JWKS{
		Keys: []JWK{kp1.ToJWK(), kp2.ToJWK()},
	}
	if len(jwks.Keys) != 2 {
		t.Errorf("JWKS has %d keys, want 2", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid == jwks.Keys[1].Kid {
		t.Error("duplicate key IDs")
	}
}
