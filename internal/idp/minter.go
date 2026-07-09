package idp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

// IDTokenMinter is a test helper that mints OIDC ID tokens signed with
// an ES256 key, simulating an IdP (Okta, Google, etc.).
type IDTokenMinter struct {
	keyPair *crypto.KeyPair
	issuer  string
}

// NewIDTokenMinter creates a test ID token minter.
func NewIDTokenMinter(kp *crypto.KeyPair, issuer string) *IDTokenMinter {
	return &IDTokenMinter{keyPair: kp, issuer: issuer}
}

// MintIDToken produces a signed OIDC ID token for testing.
func (m *IDTokenMinter) MintIDToken(sub, clientID string, extraClaims map[string]interface{}) (string, error) {
	now := time.Now()
	header := oidcHeader{
		Alg: "ES256",
		Typ: "JWT",
		Kid: string(m.keyPair.KeyID),
	}

	claims := map[string]interface{}{
		"iss": m.issuer,
		"sub": sub,
		"aud": []string{clientID},
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
	}
	for k, v := range extraClaims {
		claims[k] = v
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig, err := ecdsa.SignASN1(rand.Reader, m.keyPair.Private, crypto.HashSHA256([]byte(signingInput)))
	if err != nil {
		return "", fmt.Errorf("mint ID token: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// MinterToVerifierKeys converts a minter's keypair into the map format
// expected by JWKSVerifier.
func MinterToVerifierKeys(kp *crypto.KeyPair) map[crypto.KeyID]*ecdsa.PublicKey {
	return map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public}
}
