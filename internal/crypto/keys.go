// Package crypto provides ES256 keypair generation, JWKS encoding, and
// JWT signing/verification for AgentSSO tokens.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// KeyID is the identifier for a signing key in the JWKS endpoint.
type KeyID string

// KeyPair holds an ES256 (ECDSA P-256) key pair with metadata.
type KeyPair struct {
	KeyID     KeyID
	Private   *ecdsa.PrivateKey
	Public    *ecdsa.PublicKey
	CreatedAt time.Time
	NotAfter  time.Time
}

// GenerateKeyPair creates a new ES256 key pair with the given key ID.
// Keys are valid for 90 days from creation.
func GenerateKeyPair(kid string) (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ES256 key: %w", err)
	}
	now := time.Now()
	return &KeyPair{
		KeyID:     KeyID(kid),
		Private:   priv,
		Public:    &priv.PublicKey,
		CreatedAt: now,
		NotAfter:  now.Add(90 * 24 * time.Hour),
	}, nil
}

// IsActive reports whether the key is within its validity window.
func (kp *KeyPair) IsActive() bool {
	now := time.Now()
	return now.After(kp.CreatedAt) && now.Before(kp.NotAfter)
}

// IsRetired reports whether the key is past its signing window but
// still retained for verification.
func (kp *KeyPair) IsRetired() bool {
	return time.Now().After(kp.NotAfter.Add(-30*24*time.Hour)) && !kp.IsActive()
}

// JWK represents a JSON Web Key (RFC 7517) for ES256.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS represents a JSON Web Key Set (RFC 7517).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ToJWK converts a public ECDSA key to JWK format (RFC 7517 §6.2.1).
func (kp *KeyPair) ToJWK() JWK {
	coords := kp.Public.Curve.Params()
	xBytes := kp.Public.X.FillBytes(make([]byte, coords.BitSize/8))
	yBytes := kp.Public.Y.FillBytes(make([]byte, coords.BitSize/8))
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: string(kp.KeyID),
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// EncodePrivateKeyToPEM encodes a private key to PEM format for storage.
func (kp *KeyPair) EncodePrivateKeyToPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(kp.Private)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}

// ParsePublicKeyFromJWK reconstructs an ECDSA public key from JWK fields.
func ParsePublicKeyFromJWK(kty, crv, x, y string) (*ecdsa.PublicKey, error) {
	if kty != "EC" || crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %s/%s, expected EC/P-256", kty, crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("decode y coordinate: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// HashSHA256 computes the SHA-256 hash of the given data.
func HashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
