package idp

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

// Verifier is the interface for verifying OIDC ID tokens and extracting
// the human principal. Implementations include JWKS-based verification
// (production) and static token verification (testing).
type Verifier interface {
	// VerifyIDToken verifies an OIDC ID token and returns the principal.
	VerifyIDToken(rawToken string) (*Principal, error)
}

// JWKSVerifier verifies OIDC ID tokens using a JWKS endpoint (production).
// It fetches the provider's public keys and validates the JWT signature,
// issuer, audience, and expiry.
type JWKSVerifier struct {
	config     ProviderConfig
	publicKeys map[crypto.KeyID]*ecdsa.PublicKey
}

// NewJWKSVerifier creates a verifier from a provider config and a set of
// trusted public keys (fetched from the provider's JWKS endpoint).
func NewJWKSVerifier(cfg ProviderConfig, keys map[crypto.KeyID]*ecdsa.PublicKey) *JWKSVerifier {
	return &JWKSVerifier{config: cfg, publicKeys: keys}
}

// VerifyIDToken implements Verifier.
func (v *JWKSVerifier) VerifyIDToken(rawToken string) (*Principal, error) {
	header, claims, signingInput, sig, err := parseOIDCToken(rawToken)
	if err != nil {
		return nil, fmt.Errorf("idp: parse ID token: %w", err)
	}

	pubKey, ok := v.publicKeys[crypto.KeyID(header.Kid)]
	if !ok {
		return nil, fmt.Errorf("idp: unknown key ID %q", header.Kid)
	}

	if !ecdsa.VerifyASN1(pubKey, crypto.HashSHA256([]byte(signingInput)), sig) {
		return nil, ErrInvalidIDToken
	}

	var idClaims oidcIDTokenClaims
	if err := json.Unmarshal(claims, &idClaims); err != nil {
		return nil, fmt.Errorf("idp: unmarshal claims: %w", err)
	}

	// Validate issuer
	if idClaims.Iss != v.config.Issuer {
		return nil, fmt.Errorf("idp: issuer %q does not match expected %q", idClaims.Iss, v.config.Issuer)
	}

	// Validate audience
	if !contains(idClaims.Aud, v.config.ClientID) {
		return nil, fmt.Errorf("idp: audience does not include client_id %q", v.config.ClientID)
	}

	// Validate expiry
	now := time.Now().Unix()
	if idClaims.Exp < now {
		return nil, errors.New("idp: ID token expired")
	}

	return &Principal{
		Subject:       idClaims.Sub,
		Issuer:        idClaims.Iss,
		Email:         idClaims.Email,
		Name:          idClaims.Name,
		Groups:        idClaims.Groups,
		EstablishedAt: time.Now(),
		ExpiresAt:     time.Unix(idClaims.Exp, 0),
	}, nil
}

// oidcIDTokenClaims are the standard OIDC ID token claims.
type oidcIDTokenClaims struct {
	Iss    string   `json:"iss"`
	Sub    string   `json:"sub"`
	Aud    []string `json:"aud"`
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// StaticVerifier is a test-only verifier that accepts pre-configured tokens.
// It maps token strings to principals, allowing tests to simulate OIDC
// without a real IdP.
type StaticVerifier struct {
	tokens map[string]*Principal
}

// NewStaticVerifier creates a test verifier.
func NewStaticVerifier() *StaticVerifier {
	return &StaticVerifier{tokens: make(map[string]*Principal)}
}

// AddToken registers a token-to-principal mapping for testing.
func (sv *StaticVerifier) AddToken(token string, principal *Principal) {
	sv.tokens[token] = principal
}

// VerifyIDToken implements Verifier.
func (sv *StaticVerifier) VerifyIDToken(rawToken string) (*Principal, error) {
	p, ok := sv.tokens[rawToken]
	if !ok {
		return nil, ErrInvalidIDToken
	}
	if p.IsExpired() {
		return nil, errors.New("idp: principal session expired")
	}
	return p, nil
}

// ProviderRegistry holds multiple OIDC providers indexed by alias.
type ProviderRegistry struct {
	providers map[string]ProviderConfig
	verifiers map[string]Verifier
}

// NewProviderRegistry creates an empty provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]ProviderConfig),
		verifiers: make(map[string]Verifier),
	}
}

// Register adds a provider and its verifier to the registry.
func (r *ProviderRegistry) Register(cfg ProviderConfig, verifier Verifier) {
	r.providers[cfg.Alias] = cfg
	r.verifiers[cfg.Alias] = verifier
}

// GetProvider returns the provider config for a given alias.
func (r *ProviderRegistry) GetProvider(alias string) (ProviderConfig, bool) {
	cfg, ok := r.providers[alias]
	return cfg, ok
}

// GetVerifier returns the verifier for a given alias.
func (r *ProviderRegistry) GetVerifier(alias string) (Verifier, bool) {
	v, ok := r.verifiers[alias]
	return v, ok
}

// VerifyTokenForProvider verifies an ID token using the provider's verifier.
func (r *ProviderRegistry) VerifyTokenForProvider(alias, token string) (*Principal, error) {
	verifier, ok := r.GetVerifier(alias)
	if !ok {
		return nil, ErrUnknownProvider
	}
	return verifier.VerifyIDToken(token)
}

// oidcHeader is the JWT header for OIDC ID tokens.
type oidcHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func parseOIDCToken(token string) (*oidcHeader, []byte, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("invalid token format")
	}
	signingInput := parts[0] + "." + parts[1]

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decode header: %w", err)
	}
	var header oidcHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", nil, fmt.Errorf("unmarshal header: %w", err)
	}

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decode claims: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decode signature: %w", err)
	}

	return &header, claims, signingInput, sig, nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
