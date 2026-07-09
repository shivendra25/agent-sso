// Package jwt provides Agent Identity Token (AIT) and JIT token structures,
// claim mapping, signing, and verification.
//
// The AIT is a RFC 9068-compliant JWT access token issued by the aIdP.
// The JIT is a downstream token issued via RFC 8693 token exchange.
package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
)

var (
	ErrInvalidTokenFormat = errors.New("jwt: invalid token format")
	ErrInvalidSignature   = errors.New("jwt: invalid signature")
	ErrTokenExpired       = errors.New("jwt: token expired")
	ErrTokenNotYetValid   = errors.New("jwt: token not yet valid")
	ErrAudienceMismatch   = errors.New("jwt: audience mismatch")
	ErrIssuerMismatch     = errors.New("jwt: issuer mismatch")
)

const (
	TokenTypeAIT = "at+jwt"

	// Meta-scopes for AIT.
	ScopeAgentAttest   = "agent:attest"
	ScopeToolsExchange = "tools:exchange"
)

// ActorClaim implements the RFC 8693 §4.3 `act` claim, representing the
// delegated-from principal (the human the agent acts on behalf of).
type ActorClaim struct {
	Sub          string `json:"sub"`
	Iss          string `json:"iss"`
	DelegationID string `json:"delegation_id,omitempty"`
}

// AITClaims defines the full claim dictionary for the Agent Identity Token
// per RFC 9068 §2.2 + AgentSSO extension claims (02-ait-spec.md).
type AITClaims struct {
	// Standard JWT claims (RFC 9068 §2.2)
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Nbf      int64  `json:"nbf"`
	JTI      string `json:"jti"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`

	// Delegation chain (RFC 8693 §4.3)
	Act *ActorClaim `json:"act,omitempty"`

	// AgentSSO extension claims
	CodebaseHash   string `json:"cnp"`
	RuntimeHash    string `json:"rtm"`
	SessionID      string `json:"ses"`
	AttestationJTI string `json:"att_jti"`
	TenantID       string `json:"tenant"`
}

// JITClaims defines claims for the downstream Just-In-Time token issued
// via RFC 8693 token exchange.
type JITClaims struct {
	// Standard
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	JTI      string `json:"jti"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`

	// Delegation chain (inherited from AIT)
	Act *ActorClaim `json:"act,omitempty"`

	// AgentSSO tracking
	SessionID string `json:"ses"`
	TenantID  string `json:"tenant"`
	ParentJTI string `json:"ait_jti"`
}

// Header is the JWT header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Signer signs JWTs using the active key.
type Signer struct {
	keyPair *crypto.KeyPair
}

// NewSigner creates a signer from a key pair.
func NewSigner(kp *crypto.KeyPair) *Signer {
	return &Signer{keyPair: kp}
}

// CurrentKeyID returns the key ID of the signing key.
func (s *Signer) CurrentKeyID() crypto.KeyID {
	return s.keyPair.KeyID
}

// SignAIT signs an AIT and returns the compact JWT serialization.
func (s *Signer) SignAIT(claims *AITClaims) (string, error) {
	header := Header{
		Alg: "ES256",
		Typ: TokenTypeAIT,
		Kid: string(s.keyPair.KeyID),
	}
	return s.sign(header, claims)
}

// SignJIT signs a JIT token and returns the compact JWT serialization.
func (s *Signer) SignJIT(claims *JITClaims) (string, error) {
	header := Header{
		Alg: "ES256",
		Typ: TokenTypeAIT,
		Kid: string(s.keyPair.KeyID),
	}
	return s.sign(header, claims)
}

func (s *Signer) sign(header Header, claims interface{}) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig, err := ecdsa.SignASN1(rand.Reader, s.keyPair.Private, crypto.HashSHA256([]byte(signingInput)))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verifier verifies JWT signatures using a set of trusted public keys.
type Verifier struct {
	keys map[crypto.KeyID]*ecdsa.PublicKey
}

// NewVerifier creates a verifier from a key map (key ID → public key).
func NewVerifier(keys map[crypto.KeyID]*ecdsa.PublicKey) *Verifier {
	return &Verifier{keys: keys}
}

// VerifyAIT parses and verifies an AIT JWT, returning the claims.
func (v *Verifier) VerifyAIT(token string) (*AITClaims, error) {
	header, claims, signingInput, sig, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	if header.Typ != TokenTypeAIT {
		return nil, fmt.Errorf("jwt: unexpected token type %q, expected %q", header.Typ, TokenTypeAIT)
	}

	pubKey, ok := v.keys[crypto.KeyID(header.Kid)]
	if !ok {
		return nil, fmt.Errorf("jwt: unknown key ID %q", header.Kid)
	}

	if !ecdsa.VerifyASN1(pubKey, crypto.HashSHA256([]byte(signingInput)), sig) {
		return nil, ErrInvalidSignature
	}

	var ait AITClaims
	if err := json.Unmarshal(claims, &ait); err != nil {
		return nil, fmt.Errorf("jwt: unmarshal AIT claims: %w", err)
	}
	return &ait, nil
}

// VerifyJIT parses and verifies a JIT JWT, returning the claims.
func (v *Verifier) VerifyJIT(token string) (*JITClaims, error) {
	header, claims, signingInput, sig, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	pubKey, ok := v.keys[crypto.KeyID(header.Kid)]
	if !ok {
		return nil, fmt.Errorf("jwt: unknown key ID %q", header.Kid)
	}

	if !ecdsa.VerifyASN1(pubKey, crypto.HashSHA256([]byte(signingInput)), sig) {
		return nil, ErrInvalidSignature
	}

	var jit JITClaims
	if err := json.Unmarshal(claims, &jit); err != nil {
		return nil, fmt.Errorf("jwt: unmarshal JIT claims: %w", err)
	}
	return &jit, nil
}

// Validate checks the temporal and audience constraints of an AIT.
func (a *AITClaims) Validate(expectedIssuer, expectedAudience string) error {
	if a.Issuer != expectedIssuer {
		return ErrIssuerMismatch
	}
	if a.Audience != expectedAudience {
		return ErrAudienceMismatch
	}
	now := time.Now().Unix()
	if a.Exp < now {
		return ErrTokenExpired
	}
	if a.Nbf > now {
		return ErrTokenNotYetValid
	}
	if a.Act == nil {
		return errors.New("jwt: AIT missing required delegation act claim")
	}
	return nil
}

// HasScope checks if the token claims include the given scope.
func (a *AITClaims) HasScope(scope string) bool {
	for _, s := range strings.Fields(a.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}

func parseToken(token string) (*Header, []byte, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, ErrInvalidTokenFormat
	}
	signingInput := parts[0] + "." + parts[1]

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("jwt: decode header: %w", err)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", nil, fmt.Errorf("jwt: unmarshal header: %w", err)
	}

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("jwt: decode claims: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("jwt: decode signature: %w", err)
	}

	return &header, claims, signingInput, sig, nil
}
