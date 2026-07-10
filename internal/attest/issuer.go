// Package attest handles the AIT issuance flow: accepts a signed attestation
// document + an OIDC ID token (establishing the human principal), verifies
// both, and issues an Agent Identity Token (AIT).
//
// See docs/spec/02-ait-spec.md and 03-attestation-spec.md.
package attest

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/shivendra25/agent-sso/internal/attestation"
	"github.com/shivendra25/agent-sso/internal/idp"
	"github.com/shivendra25/agent-sso/internal/jwt"
)

var (
	ErrMissingAttestation = errors.New("attest: attestation document required")
	ErrMissingIDToken     = errors.New("attest: OIDC ID token required")
	ErrAttestationFailed  = errors.New("attest: attestation verification failed")
	ErrPrincipalFailed    = errors.New("attest: principal verification failed")
	ErrSessionExpired     = errors.New("attest: principal session expired")
)

// Request is the input to the AIT issuance endpoint.
type Request struct {
	// SignedAttestation is the compact-serialized attestation document
	// from the agent runtime.
	SignedAttestation string `json:"signed_attestation"`

	// OIDCIDToken is the raw OIDC ID token from the corporate IdP,
	// establishing the human principal this agent acts on behalf of.
	OIDCIDToken string `json:"oidc_id_token"`

	// OIDCProviderAlias identifies which IdP provider to use
	// (e.g., "okta", "google").
	OIDCProviderAlias string `json:"oidc_provider_alias"`

	// SessionID is an optional agent-provided session identifier.
	// If empty, a new one is generated.
	SessionID string `json:"session_id,omitempty"`

	// TenantID is the AgentSSO tenant this agent belongs to.
	TenantID string `json:"tenant_id"`
}

// Response is the output of the AIT issuance endpoint.
type Response struct {
	AIT          string `json:"ait"`
	ExpiresAt    int64  `json:"expires_at"`
	IssuedAt     int64  `json:"issued_at"`
	JTI          string `json:"jti"`
	AgentID      string `json:"agent_id"`
	PrincipalSub string `json:"principal_sub"`
}

// Issuer coordinates the AIT issuance flow.
type Issuer struct {
	attestationVerifier *attestation.Verifier
	providerRegistry    *idp.ProviderRegistry
	jwtSigner           *jwt.Signer
	issuerURL           string
	tokenEndpoint       string
	aitTTL              time.Duration
}

// NewIssuer creates a new AIT issuer.
func NewIssuer(
	attestVerifier *attestation.Verifier,
	providers *idp.ProviderRegistry,
	signer *jwt.Signer,
	issuerURL string,
	tokenEndpoint string,
	aitTTL time.Duration,
) *Issuer {
	return &Issuer{
		attestationVerifier: attestVerifier,
		providerRegistry:    providers,
		jwtSigner:           signer,
		issuerURL:           issuerURL,
		tokenEndpoint:       tokenEndpoint,
		aitTTL:              aitTTL,
	}
}

// Issue validates the attestation + OIDC ID token and issues an AIT.
func (i *Issuer) Issue(req *Request) (*Response, error) {
	if req.SignedAttestation == "" {
		return nil, ErrMissingAttestation
	}
	if req.OIDCIDToken == "" || req.OIDCProviderAlias == "" {
		return nil, ErrMissingIDToken
	}

	// Step 1: Verify the attestation document.
	signedAtt, err := attestation.ParseSignedAttestation(req.SignedAttestation)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationFailed, err)
	}
	attResult, err := i.attestationVerifier.Verify(signedAtt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationFailed, err)
	}

	// Step 2: Verify the OIDC ID token to establish the human principal.
	principal, err := i.providerRegistry.VerifyTokenForProvider(req.OIDCProviderAlias, req.OIDCIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrincipalFailed, err)
	}
	if principal.IsExpired() {
		return nil, ErrSessionExpired
	}

	// Step 3: Build AIT claims.
	now := time.Now()
	exp := now.Add(i.aitTTL)
	jti := "ait_" + uuid.NewString()
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = "ses_" + uuid.NewString()
	}

	claims := &jwt.AITClaims{
		Issuer:   i.issuerURL,
		Subject:  attResult.AgentID,
		Audience: i.tokenEndpoint,
		Exp:      exp.Unix(),
		Iat:      now.Unix(),
		Nbf:      now.Unix(),
		JTI:      jti,
		ClientID: attResult.HostID,
		Scope:    jwt.ScopeAgentAttest + " " + jwt.ScopeToolsExchange,
		Act: &jwt.ActorClaim{
			Sub:          principal.ActorSubject(req.OIDCProviderAlias),
			Iss:          principal.Issuer,
			DelegationID: "del_" + uuid.NewString(),
		},
		CodebaseHash:   attResult.CodebaseHash,
		RuntimeHash:    attResult.RuntimeHash,
		SessionID:      sessionID,
		AttestationJTI: attResult.JTI,
		TenantID:       req.TenantID,
	}

	// Step 4: Sign the AIT.
	token, err := i.jwtSigner.SignAIT(claims)
	if err != nil {
		return nil, fmt.Errorf("attest: sign AIT: %w", err)
	}

	return &Response{
		AIT:          token,
		ExpiresAt:    exp.Unix(),
		IssuedAt:     now.Unix(),
		JTI:          jti,
		AgentID:      attResult.AgentID,
		PrincipalSub: principal.Subject,
	}, nil
}
