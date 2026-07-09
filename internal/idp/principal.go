// Package idp implements OIDC inbound federation for establishing human
// principals. The aIdP accepts OIDC ID tokens from corporate IdPs (Okta,
// Entra ID, Google) and extracts the human principal identity that becomes
// the delegation chain root in every AIT.
//
// See docs/spec/01-architecture.md Step 1 (Human login).
package idp

import (
	"errors"
	"time"
)

var (
	ErrInvalidIDToken    = errors.New("idp: invalid ID token")
	ErrUnknownProvider   = errors.New("idp: unknown provider")
	ErrPrincipalMismatch = errors.New("idp: principal mismatch")
)

// Principal represents a verified human identity established via OIDC.
// This is the `act.sub` delegation chain root in every AIT.
type Principal struct {
	// Subject is the OIDC `sub` claim from the IdP (globally unique per IdP).
	Subject string `json:"subject"`

	// Issuer is the OIDC `iss` claim (the IdP's issuer URL).
	Issuer string `json:"issuer"`

	// Email is the human's email (from `email` claim, if present).
	Email string `json:"email,omitempty"`

	// Name is the human's display name (from `name` claim, if present).
	Name string `json:"name,omitempty"`

	// Groups are the human's group memberships (from `groups` claim).
	Groups []string `json:"groups,omitempty"`

	// TenantID is the AgentSSO tenant this principal belongs to.
	TenantID string `json:"tenant_id,omitempty"`

	// EstablishedAt is when this principal was verified.
	EstablishedAt time.Time `json:"established_at"`

	// ExpiresAt is when the principal's session expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired reports whether the principal's session has expired.
func (p *Principal) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// ActorSubject returns the canonical string for the AIT `act.sub` claim.
// Format: "oidc:<provider_alias>:<oidc_sub>"
func (p *Principal) ActorSubject(providerAlias string) string {
	return "oidc:" + providerAlias + ":" + p.Subject
}

// ProviderConfig holds configuration for an OIDC provider.
type ProviderConfig struct {
	// Alias is the short name for this provider (e.g., "okta", "google").
	Alias string `json:"alias"`

	// Issuer is the OIDC issuer URL (e.g., "https://acme.okta.com").
	Issuer string `json:"issuer"`

	// ClientID is the OAuth client ID registered with this provider.
	ClientID string `json:"client_id"`

	// ClientSecret is the OAuth client secret (for confidential clients).
	ClientSecret string `json:"client_secret,omitempty"`

	// RedirectURL is the callback URL for this aIdP instance.
	RedirectURL string `json:"redirect_url"`

	// Scopes are the OIDC scopes to request (typically "openid email profile").
	Scopes []string `json:"scopes"`
}
