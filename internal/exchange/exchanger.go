// Package exchange implements RFC 8693 Token Exchange for AgentSSO.
// It accepts an AIT (subject token) + resource + scope, validates the AIT,
// runs the policy engine, and issues a short-lived, audience-bound JIT
// token carrying the inherited delegation chain.
//
// See docs/spec/04-token-exchange.md.
package exchange

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/shivendra25/agent-sso/internal/jwt"
)

var (
	ErrInvalidGrantType      = errors.New("exchange: unsupported grant_type")
	ErrMissingSubjectToken   = errors.New("exchange: subject_token required")
	ErrMissingResource       = errors.New("exchange: resource parameter required")
	ErrMissingScope          = errors.New("exchange: scope parameter required")
	ErrInvalidResource       = errors.New("exchange: invalid resource URI")
	ErrPolicyDenied          = errors.New("exchange: policy denied scope")
	ErrPolicyNarrowedToEmpty = errors.New("exchange: policy narrowed scope to empty set")
)

const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// Request is the input to the token exchange endpoint (RFC 8693 §2.1).
type Request struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	Resource           string `json:"resource"`
	Scope              string `json:"scope"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
}

// Response is the output of a successful token exchange (RFC 8693 §3.1).
type Response struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// PolicyEvaluator is the interface for the policy engine that decides
// which scopes are allowed for a given (agent, principal, resource) tuple.
// Implemented by the OPA policy engine (Brick 9).
type PolicyEvaluator interface {
	// Evaluate returns the allowed scopes (a subset of requested) or an
	// error if the request is denied entirely.
	Evaluate(agentID, principalSub, resource, requestedScope string) (allowedScope string, err error)
}

// Exchanger coordinates the token exchange flow.
type Exchanger struct {
	verifier  *jwt.Verifier
	signer    *jwt.Signer
	policy    PolicyEvaluator
	issuerURL string
	jitTTL    time.Duration
}

// NewExchanger creates a new token exchanger.
func NewExchanger(
	verifier *jwt.Verifier,
	signer *jwt.Signer,
	policy PolicyEvaluator,
	issuerURL string,
	jitTTL time.Duration,
) *Exchanger {
	return &Exchanger{
		verifier:  verifier,
		signer:    signer,
		policy:    policy,
		issuerURL: issuerURL,
		jitTTL:    jitTTL,
	}
}

// Exchange validates the AIT and issues a JIT token.
func (e *Exchanger) Exchange(req *Request) (*Response, error) {
	// Step 1: Validate grant type
	if req.GrantType != GrantTypeTokenExchange {
		return nil, ErrInvalidGrantType
	}
	if req.SubjectToken == "" {
		return nil, ErrMissingSubjectToken
	}
	if req.Resource == "" {
		return nil, ErrMissingResource
	}
	if req.Scope == "" {
		return nil, ErrMissingScope
	}

	// Step 2: Validate resource URI format (RFC 8707 §2)
	if !isValidResourceURI(req.Resource) {
		return nil, ErrInvalidResource
	}

	// Step 3: Verify the AIT (subject token)
	ait, err := e.verifier.VerifyAIT(req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("exchange: verify AIT: %w", err)
	}

	// Step 4: Validate AIT temporal + audience constraints
	aitAudience := e.issuerURL + "/oauth/token"
	if err := ait.Validate(e.issuerURL, aitAudience); err != nil {
		return nil, fmt.Errorf("exchange: AIT validation: %w", err)
	}

	// Step 5: Verify AIT has tools:exchange scope
	if !ait.HasScope(jwt.ScopeToolsExchange) {
		return nil, fmt.Errorf("exchange: AIT lacks tools:exchange scope")
	}

	// Step 6: Policy check — determine allowed scopes
	allowedScope, err := e.policy.Evaluate(ait.Subject, ait.Act.Sub, req.Resource, req.Scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if allowedScope == "" {
		return nil, ErrPolicyNarrowedToEmpty
	}

	// Step 7: Issue JIT token
	now := time.Now()
	exp := now.Add(e.jitTTL)
	jti := "jit_" + uuid.NewString()

	jit := &jwt.JITClaims{
		Issuer:    e.issuerURL,
		Subject:   ait.Subject,
		Audience:  req.Resource,
		Exp:       exp.Unix(),
		Iat:       now.Unix(),
		JTI:       jti,
		ClientID:  ait.ClientID,
		Scope:     allowedScope,
		Act:       ait.Act, // Inherited verbatim — delegation chain preserved
		SessionID: ait.SessionID,
		TenantID:  ait.TenantID,
		ParentJTI: ait.JTI,
	}

	token, err := e.signer.SignJIT(jit)
	if err != nil {
		return nil, fmt.Errorf("exchange: sign JIT: %w", err)
	}

	return &Response{
		AccessToken:     token,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(e.jitTTL.Seconds()),
		Scope:           allowedScope,
	}, nil
}

// isValidResourceURI validates a resource parameter per RFC 8707 §2.
// Must be an absolute URI with scheme (http or https) and host, no fragment.
// In production, all resource URIs MUST be https. http is allowed for
// localhost and test environments only.
func isValidResourceURI(uri string) bool {
	if uri == "" {
		return false
	}
	if strings.Contains(uri, "#") {
		return false
	}
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "http://") {
		return false
	}
	// Must have a host
	rest := strings.TrimPrefix(uri, "https://")
	rest = strings.TrimPrefix(rest, "http://")
	if rest == "" {
		return false
	}
	host := rest
	if idx := strings.Index(rest, "/"); idx >= 0 {
		host = rest[:idx]
	}
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		// Has port — validate it's numeric
		portPart := host[strings.Index(host, ":")+1:]
		if portPart == "" {
			return false
		}
		for _, c := range portPart {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
