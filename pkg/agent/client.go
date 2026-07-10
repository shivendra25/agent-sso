// Package agent provides the AgentSSO Agent SDK for Go.
//
// The SDK allows agent runtimes (e.g., opencode) to:
//   - Attest and obtain an AIT (Agent Identity Token)
//   - Call MCP servers through the Credential Boundary Gateway
//   - Ensure credentials never enter LLM context
//
// Usage:
//
//	client := agent.New(agent.Config{
//	    AIdPURL:     "https://aidp.agentsso.io",
//	    GatewayURL:  "https://gateway.agentsso.io",
//	    TenantID:    "tnt_acme",
//	})
//	ait, err := client.Attest(ctx, attestationDoc, oidcIDToken, "okta")
//	resp, err := client.Call(ctx, ait, "github", "v1/prs/42", "GET", nil)
//
// The AIT is held in the client process — never passed to the LLM.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrAttestFailed  = errors.New("agent: attestation/issuance failed")
	ErrCallFailed    = errors.New("agent: tool call failed")
	ErrNoGateway     = errors.New("agent: gateway URL not configured")
	ErrNotConfigured = errors.New("agent: client not configured")
)

// Config holds the SDK configuration.
type Config struct {
	// AIdPURL is the Agent Identity Provider URL.
	AIdPURL string `json:"aidp_url"`

	// GatewayURL is the Credential Boundary Gateway URL.
	GatewayURL string `json:"gateway_url"`

	// TenantID is the AgentSSO tenant ID.
	TenantID string `json:"tenant_id"`

	// HTTPTimeout for all HTTP calls (default 30s).
	HTTPTimeout time.Duration `json:"http_timeout,omitempty"`
}

// Client is the AgentSSO agent SDK client.
type Client struct {
	config     Config
	httpClient *http.Client
}

// New creates a new agent SDK client.
func New(cfg Config) *Client {
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		config:     cfg,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// AttestRequest is the body sent to /v1/attest on the aIdP.
type AttestRequest struct {
	SignedAttestation string `json:"signed_attestation"`
	OIDCIDToken       string `json:"oidc_id_token"`
	OIDCProviderAlias string `json:"oidc_provider_alias"`
	SessionID         string `json:"session_id,omitempty"`
	TenantID          string `json:"tenant_id"`
}

// AttestResponse is the response from /v1/attest.
type AttestResponse struct {
	AIT          string `json:"ait"`
	ExpiresAt    int64  `json:"expires_at"`
	IssuedAt     int64  `json:"issued_at"`
	JTI          string `json:"jti"`
	AgentID      string `json:"agent_id"`
	PrincipalSub string `json:"principal_sub"`
}

// Attest submits the attestation document + OIDC ID token to the aIdP
// and returns the AIT. The AIT must be stored in the agent runtime process
// memory — never in LLM context.
func (c *Client) Attest(ctx context.Context, signedAttestation, oidcIDToken, providerAlias string) (*AttestResponse, error) {
	if c.config.AIdPURL == "" {
		return nil, fmt.Errorf("%w: AIdPURL not set", ErrNotConfigured)
	}

	body, _ := json.Marshal(AttestRequest{
		SignedAttestation: signedAttestation,
		OIDCIDToken:       oidcIDToken,
		OIDCProviderAlias: providerAlias,
		TenantID:          c.config.TenantID,
	})

	url := strings.TrimSuffix(c.config.AIdPURL, "/") + "/v1/attest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("agent: build attest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrAttestFailed, resp.StatusCode, respBody)
	}

	var result AttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("agent: decode attest response: %w", err)
	}

	return &result, nil
}

// CallResult is the result of a tool call through the gateway.
type CallResult struct {
	StatusCode int             `json:"status_code"`
	Body       json.RawMessage `json:"body"`
}

// Call makes a tool call through the Credential Boundary Gateway.
// The AIT is sent via the X-AIT header; the gateway injects the JIT
// out-of-band. The LLM never sees a bearer token.
func (c *Client) Call(ctx context.Context, ait, serverAlias, path, method string, body []byte) (*CallResult, error) {
	if c.config.GatewayURL == "" {
		return nil, ErrNoGateway
	}

	url := strings.TrimSuffix(c.config.GatewayURL, "/") + "/v1/call/" + serverAlias + "/" + strings.TrimPrefix(path, "/")

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("agent: build call request: %w", err)
	}
	req.Header.Set("X-AIT", ait)
	req.Header.Set("X-Session", c.config.TenantID) // simplified for v1
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallFailed, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("agent: read response: %w", err)
	}

	return &CallResult{
		StatusCode: resp.StatusCode,
		Body:       respBody,
	}, nil
}

// CallJSON is a convenience method that marshals the request body to JSON
// and unmarshals the response into the target.
func (c *Client) CallJSON(ctx context.Context, ait, serverAlias, path string, request interface{}, response interface{}) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("agent: marshal request: %w", err)
	}

	result, err := c.Call(ctx, ait, serverAlias, path, http.MethodPost, body)
	if err != nil {
		return err
	}

	if result.StatusCode >= 400 {
		return fmt.Errorf("%w: HTTP %d: %s", ErrCallFailed, result.StatusCode, result.Body)
	}

	if len(result.Body) > 0 && response != nil {
		if err := json.Unmarshal(result.Body, response); err != nil {
			return fmt.Errorf("agent: unmarshal response: %w", err)
		}
	}

	return nil
}

// GetJWKS fetches the aIdP's JWKS document for token verification.
func (c *Client) GetJWKS(ctx context.Context) ([]byte, error) {
	url := strings.TrimSuffix(c.config.AIdPURL, "/") + "/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("agent: build JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// GetASMetadata fetches the RFC 8414 Authorization Server Metadata.
func (c *Client) GetASMetadata(ctx context.Context) ([]byte, error) {
	url := strings.TrimSuffix(c.config.AIdPURL, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("agent: build metadata request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
