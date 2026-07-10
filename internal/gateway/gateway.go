// Package gateway implements the AgentSSO Credential Boundary (Tool Gateway).
//
// The gateway is the defensive layer ensuring credentials never enter the
// LLM context. The agent sends tool calls to the gateway; the gateway
// exchanges the AIT for a JIT, injects Authorization: Bearer out-of-band,
// and forwards to the MCP server. Only the response body is returned to
// the agent — no tokens, no auth headers.
//
// See docs/spec/06-gateway.md.
package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shivendra25/agent-sso/internal/exchange"
	"github.com/shivendra25/agent-sso/internal/jwt"
	"github.com/shivendra25/agent-sso/internal/registry"
)

var (
	ErrNoAIT           = errors.New("gateway: AIT required in X-AIT header")
	ErrNoSession       = errors.New("gateway: session ID required in X-Session header")
	ErrServerNotFound  = errors.New("gateway: server alias not found in registry")
	ErrTokenExchange   = errors.New("gateway: token exchange failed")
	ErrUpstreamError   = errors.New("gateway: upstream MCP server error")
	ErrInvalidResponse = errors.New("gateway: invalid upstream response")
)

// Config holds the gateway configuration.
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	TokenTTL     time.Duration // JIT cache TTL
}

// DefaultConfig returns a development gateway configuration.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8444",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		TokenTTL:     5 * time.Minute,
	}
}

// Gateway is the Credential Boundary HTTP reverse proxy.
type Gateway struct {
	config      Config
	exchanger   *exchange.Exchanger
	registry    registry.Registry
	discoverer  *registry.Discoverer
	jwtVerifier *jwt.Verifier
	tokenCache  *TokenCache
	httpClient  *http.Client
	logger      *slog.Logger
}

// New creates a new gateway instance.
func New(
	cfg Config,
	ex *exchange.Exchanger,
	reg registry.Registry,
	verifier *jwt.Verifier,
	logger *slog.Logger,
) *Gateway {
	return &Gateway{
		config:      cfg,
		exchanger:   ex,
		registry:    reg,
		discoverer:  registry.NewDiscoverer(),
		jwtVerifier: verifier,
		tokenCache:  NewTokenCache(cfg.TokenTTL),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		logger:      logger,
	}
}

// CallRequest is the input for a tool call through the gateway.
type CallRequest struct {
	AIT         string            `json:"-"` // from X-AIT header
	SessionID   string            `json:"-"` // from X-Session header
	ServerAlias string            `json:"server_alias"`
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Body        json.RawMessage   `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// CallResponse is the result of a tool call.
type CallResponse struct {
	StatusCode int               `json:"status_code"`
	Body       json.RawMessage   `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// Call forwards a tool call to the target MCP server with an injected JIT.
// This is the core credential-boundary function: the agent never sees the
// bearer token, only the response data.
func (g *Gateway) Call(ctx context.Context, req *CallRequest) (*CallResponse, error) {
	if req.AIT == "" {
		return nil, ErrNoAIT
	}
	if req.SessionID == "" {
		return nil, ErrNoSession
	}

	// Step 1: Look up the MCP server in the registry
	// Extract tenant from the AIT to scope the registry lookup
	tenantID, err := g.extractTenantFromAIT(req.AIT)
	if err != nil {
		return nil, fmt.Errorf("gateway: extract tenant: %w", err)
	}
	server, _, err := registry.ResolveServer(g.registry, g.discoverer, tenantID, req.ServerAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServerNotFound, err)
	}

	// Step 2: Get or mint a JIT for this server (out-of-context exchange)
	jit, err := g.getJIT(ctx, req.AIT, server.ServerURL, req.ServerAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Step 3: Build the upstream request
	upstreamURL := strings.TrimSuffix(server.ServerURL, "/") + "/" + strings.TrimPrefix(req.Path, "/")
	method := req.Method
	if method == "" {
		method = http.MethodPost
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, method, upstreamURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("gateway: build upstream request: %w", err)
	}

	// Step 4: Inject Authorization out-of-band — LLM never sees this
	upstreamReq.Header.Set("Authorization", "Bearer "+jit)
	upstreamReq.Header.Set("Content-Type", "application/json")
	for k, v := range req.Headers {
		// Never allow caller to override Authorization
		if strings.EqualFold(k, "authorization") {
			continue
		}
		upstreamReq.Header.Set(k, v)
	}

	// Step 5: Execute the upstream call
	resp, err := g.httpClient.Do(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamError, err)
	}
	defer resp.Body.Close()

	// Step 6: Read and return only the body — strip all auth headers
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrInvalidResponse, err)
	}

	// Filter headers: strip WWW-Authenticate, Set-Cookie, Authorization
	filteredHeaders := make(map[string]string)
	for k, v := range resp.Header {
		lowerK := strings.ToLower(k)
		if lowerK == "www-authenticate" || lowerK == "set-cookie" || lowerK == "authorization" {
			continue
		}
		if len(v) > 0 {
			filteredHeaders[k] = v[0]
		}
	}

	g.logger.Info("tool call",
		"server", req.ServerAlias,
		"path", req.Path,
		"method", method,
		"status", resp.StatusCode,
		"session", req.SessionID,
	)

	return &CallResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    filteredHeaders,
	}, nil
}

// getJIT retrieves a cached JIT or exchanges the AIT for a new one.
// Cache key: (agent_id, server_url, scope_set)
func (g *Gateway) getJIT(ctx context.Context, ait, resource, serverAlias string) (string, error) {
	// For v1, we always exchange. Token caching will be enhanced in Brick 11.
	cacheKey := ait + ":" + resource
	if cached, ok := g.tokenCache.Get(cacheKey); ok {
		return cached, nil
	}

	resp, err := g.exchanger.Exchange(&exchange.Request{
		GrantType:        exchange.GrantTypeTokenExchange,
		SubjectToken:     ait,
		SubjectTokenType: exchange.TokenTypeAccessToken,
		Resource:         resource,
		Scope:            inferScopesForServer(serverAlias),
	})
	if err != nil {
		return "", err
	}

	g.tokenCache.Set(cacheKey, resp.AccessToken)
	return resp.AccessToken, nil
}

// inferScopesForServer returns a scope string for the given server alias.
// In v1, we request a generic read scope; policy engine will narrow it.
// v2 will have explicit scope negotiation.
func inferScopesForServer(alias string) string {
	return alias + ":read"
}

// extractTenantFromAIT decodes the AIT to get the tenant ID without
// verifying the signature (the exchanger will verify it).
func (g *Gateway) extractTenantFromAIT(ait string) (string, error) {
	// Quick decode of JWT payload without verification
	parts := strings.Split(ait, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	tenant, ok := claims["tenant"]
	if !ok {
		return "default", nil
	}
	s, ok := tenant.(string)
	if !ok {
		return "default", nil
	}
	return s, nil
}

// --- TokenCache ---

// TokenCache holds short-lived JIT tokens keyed by (AIT, resource).
type TokenCache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	items map[string]cacheItem
}

type cacheItem struct {
	token     string
	expiresAt time.Time
}

func NewTokenCache(ttl time.Duration) *TokenCache {
	return &TokenCache{ttl: ttl, items: make(map[string]cacheItem)}
}

func (c *TokenCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return "", false
	}
	return item.token, true
}

func (c *TokenCache) Set(key, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cacheItem{
		token:     token,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *TokenCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]cacheItem)
}

// --- HTTP server helpers ---

// ServeHTTP implements http.Handler for the gateway.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle healthz first (any method)
	if r.URL.Path == "/healthz" {
		writeGatewayJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	if r.Method != http.MethodPost {
		writeGatewayError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	ait := r.Header.Get("X-AIT")
	sessionID := r.Header.Get("X-Session")

	// Parse path: /v1/call/{server_alias}/{path...}
	if !strings.HasPrefix(r.URL.Path, "/v1/call/") {
		writeGatewayError(w, http.StatusNotFound, "not_found", "unknown path")
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/v1/call/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 1 {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "missing server alias")
		return
	}
	serverAlias := parts[0]
	path := ""
	if len(parts) > 1 {
		path = parts[1]
	}

	body, _ := io.ReadAll(r.Body)

	resp, err := g.Call(r.Context(), &CallRequest{
		AIT:         ait,
		SessionID:   sessionID,
		ServerAlias: serverAlias,
		Path:        path,
		Method:      r.Method,
		Body:        body,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNoAIT):
			writeGatewayError(w, http.StatusUnauthorized, "ait_required", err.Error())
		case errors.Is(err, ErrNoSession):
			writeGatewayError(w, http.StatusBadRequest, "session_required", err.Error())
		case errors.Is(err, ErrServerNotFound):
			writeGatewayError(w, http.StatusNotFound, "server_not_found", err.Error())
		case errors.Is(err, ErrTokenExchange):
			writeGatewayError(w, http.StatusUnauthorized, "token_exchange_failed", err.Error())
		case errors.Is(err, ErrUpstreamError):
			writeGatewayError(w, http.StatusBadGateway, "upstream_error", err.Error())
		default:
			writeGatewayError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}

	writeGatewayJSON(w, resp.StatusCode, resp.Body)
}

func writeGatewayJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	switch v := data.(type) {
	case json.RawMessage:
		w.Write(v)
	default:
		json.NewEncoder(w).Encode(v)
	}
}

func writeGatewayError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
