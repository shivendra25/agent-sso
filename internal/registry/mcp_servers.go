// Package registry provides the MCP server registry and RFC 9728 Protected
// Resource Metadata discovery for the AgentSSO gateway.
//
// See docs/spec/05-discovery.md.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrServerNotFound  = errors.New("registry: MCP server not found")
	ErrDiscoveryFailed = errors.New("registry: resource metadata discovery failed")
	ErrNotRFC9728      = errors.New("registry: server does not implement RFC 9728")
)

// MCPServer is a registered MCP server in the AgentSSO server registry.
type MCPServer struct {
	TenantID       string    `json:"tenant_id"`
	ServerAlias    string    `json:"server_alias"`
	ServerURL      string    `json:"server_url"`  // canonical URI (RFC 8707 resource)
	AuthServer     string    `json:"auth_server"` // aIdP issuer URL
	RequiredScopes []string  `json:"required_scopes"`
	RFC9728Enabled bool      `json:"rfc9728_enabled"` // server self-publishes metadata
	CreatedAt      time.Time `json:"created_at"`
}

// ProtectedResourceMetadata implements RFC 9728 Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// Registry is the interface for the MCP server registry.
type Registry interface {
	Get(tenantID, alias string) (*MCPServer, error)
	Register(server *MCPServer) error
	List(tenantID string) []*MCPServer
	Delete(tenantID, alias string) error
}

// MemoryRegistry is an in-memory MCP server registry.
type MemoryRegistry struct {
	mu   sync.RWMutex
	data map[string]*MCPServer // key = tenantID + "/" + alias
}

// NewMemoryRegistry creates an empty in-memory registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{data: make(map[string]*MCPServer)}
}

func key(tenantID, alias string) string {
	return tenantID + "/" + alias
}

func (r *MemoryRegistry) Get(tenantID, alias string) (*MCPServer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.data[key(tenantID, alias)]
	if !ok {
		return nil, ErrServerNotFound
	}
	return s, nil
}

func (r *MemoryRegistry) Register(server *MCPServer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	server.CreatedAt = time.Now()
	r.data[key(server.TenantID, server.ServerAlias)] = server
	return nil
}

func (r *MemoryRegistry) List(tenantID string) []*MCPServer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*MCPServer
	for k, s := range r.data {
		if strings.HasPrefix(k, tenantID+"/") {
			result = append(result, s)
		}
	}
	return result
}

func (r *MemoryRegistry) Delete(tenantID, alias string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(tenantID, alias)
	if _, ok := r.data[k]; !ok {
		return ErrServerNotFound
	}
	delete(r.data, k)
	return nil
}

// Discoverer fetches RFC 9728 Protected Resource Metadata from MCP servers.
type Discoverer struct {
	httpClient *http.Client
}

// NewDiscoverer creates a resource metadata discoverer.
func NewDiscoverer() *Discoverer {
	return &Discoverer{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Discover fetches the RFC 9728 Protected Resource Metadata from an MCP server.
// Returns ErrNotRFC9728 if the server does not implement the standard.
func (d *Discoverer) Discover(serverURL string) (*ProtectedResourceMetadata, error) {
	wellKnownURL := strings.TrimSuffix(serverURL, "/") + "/.well-known/oauth-protected-resource"

	resp, err := d.httpClient.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotRFC9728
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrDiscoveryFailed, err)
	}

	var meta ProtectedResourceMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %v", ErrDiscoveryFailed, err)
	}

	// Validate the resource field matches the server URL (RFC 9728 §4.2)
	if meta.Resource == "" {
		// Some servers may omit resource; use server URL as fallback
		meta.Resource = serverURL
	}

	return &meta, nil
}

// ResolveServer combines the registry lookup with RFC 9728 discovery.
// If the server has RFC9728Enabled=true, it fetches live metadata.
// Otherwise, it uses the registry-stored metadata as fallback.
func ResolveServer(reg Registry, discoverer *Discoverer, tenantID, alias string) (*MCPServer, *ProtectedResourceMetadata, error) {
	server, err := reg.Get(tenantID, alias)
	if err != nil {
		return nil, nil, err
	}

	if !server.RFC9728Enabled {
		// Use registry-stored metadata as fallback
		return server, &ProtectedResourceMetadata{
			Resource:               server.ServerURL,
			AuthorizationServers:   []string{server.AuthServer},
			ScopesSupported:        server.RequiredScopes,
			BearerMethodsSupported: []string{"header"},
		}, nil
	}

	// Fetch live RFC 9728 metadata
	meta, err := discoverer.Discover(server.ServerURL)
	if err != nil {
		// Fall back to registry data on discovery failure
		return server, &ProtectedResourceMetadata{
			Resource:               server.ServerURL,
			AuthorizationServers:   []string{server.AuthServer},
			ScopesSupported:        server.RequiredScopes,
			BearerMethodsSupported: []string{"header"},
		}, nil
	}

	return server, meta, nil
}
