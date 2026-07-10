package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMemoryRegistryCRUD(t *testing.T) {
	reg := NewMemoryRegistry()

	srv := &MCPServer{
		TenantID:       "tnt_test",
		ServerAlias:    "github",
		ServerURL:      "https://mcp.github.example.com",
		AuthServer:     "https://aidp.test",
		RequiredScopes: []string{"github:prs:read", "github:prs:write"},
		RFC9728Enabled: false,
	}
	if err := reg.Register(srv); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := reg.Get("tnt_test", "github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ServerURL != "https://mcp.github.example.com" {
		t.Errorf("ServerURL = %q", got.ServerURL)
	}
	if got.AuthServer != "https://aidp.test" {
		t.Errorf("AuthServer = %q", got.AuthServer)
	}
	if len(got.RequiredScopes) != 2 {
		t.Errorf("RequiredScopes len = %d", len(got.RequiredScopes))
	}

	list := reg.List("tnt_test")
	if len(list) != 1 {
		t.Errorf("List len = %d, want 1", len(list))
	}

	listOther := reg.List("tnt_other")
	if len(listOther) != 0 {
		t.Errorf("List other tenant len = %d, want 0", len(listOther))
	}

	if err := reg.Delete("tnt_test", "github"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := reg.Get("tnt_test", "github"); err == nil {
		t.Error("expected error after delete")
	}
}

func TestMemoryRegistryNotFound(t *testing.T) {
	reg := NewMemoryRegistry()
	_, err := reg.Get("tnt_test", "nonexistent")
	if err != ErrServerNotFound {
		t.Errorf("expected ErrServerNotFound, got %v", err)
	}
}

func TestDiscovererRFC9728Success(t *testing.T) {
	meta := ProtectedResourceMetadata{
		Resource:               "https://mcp.github.example.com",
		AuthorizationServers:   []string{"https://aidp.test"},
		ScopesSupported:        []string{"github:prs:read"},
		BearerMethodsSupported: []string{"header"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()

	d := NewDiscoverer()
	result, err := d.Discover(srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if result.Resource != "https://mcp.github.example.com" {
		t.Errorf("Resource = %q", result.Resource)
	}
	if len(result.AuthorizationServers) != 1 || result.AuthorizationServers[0] != "https://aidp.test" {
		t.Errorf("AuthorizationServers = %v", result.AuthorizationServers)
	}
	if len(result.ScopesSupported) != 1 || result.ScopesSupported[0] != "github:prs:read" {
		t.Errorf("ScopesSupported = %v", result.ScopesSupported)
	}
}

func TestDiscovererNotRFC9728(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d := NewDiscoverer()
	_, err := d.Discover(srv.URL)
	if err != ErrNotRFC9728 {
		t.Errorf("expected ErrNotRFC9728, got %v", err)
	}
}

func TestDiscovererServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := NewDiscoverer()
	_, err := d.Discover(srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestResolveServerRegistryFallback(t *testing.T) {
	reg := NewMemoryRegistry()
	reg.Register(&MCPServer{
		TenantID:       "tnt_test",
		ServerAlias:    "github",
		ServerURL:      "https://mcp.github.example.com",
		AuthServer:     "https://aidp.test",
		RequiredScopes: []string{"github:prs:read"},
		RFC9728Enabled: false, // use registry fallback
	})

	d := NewDiscoverer()
	server, meta, err := ResolveServer(reg, d, "tnt_test", "github")
	if err != nil {
		t.Fatalf("ResolveServer: %v", err)
	}
	if server.ServerAlias != "github" {
		t.Errorf("ServerAlias = %q", server.ServerAlias)
	}
	if meta.Resource != "https://mcp.github.example.com" {
		t.Errorf("Resource = %q", meta.Resource)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://aidp.test" {
		t.Errorf("AuthorizationServers = %v", meta.AuthorizationServers)
	}
}

func TestResolveServerLiveDiscovery(t *testing.T) {
	reg := NewMemoryRegistry()
	// Use a non-routable URL to trigger fallback
	reg.Register(&MCPServer{
		TenantID:       "tnt_test",
		ServerAlias:    "github",
		ServerURL:      "https://mcp.github.example.com",
		AuthServer:     "https://aidp.test",
		RequiredScopes: []string{"github:prs:read"},
		RFC9728Enabled: true, // attempt live discovery (will fail, fall back)
	})

	d := NewDiscoverer()
	server, meta, err := ResolveServer(reg, d, "tnt_test", "github")
	if err != nil {
		t.Fatalf("ResolveServer: %v", err)
	}
	if server == nil || meta == nil {
		t.Fatal("server or meta is nil")
	}
	// Should fall back to registry data
	if meta.Resource != "https://mcp.github.example.com" {
		t.Errorf("Resource = %q", meta.Resource)
	}
}

func TestResolveServerNotFound(t *testing.T) {
	reg := NewMemoryRegistry()
	d := NewDiscoverer()
	_, _, err := ResolveServer(reg, d, "tnt_test", "nonexistent")
	if err != ErrServerNotFound {
		t.Errorf("expected ErrServerNotFound, got %v", err)
	}
}
