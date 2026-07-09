package attestation

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// Registry is the interface for looking up trusted agent registrations.
type Registry interface {
	// Get retrieves the agent registration for a given host ID.
	Get(hostID string) (*AgentRegistration, error)
	// Register adds or updates an agent registration.
	Register(reg *AgentRegistration) error
	// List returns all registered agents.
	List() []*AgentRegistration
}

// AgentRegistration defines a trusted agent runtime in the registry.
type AgentRegistration struct {
	AgentID          string
	HostID           string
	HostPublicKey    ed25519.PublicKey
	AllowedCodebases []string
	AllowedRuntimes  []string
}

// MemoryRegistry is an in-memory implementation of Registry for v1.
// Will be replaced by Postgres in production.
type MemoryRegistry struct {
	mu   sync.RWMutex
	data map[string]*AgentRegistration
}

// NewMemoryRegistry creates an empty in-memory registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{data: make(map[string]*AgentRegistration)}
}

func (r *MemoryRegistry) Get(hostID string) (*AgentRegistration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.data[hostID]
	if !ok {
		return nil, fmt.Errorf("registry: host %q not found", hostID)
	}
	return reg, nil
}

func (r *MemoryRegistry) Register(reg *AgentRegistration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[reg.HostID] = reg
	return nil
}

func (r *MemoryRegistry) List() []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*AgentRegistration, 0, len(r.data))
	for _, reg := range r.data {
		result = append(result, reg)
	}
	return result
}
