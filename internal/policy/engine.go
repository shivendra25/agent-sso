// Package policy implements the AgentSSO policy engine for scope evaluation.
//
// Design: default-deny with explicit allow rules. The engine evaluates
// whether a given (agent_id, principal, resource, requested_scope) tuple
// is allowed, returning the intersection of requested and allowed scopes.
//
// In v1, policies are stored as simple JSON rules (not full OPA/Rego, which
// is a heavy dependency). v2 will migrate to OPA's Go SDK for full Rego
// support.
//
// See docs/spec/01-architecture.md (Policy Engine) and
// docs/threat-model/mitigations.md (T5: Privilege Escalation).
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	ErrPolicyNotLoaded = errors.New("policy: no policy loaded")
	ErrEvalFailed      = errors.New("policy: evaluation failed")
)

// PolicyInput is the input to the policy evaluation.
type PolicyInput struct {
	AgentID        string `json:"agent_id"`
	PrincipalSub   string `json:"principal_sub"`
	Resource       string `json:"resource"`
	RequestedScope string `json:"requested_scope"`
}

// AllowRule defines an explicit scope grant.
type AllowRule struct {
	AgentID       string   `json:"agent_id"`      // "*" = match all agents
	PrincipalSub  string   `json:"principal_sub"` // "*" = match all principals
	Resource      string   `json:"resource"`      // "*" = match all resources (not recommended)
	AllowedScopes []string `json:"allowed_scopes"`
}

// Policy is the policy document containing all allow rules.
type Policy struct {
	Default string      `json:"default"` // "deny" (default) or "allow"
	Rules   []AllowRule `json:"rules"`
}

// Engine implements the exchange.PolicyEvaluator interface.
type Engine struct {
	mu     sync.RWMutex
	policy *Policy
}

// NewEngine creates an empty policy engine with a default-deny policy.
func NewEngine() *Engine {
	return &Engine{
		policy: &Policy{Default: "deny", Rules: nil},
	}
}

// LoadFromFile loads a policy document from a JSON file.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy: read file: %w", err)
	}
	return e.LoadFromBytes(data)
}

// LoadFromBytes loads a policy document from JSON bytes.
func (e *Engine) LoadFromBytes(data []byte) error {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("policy: unmarshal: %w", err)
	}
	if p.Default == "" {
		p.Default = "deny"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = &p
	return nil
}

// SetPolicy sets the policy directly (for testing).
func (e *Engine) SetPolicy(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = p
}

// Evaluate implements exchange.PolicyEvaluator. Returns the intersection
// of requested and allowed scopes, or an error if denied entirely.
func (e *Engine) Evaluate(agentID, principalSub, resource, requestedScope string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.policy == nil {
		return "", ErrPolicyNotLoaded
	}

	// Default deny
	if e.policy.Default != "allow" {
		// Find matching rules
		allowed := e.collectAllowedScopes(agentID, principalSub, resource)
		if len(allowed) == 0 {
			return "", ErrEvalFailed
		}
		// Intersect with requested
		result := intersectScopes(requestedScope, allowed)
		if result == "" {
			return "", ErrEvalFailed
		}
		return result, nil
	}

	// Default allow (not recommended for production)
	return requestedScope, nil
}

// collectAllowedScopes scans all matching rules and collects the union
// of allowed scopes.
func (e *Engine) collectAllowedScopes(agentID, principalSub, resource string) []string {
	var allowed []string
	for _, r := range e.policy.Rules {
		if ruleMatches(r, agentID, principalSub, resource) {
			allowed = append(allowed, r.AllowedScopes...)
		}
	}
	return dedupStrings(allowed)
}

func ruleMatches(r AllowRule, agentID, principalSub, resource string) bool {
	if r.AgentID != "*" && r.AgentID != agentID {
		return false
	}
	if r.PrincipalSub != "*" && r.PrincipalSub != principalSub {
		return false
	}
	if r.Resource != "*" && r.Resource != resource {
		return false
	}
	return true
}

func intersectScopes(requestedStr string, allowed []string) string {
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}
	var result []string
	for _, s := range strings.Fields(requestedStr) {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return strings.Join(result, " ")
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
