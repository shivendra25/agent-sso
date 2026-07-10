package policy

import (
	"errors"
	"testing"
)

func TestEvaluateDefaultDenyNoRules(t *testing.T) {
	e := NewEngine()
	_, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read")
	if err == nil {
		t.Fatal("expected denial with no rules (default deny)")
	}
}

func TestEvaluateExplicitAllow(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "oidc:okta:user-1",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
		},
	})

	allowed, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed != "github:prs:read" {
		t.Errorf("allowed = %q, want github:prs:read", allowed)
	}
}

func TestEvaluateScopeNarrowing(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "*",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"}, // only read, not write
			},
		},
	})

	// Request read + write, only read should be returned
	allowed, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read github:prs:write")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed != "github:prs:read" {
		t.Errorf("allowed = %q, want github:prs:read only", allowed)
	}
}

func TestEvaluateDenyUnknownAgent(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "oidc:okta:user-1",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
		},
	})

	_, err := e.Evaluate("a:unknown-agent", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read")
	if err == nil {
		t.Fatal("expected denial for unknown agent")
	}
}

func TestEvaluateDenyWrongResource(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "oidc:okta:user-1",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
		},
	})

	_, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.slack.test", "github:prs:read")
	if err == nil {
		t.Fatal("expected denial for wrong resource")
	}
}

func TestEvaluateWildcardPrincipal(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "*",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
		},
	})

	_, err := e.Evaluate("a:agent-1", "oidc:okta:anyone", "https://mcp.github.test", "github:prs:read")
	if err != nil {
		t.Fatalf("Expected allow with wildcard principal: %v", err)
	}
}

func TestEvaluateMultipleRulesUnion(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "*",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
			{
				AgentID:       "*",
				PrincipalSub:  "oidc:okta:user-1",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:write"},
			},
		},
	})

	// agent-1 with user-1 should get union (read + write)
	allowed, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read github:prs:write")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed != "github:prs:read github:prs:write" {
		t.Errorf("allowed = %q, want both read and write", allowed)
	}
}

func TestEvaluateRequestedScopeNotInAllowedSet(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "deny",
		Rules: []AllowRule{
			{
				AgentID:       "a:agent-1",
				PrincipalSub:  "oidc:okta:user-1",
				Resource:      "https://mcp.github.test",
				AllowedScopes: []string{"github:prs:read"},
			},
		},
	})

	// Request admin scope that isn't in allowed set
	_, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:repos:admin")
	if err == nil {
		t.Fatal("expected denial for scope not in allowed set")
	}
}

func TestEvaluateDefaultAllow(t *testing.T) {
	e := NewEngine()
	e.SetPolicy(&Policy{
		Default: "allow",
	})

	allowed, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed != "github:prs:read" {
		t.Errorf("allowed = %q, want github:prs:read", allowed)
	}
}

func TestLoadFromBytes(t *testing.T) {
	e := NewEngine()
	jsonPolicy := `{
		"default": "deny",
		"rules": [
			{
				"agent_id": "a:agent-1",
				"principal_sub": "oidc:okta:user-1",
				"resource": "https://mcp.github.test",
				"allowed_scopes": ["github:prs:read"]
			}
		]
	}`
	if err := e.LoadFromBytes([]byte(jsonPolicy)); err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}

	allowed, err := e.Evaluate("a:agent-1", "oidc:okta:user-1", "https://mcp.github.test", "github:prs:read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed != "github:prs:read" {
		t.Errorf("allowed = %q", allowed)
	}
}

func TestLoadFromBytesInvalidJSON(t *testing.T) {
	e := NewEngine()
	err := e.LoadFromBytes([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNoPolicyLoaded(t *testing.T) {
	e := &Engine{policy: nil}
	_, err := e.Evaluate("a:1", "p", "r", "s")
	if !errors.Is(err, ErrPolicyNotLoaded) {
		t.Errorf("expected ErrPolicyNotLoaded, got %v", err)
	}
}
