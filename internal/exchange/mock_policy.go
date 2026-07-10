package exchange

import "strings"

// MockPolicyEvaluator is a test-only PolicyEvaluator that either allows
// all requested scopes or denies based on configuration.
type MockPolicyEvaluator struct {
	// AllowAll, if true, returns the requested scope unchanged.
	AllowAll bool
	// AllowedScopes, if set and AllowAll is false, returns the intersection
	// of requested and AllowedScopes.
	AllowedScopes []string
	// DenyError, if non-nil, causes Evaluate to return this error.
	DenyError error
}

// Evaluate implements PolicyEvaluator.
func (m *MockPolicyEvaluator) Evaluate(agentID, principalSub, resource, requestedScope string) (string, error) {
	if m.DenyError != nil {
		return "", m.DenyError
	}
	if m.AllowAll {
		return requestedScope, nil
	}
	requested := strings.Fields(requestedScope)
	var allowed []string
	for _, s := range requested {
		for _, a := range m.AllowedScopes {
			if s == a {
				allowed = append(allowed, s)
				break
			}
		}
	}
	if len(allowed) == 0 {
		return "", nil
	}
	return strings.Join(allowed, " "), nil
}
