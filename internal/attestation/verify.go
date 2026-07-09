package attestation

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// Verifier verifies signed attestation documents against a trusted runtime registry.
type Verifier struct {
	registry Registry
}

// NewVerifier creates an attestation verifier with the given registry.
func NewVerifier(reg Registry) *Verifier {
	return &Verifier{registry: reg}
}

// VerificationResult holds the result of a successful attestation verification.
type VerificationResult struct {
	AgentID      string
	CodebaseHash string
	RuntimeHash  string
	HostID       string
	JTI          string
}

// Verify validates a SignedAttestation against the registry and returns
// the verified document contents.
func (v *Verifier) Verify(sa *SignedAttestation) (*VerificationResult, error) {
	if sa.Header.Typ != AttestationTokenType {
		return nil, errors.New("attestation: unexpected token type " + sa.Header.Typ)
	}
	if sa.Header.Alg != "EdDSA" {
		return nil, errors.New("attestation: unexpected algorithm " + sa.Header.Alg)
	}

	// Look up the host's public key from the registry.
	registration, err := v.registry.Get(sa.Document.HostID)
	if err != nil {
		return nil, ErrUnknownHost
	}

	// Verify the Ed25519 signature.
	if !ed25519.Verify(registration.HostPublicKey, sa.SigningInput(), sa.Signature) {
		return nil, ErrInvalidSignature
	}

	// Check attestation has not expired.
	if time.Now().After(sa.Document.ExpiresAt) {
		return nil, ErrAttestationExpired
	}

	// Verify the agent is registered.
	if sa.Document.AgentID != registration.AgentID {
		return nil, ErrAgentNotRegistered
	}

	// Verify codebase hash is in the allowed set.
	if !contains(registration.AllowedCodebases, sa.Document.CodebaseHash) {
		return nil, ErrCodebaseNotAllowed
	}

	// Verify runtime hash is in the allowed set.
	if !contains(registration.AllowedRuntimes, sa.Document.RuntimeHash) {
		return nil, ErrRuntimeNotAllowed
	}

	return &VerificationResult{
		AgentID:      sa.Document.AgentID,
		CodebaseHash: sa.Document.CodebaseHash,
		RuntimeHash:  sa.Document.RuntimeHash,
		HostID:       sa.Document.HostID,
		JTI:          sa.Document.JTI,
	}, nil
}

// VerifyDrift compares two verification results to detect codebase/runtime drift.
// Returns nil if no drift, or an error describing the drift.
func VerifyDrift(old, new *VerificationResult) error {
	if old.CodebaseHash != new.CodebaseHash {
		return errors.New("attestation: codebase drift detected")
	}
	if old.RuntimeHash != new.RuntimeHash {
		return errors.New("attestation: runtime drift detected")
	}
	return nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
