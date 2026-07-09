package attestation

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func newTestRegistry(t *testing.T) *MemoryRegistry {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	reg := &AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:def456"},
	}
	registry := NewMemoryRegistry()
	if err := registry.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return registry
}

func newTestAttestationDoc() *AttestationDocument {
	now := time.Now()
	return &AttestationDocument{
		AgentID:      "a:test-agent-001",
		CodebaseHash: "sha256:abc123",
		RuntimeHash:  "sha256:def456",
		StartedAt:    now,
		ExpiresAt:    now.Add(15 * time.Minute),
		HostID:       "host-001",
		HostClaims:   map[string]string{"platform": "opencode", "version": "0.5.0"},
		JTI:          "att-test-001",
	}
}

func TestAttestationSignAndVerify(t *testing.T) {
	registry := newTestRegistry(t)

	// Generate keypair for the host and re-register with it so we can sign+verify
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	reg2 := &AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub2,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:def456"},
	}
	registry.Register(reg2)

	signer := NewAttestationSigner("host-001", priv2)
	doc := newTestAttestationDoc()

	raw, err := signer.Sign(doc)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, err := ParseSignedAttestation(raw)
	if err != nil {
		t.Fatalf("ParseSignedAttestation: %v", err)
	}

	verifier := NewVerifier(registry)
	result, err := verifier.Verify(parsed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.AgentID != "a:test-agent-001" {
		t.Errorf("AgentID = %q, want a:test-agent-001", result.AgentID)
	}
	if result.CodebaseHash != "sha256:abc123" {
		t.Errorf("CodebaseHash = %q", result.CodebaseHash)
	}
	if result.JTI != "att-test-001" {
		t.Errorf("JTI = %q", result.JTI)
	}
}

func TestAttestationInvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	registry := NewMemoryRegistry()
	registry.Register(&AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:def456"},
	})

	// Sign with a different key
	_, privWrong, _ := ed25519.GenerateKey(nil)
	signer := NewAttestationSigner("host-001", privWrong)
	doc := newTestAttestationDoc()
	raw, _ := signer.Sign(doc)

	parsed, _ := ParseSignedAttestation(raw)
	verifier := NewVerifier(registry)
	_, err := verifier.Verify(parsed)
	if err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestAttestationUnknownHost(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer := NewAttestationSigner("unknown-host", priv)
	doc := newTestAttestationDoc()
	raw, _ := signer.Sign(doc)

	parsed, _ := ParseSignedAttestation(raw)
	verifier := NewVerifier(NewMemoryRegistry())
	if _, err := verifier.Verify(parsed); err == nil {
		t.Fatal("expected unknown host error")
	}
}

func TestAttestationExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	registry := NewMemoryRegistry()
	registry.Register(&AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:def456"},
	})

	signer := NewAttestationSigner("host-001", priv)
	doc := newTestAttestationDoc()
	doc.ExpiresAt = time.Now().Add(-1 * time.Minute) // expired
	raw, _ := signer.Sign(doc)

	parsed, _ := ParseSignedAttestation(raw)
	verifier := NewVerifier(registry)
	if _, err := verifier.Verify(parsed); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestAttestationCodebaseNotAllowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	registry := NewMemoryRegistry()
	registry.Register(&AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub,
		AllowedCodebases: []string{"sha256:allowed"},
		AllowedRuntimes:  []string{"sha256:def456"},
	})

	signer := NewAttestationSigner("host-001", priv)
	doc := newTestAttestationDoc()
	doc.CodebaseHash = "sha256:notallowed"
	raw, _ := signer.Sign(doc)

	parsed, _ := ParseSignedAttestation(raw)
	verifier := NewVerifier(registry)
	if _, err := verifier.Verify(parsed); err == nil {
		t.Fatal("expected codebase not allowed error")
	}
}

func TestAttestationRuntimeNotAllowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	registry := NewMemoryRegistry()
	registry.Register(&AgentRegistration{
		AgentID:          "a:test-agent-001",
		HostID:           "host-001",
		HostPublicKey:    pub,
		AllowedCodebases: []string{"sha256:abc123"},
		AllowedRuntimes:  []string{"sha256:allowed"},
	})

	signer := NewAttestationSigner("host-001", priv)
	doc := newTestAttestationDoc()
	doc.RuntimeHash = "sha256:notallowed"
	raw, _ := signer.Sign(doc)

	parsed, _ := ParseSignedAttestation(raw)
	verifier := NewVerifier(registry)
	if _, err := verifier.Verify(parsed); err == nil {
		t.Fatal("expected runtime not allowed error")
	}
}

func TestVerifyDriftNoChange(t *testing.T) {
	a := &VerificationResult{CodebaseHash: "sha256:abc", RuntimeHash: "sha256:def"}
	b := &VerificationResult{CodebaseHash: "sha256:abc", RuntimeHash: "sha256:def"}
	if err := VerifyDrift(a, b); err != nil {
		t.Errorf("unexpected drift error: %v", err)
	}
}

func TestVerifyDriftCodebaseChanged(t *testing.T) {
	a := &VerificationResult{CodebaseHash: "sha256:abc", RuntimeHash: "sha256:def"}
	b := &VerificationResult{CodebaseHash: "sha256:xyz", RuntimeHash: "sha256:def"}
	if err := VerifyDrift(a, b); err == nil {
		t.Fatal("expected codebase drift error")
	}
}

func TestVerifyDriftRuntimeChanged(t *testing.T) {
	a := &VerificationResult{CodebaseHash: "sha256:abc", RuntimeHash: "sha256:def"}
	b := &VerificationResult{CodebaseHash: "sha256:abc", RuntimeHash: "sha256:xyz"}
	if err := VerifyDrift(a, b); err == nil {
		t.Fatal("expected runtime drift error")
	}
}

func TestComputeCodebaseHash(t *testing.T) {
	h := ComputeCodebaseHash("abc123def")
	if h != "sha256:abc123def" {
		t.Errorf("ComputeCodebaseHash = %q, want sha256:abc123def", h)
	}
}

func TestComputeRuntimeHash(t *testing.T) {
	h1 := ComputeRuntimeHash("opencode", "0.5.0", "builder-1")
	h2 := ComputeRuntimeHash("opencode", "0.5.0", "builder-1")
	if h1 != h2 {
		t.Error("ComputeRuntimeHash not deterministic")
	}
	h3 := ComputeRuntimeHash("opencode", "0.5.1", "builder-1")
	if h1 == h3 {
		t.Error("ComputeRuntimeHash should differ for different versions")
	}
}

func TestInvalidAttestationFormat(t *testing.T) {
	if _, err := ParseSignedAttestation("not.valid"); err == nil {
		t.Error("expected format error for invalid attestation")
	}
}

func TestRegistryList(t *testing.T) {
	r := NewMemoryRegistry()
	r.Register(&AgentRegistration{AgentID: "a:1", HostID: "h1"})
	r.Register(&AgentRegistration{AgentID: "a:2", HostID: "h2"})
	list := r.List()
	if len(list) != 2 {
		t.Errorf("List returned %d items, want 2", len(list))
	}
}
