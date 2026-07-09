// Package attestation provides the attestation document schema, verification,
// and a trusted runtime registry for agent identity attestation.
//
// See docs/spec/03-attestation-spec.md for the full specification.
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidAttestationFormat = errors.New("attestation: invalid format")
	ErrInvalidSignature         = errors.New("attestation: invalid signature")
	ErrUnknownHost              = errors.New("attestation: unknown host")
	ErrAttestationExpired       = errors.New("attestation: expired")
	ErrAgentNotRegistered       = errors.New("attestation: agent not registered")
	ErrCodebaseNotAllowed       = errors.New("attestation: codebase hash not allowed")
	ErrRuntimeNotAllowed        = errors.New("attestation: runtime hash not allowed")
)

// AttestationDocument is the payload of an agent runtime attestation.
// See docs/spec/03-attestation-spec.md.
type AttestationDocument struct {
	AgentID      string            `json:"agent_id"`
	CodebaseHash string            `json:"codebase_hash"`
	RuntimeHash  string            `json:"runtime_hash"`
	StartedAt    time.Time         `json:"started_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	HostID       string            `json:"host_id"`
	HostClaims   map[string]string `json:"host_claims,omitempty"`
	JTI          string            `json:"jti"`
}

// SignedAttestation is a JWS-like compact envelope containing an
// attestation document signed by the host platform's Ed25519 key.
//
// Format: base64url(header).base64url(payload).base64url(signature)
type SignedAttestation struct {
	Header    AttestationHeader
	Document  AttestationDocument
	Signature []byte
	Raw       string
}

// AttestationHeader is the JWS header for an attestation document.
type AttestationHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

const AttestationTokenType = "agent-attestation+jwt"

// ParseSignedAttestation parses a compact-serialized signed attestation
// without verifying the signature.
func ParseSignedAttestation(raw string) (*SignedAttestation, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidAttestationFormat
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("attestation: decode header: %w", err)
	}
	var header AttestationHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("attestation: unmarshal header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("attestation: decode payload: %w", err)
	}
	var doc AttestationDocument
	if err := json.Unmarshal(payloadJSON, &doc); err != nil {
		return nil, fmt.Errorf("attestation: unmarshal document: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("attestation: decode signature: %w", err)
	}

	return &SignedAttestation{
		Header:    header,
		Document:  doc,
		Signature: sig,
		Raw:       raw,
	}, nil
}

// SigningInput returns the header.payload portion that was signed.
func (sa *SignedAttestation) SigningInput() []byte {
	parts := strings.Split(sa.Raw, ".")
	return []byte(parts[0] + "." + parts[1])
}

// AttestationSigner signs attestation documents with an Ed25519 key.
type AttestationSigner struct {
	hostID string
	key    ed25519.PrivateKey
}

// NewAttestationSigner creates a signer from an Ed25519 private key.
func NewAttestationSigner(hostID string, key ed25519.PrivateKey) *AttestationSigner {
	return &AttestationSigner{hostID: hostID, key: key}
}

// Sign produces a compact-serialized signed attestation.
func (s *AttestationSigner) Sign(doc *AttestationDocument) (string, error) {
	doc.HostID = s.hostID

	header := AttestationHeader{
		Alg: "EdDSA",
		Typ: AttestationTokenType,
		Kid: "host:" + s.hostID,
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(doc)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)

	sig := ed25519.Sign(s.key, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ComputeCodebaseHash computes the attestation codebase hash from a git tree SHA.
func ComputeCodebaseHash(gitTreeSHA string) string {
	return "sha256:" + gitTreeSHA
}

// ComputeRuntimeHash computes the attestation runtime hash.
func ComputeRuntimeHash(runtimeName, runtimeVersion, builderID string) string {
	data := runtimeName + ":" + runtimeVersion + ":" + builderID
	h := sha256.Sum256([]byte(data))
	return "sha256:" + fmt.Sprintf("%x", h[:])
}
