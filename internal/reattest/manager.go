// Package reattest implements continuous re-attestation and drift detection.
//
// Every N minutes, the aIdP requests re-attestation from active agent
// runtimes. If the codebase_hash or runtime_hash has changed (drift),
// the AIT is revoked (jti blocklisted) and an audit alert is logged.
//
// See docs/spec/03-attestation-spec.md (Continuous Re-Attestation) and
// docs/threat-model/threats.md (T6: Codebase/Runtime Drift).
package reattest

import (
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/shivendra25/agent-sso/internal/attestation"
	"github.com/shivendra25/agent-sso/internal/audit"
)

var (
	ErrNotRegistered = errors.New("reattest: agent session not registered")
)

// Session tracks an active agent session for re-attestation.
type Session struct {
	AgentID      string
	SessionID    string
	JTI          string // AIT JTI (for revocation)
	InitialHash  *attestation.VerificationResult
	ReattestFunc func() (string, error) // returns signed attestation doc
	LastChecked  time.Time
	Revoked      bool
}

// Manager coordinates continuous re-attestation for active sessions.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session // key = session_id
	verifier *attestation.Verifier
	auditLog audit.Logger
	interval time.Duration
	logger   *slog.Logger
}

// NewManager creates a re-attestation manager.
func NewManager(verifier *attestation.Verifier, auditLog audit.Logger, interval time.Duration, logger *slog.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		verifier: verifier,
		auditLog: auditLog,
		interval: interval,
		logger:   logger,
	}
}

// Register adds an active session for re-attestation monitoring.
func (m *Manager) Register(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.SessionID] = s
	m.logger.Info("session registered for re-attestation", "agent_id", s.AgentID, "session", s.SessionID)
}

// Revoke marks a session as revoked (e.g., on drift) and logs an audit entry.
func (m *Manager) Revoke(sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return ErrNotRegistered
	}
	s.Revoked = true

	m.auditLog.Append(&audit.Entry{
		EventType: audit.EventAITRevoked,
		AgentID:   s.AgentID,
		SessionID: sessionID,
		JTI:       s.JTI,
		Action:    reason,
	})

	m.logger.Warn("session revoked", "agent_id", s.AgentID, "session", sessionID, "reason", reason)
	return nil
}

// CheckReattest re-verifies a single session's attestation.
// Returns nil if no drift, or an error describing the drift.
func (m *Manager) CheckReattest(sessionID string) error {
	m.mu.Lock()
	s, ok := m.sessions[sessionID]
	m.mu.Unlock()
	if !ok {
		return ErrNotRegistered
	}

	// Get fresh attestation from the agent runtime
	rawAtt, err := s.ReattestFunc()
	if err != nil {
		return err
	}

	signed, err := attestation.ParseSignedAttestation(rawAtt)
	if err != nil {
		return err
	}

	result, err := m.verifier.Verify(signed)
	if err != nil {
		// Attestation failed — revoke
		_ = m.Revoke(sessionID, "attestation_verification_failed: "+err.Error())
		return err
	}

	// Check for drift
	if err := attestation.VerifyDrift(s.InitialHash, result); err != nil {
		_ = m.Revoke(sessionID, "drift_detected: "+err.Error())
		m.auditLog.Append(&audit.Entry{
			EventType: audit.EventDriftDetected,
			AgentID:   s.AgentID,
			SessionID: sessionID,
			JTI:       s.JTI,
			Action:    err.Error(),
		})
		return err
	}

	// No drift — update last checked
	m.mu.Lock()
	s.LastChecked = time.Now()
	m.mu.Unlock()

	m.auditLog.Append(&audit.Entry{
		EventType: audit.EventTokenExchange,
		AgentID:   s.AgentID,
		SessionID: sessionID,
		JTI:       s.JTI,
		Action:    "re-attestation_passed",
	})

	return nil
}

// CheckAll runs re-attestation for all active (non-revoked) sessions.
func (m *Manager) CheckAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id, s := range m.sessions {
		if !s.Revoked {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()

	for _, id := range ids {
		if err := m.CheckReattest(id); err != nil {
			m.logger.Warn("re-attestation failed", "session", id, "error", err)
		}
	}
}

// ActiveSessions returns the count of non-revoked sessions.
func (m *Manager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, s := range m.sessions {
		if !s.Revoked {
			count++
		}
	}
	return count
}

// IsRevoked checks if a session has been revoked.
func (m *Manager) IsRevoked(sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return false
	}
	return s.Revoked
}

// RemoveSession removes a session from monitoring (e.g., on logout/expiry).
func (m *Manager) RemoveSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
}

// HostSigner is a helper that produces attestation documents on re-attest.
// Simulates the agent runtime re-attesting with its host key.
type HostSigner struct {
	signer *attestation.AttestationSigner
	doc    *attestation.AttestationDocument
}

// NewHostSigner creates a host signer for re-attestation testing.
func NewHostSigner(hostID string, priv ed25519.PrivateKey, doc *attestation.AttestationDocument) *HostSigner {
	return &HostSigner{
		signer: attestation.NewAttestationSigner(hostID, priv),
		doc:    doc,
	}
}

// ProduceAttestation returns a fresh signed attestation document.
func (h *HostSigner) ProduceAttestation() (string, error) {
	h.doc.ExpiresAt = time.Now().Add(15 * time.Minute)
	return h.signer.Sign(h.doc)
}
