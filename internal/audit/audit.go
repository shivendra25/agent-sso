// Package audit implements the tamper-evident, hash-chained audit log
// for AgentSSO. Every action (token exchange, tool call, drift detection)
// is logged with (principal, agent, scope, resource, action, jti, timestamp)
// and chained via SHA-256 hashes.
//
// See docs/spec/01-architecture.md (Audit Log) and
// docs/threat-model/threats.md (T9: Audit Log Tampering).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrLogCorrupted = errors.New("audit: log chain corrupted")
)

// EventType categorizes audit entries.
type EventType string

const (
	EventTokenExchange EventType = "TOKEN_EXCHANGE"
	EventToolCall      EventType = "TOOL_CALL"
	EventAITIssued     EventType = "AIT_ISSUED"
	EventDriftDetected EventType = "DRIFT_DETECTED"
	EventAITRevoked    EventType = "AIT_REVOKED"
	EventPolicyDeny    EventType = "POLICY_DENY"
)

// Entry is a single audit log entry.
type Entry struct {
	Sequence     int       `json:"sequence"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    EventType `json:"event_type"`
	TenantID     string    `json:"tenant_id"`
	PrincipalSub string    `json:"principal_sub"`
	AgentID      string    `json:"agent_id"`
	SessionID    string    `json:"session_id"`
	Scope        string    `json:"scope"`
	Resource     string    `json:"resource,omitempty"`
	Action       string    `json:"action,omitempty"`
	JTI          string    `json:"jti"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
}

// Logger is the audit log interface.
type Logger interface {
	Append(entry *Entry) error
	Verify() error
	Entries() []*Entry
	LatestHash() string
}

// MemoryLogger is an in-memory, hash-chained audit log.
type MemoryLogger struct {
	mu      sync.Mutex
	entries []*Entry
}

// NewMemoryLogger creates an empty in-memory audit log.
func NewMemoryLogger() *MemoryLogger {
	return &MemoryLogger{entries: make([]*Entry, 0)}
}

// Append adds an entry to the log, computing its hash chain.
func (l *MemoryLogger) Append(entry *Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Sequence = len(l.entries) + 1
	entry.Timestamp = time.Now().UTC()

	// Compute prev_hash from the last entry
	if len(l.entries) == 0 {
		emptyHash := sha256.Sum256(nil)
		entry.PrevHash = hex.EncodeToString(emptyHash[:])
	} else {
		entry.PrevHash = l.entries[len(l.entries)-1].Hash
	}

	// Compute this entry's hash
	entry.Hash = computeHash(entry)

	l.entries = append(l.entries, entry)
	return nil
}

// Verify recomputes the entire hash chain and returns an error if any
// entry has been tampered with.
func (l *MemoryLogger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	emptyHash := sha256.Sum256(nil)
	prevHash := hex.EncodeToString(emptyHash[:])
	for i, e := range l.entries {
		if e.Sequence != i+1 {
			return fmt.Errorf("%w: sequence mismatch at entry %d", ErrLogCorrupted, i)
		}
		if e.PrevHash != prevHash {
			return fmt.Errorf("%w: prev_hash mismatch at entry %d", ErrLogCorrupted, i)
		}
		expectedHash := computeHash(e)
		if e.Hash != expectedHash {
			return fmt.Errorf("%w: hash mismatch at entry %d", ErrLogCorrupted, i)
		}
		prevHash = e.Hash
	}
	return nil
}

// Entries returns a copy of all log entries.
func (l *MemoryLogger) Entries() []*Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// LatestHash returns the hash of the most recent entry, or empty string
// if the log is empty.
func (l *MemoryLogger) LatestHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return ""
	}
	return l.entries[len(l.entries)-1].Hash
}

// computeHash computes the SHA-256 hash of an entry, binding it to the
// previous entry's hash.
func computeHash(e *Entry) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.Sequence, e.Timestamp.Format(time.RFC3339Nano),
		e.EventType, e.TenantID, e.PrincipalSub, e.AgentID,
		e.SessionID, e.Scope, e.Resource, e.Action, e.JTI, e.PrevHash,
	)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ToJSON serializes an entry to JSON (for external publication/verification).
func (e *Entry) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}
