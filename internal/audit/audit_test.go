package audit

import (
	"testing"
	"time"
)

func TestAppendAndVerify(t *testing.T) {
	log := NewMemoryLogger()

	e1 := &Entry{
		EventType:    EventAITIssued,
		TenantID:     "tnt_test",
		PrincipalSub: "oidc:okta:user-001",
		AgentID:      "a:test-agent-001",
		SessionID:    "ses_001",
		Scope:        "agent:attest tools:exchange",
		JTI:          "ait_001",
	}
	if err := log.Append(e1); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if e1.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", e1.Sequence)
	}
	if e1.Hash == "" {
		t.Error("Hash is empty after Append")
	}

	e2 := &Entry{
		EventType:    EventTokenExchange,
		TenantID:     "tnt_test",
		PrincipalSub: "oidc:okta:user-001",
		AgentID:      "a:test-agent-001",
		SessionID:    "ses_001",
		Scope:        "github:prs:read",
		Resource:     "https://mcp.github.test",
		JTI:          "jit_001",
	}
	if err := log.Append(e2); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	if e2.Sequence != 2 {
		t.Errorf("Sequence = %d, want 2", e2.Sequence)
	}
	if e2.PrevHash != e1.Hash {
		t.Error("e2.PrevHash should equal e1.Hash")
	}

	// Verify the chain is intact
	if err := log.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyCorrupted(t *testing.T) {
	log := NewMemoryLogger()

	e1 := &Entry{EventType: EventAITIssued, JTI: "ait_001"}
	log.Append(e1)
	e2 := &Entry{EventType: EventTokenExchange, JTI: "jit_001"}
	log.Append(e2)

	// Tamper with the first entry
	log.entries[0].AgentID = "a:HAMMERED"

	err := log.Verify()
	if err == nil {
		t.Fatal("expected corruption error")
	}
}

func TestLatestHash(t *testing.T) {
	log := NewMemoryLogger()

	if log.LatestHash() != "" {
		t.Error("expected empty hash for empty log")
	}

	log.Append(&Entry{EventType: EventAITIssued, JTI: "ait_001"})
	h1 := log.LatestHash()
	if h1 == "" {
		t.Fatal("expected non-empty hash after append")
	}

	log.Append(&Entry{EventType: EventTokenExchange, JTI: "jit_001"})
	h2 := log.LatestHash()
	if h2 == h1 {
		t.Error("hash should change after new entry")
	}
}

func TestEntries(t *testing.T) {
	log := NewMemoryLogger()
	log.Append(&Entry{EventType: EventAITIssued, JTI: "jti1"})
	log.Append(&Entry{EventType: EventTokenExchange, JTI: "jti2"})
	log.Append(&Entry{EventType: EventToolCall, JTI: "jti3"})

	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	for i, e := range entries {
		if e.Sequence != i+1 {
			t.Errorf("entry %d Sequence = %d, want %d", i, e.Sequence, i+1)
		}
	}
}

func TestEntryToJSON(t *testing.T) {
	e := &Entry{
		Sequence:     1,
		Timestamp:    time.Now().UTC(),
		EventType:    EventAITIssued,
		TenantID:     "tnt_test",
		PrincipalSub: "oidc:okta:user-001",
		AgentID:      "a:test-001",
		SessionID:    "ses_001",
		Scope:        "agent:attest",
		JTI:          "ait_001",
		PrevHash:     "prev",
		Hash:         "this_hash",
	}
	data, err := e.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JSON output is empty")
	}
}

func TestHashChainIntegrity(t *testing.T) {
	log := NewMemoryLogger()

	for i := 0; i < 100; i++ {
		log.Append(&Entry{
			EventType:    EventTokenExchange,
			TenantID:     "tnt_test",
			PrincipalSub: "oidc:okta:user-001",
			AgentID:      "a:test-agent-001",
			SessionID:    "ses_001",
			Scope:        "github:prs:read",
			Resource:     "https://mcp.github.test",
			JTI:          "jit_" + string(rune('A'+i)),
		})
	}

	if err := log.Verify(); err != nil {
		t.Fatalf("Verify after 100 entries: %v", err)
	}

	if len(log.Entries()) != 100 {
		t.Errorf("got %d entries, want 100", len(log.Entries()))
	}
}

func TestThreadSafety(t *testing.T) {
	log := NewMemoryLogger()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 50; j++ {
				log.Append(&Entry{
					EventType: EventTokenExchange,
					JTI:       "jit_go",
				})
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if err := log.Verify(); err != nil {
		t.Fatalf("Verify after concurrent appends: %v", err)
	}
	if len(log.Entries()) != 500 {
		t.Errorf("got %d entries, want 500", len(log.Entries()))
	}
}
