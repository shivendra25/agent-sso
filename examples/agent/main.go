// Example_agent_demonstrates a complete AgentSSO flow using the SDK.
// This mirrors the integration test but shows how a real agent runtime
// (e.g., opencode) would integrate AgentSSO.
//
// Flow:
//  1. Agent attests with its hosting platform's attestation key
//  2. Human logs in via OIDC (Okta/Google) — the ID token goes to the aIdP
//  3. aIdP issues an AIT (Agent Identity Token) — held in agent process memory
//  4. Agent calls the gateway to make tool calls — gateway injects JIT
//  5. MCP server receives authenticated request — returns data
//  6. Agent gets response — LLM context never contained a bearer token
package agent_test

import (
	"context"
	"fmt"
	"log"

	"github.com/shivendra25/agent-sso/pkg/agent"
)

func Example_agent() {
	// In a real deployment, these URLs point to your AgentSSO instances.
	client := agent.New(agent.Config{
		AIdPURL:    "https://aidp.agentsso.io",
		GatewayURL: "https://gateway.agentsso.io",
		TenantID:   "tnt_acme",
	})

	ctx := context.Background()

	// Step 1: Attest — the agent runtime produces a signed attestation
	// document (codebase hash + runtime hash) and the human's OIDC ID token.
	// The aIdP verifies both and returns an AIT.
	ait, err := client.Attest(ctx, "signed-attestation-doc", "oidc-id-token", "okta")
	if err != nil {
		log.Fatalf("Attest: %v", err)
	}
	fmt.Printf("AIT issued for agent %s acting as %s\n", ait.AgentID, ait.PrincipalSub)

	// Step 2: Call MCP servers through the gateway.
	// The AIT is sent via X-AIT header — the gateway exchanges it for a
	// JIT and injects Authorization: Bearer <jit> out-of-band.
	// The LLM context NEVER contains a bearer token.
	result, err := client.Call(ctx, ait.AIT, "github", "v1/prs/42", "GET", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	fmt.Printf("MCP server response: %s\n", result.Body)

	// Step 3: The response body is the only thing the LLM sees.
	// No tokens, no auth headers, no credentials.
	// A prompt-injection attacker cannot exfiltrate what the LLM never had.
}
