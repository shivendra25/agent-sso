// Package main is the Credential Boundary Gateway service binary.
//
// The gateway runs as a standalone HTTP server that proxies tool calls
// from agent runtimes to MCP servers, injecting credentials out-of-band.
//
// Usage:
//
//	agent-sso-gateway --addr :8444 --aidp-url https://aidp.agentsso.io
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/exchange"
	"github.com/shivendra25/agent-sso/internal/gateway"
	"github.com/shivendra25/agent-sso/internal/jwt"
	"github.com/shivendra25/agent-sso/internal/policy"
	"github.com/shivendra25/agent-sso/internal/registry"
)

func main() {
	addr := flag.String("addr", ":8444", "Gateway listen address")
	aidpURL := flag.String("aidp-url", "https://aidp.agentsso.io", "aIdP issuer URL")
	policyFile := flag.String("policy", "", "Path to policy JSON file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Generate or load signing key (v1: ephemeral)
	kp, err := crypto.GenerateKeyPair(fmt.Sprintf("gw-%s", time.Now().Format("2006-01-02")))
	if err != nil {
		logger.Error("failed to generate key pair", "error", err)
		os.Exit(1)
	}

	verifier := jwt.NewVerifier(map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public})
	signer := jwt.NewSigner(kp)

	// Load policy
	policyEngine := policy.NewEngine()
	if *policyFile != "" {
		if err := policyEngine.LoadFromFile(*policyFile); err != nil {
			logger.Error("failed to load policy", "error", err, "file", *policyFile)
			os.Exit(1)
		}
		logger.Info("policy loaded", "file", *policyFile)
	} else {
		// Default-deny with a basic rule
		policyEngine.SetPolicy(&policy.Policy{
			Default: "deny",
			Rules: []policy.AllowRule{
				{
					AgentID:       "*",
					PrincipalSub:  "*",
					Resource:      "*",
					AllowedScopes: []string{"github:read", "slack:read", "jira:read"},
				},
			},
		})
		logger.Info("using default policy (read-only scopes)")
	}

	// Create token exchanger
	exchanger := exchange.NewExchanger(verifier, signer, policyEngine, *aidpURL, 5*time.Minute)

	// Create MCP server registry (v1: populated via API or config file)
	mcpRegistry := registry.NewMemoryRegistry()

	// Create gateway
	cfg := gateway.DefaultConfig()
	cfg.Addr = *addr
	gw := gateway.New(cfg, exchanger, mcpRegistry, verifier, logger)

	// HTTP server
	srv := &http.Server{
		Addr:         *addr,
		Handler:      gw,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Register default MCP server from environment (v1 convenience)
	if envServers := os.Getenv("AGENTSSO_MCP_SERVERS"); envServers != "" {
		var servers []registry.MCPServer
		if err := json.Unmarshal([]byte(envServers), &servers); err != nil {
			logger.Error("failed to parse AGENTSSO_MCP_SERVERS", "error", err)
		}
		for _, s := range servers {
			mcpRegistry.Register(&s)
			logger.Info("registered MCP server", "alias", s.ServerAlias, "url", s.ServerURL)
		}
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down gateway...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}()

	logger.Info("AgentSSO gateway starting", "addr", *addr, "aidp_url", *aidpURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
