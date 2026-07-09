// Package main is the aIdP (Agent Identity Provider) service binary.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Generate or load signing key pair (v1: generated on startup)
	// In production this would be loaded from KMS/secrets manager.
	kp, err := crypto.GenerateKeyPair(fmt.Sprintf("aidp-%s", time.Now().Format("2006-01-02")))
	if err != nil {
		logger.Error("failed to generate key pair", "error", err)
		os.Exit(1)
	}
	logger.Info("signing key generated", "kid", kp.KeyID)

	cfg := server.DefaultConfig()
	srv := server.New(cfg, kp, logger)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
