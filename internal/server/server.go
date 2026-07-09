// Package server implements the Agent Identity Provider (aIdP) HTTP server.
//
// The aIdP exposes:
//   - /.well-known/oauth-authorization-server (RFC 8414 AS metadata)
//   - /.well-known/jwks.json (RFC 7517 JWKS)
//   - /oauth/register (RFC 7591 dynamic client registration)
//   - /oauth/token (RFC 8693 token exchange)
//   - /oauth/revoke (token revocation)
//   - /v1/attest (attestation submission + AIT issuance)
//   - /v1/reattest (continuous re-attestation)
//   - /login/oidc/{provider} (OIDC inbound)
//   - /callback/oidc/{provider} (OIDC callback)
//   - /healthz
package server

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net/http"
	"time"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/jwt"
)

// Config holds configuration for the aIdP server.
type Config struct {
	Issuer       string
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DefaultConfig returns a development configuration.
func DefaultConfig() Config {
	return Config{
		Issuer:       "https://aidp.agentsso.io",
		Addr:         ":8443",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

// Server is the Agent Identity Provider HTTP server.
type Server struct {
	config   Config
	keyPair  *crypto.KeyPair
	signer   *jwt.Signer
	verifier *jwt.Verifier
	logger   *slog.Logger
	mux      *http.ServeMux
	http     *http.Server
}

// New creates a new aIdP server.
func New(cfg Config, kp *crypto.KeyPair, logger *slog.Logger) *Server {
	signer := jwt.NewSigner(kp)
	keys := map[crypto.KeyID]*ecdsa.PublicKey{kp.KeyID: kp.Public}
	verifier := jwt.NewVerifier(keys)

	s := &Server{
		config:   cfg,
		keyPair:  kp,
		signer:   signer,
		verifier: verifier,
		logger:   logger,
		mux:      http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// registerRoutes wires all HTTP routes.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleASMetadata)
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	s.http = &http.Server{
		Addr:         s.config.Addr,
		Handler:      s.loggingMiddleware(s.mux),
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}
	s.logger.Info("aIdP server starting", "addr", s.config.Addr, "issuer", s.config.Issuer)
	return s.http.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

// Config returns the server configuration.
func (s *Server) Config() Config {
	return s.config
}

// loggingMiddleware logs each request.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"issuer": s.config.Issuer,
	})
}
