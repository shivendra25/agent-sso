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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/shivendra25/agent-sso/internal/attest"
	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/exchange"
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
	config    Config
	keyPair   *crypto.KeyPair
	signer    *jwt.Signer
	verifier  *jwt.Verifier
	issuer    *attest.Issuer
	exchanger *exchange.Exchanger
	logger    *slog.Logger
	mux       *http.ServeMux
	http      *http.Server
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

// SetIssuer configures the AIT issuance endpoint.
func (s *Server) SetIssuer(issuer *attest.Issuer) {
	s.issuer = issuer
	s.mux.HandleFunc("/v1/attest", s.handleAttest)
}

// SetExchanger configures the token exchange endpoint.
func (s *Server) SetExchanger(ex *exchange.Exchanger) {
	s.exchanger = ex
	s.mux.HandleFunc("/oauth/token", s.handleTokenExchange)
}

// registerRoutes wires all HTTP routes.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleASMetadata)
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
}

// handleAttest is the AIT issuance endpoint (POST /v1/attest).
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if s.issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "AIT issuer not configured")
		return
	}

	var req attest.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	resp, err := s.issuer.Issue(&req)
	if err != nil {
		switch {
		case errors.Is(err, attest.ErrMissingAttestation):
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		case errors.Is(err, attest.ErrMissingIDToken):
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		case errors.Is(err, attest.ErrAttestationFailed):
			writeError(w, http.StatusUnauthorized, "invalid_attestation", err.Error())
		case errors.Is(err, attest.ErrPrincipalFailed):
			writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		case errors.Is(err, attest.ErrSessionExpired):
			writeError(w, http.StatusUnauthorized, "session_expired", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleTokenExchange is the RFC 8693 token exchange endpoint (POST /oauth/token).
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if s.exchanger == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "token exchange not configured")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	req := exchange.Request{
		GrantType:          r.FormValue("grant_type"),
		SubjectToken:       r.FormValue("subject_token"),
		SubjectTokenType:   r.FormValue("subject_token_type"),
		Resource:           r.FormValue("resource"),
		Scope:              r.FormValue("scope"),
		RequestedTokenType: r.FormValue("requested_token_type"),
	}

	resp, err := s.exchanger.Exchange(&req)
	if err != nil {
		switch {
		case errors.Is(err, exchange.ErrInvalidGrantType):
			writeError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
		case errors.Is(err, exchange.ErrMissingSubjectToken),
			errors.Is(err, exchange.ErrMissingResource),
			errors.Is(err, exchange.ErrMissingScope),
			errors.Is(err, exchange.ErrInvalidResource):
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		case errors.Is(err, exchange.ErrPolicyDenied):
			writeError(w, http.StatusForbidden, "invalid_scope", err.Error())
		case errors.Is(err, exchange.ErrPolicyNarrowedToEmpty):
			writeError(w, http.StatusForbidden, "insufficient_scope", err.Error())
		default:
			writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
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
