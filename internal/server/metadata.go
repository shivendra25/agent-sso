package server

import (
	"encoding/json"
	"net/http"

	"github.com/shivendra25/agent-sso/internal/crypto"
	"github.com/shivendra25/agent-sso/internal/jwt"
)

// ASMetadata implements RFC 8414 Authorization Server Metadata.
// See docs/spec/05-discovery.md.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
}

// handleASMetadata returns the RFC 8414 Authorization Server Metadata document.
func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	tokenEndpoint := s.config.Issuer + "/oauth/token"
	metadata := ASMetadata{
		Issuer:                            s.config.Issuer,
		TokenEndpoint:                     tokenEndpoint,
		JwksURI:                           s.config.Issuer + "/.well-known/jwks.json",
		RegistrationEndpoint:              s.config.Issuer + "/oauth/register",
		ResponseTypesSupported:            []string{"token"},
		GrantTypesSupported:               []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic"},
		RevocationEndpoint:                s.config.Issuer + "/oauth/revoke",
		IntrospectionEndpoint:             s.config.Issuer + "/oauth/introspect",
		ScopesSupported:                   []string{jwt.ScopeAgentAttest, jwt.ScopeToolsExchange},
	}
	writeJSON(w, http.StatusOK, metadata)
}

// handleJWKS returns the JWKS document (RFC 7517) containing the public
// signing keys for AIT/JIT verification.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := crypto.JWKS{
		Keys: []crypto.JWK{s.keyPair.ToJWK()},
	}
	writeJSON(w, http.StatusOK, jwks)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError writes a standard OAuth 2.1 error response.
func writeError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}
