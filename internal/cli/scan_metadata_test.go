package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchAuthServerMetadataWithPathIssuer(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	issuer := server.URL + "/login/oauth/"
	expectedDiscovery := server.URL + "/.well-known/oauth-authorization-server/login/oauth"

	mux.HandleFunc("/.well-known/oauth-authorization-server/login/oauth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           server.URL + "/authorize",
			"token_endpoint":                   server.URL + "/token",
			"response_types_supported":         []string{"code"},
			"grant_types_supported":            []string{"authorization_code"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	trace := []traceEntry{}
	findings, _, _, _ := fetchAuthServerMetadata(server.Client(), scanConfig{
		RFCMode:             "best-effort",
		AllowPrivateIssuers: true,
	}, prmResult{
		AuthorizationServers: []string{issuer},
	}, &trace, io.Discard)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
	if len(trace) == 0 {
		t.Fatalf("expected trace entries, got none")
	}
	if trace[0].URL != expectedDiscovery {
		t.Fatalf("expected discovery URL %q, got %q", expectedDiscovery, trace[0].URL)
	}
}

func TestFetchAuthServerMetadataOIDCAppendFallback(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	issuer := server.URL + "/organizations/v2.0"
	appendDiscovery := server.URL + "/organizations/v2.0/.well-known/openid-configuration"
	mux.HandleFunc("/.well-known/oauth-authorization-server/organizations/v2.0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/openid-configuration/organizations/v2.0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/organizations/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           server.URL + "/contoso/v2.0",
			"authorization_endpoint":           server.URL + "/authorize",
			"token_endpoint":                   server.URL + "/token",
			"response_types_supported":         []string{"code"},
			"grant_types_supported":            []string{"authorization_code"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	trace := []traceEntry{}
	findings, evidence, _, _ := fetchAuthServerMetadata(server.Client(), scanConfig{
		RFCMode:             "best-effort",
		AllowPrivateIssuers: true,
	}, prmResult{
		AuthorizationServers: []string{issuer},
	}, &trace, io.Discard)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
	if !strings.Contains(evidence, appendDiscovery) {
		t.Fatalf("expected evidence to include append discovery URL %q", appendDiscovery)
	}
	if !strings.Contains(evidence, "OIDC discovery endpoint") {
		t.Fatalf("expected evidence to note OIDC discovery success, got %q", evidence)
	}
}
