package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Ensures the VS Code profile flags resource mismatches after redirects.
// Example trace:
// 1) GET /mcp -> 301 Location: /mcp/
// 2) GET /mcp/ -> 401 WWW-Authenticate resource_metadata=.../oauth-protected-resource/mcp
// 3) PRM resource returns "https://host/mcp" while the resolved target is "https://host/mcp/"
// The VS Code profile compares PRM resource against the resolved endpoint and should flag mismatch.
func TestVSCodeProfileResourceMismatchAfterRedirect(t *testing.T) {
	server := newVSCodeRedirectMismatchServer(t)
	defer server.Close()

	report := runScanForServerProfile(t, server.URL+"/mcp", "vscode")

	if !hasFinding(report.Findings, "PRM_RESOURCE_MISMATCH") {
		t.Fatalf("expected PRM_RESOURCE_MISMATCH finding")
	}
}

// Ensures the VS Code profile flags missing path-suffix PRM endpoints.
// Example trace:
// 1) POST/GET /mcp -> 401 with resource_metadata=.../oauth-protected-resource/mcp
// 2) GET /.well-known/oauth-protected-resource/mcp -> 404
// 3) GET /.well-known/oauth-protected-resource -> 200 (valid root PRM)
// VS Code prefers the path-suffix PRM, so a missing endpoint is flagged.
func TestVSCodeProfilePathSuffixMissing(t *testing.T) {
	server := newVSCodePathSuffixMissingServer(t)
	defer server.Close()

	report := runScanForServerProfile(t, server.URL+"/mcp", "vscode")

	if !hasFinding(report.Findings, "PRM_WELLKNOWN_PATH_SUFFIX_MISSING") {
		t.Fatalf("expected PRM_WELLKNOWN_PATH_SUFFIX_MISSING finding")
	}
}

// Ensures scope whitespace warnings are emitted under the VS Code profile.
// Example: metadata scopes_supported includes "user_impersonation " (trailing space).
// VS Code treats scope strings literally, so whitespace risks repeated login prompts.
func TestVSCodeProfileScopesWhitespaceRisk(t *testing.T) {
	server := newVSCodeScopesWhitespaceServer(t)
	defer server.Close()

	report := runScanForServerProfile(t, server.URL+"/mcp", "vscode")

	if !hasFinding(report.Findings, "SCOPES_WHITESPACE_RISK") {
		t.Fatalf("expected SCOPES_WHITESPACE_RISK finding")
	}
}

// newVSCodeRedirectMismatchServer simulates a redirecting MCP endpoint with PRM resource mismatch.
// The PRM claims a resource without a trailing slash while the resolved MCP endpoint ends with "/".
func newVSCodeRedirectMismatchServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, baseURL+"/mcp/", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp/",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	addAuthMetadataHandlers(mux, baseURL, []string{"user_impersonation"})

	return server
}

// newVSCodePathSuffixMissingServer simulates a missing path-suffix PRM endpoint with a root fallback.
// This models services that only publish root PRM even when the MCP endpoint has a path.
func newVSCodePathSuffixMissingServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	addAuthMetadataHandlers(mux, baseURL, []string{"user_impersonation"})

	return server
}

// newVSCodeScopesWhitespaceServer exposes whitespace in scopes_supported for linting.
// The VS Code profile treats this as a compatibility warning.
func newVSCodeScopesWhitespaceServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	addAuthMetadataHandlers(mux, baseURL, []string{"user_impersonation "})

	return server
}

// addAuthMetadataHandlers registers auth server metadata endpoints shared by VS Code fixtures.
// It includes a legacy root well-known endpoint to support VS Code's optional probe.
func addAuthMetadataHandlers(mux *http.ServeMux, baseURL string, scopes []string) {
	mux.HandleFunc("/issuer/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
			"scopes_supported":       scopes,
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})
}
