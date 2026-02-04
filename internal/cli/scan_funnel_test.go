package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPProbeMissingWWWAuthenticate(t *testing.T) {
	server := newProbeMissingAuthServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "DISCOVERY_NO_WWW_AUTHENTICATE") {
		t.Fatalf("expected DISCOVERY_NO_WWW_AUTHENTICATE finding")
	}
	if step := findStep(report.Steps, 1); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 1 to fail, got %+v", step)
	}
}

func TestMCPInitializeNonJSONFailure(t *testing.T) {
	server := newInitializeNonJSONServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "MCP_INITIALIZE_FAILED") {
		t.Fatalf("expected MCP_INITIALIZE_FAILED finding")
	}
	if step := findStep(report.Steps, 2); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 2 to fail, got %+v", step)
	}
}

func TestPRMContentTypeNotJSON(t *testing.T) {
	server := newPRMContentTypeServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "PRM_CONTENT_TYPE_NOT_JSON") {
		t.Fatalf("expected PRM_CONTENT_TYPE_NOT_JSON finding")
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 3 to fail, got %+v", step)
	}
}

func TestAuthServerMetadataMissingTokenEndpoint(t *testing.T) {
	server := newAuthMetadataMissingTokenServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "AUTH_SERVER_METADATA_INVALID") {
		t.Fatalf("expected AUTH_SERVER_METADATA_INVALID finding")
	}
	if step := findStep(report.Steps, 4); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 4 to fail, got %+v", step)
	}
}

func newProbeMissingAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	return httptest.NewServer(mux)
}

func newInitializeNonJSONServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	})

	return httptest.NewServer(mux)
}

func newPRMContentTypeServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	})

	return server
}

func newAuthMetadataMissingTokenServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
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

	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
		})
	})

	return server
}
