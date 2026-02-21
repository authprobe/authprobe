package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthRequiredButNotAdvertised(t *testing.T) {
	server := newAuthRequiredNoDiscoveryServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if report.PrimaryFinding.Code != "AUTH_REQUIRED_BUT_NOT_ADVERTISED" {
		t.Fatalf("expected primary finding AUTH_REQUIRED_BUT_NOT_ADVERTISED, got %q", report.PrimaryFinding.Code)
	}
	if hasFinding(report.Findings, "MCP_INITIALIZE_FAILED") {
		t.Fatalf("did not expect MCP_INITIALIZE_FAILED when auth is required but not advertised")
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 3 to fail, got %+v", step)
	}
	if step := findStep(report.Steps, 1); step != nil && bytes.Contains([]byte(step.Detail), []byte("auth not required")) {
		t.Fatalf("did not expect step 1 to claim auth not required")
	}
}

func TestOAuthDiscoveryAdvertised(t *testing.T) {
	server := newOAuthDiscoveryServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if hasFinding(report.Findings, "AUTH_REQUIRED_BUT_NOT_ADVERTISED") {
		t.Fatalf("did not expect AUTH_REQUIRED_BUT_NOT_ADVERTISED when OAuth discovery is advertised")
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status == "FAIL" {
		t.Fatalf("expected step 3 to avoid failing when PRM is available, got %+v", step)
	}
}

func TestNoAuthRequiredDoesNotTriggerAuthFinding(t *testing.T) {
	server := newNoAuthServer(t)
	defer server.Close()

	report := runScanForServerAllowNoFindings(t, server.URL+"/mcp")

	if hasFinding(report.Findings, "AUTH_REQUIRED_BUT_NOT_ADVERTISED") {
		t.Fatalf("did not expect AUTH_REQUIRED_BUT_NOT_ADVERTISED for public server")
	}
	if hasFinding(report.Findings, "DISCOVERY_NO_WWW_AUTHENTICATE") {
		t.Fatalf("did not expect DISCOVERY_NO_WWW_AUTHENTICATE for public server")
	}
}

func TestDiscoveryNoWWWAuthenticateButPRMAvailable(t *testing.T) {
	server := newSentryLikeServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if hasFinding(report.Findings, "AUTH_REQUIRED_BUT_NOT_ADVERTISED") {
		t.Fatalf("did not expect AUTH_REQUIRED_BUT_NOT_ADVERTISED when PRM is available")
	}
	got := findFinding(report.Findings, "DISCOVERY_NO_WWW_AUTHENTICATE")
	if got == nil {
		t.Fatalf("expected DISCOVERY_NO_WWW_AUTHENTICATE finding")
	}
	if got.Severity != "low" {
		t.Fatalf("expected DISCOVERY_NO_WWW_AUTHENTICATE severity low, got %q", got.Severity)
	}
	if report.PrimaryFinding.Code != "" {
		t.Fatalf("expected no primary finding, got %q", report.PrimaryFinding.Code)
	}
}

func TestDiscoveryNoWWWAuthenticateDeadEnd(t *testing.T) {
	server := newDeadEndDiscoveryServer(t)
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if report.PrimaryFinding.Code != "AUTH_REQUIRED_BUT_NOT_ADVERTISED" {
		t.Fatalf("expected primary finding AUTH_REQUIRED_BUT_NOT_ADVERTISED, got %q", report.PrimaryFinding.Code)
	}
	if !hasFinding(report.Findings, "AUTH_REQUIRED_BUT_NOT_ADVERTISED") {
		t.Fatalf("expected AUTH_REQUIRED_BUT_NOT_ADVERTISED finding")
	}
}

func newAuthRequiredNoDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32001,
				"message": "Authentication failed: Unable to verify your user identity",
			},
		})
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return httptest.NewServer(mux)
}

func newOAuthDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	baseURL := server.URL
	wwwAuth := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL)

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", wwwAuth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("WWW-Authenticate", wwwAuth)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32001,
				"message": "Unauthorized",
			},
		})
	})

	prmPayload := map[string]any{
		"resource":              baseURL + "/mcp",
		"authorization_servers": []string{baseURL + "/issuer"},
	}
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prmPayload)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prmPayload)
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
			"code_challenge_methods_supported": []string{
				"S256",
			},
		})
	})

	return server
}

func newNoAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}

		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": SupportedMCPProtocolVersion,
					"capabilities":    map[string]any{},
				},
			})
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	return httptest.NewServer(mux)
}

func newSentryLikeServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32001,
				"message": "Unauthorized",
			},
		})
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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
			"token_endpoint":         baseURL + "/token",
			"registration_endpoint":  baseURL + "/register",
			"code_challenge_methods_supported": []string{
				"S256",
			},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	return server
}

func newDeadEndDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

func runScanForServerAllowNoFindings(t *testing.T, target string) ScanReport {
	t.Helper()
	var stdout bytes.Buffer
	var verbose bytes.Buffer
	report, _, err := RunScanFunnel(ScanConfig{
		Target:              target,
		Timeout:             5 * time.Second,
		MCPMode:             "best-effort",
		RFCMode:             "best-effort",
		AllowPrivateIssuers: true,
		Insecure:            true,
	}, &stdout, &verbose)
	if err != nil {
		t.Fatalf("RunScanFunnel error: %v", err)
	}
	return report
}
