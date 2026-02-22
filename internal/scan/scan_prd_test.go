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

func TestRootPRM404PathPRM200(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL
	issuer := baseURL + "/issuer"

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfigInsecure(t, baseURL+"/mcp", true, "best-effort")
	got := findFinding(report.Findings, "DISCOVERY_ROOT_WELLKNOWN_404")
	if got == nil {
		t.Fatalf("expected DISCOVERY_ROOT_WELLKNOWN_404 finding")
	}
	if got.Severity != "low" {
		t.Fatalf("expected DISCOVERY_ROOT_WELLKNOWN_404 severity low, got %q", got.Severity)
	}
	if report.PrimaryFinding.Code != "" {
		t.Fatalf("expected no primary finding, got %q", report.PrimaryFinding.Code)
	}
	if !report.PRMOK {
		t.Fatalf("expected prm_ok to be true")
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status != "PASS" {
		t.Fatalf("expected step 3 to pass, got %+v", step)
	}
}

func TestOriginOnlyRootPRM404Fails(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	report := runScanWithConfigInsecure(t, baseURL, true, "best-effort")
	got := findFinding(report.Findings, "DISCOVERY_ROOT_WELLKNOWN_404")
	if got == nil {
		t.Fatalf("expected DISCOVERY_ROOT_WELLKNOWN_404 finding")
	}
	if got.Severity != "high" {
		t.Fatalf("expected DISCOVERY_ROOT_WELLKNOWN_404 severity high, got %q", got.Severity)
	}
	if report.PrimaryFinding.Code != "OAUTH_DISCOVERY_UNAVAILABLE" && report.PrimaryFinding.Code != "DISCOVERY_ROOT_WELLKNOWN_404" {
		t.Fatalf("expected primary finding OAUTH_DISCOVERY_UNAVAILABLE or DISCOVERY_ROOT_WELLKNOWN_404, got %q", report.PrimaryFinding.Code)
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 3 to fail, got %+v", step)
	}
}

func TestAllPRMEndpointsFail(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	report := runScanWithConfigInsecure(t, baseURL+"/mcp", true, "best-effort")
	if !hasFinding(report.Findings, "OAUTH_DISCOVERY_UNAVAILABLE") {
		t.Fatalf("expected OAUTH_DISCOVERY_UNAVAILABLE Finding")
	}
	if report.PrimaryFinding.Code != "OAUTH_DISCOVERY_UNAVAILABLE" {
		t.Fatalf("expected primary finding OAUTH_DISCOVERY_UNAVAILABLE, got %q", report.PrimaryFinding.Code)
	}
	if step := findStep(report.Steps, 3); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 3 to fail, got %+v", step)
	}
}

func TestPRMMissingAuthorizationServers(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource": baseURL,
		})
	})

	report := runScanWithConfig(t, baseURL, true, "best-effort")
	if !hasFinding(report.Findings, "PRM_MISSING_AUTHORIZATION_SERVERS") {
		t.Fatalf("expected PRM_MISSING_AUTHORIZATION_SERVERS Finding")
	}
}

func TestPRMResourceMismatch(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/other",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfig(t, baseURL, true, "best-effort")
	if !hasFinding(report.Findings, "PRM_RESOURCE_MISMATCH") {
		t.Fatalf("expected PRM_RESOURCE_MISMATCH Finding")
	}
}

func TestPRMResourceExactMatch(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
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
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfig(t, baseURL+"/mcp", true, "best-effort")
	if hasFinding(report.Findings, "PRM_RESOURCE_MISMATCH") {
		t.Fatalf("did not expect PRM_RESOURCE_MISMATCH Finding")
	}
	if hasFinding(report.Findings, "PRM_RESOURCE_TRAILING_SLASH") {
		t.Fatalf("did not expect PRM_RESOURCE_TRAILING_SLASH Finding")
	}
}

func TestPRMResourceTrailingSlashWarning(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
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
			"resource":              baseURL + "/mcp/",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfig(t, baseURL+"/mcp", true, "best-effort")
	if !hasFinding(report.Findings, "PRM_RESOURCE_TRAILING_SLASH") {
		t.Fatalf("expected PRM_RESOURCE_TRAILING_SLASH Finding")
	}
	if hasFinding(report.Findings, "PRM_RESOURCE_MISMATCH") {
		t.Fatalf("did not expect PRM_RESOURCE_MISMATCH Finding")
	}
}

func TestPRMResourceMatrixTrailingSlashWarning(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
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
			"resource":              baseURL + "/mcp/",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfig(t, baseURL+"/mcp/", true, "best-effort")
	if !hasFinding(report.Findings, "PRM_RESOURCE_TRAILING_SLASH") {
		t.Fatalf("expected PRM_RESOURCE_TRAILING_SLASH Finding")
	}
	if hasFinding(report.Findings, "PRM_RESOURCE_MISMATCH") {
		t.Fatalf("did not expect PRM_RESOURCE_MISMATCH Finding")
	}
}

func TestHeaderStrippedByProxySuspected(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
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
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	report := runScanWithConfig(t, baseURL+"/mcp", true, "best-effort")
	if !hasFinding(report.Findings, "HEADER_STRIPPED_BY_PROXY_SUSPECTED") {
		t.Fatalf("expected HEADER_STRIPPED_BY_PROXY_SUSPECTED Finding")
	}
}

func TestPRMPathSuffixMissing(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource": baseURL + "/mcp",
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	report := runScanWithConfig(t, baseURL+"/mcp", true, "best-effort")
	if !hasFinding(report.Findings, "PRM_WELLKNOWN_PATH_SUFFIX_MISSING") {
		t.Fatalf("expected PRM_WELLKNOWN_PATH_SUFFIX_MISSING Finding")
	}
}

func TestPRMJWKSURINotHTTPS(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource": baseURL,
			"jwks_uri": "http://example.com/jwks",
		})
	})

	report := runScanWithConfig(t, baseURL, true, "best-effort")
	if !hasFinding(report.Findings, "PRM_JWKS_URI_NOT_HTTPS") {
		t.Fatalf("expected PRM_JWKS_URI_NOT_HTTPS Finding")
	}
}

func TestAuthServerIssuerPrivateBlocked(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL,
			"authorization_servers": []string{"http://127.0.0.1:1234/issuer"},
		})
	})

	report := runScanWithConfig(t, baseURL, false, "off")
	if !hasFinding(report.Findings, "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED") {
		t.Fatalf("expected AUTH_SERVER_ISSUER_PRIVATE_BLOCKED Finding")
	}
}

func runScanWithConfig(t *testing.T, target string, allowPrivate bool, rfcMode string) ScanReport {
	t.Helper()
	var stdout bytes.Buffer
	var verbose bytes.Buffer
	report, _, err := RunScanFunnel(ScanConfig{
		Target:              target,
		Timeout:             5 * time.Second,
		MCPMode:             "best-effort",
		RFCMode:             rfcMode,
		AllowPrivateIssuers: allowPrivate,
	}, &stdout, &verbose)
	if err != nil {
		t.Fatalf("RunScanFunnel error: %v", err)
	}
	return report
}

func runScanWithConfigInsecure(t *testing.T, target string, allowPrivate bool, rfcMode string) ScanReport {
	t.Helper()
	var stdout bytes.Buffer
	var verbose bytes.Buffer
	report, _, err := RunScanFunnel(ScanConfig{
		Target:              target,
		Timeout:             5 * time.Second,
		MCPMode:             "best-effort",
		RFCMode:             rfcMode,
		AllowPrivateIssuers: allowPrivate,
		Insecure:            true,
	}, &stdout, &verbose)
	if err != nil {
		t.Fatalf("RunScanFunnel error: %v", err)
	}
	return report
}

func TestAllowPrivateIssuersSuppressesHTTPSEnforcementForLocalMCP(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	baseURL := server.URL
	target := baseURL + "/mcp"

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "test", "version": "1"}}})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": target, "authorization_servers": []string{baseURL}})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": target, "authorization_servers": []string{baseURL}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": baseURL, "authorization_endpoint": baseURL + "/authorize", "token_endpoint": baseURL + "/token", "registration_endpoint": baseURL + "/register"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_request"})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
	})

	var stdout bytes.Buffer
	var verbose bytes.Buffer
	report, _, err := RunScanFunnel(ScanConfig{Target: target, Timeout: 5 * time.Second, MCPMode: "off", RFCMode: "best-effort", AllowPrivateIssuers: true}, &stdout, &verbose)
	if err != nil {
		t.Fatalf("RunScanFunnel error: %v", err)
	}
	if hasFinding(report.Findings, "RFC3986_ABSOLUTE_HTTPS_REQUIRED") {
		t.Fatalf("did not expect RFC3986_ABSOLUTE_HTTPS_REQUIRED when allow-private-issuers is true")
	}
}

func TestPublicServerWithoutPRMSkipsPRMStep(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "test", "version": "1"}}})
	})

	report := runScanWithConfig(t, server.URL+"/mcp", true, "best-effort")
	if step := findStep(report.Steps, 3); step == nil || step.Status != "SKIP" {
		t.Fatalf("expected step 3 to skip for public server without PRM, got %+v", step)
	}
	if hasFinding(report.Findings, "OAUTH_DISCOVERY_UNAVAILABLE") {
		t.Fatalf("did not expect OAUTH_DISCOVERY_UNAVAILABLE finding for public server")
	}
}
