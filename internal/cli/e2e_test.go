package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authprobe/internal/scan"
)

// ---------------------------------------------------------------------------
// E2E helper: run the full CLI Run() against a test server
// ---------------------------------------------------------------------------

func runE2E(t *testing.T, args []string) (stdout, stderr string, exitCode int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

// ---------------------------------------------------------------------------
// Mock server builders
// ---------------------------------------------------------------------------

// newFullOAuthServer returns an httptest.Server that simulates a fully
// RFC-compliant MCP OAuth flow: 401 with PRM hint → valid PRM → valid
// auth server metadata (RFC 8414) → token endpoint → DCR endpoint.
func newFullOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL
	issuer := baseURL

	// Step 1: MCP probe → 401 with WWW-Authenticate
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// POST: JSON-RPC (for MCP initialize — returns 401)
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})

	// PRM (root well-known)
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	// PRM (path-suffix)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})

	// Auth server metadata (RFC 8414)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           baseURL + "/authorize",
			"token_endpoint":                   baseURL + "/token",
			"registration_endpoint":            baseURL + "/register",
			"response_types_supported":         []string{"code"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	// Token endpoint → 400 (expected for empty probe request)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
	})

	// DCR endpoint → 401 (requires auth → means NOT open registration)
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	return server
}

// newPublicMCPServer returns an httptest.Server simulating a public (no-auth)
// MCP server that responds with valid JSON-RPC.
func newPublicMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}

		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": "2025-11-25",
					"capabilities":    map[string]any{},
				},
			})
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{"name": "echo", "inputSchema": map[string]any{"type": "object"}},
					},
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

// newOpenDCRServer returns a server where DCR is open (accepts unauthenticated
// registration) — a security finding.
func newOpenDCRServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL
	issuer := baseURL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           baseURL + "/authorize",
			"token_endpoint":                   baseURL + "/token",
			"registration_endpoint":            baseURL + "/register",
			"response_types_supported":         []string{"code"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
	})
	// DCR endpoint → 201 Created (open registration!)
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		})
	})

	return server
}

// new405WithPRMServer simulates a server that returns 405 on GET (like
// Google Compute MCP) but has PRM available.
func new405WithPRMServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL
	issuer := baseURL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{issuer},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           baseURL + "/authorize",
			"token_endpoint":                   baseURL + "/token",
			"response_types_supported":         []string{"code"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
	})

	return server
}

// ---------------------------------------------------------------------------
// E2E tests: full CLI Run() invocations
// ---------------------------------------------------------------------------

func TestE2E_FullOAuthCompliant(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	stdout, stderr, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
	// Output should contain funnel steps
	if !strings.Contains(stdout, "Step 1") {
		t.Error("expected funnel Step 1 in output")
	}
	if !strings.Contains(stdout, "Step 3") {
		t.Error("expected funnel Step 3 in output")
	}
}

func TestE2E_PublicMCPServer(t *testing.T) {
	server := newPublicMCPServer(t)
	defer server.Close()

	stdout, stderr, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	// Public server should show "no OAuth configuration found" or similar
	if !strings.Contains(stdout, "Step 1") {
		t.Error("expected funnel Step 1 in output")
	}
}

func TestE2E_OpenDCRFinding(t *testing.T) {
	server := newOpenDCRServer(t)
	defer server.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	stdout, stderr, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--json", jsonPath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON: %v", err)
	}
	var report scan.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.Code == "DCR_ENDPOINT_OPEN" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DCR_ENDPOINT_OPEN finding in report, got findings: %+v", report.Findings)
	}
}

func TestE2E_405WithPRMDiscovery(t *testing.T) {
	server := new405WithPRMServer(t)
	defer server.Close()

	stdout, stderr, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	// 405 should still discover auth via PRM
	if !strings.Contains(stdout, "Step 3") {
		t.Error("expected Step 3 (PRM) in output")
	}
}

func TestE2E_FailOnHigh(t *testing.T) {
	server := newOpenDCRServer(t)
	defer server.Close()

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--fail-on", "high",
		"--allow-private-issuers",
	})

	// DCR_ENDPOINT_OPEN is high severity → should exit 2
	if code != 2 {
		t.Fatalf("expected exit 2 (high-severity finding), got %d", code)
	}
}

func TestE2E_FailOnNone(t *testing.T) {
	server := newOpenDCRServer(t)
	defer server.Close()

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0 (fail-on=none), got %d", code)
	}
}

func TestE2E_VerboseOutput(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	stdout, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--verbose",
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	// Verbose output should contain HTTP request/response markers
	if !strings.Contains(stdout, "==") {
		t.Error("expected verbose section headings (== ... ==)")
	}
}

func TestE2E_JSONOutputToFile(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--json", jsonPath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	var report scan.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON output: %v\ncontent: %s", err, string(data))
	}
	if report.Target != server.URL+"/mcp" {
		t.Errorf("target mismatch: got %q", report.Target)
	}
	if len(report.Steps) == 0 {
		t.Error("expected at least one step in JSON report")
	}
}

func TestE2E_MarkdownOutputToFile(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()
	mdPath := filepath.Join(dir, "report.md")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--md", mdPath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read MD output: %v", err)
	}
	md := string(data)
	if !strings.Contains(md, "# AuthProbe report") {
		preview := md
		if len(preview) > 200 {
			preview = preview[:200]
		}
		t.Errorf("expected markdown heading '# AuthProbe report', got:\n%s", preview)
	}
	if !strings.Contains(md, "Scanning:") {
		t.Error("expected 'Scanning:' in markdown")
	}
}

func TestE2E_TraceASCIIOutputToFile(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.txt")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--trace-ascii", tracePath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("failed to read trace output: %v", err)
	}
	trace := string(data)
	if len(trace) == 0 {
		t.Error("expected non-empty trace output")
	}
}

func TestE2E_BundleOutputToFile(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.zip")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--bundle", bundlePath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("bundle file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("bundle file is empty")
	}
}

func TestE2E_OutputDir(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--json", "report.json",
		"--md", "report.md",
		"--output-dir", dir,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Error("expected report.json in output dir")
	}
	if _, err := os.Stat(filepath.Join(dir, "report.md")); err != nil {
		t.Error("expected report.md in output dir")
	}
}

func TestE2E_MissingURL(t *testing.T) {
	_, stderr, code := runE2E(t, []string{"scan"})

	if code != 3 {
		t.Fatalf("expected exit 3, got %d", code)
	}
	if !strings.Contains(stderr, "<mcp_url> is required") {
		t.Errorf("expected URL required error, got: %s", stderr)
	}
}

func TestE2E_UnknownCommand(t *testing.T) {
	_, _, code := runE2E(t, []string{"bogus"})
	if code != 3 {
		t.Fatalf("expected exit 3 for unknown command, got %d", code)
	}
}

func TestE2E_Help(t *testing.T) {
	stdout, _, code := runE2E(t, []string{"--help"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "authprobe") {
		t.Error("expected help output")
	}
}

func TestE2E_ScanHelp(t *testing.T) {
	stdout, _, code := runE2E(t, []string{"scan", "--help"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "scan") {
		t.Error("expected scan help output")
	}
}

func TestE2E_VerboseWithMarkdown(t *testing.T) {
	server := newFullOAuthServer(t)
	defer server.Close()

	dir := t.TempDir()
	mdPath := filepath.Join(dir, "report.md")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--verbose",
		"--md", mdPath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read MD: %v", err)
	}
	md := string(data)
	// When --verbose and --md are combined, verbose output should be appended
	if !strings.Contains(md, "Verbose output") {
		t.Error("expected verbose section in markdown when --verbose and --md are combined")
	}
}

func TestE2E_MCPModeOff(t *testing.T) {
	server := newPublicMCPServer(t)
	defer server.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	_, _, code := runE2E(t, []string{
		"scan", server.URL + "/mcp",
		"--mcp", "off",
		"--json", jsonPath,
		"--fail-on", "none",
		"--allow-private-issuers",
	})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON: %v", err)
	}
	var report scan.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// With --mcp off, Step 2 should be SKIP
	for _, step := range report.Steps {
		if step.ID == 2 && step.Status != "SKIP" {
			t.Errorf("expected Step 2 to be SKIP with --mcp off, got %q", step.Status)
		}
	}
}

func TestE2E_InvalidFlag(t *testing.T) {
	_, _, code := runE2E(t, []string{"scan", "--no-such-flag", "https://example.com"})
	if code != 3 {
		t.Fatalf("expected exit 3 for invalid flag, got %d", code)
	}
}
