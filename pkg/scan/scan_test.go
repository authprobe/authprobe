package scan_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	publicscan "authprobe/pkg/scan"
)

// TestRunScansHTTPMCPServerThroughPublicAPI proves embedders can run the engine without CLI subprocesses.
//
// Args:
//   - t *testing.T: Test controller used for assertions and cleanup.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Fails when the public API cannot produce a typed report from an httptest server.
func TestRunScansHTTPMCPServerThroughPublicAPI(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	targetURL := server.URL + "/mcp"
	issuerURL := server.URL + "/issuer"
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              targetURL,
			"authorization_servers": []string{issuerURL},
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              targetURL,
			"authorization_servers": []string{issuerURL},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuerURL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})

	result, err := publicscan.Run(publicscan.Options{
		TargetURL:           targetURL,
		MCPMode:             publicscan.MCPModeBestEffort,
		RFCMode:             publicscan.RFCModeBestEffort,
		Timeout:             2 * time.Second,
		Headers:             http.Header{"X-Test-Caller": []string{"mcpd"}},
		AllowPrivateIssuers: true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Report.Target != targetURL {
		t.Fatalf("report target = %q, want %q", result.Report.Target, targetURL)
	}
	if result.Report.MCPMode != string(publicscan.MCPModeBestEffort) {
		t.Fatalf("report MCP mode = %q", result.Report.MCPMode)
	}
	if result.Report.RFCMode != string(publicscan.RFCModeBestEffort) {
		t.Fatalf("report RFC mode = %q", result.Report.RFCMode)
	}
	if !result.Report.PRMOK {
		t.Fatalf("expected PRMOK in report")
	}
	if result.Report.AuthDiscovery.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("token endpoint = %q", result.Report.AuthDiscovery.TokenEndpoint)
	}
	if len(result.Report.Steps) != 6 {
		t.Fatalf("step count = %d, want 6", len(result.Report.Steps))
	}
	if !strings.Contains(result.Summary.Stdout, "Funnel") {
		t.Fatalf("summary stdout did not include funnel output")
	}
}

// TestValidateOptionsAcceptsDefaults proves omitted modes and timeouts stay usable for callers.
//
// Args:
//   - t *testing.T: Test controller used for assertions.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Fails when defaultable options are rejected.
func TestValidateOptionsAcceptsDefaults(t *testing.T) {
	if err := publicscan.ValidateOptions(publicscan.Options{TargetURL: "https://mcp.example.com/mcp"}); err != nil {
		t.Fatalf("ValidateOptions returned error: %v", err)
	}
}

// TestValidateOptionsRejectsInvalidTarget proves target URLs are validated before network I/O.
//
// Args:
//   - t *testing.T: Test controller used for assertions.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Fails when an unsupported target URL passes validation.
func TestValidateOptionsRejectsInvalidTarget(t *testing.T) {
	err := publicscan.ValidateOptions(publicscan.Options{TargetURL: "file:///tmp/socket"})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("validation error = %q, want scheme detail", err.Error())
	}
}

// TestValidateOptionsRejectsInvalidMode proves typed modes fail fast when cast from bad strings.
//
// Args:
//   - t *testing.T: Test controller used for assertions.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Fails when unsupported MCP or RFC modes are accepted.
func TestValidateOptionsRejectsInvalidMode(t *testing.T) {
	err := publicscan.ValidateOptions(publicscan.Options{
		TargetURL: "https://mcp.example.com/mcp",
		MCPMode:   publicscan.MCPMode("aggressive"),
	})
	if err == nil {
		t.Fatalf("expected MCP mode validation error")
	}
	if !strings.Contains(err.Error(), "mcp mode") {
		t.Fatalf("validation error = %q, want MCP mode detail", err.Error())
	}
}

// TestValidateOptionsRejectsUnsafeHeader proves header values cannot smuggle extra lines.
//
// Args:
//   - t *testing.T: Test controller used for assertions.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Fails when malformed headers are accepted.
func TestValidateOptionsRejectsUnsafeHeader(t *testing.T) {
	err := publicscan.ValidateOptions(publicscan.Options{
		TargetURL: "https://mcp.example.com/mcp",
		Headers:   http.Header{"X-Test": []string{"ok\r\nInjected: true"}},
	})
	if err == nil {
		t.Fatalf("expected header validation error")
	}
	if !strings.Contains(err.Error(), "newline") {
		t.Fatalf("validation error = %q, want newline detail", err.Error())
	}
}
