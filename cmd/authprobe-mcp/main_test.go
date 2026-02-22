package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authprobe/internal/mcpserver"
)

// TestStartupConnectMessageStdio validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestStartupConnectMessageStdio(t *testing.T) {
	msg := startupConnectMessage("stdio", "127.0.0.1:38080", "/mcp", false)
	if !strings.Contains(msg, "Client config") {
		t.Fatalf("expected client config in startup message, got: %s", msg)
	}
	if !strings.Contains(msg, `"command"`) || !strings.Contains(msg, `"args"`) {
		t.Fatalf("expected command/args in startup message, got: %s", msg)
	}
}

// TestStartupConnectMessageHTTP validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestStartupConnectMessageHTTP(t *testing.T) {
	msg := startupConnectMessage("http", "127.0.0.1:38080", "mcp", true)
	if !strings.Contains(msg, "http://127.0.0.1:38080/mcp") {
		t.Fatalf("expected HTTP URL in startup message, got: %s", msg)
	}
	if !strings.Contains(msg, "auth-required") {
		t.Fatalf("expected auth mode in startup message, got: %s", msg)
	}
}

// TestNormalizePath validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/mcp"},
		{"mcp", "/mcp"},
		{"/mcp", "/mcp"},
	}
	for _, tc := range cases {
		if got := normalizePath(tc.in); got != tc.want {
			t.Fatalf("normalizePath(%q) got %q want %q", tc.in, got, tc.want)
		}
	}
}

// TestHTTPMCPProbeChallenge validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestHTTPMCPProbeChallenge(t *testing.T) {
	s := mcpserver.New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	ts := httptest.NewServer(buildHTTPMux(s, "/mcp", true))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status got %d want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("missing resource_metadata challenge header")
	}
}

// TestHTTPMCPProbePublicMode validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestHTTPMCPProbePublicMode(t *testing.T) {
	s := mcpserver.New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	ts := httptest.NewServer(buildHTTPMux(s, "/mcp", false))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status got %d want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestHTTPPRMDiscoveryEndpoints validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestHTTPPRMDiscoveryEndpoints(t *testing.T) {
	s := mcpserver.New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	ts := httptest.NewServer(buildHTTPMux(s, "/mcp", true))
	defer ts.Close()

	for _, endpoint := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(ts.URL + endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status got %d want %d", endpoint, resp.StatusCode, http.StatusOK)
		}
		var payload map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			_ = resp.Body.Close()
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if payload["resource"] != ts.URL+"/mcp" {
			t.Fatalf("%s resource got %v", endpoint, payload["resource"])
		}
		servers, ok := payload["authorization_servers"].([]any)
		if !ok || len(servers) == 0 {
			t.Fatalf("%s missing authorization_servers", endpoint)
		}
	}
}

// TestHTTPPRMDiscoveryDisabledInPublicMode validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestHTTPPRMDiscoveryDisabledInPublicMode(t *testing.T) {
	s := mcpserver.New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	ts := httptest.NewServer(buildHTTPMux(s, "/mcp", false))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status got %d want %d", resp.StatusCode, http.StatusNotFound)
	}
}
