package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authMCPServer validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func authMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+r.URL.Scheme+`://`+r.Host+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing token"}`))
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: message\ndata: ok\n\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// TestScanHTTPAuthRequired validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestScanHTTPAuthRequired(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe_scan_http", map[string]any{"target_url": ts.URL + "/mcp", "mcp_mode": "off"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", result["status"])
	}
	if result["next_action"] == nil {
		t.Fatalf("expected next_action")
	}
}

// TestScanHTTPAuthenticated validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestScanHTTPAuthenticated(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe_scan_http_authenticated", map[string]any{"target_url": ts.URL + "/mcp", "authorization": "Bearer test-token", "mcp_mode": "off"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected ok, got %v", result["status"])
	}
}

// TestRedactionNoTokenLeak validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestRedactionNoTokenLeak(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe_scan_http_authenticated", map[string]any{"target_url": ts.URL + "/mcp", "authorization": "Bearer super-secret-token", "mcp_mode": "off"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "super-secret-token") {
		t.Fatalf("token leaked in result: %s", string(payload))
	}
}

// TestToolDescriptionsContainAuthFlowInstruction validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestToolDescriptionsContainAuthFlowInstruction(t *testing.T) {
	tools := toolDefinitions()
	for _, tool := range tools {
		if tool["name"] == "authprobe_scan_http" {
			desc := tool["description"].(string)
			if !strings.Contains(desc, "auth_required") || !strings.Contains(desc, "scan_http_authenticated") {
				t.Fatalf("scan_http description missing orchestration guidance: %s", desc)
			}
			return
		}
	}
	t.Fatalf("scan tool not found")
}

// TestHTTPTransportInitialize validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestHTTPTransportInitialize(t *testing.T) {
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	h := httptest.NewServer(http.HandlerFunc(s.ServeHTTP))
	defer h.Close()

	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	resp, err := http.Post(h.URL, "application/json", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != nil {
		t.Fatalf("unexpected rpc error: %v", payload["error"])
	}
}

// TestRejectsNullJSONRPCID validates expected behavior for this unit-test scenario.
// Inputs: testing context plus scenario-specific fixtures/arguments.
// Outputs: none (fails test on unexpected results).
func TestRejectsNullJSONRPCID(t *testing.T) {
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	h := httptest.NewServer(http.HandlerFunc(s.ServeHTTP))
	defer h.Close()

	req := []byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list","params":{}}`)
	resp, err := http.Post(h.URL, "application/json", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected JSON-RPC error, got: %v", payload)
	}
	if errObj["code"] != float64(-32600) {
		t.Fatalf("expected error code -32600, got: %v", errObj["code"])
	}
}
