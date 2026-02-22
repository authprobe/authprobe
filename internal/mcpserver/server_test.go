package mcpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func authMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+"http://"+r.Host+`/.well-known/oauth-protected-resource/mcp"`)
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
		switch r.URL.Path {
		case "/mcp":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			method, _ := req["method"].(string)
			w.Header().Set("Content-Type", "application/json")
			if method == "initialize" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"ok","version":"1"}}}`))
				return
			}
			if method == "tools/list" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"x","inputSchema":{"type":"object"}}]}}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestScanHTTPAuthRequired(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": ts.URL + "/mcp", "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", result["status"])
	}
	if result["auth_request"] == nil || result["next_action"] == nil {
		t.Fatalf("expected auth_request and next_action")
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "Provide Authorization header") {
		t.Fatalf("response should not ask for raw Authorization header")
	}
}

func TestScanHTTPWithCredentialRef(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	t.Setenv("AUTHPROBE_MCP_CREDENTIALS", "ref1=Bearer test-token")
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http_with_credentials", map[string]any{"target_url": ts.URL + "/mcp", "credential_ref": "ref1", "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected ok, got %v", result["status"])
	}
}

func TestRedactionNoTokenLeak(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	t.Setenv("AUTHPROBE_MCP_CREDENTIALS", "ref1=Bearer super-secret-token")
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http_with_credentials", map[string]any{"target_url": ts.URL + "/mcp", "credential_ref": "ref1", "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "super-secret-token") {
		t.Fatalf("token leaked in result: %s", string(payload))
	}
}

func TestCredentialFileProvider(t *testing.T) {
	f, err := os.CreateTemp("", "authprobe-creds-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`{"demo":"Bearer abc"}`)
	_ = f.Close()
	t.Setenv("AUTHPROBE_MCP_CREDENTIALS_FILE", f.Name())
	provider := envCredentialProvider{}
	value, err := provider.ResolveAuthorization(nil, "demo", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if value != "Bearer abc" {
		t.Fatalf("unexpected value %q", value)
	}
}
