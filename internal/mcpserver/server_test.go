package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

type oauthFixture struct {
	server       *httptest.Server
	authorized   atomic.Bool
	tokenPolls   atomic.Int32
	probeWaitHit atomic.Bool
}

type dcrOnlyFixture struct {
	server      *httptest.Server
	registerHit atomic.Int32
}

// newDCROnlyFixture returns an OAuth fixture that advertises DCR but no device flow.
// Inputs: testing handle.
// Outputs: fixture with test server URL and register call counter.
func newDCROnlyFixture(t *testing.T) *dcrOnlyFixture {
	t.Helper()
	fx := &dcrOnlyFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, fx.server.URL))
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"ok","version":"1"}}}`))
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"resource":"%s/mcp","authorization_servers":["%s"]}`, fx.server.URL, fx.server.URL)))
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/authorize","registration_endpoint":"%s/register","token_endpoint":"%s/token","grant_types_supported":["authorization_code"]}`, fx.server.URL, fx.server.URL, fx.server.URL, fx.server.URL)))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		fx.registerHit.Add(1)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		redirects, _ := req["redirect_uris"].([]any)
		grantTypes, _ := req["grant_types"].([]any)
		hasAuthCode := false
		for _, gt := range grantTypes {
			if s, _ := gt.(string); s == "authorization_code" {
				hasAuthCode = true
				break
			}
		}
		if len(redirects) == 0 || !hasAuthCode {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client_metadata","error_description":"redirect_uris and authorization_code required"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"dcr-only-client"}`))
	})
	fx.server = httptest.NewServer(mux)
	return fx
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	fx := &oauthFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.RawQuery, "hang=1") {
				fx.probeWaitHit.Store(true)
				time.Sleep(2500 * time.Millisecond)
			}
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, fx.server.URL))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"missing token"}`))
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: message\ndata: ok\n\n"))
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing token"}`))
			return
		}
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
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"resource":"%s/mcp","authorization_servers":["%s"]}`, fx.server.URL, fx.server.URL)))
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/authorize","registration_endpoint":"%s/register","token_endpoint":"%s/token","device_authorization_endpoint":"%s/device","grant_types_supported":["urn:ietf:params:oauth:grant-type:device_code"]}`, fx.server.URL, fx.server.URL, fx.server.URL, fx.server.URL, fx.server.URL)))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-123"}`))
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"device_code":"dev-123","verification_uri_complete":"%s/verify?user_code=ABCD","verification_uri":"%s/verify","user_code":"ABCD","interval":1,"expires_in":600}`, fx.server.URL, fx.server.URL)))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fx.tokenPolls.Add(1)
		if !fx.authorized.Load() {
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"fixture-access-token","token_type":"Bearer","expires_in":3600}`))
	})
	fx.server = httptest.NewServer(mux)
	return fx
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

func TestScanHTTPAutoUnavailableIncludesReason(t *testing.T) {
	ts := authMCPServer(t)
	defer ts.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": ts.URL + "/mcp", "auth_assist": "auto", "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", result["status"])
	}
	authAssist, ok := result["auth_assist"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth_assist details")
	}
	if authAssist["status"] != "unavailable" {
		t.Fatalf("expected unavailable auth_assist status, got %v", authAssist["status"])
	}
	reason, _ := authAssist["reason"].(string)
	if !strings.Contains(reason, "device_authorization_endpoint") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestScanHTTPAutoRunsDCRWithoutDeviceFlow(t *testing.T) {
	fx := newDCROnlyFixture(t)
	defer fx.server.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": fx.server.URL + "/mcp", "auth_assist": "auto", "allow_private_issuers": true, "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", result["status"])
	}
	authAssist, ok := result["auth_assist"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth_assist details")
	}
	if authAssist["status"] != "dcr_completed" {
		t.Fatalf("expected dcr_completed status, got %v", authAssist["status"])
	}
	if authAssist["client_id"] != "dcr-only-client" {
		t.Fatalf("expected client_id from dcr, got %v", authAssist["client_id"])
	}
	authReq, ok := result["auth_request"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth_request details")
	}
	if authReq["client_id"] != "dcr-only-client" {
		t.Fatalf("expected auth_request.client_id from dcr, got %v", authReq["client_id"])
	}
	if fx.registerHit.Load() == 0 {
		t.Fatalf("expected DCR /register endpoint to be called")
	}
}

func TestScanHTTPOffSkipsAutoDCR(t *testing.T) {
	fx := newDCROnlyFixture(t)
	defer fx.server.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	result, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": fx.server.URL + "/mcp", "auth_assist": "off", "allow_private_issuers": true, "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "auth_required" {
		t.Fatalf("expected auth_required, got %v", result["status"])
	}
	if _, ok := result["auth_assist"]; ok {
		t.Fatalf("did not expect auth_assist payload when auth_assist=off")
	}
	authReq, ok := result["auth_request"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth_request details")
	}
	if _, hasClientID := authReq["client_id"]; hasClientID {
		t.Fatalf("did not expect auth_request.client_id when auth_assist=off")
	}
	if fx.registerHit.Load() == 0 {
		t.Fatalf("expected baseline scan DCR probing to hit /register at least once")
	}
}

func TestScanHTTPAutoAndResume(t *testing.T) {
	fx := newOAuthFixture(t)
	defer fx.server.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	start, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": fx.server.URL + "/mcp", "auth_assist": "auto", "allow_private_issuers": true, "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if start["status"] != "awaiting_user_auth" {
		payload, _ := json.Marshal(start)
		t.Fatalf("expected awaiting_user_auth, got %v payload=%s", start["status"], payload)
	}
	scanID, _ := start["scan_id"].(string)
	if scanID == "" {
		t.Fatalf("expected scan_id")
	}
	if _, ok := start["login_url"].(string); !ok {
		t.Fatalf("expected login_url")
	}
	pending, err := s.callTool("authprobe.scan_resume", map[string]any{"scan_id": scanID})
	if err != nil {
		t.Fatal(err)
	}
	if pending["status"] != "awaiting_user_auth" {
		t.Fatalf("expected awaiting_user_auth before authorization, got %v", pending["status"])
	}
	fx.authorized.Store(true)
	done, err := s.callTool("authprobe.scan_resume", map[string]any{"scan_id": scanID})
	if err != nil {
		t.Fatal(err)
	}
	if done["status"] != "ok" {
		t.Fatalf("expected ok, got %v", done["status"])
	}
	payload, _ := json.Marshal(done)
	serialized := string(payload)
	for _, needle := range []string{"fixture-access-token", "access_token", "refresh_token", "id_token", "Bearer "} {
		if strings.Contains(serialized, needle) {
			t.Fatalf("token leaked in result (%s): %s", needle, serialized)
		}
	}
}

func TestScanHTTPAutoProbeTimeoutDoesNotHang(t *testing.T) {
	fx := newOAuthFixture(t)
	defer fx.server.Close()
	s := New(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	started := time.Now()
	result, err := s.callTool("authprobe.scan_http", map[string]any{"target_url": fx.server.URL + "/mcp?hang=1", "auth_assist": "auto", "allow_private_issuers": true, "timeout_seconds": 6, "mcp_mode": "best-effort"})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("scan took too long; probe timeout should fail fast")
	}
	if result["status"] != "awaiting_user_auth" {
		payload, _ := json.Marshal(result)
		t.Fatalf("expected awaiting_user_auth, got %v payload=%s", result["status"], payload)
	}
	if !fx.probeWaitHit.Load() {
		t.Fatalf("fixture did not execute delayed GET probe path")
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
