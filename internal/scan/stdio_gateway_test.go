package scan

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartStdioGateway_DebugShowsAuthprobeProbePayloads(t *testing.T) {
	tmpDir := t.TempDir()
	serverPath := filepath.Join(tmpDir, "mock_stdio_server.sh")
	serverScript := `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mock","version":"1.0"}}}'
      ;;
    *'"method":"tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo","inputSchema":{"type":"object"}}]}}'
      ;;
    *)
      printf '%s\n' '{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"unsupported"}}'
      ;;
  esac
done
`
	if err := os.WriteFile(serverPath, []byte(serverScript), 0o700); err != nil {
		t.Fatalf("write mock stdio server: %v", err)
	}

	target, cleanup, err := StartStdioGateway(serverPath, "/mcp", 4*time.Second)
	if err != nil {
		t.Fatalf("StartStdioGateway: %v", err)
	}
	defer cleanup()

	client := &http.Client{Timeout: 4 * time.Second}
	config := ScanConfig{Target: target, Timeout: 4 * time.Second}
	trace := []TraceEntry{}
	tools, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("unexpected tools: %#v", tools)
	}

	debugURL := strings.TrimSuffix(target, "/mcp") + "/debug"
	resp, err := client.Get(debugURL)
	if err != nil {
		t.Fatalf("GET debug: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("debug status: got %d want %d", resp.StatusCode, http.StatusOK)
	}
	var debug struct {
		Command      string `json:"command"`
		RequestCount int    `json:"request_count"`
		LastRequest  string `json:"last_request"`
		LastResponse string `json:"last_response"`
		LastError    string `json:"last_error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&debug); err != nil {
		t.Fatalf("decode debug: %v", err)
	}

	if debug.RequestCount < 2 {
		t.Fatalf("request_count: got %d want >=2", debug.RequestCount)
	}
	if strings.TrimSpace(debug.Command) == "" {
		t.Fatalf("expected command to be present, got %q", debug.Command)
	}
	if !strings.Contains(debug.LastRequest, `"method":"tools/list"`) {
		t.Fatalf("last_request missing tools/list: %q", debug.LastRequest)
	}
	if !strings.Contains(debug.LastResponse, `"tools":[`) {
		t.Fatalf("last_response missing tools payload: %q", debug.LastResponse)
	}
	if debug.LastError != "" {
		t.Fatalf("unexpected last_error: %q", debug.LastError)
	}
}

func TestStartStdioGateway_CustomPath(t *testing.T) {
	tmpDir := t.TempDir()
	serverPath := filepath.Join(tmpDir, "mock_stdio_server.sh")
	serverScript := `#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
done
`
	if err := os.WriteFile(serverPath, []byte(serverScript), 0o700); err != nil {
		t.Fatalf("write mock stdio server: %v", err)
	}
	target, cleanup, err := StartStdioGateway(serverPath, "/custom-endpoint", 2*time.Second)
	if err != nil {
		t.Fatalf("StartStdioGateway: %v", err)
	}
	defer cleanup()
	if !strings.HasSuffix(target, "/custom-endpoint") {
		t.Fatalf("target mismatch: %q", target)
	}
}

func TestStartStdioGateway_StreamableHTTPMethods(t *testing.T) {
	tmpDir := t.TempDir()
	serverPath := filepath.Join(tmpDir, "mock_stdio_server.sh")
	serverScript := `#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
done
`
	if err := os.WriteFile(serverPath, []byte(serverScript), 0o700); err != nil {
		t.Fatalf("write mock stdio server: %v", err)
	}

	target, cleanup, err := StartStdioGateway(serverPath, "/", 2*time.Second)
	if err != nil {
		t.Fatalf("StartStdioGateway: %v", err)
	}
	defer cleanup()

	client := &http.Client{Timeout: 2 * time.Second}

	getResp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET gateway root: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status: got %d want %d", getResp.StatusCode, http.StatusOK)
	}
	if got := getResp.Header.Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("GET content-type: got %q want includes %q", got, "text/event-stream")
	}

	optionsReq, err := http.NewRequest(http.MethodOptions, target, nil)
	if err != nil {
		t.Fatalf("OPTIONS request: %v", err)
	}
	optionsResp, err := client.Do(optionsReq)
	if err != nil {
		t.Fatalf("OPTIONS gateway root: %v", err)
	}
	defer optionsResp.Body.Close()
	if optionsResp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatalf("OPTIONS status must not be 405")
	}
}
