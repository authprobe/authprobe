package scan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockMCPServer creates a test HTTP server that implements the MCP protocol.
// It handles the initialize and tools/list JSON-RPC methods.
type mockMCPServer struct {
	// Tools to return from tools/list
	Tools []MCPToolDetail
	// SessionID to return in MCP-Session-Id header (optional)
	SessionID string
	// InitializeProtocolVersion sets the protocolVersion in initialize result.
	InitializeProtocolVersion string
	// InitializeError if set, returns this error from initialize
	InitializeError *jsonRPCError
	// InitializeStatusCode overrides the status code for initialize errors.
	InitializeStatusCode int
	// ToolsListError if set, returns this error from tools/list
	ToolsListError *jsonRPCError
	// ToolsListStatusCode overrides the status code for tools/list errors.
	ToolsListStatusCode int
	// RequireSessionID if true, tools/list requires a valid session ID
	RequireSessionID bool
	// ReceivedRequests tracks all requests received
	ReceivedRequests []jsonRPCRequest
	// ReceivedProtocolVersions tracks MCP-Protocol-Version headers
	ReceivedProtocolVersions []string
}

func (m *mockMCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	m.ReceivedRequests = append(m.ReceivedRequests, req)
	m.ReceivedProtocolVersions = append(m.ReceivedProtocolVersions, r.Header.Get("MCP-Protocol-Version"))

	w.Header().Set("Content-Type", "application/json")

	switch req.Method {
	case "initialize":
		m.handleInitialize(w, req)
	case "tools/list":
		m.handleToolsList(w, r, req)
	default:
		m.writeError(w, req.ID, -32601, "Method not found")
	}
}

func (m *mockMCPServer) handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	if m.InitializeError != nil {
		if m.InitializeStatusCode != 0 {
			w.WriteHeader(m.InitializeStatusCode)
		}
		m.writeErrorResponse(w, req.ID, m.InitializeError)
		return
	}

	// Set session ID header if configured
	if m.SessionID != "" {
		w.Header().Set("MCP-Session-Id", m.SessionID)
	}

	protocolVersion := mcpProtocolVersion
	if strings.TrimSpace(m.InitializeProtocolVersion) != "" {
		protocolVersion = m.InitializeProtocolVersion
	}
	result := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "mock-mcp-server",
			"version": "1.0.0",
		},
	}

	m.writeResult(w, req.ID, result)
}

func (m *mockMCPServer) handleToolsList(w http.ResponseWriter, r *http.Request, req jsonRPCRequest) {
	// Check session ID if required
	if m.RequireSessionID {
		sessionID := r.Header.Get("MCP-Session-Id")
		if sessionID == "" || (m.SessionID != "" && sessionID != m.SessionID) {
			m.writeError(w, req.ID, -32000, "Invalid or missing session ID")
			return
		}
	}

	if m.ToolsListError != nil {
		if m.ToolsListStatusCode != 0 {
			w.WriteHeader(m.ToolsListStatusCode)
		}
		m.writeErrorResponse(w, req.ID, m.ToolsListError)
		return
	}

	result := map[string]any{
		"tools": m.Tools,
	}

	m.writeResult(w, req.ID, result)
}

func (m *mockMCPServer) writeResult(w http.ResponseWriter, id any, result any) {
	resultBytes, _ := json.Marshal(result)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resultBytes,
	}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockMCPServer) writeError(w http.ResponseWriter, id any, code int, message string) {
	m.writeErrorResponse(w, id, &jsonRPCError{Code: code, Message: message})
}

func (m *mockMCPServer) writeErrorResponse(w http.ResponseWriter, id any, err *jsonRPCError) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   err,
	}
	json.NewEncoder(w).Encode(resp)
}

func TestFetchMCPTools_Success(t *testing.T) {
	// Create a mock MCP server with some tools
	mockServer := &mockMCPServer{
		SessionID: "test-session-123",
		Tools: []MCPToolDetail{
			{
				Name:        "echo",
				Description: "Echoes the input back",
			},
			{
				Name:        "add",
				Description: "Adds two numbers",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}}}`),
			},
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	// Create HTTP client and config
	client := &http.Client{}
	config := ScanConfig{
		Target:             server.URL,
		MCPMode:            "best-effort",
		MCPProtocolVersion: mcpProtocolVersion,
	}

	// Call FetchMCPTools with a trace slice (required by addTrace)
	var trace []TraceEntry
	tools, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools failed: %v", err)
	}

	// Verify we got the expected tools
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	if tools[0].Name != "echo" {
		t.Errorf("expected first tool name 'echo', got %q", tools[0].Name)
	}
	if tools[1].Name != "add" {
		t.Errorf("expected second tool name 'add', got %q", tools[1].Name)
	}

	// Verify the server received both requests
	if len(mockServer.ReceivedRequests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(mockServer.ReceivedRequests))
	}
	if mockServer.ReceivedRequests[0].Method != "initialize" {
		t.Errorf("expected first request method 'initialize', got %q", mockServer.ReceivedRequests[0].Method)
	}
	if mockServer.ReceivedRequests[1].Method != "tools/list" {
		t.Errorf("expected second request method 'tools/list', got %q", mockServer.ReceivedRequests[1].Method)
	}
}

func TestFetchMCPTools_EmptyToolsList(t *testing.T) {
	mockServer := &mockMCPServer{
		Tools: []MCPToolDetail{}, // Empty tools list
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	tools, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools failed: %v", err)
	}

	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestFetchMCPTools_InitializeError(t *testing.T) {
	mockServer := &mockMCPServer{
		InitializeError: &jsonRPCError{
			Code:    -32000,
			Message: "Server initialization failed",
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedSubstr := "initialize failed"
	if !containsSubstring(err.Error(), expectedSubstr) {
		t.Errorf("expected error to contain %q, got %q", expectedSubstr, err.Error())
	}
}

func TestFetchMCPTools_ToolsListError(t *testing.T) {
	mockServer := &mockMCPServer{
		ToolsListError: &jsonRPCError{
			Code:    -32000,
			Message: "Tools list unavailable",
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedSubstr := "tools/list failed"
	if !containsSubstring(err.Error(), expectedSubstr) {
		t.Errorf("expected error to contain %q, got %q", expectedSubstr, err.Error())
	}
}

func TestFetchMCPTools_Unauthorized(t *testing.T) {
	// Create a server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedSubstr := "unauthorized"
	if !containsSubstring(err.Error(), expectedSubstr) {
		t.Errorf("expected error to contain %q, got %q", expectedSubstr, err.Error())
	}
}

func TestFetchMCPTools_WithSessionIDFromHeader(t *testing.T) {
	mockServer := &mockMCPServer{
		SessionID:        "header-session-456",
		RequireSessionID: true,
		Tools: []MCPToolDetail{
			{Name: "test-tool"},
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	tools, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools failed: %v", err)
	}

	if len(tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(tools))
	}
}

func TestFetchMCPTools_WithManyTools(t *testing.T) {
	// Create a server with many tools to test pagination-like behavior
	tools := make([]MCPToolDetail, 50)
	for i := 0; i < 50; i++ {
		tools[i] = MCPToolDetail{
			Name:        "tool-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Description: "Test tool number " + string(rune('0'+i)),
		}
	}

	mockServer := &mockMCPServer{
		Tools: tools,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	result, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools failed: %v", err)
	}

	if len(result) != 50 {
		t.Errorf("expected 50 tools, got %d", len(result))
	}
}

func TestFetchMCPTools_ToolWithComplexSchema(t *testing.T) {
	mockServer := &mockMCPServer{
		Tools: []MCPToolDetail{
			{
				Name:        "complex-tool",
				Description: "A tool with complex input/output schemas",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"query": {"type": "string"},
						"options": {
							"type": "object",
							"properties": {
								"limit": {"type": "integer"},
								"offset": {"type": "integer"}
							}
						}
					},
					"required": ["query"]
				}`),
				OutputSchema: json.RawMessage(`{
					"type": "array",
					"items": {"type": "object"}
				}`),
				Annotations: map[string]any{
					"category": "search",
					"version":  "1.0",
				},
			},
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	tools, err := FetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("FetchMCPTools failed: %v", err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	tool := tools[0]
	if tool.Name != "complex-tool" {
		t.Errorf("expected tool name 'complex-tool', got %q", tool.Name)
	}
	if len(tool.InputSchema) == 0 {
		t.Error("expected non-empty input schema")
	}
	if len(tool.OutputSchema) == 0 {
		t.Error("expected non-empty output schema")
	}
	if tool.Annotations["category"] != "search" {
		t.Errorf("expected annotation category 'search', got %v", tool.Annotations["category"])
	}
}

func TestMCPProtocolNegotiationAppliedInFunnel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			if r.Header.Get("MCP-Protocol-Version") == mcpProtocolVersion {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error": map[string]any{
						"code":    -32600,
						"message": "Unsupported protocol version (supported versions: 2025-06-18)",
						"data": map[string]any{
							"supportedVersions": []string{"2025-06-18"},
						},
					},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]any{"tools": map[string]any{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if got := r.Header.Get("MCP-Protocol-Version"); got != "2025-06-18" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error": map[string]any{
						"code":    -32600,
						"message": "Bad Request: Unsupported protocol version (supported versions: 2025-06-18)",
					},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"tools": []any{}},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"error":   map[string]any{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer server.Close()

	report, _, err := RunScanFunnel(ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
		RFCMode: "off",
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("RunScanFunnel failed: %v", err)
	}

	if report.PrimaryFinding.Code == "MCP_PROTOCOL_VERSION_NEGOTIATION_NOT_APPLIED" {
		t.Fatalf("expected negotiation to be applied, got primary finding %q", report.PrimaryFinding.Code)
	}

	for _, finding := range report.Findings {
		if finding.Code == "MCP_PROTOCOL_VERSION_NEGOTIATION_NOT_APPLIED" {
			t.Fatalf("unexpected finding: %q", finding.Code)
		}
	}
}

func TestMCPToolsListFailedPrimaryFinding(t *testing.T) {
	mockServer := &mockMCPServer{
		ToolsListError: &jsonRPCError{
			Code:    -32000,
			Message: "tools/list unavailable",
		},
		ToolsListStatusCode: http.StatusBadRequest,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	report, _, err := RunScanFunnel(ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
		RFCMode: "off",
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("RunScanFunnel failed: %v", err)
	}

	if report.PrimaryFinding.Code != "MCP_TOOLS_LIST_FAILED" {
		t.Fatalf("expected primary finding MCP_TOOLS_LIST_FAILED, got %q", report.PrimaryFinding.Code)
	}
}

// containsSubstring checks if s contains substr (case-insensitive would need strings.Contains with ToLower)
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsSubstringHelper(s, substr)))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// probeMCP Tests
// =============================================================================

// mockProbeServer creates a test HTTP server for testing the probeMCP function.
// It handles GET requests and returns configurable responses.
type mockProbeServer struct {
	// StatusCode to return (default 200)
	StatusCode int
	// WWWAuthenticate header value (for 401 responses)
	WWWAuthenticate string
	// ContentType header value
	ContentType string
	// Body to return
	Body string
}

func (m *mockProbeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Verify it's a GET request with the expected Accept header
	if r.Method != http.MethodGet {
		// For non-GET, let it through but return the configured status
	}

	if m.ContentType != "" {
		w.Header().Set("Content-Type", m.ContentType)
	}
	if m.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", m.WWWAuthenticate)
	}

	statusCode := m.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)
	if m.Body != "" {
		w.Write([]byte(m.Body))
	}
}

func TestProbeMCP_401WithResourceMetadata(t *testing.T) {
	// Server returns 401 with WWW-Authenticate containing resource_metadata
	mockServer := &mockProbeServer{
		StatusCode:      http.StatusUnauthorized,
		WWWAuthenticate: `Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"`,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	resourceMetadata, resolvedTarget, findings, summary, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if !authRequired {
		t.Error("expected authRequired=true")
	}

	if resourceMetadata != "https://auth.example.com/.well-known/oauth-protected-resource" {
		t.Errorf("resourceMetadata: got %q, want %q", resourceMetadata, "https://auth.example.com/.well-known/oauth-protected-resource")
	}

	if resolvedTarget != server.URL {
		t.Errorf("resolvedTarget: got %q, want %q", resolvedTarget, server.URL)
	}

	if summary != "401 with resource_metadata" {
		t.Errorf("summary: got %q, want %q", summary, "401 with resource_metadata")
	}

	// Should have no findings for a proper 401 response
	for _, f := range findings {
		if f.Code == "DISCOVERY_NO_WWW_AUTHENTICATE" {
			t.Errorf("unexpected finding: %s", f.Code)
		}
	}

	// Verify trace was recorded
	if len(trace) != 1 {
		t.Errorf("expected 1 trace entry, got %d", len(trace))
	}
}

func TestProbeMCP_401WithoutResourceMetadata(t *testing.T) {
	// Server returns 401 but WWW-Authenticate doesn't contain resource_metadata
	mockServer := &mockProbeServer{
		StatusCode:      http.StatusUnauthorized,
		WWWAuthenticate: `Bearer realm="example"`,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	resourceMetadata, _, findings, summary, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if !authRequired {
		t.Error("expected authRequired=true")
	}

	if resourceMetadata != "" {
		t.Errorf("resourceMetadata should be empty, got %q", resourceMetadata)
	}

	if summary != "missing WWW-Authenticate/resource_metadata" {
		t.Errorf("summary: got %q, want %q", summary, "missing WWW-Authenticate/resource_metadata")
	}

	for _, f := range findings {
		if f.Code == "DISCOVERY_NO_WWW_AUTHENTICATE" {
			t.Error("unexpected DISCOVERY_NO_WWW_AUTHENTICATE finding")
		}
	}
}

func TestProbeMCP_200OK(t *testing.T) {
	// Server returns 200 OK - no auth required
	mockServer := &mockProbeServer{
		StatusCode:  http.StatusOK,
		ContentType: "text/event-stream",
		Body:        "data: hello\n\n",
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	resourceMetadata, _, findings, summary, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if authRequired {
		t.Error("expected authRequired=false for 200 OK")
	}

	if resourceMetadata != "" {
		t.Errorf("resourceMetadata should be empty for 200 OK, got %q", resourceMetadata)
	}

	if summary != "auth not required" {
		t.Errorf("summary: got %q, want %q", summary, "auth not required")
	}

	// No MCP findings expected for proper SSE content type
	for _, f := range findings {
		if f.Code == "MCP_GET_NOT_SSE" {
			t.Errorf("unexpected MCP_GET_NOT_SSE finding")
		}
	}
}

func TestProbeMCP_200WithWrongContentType(t *testing.T) {
	// Server returns 200 but with wrong content type (not SSE)
	mockServer := &mockProbeServer{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Body:        `{"error": "not SSE"}`,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, _, findings, _, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if authRequired {
		t.Error("expected authRequired=false for 200")
	}

	// Should have MCP finding about wrong content type
	found := false
	for _, f := range findings {
		if f.Code == "MCP_GET_NOT_SSE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected MCP_GET_NOT_SSE finding for non-SSE content type")
	}
}

func TestProbeMCP_405MethodNotAllowed(t *testing.T) {
	// Server returns 405 Method Not Allowed - auth not required
	// 405 means server doesn't support GET/SSE, but doesn't indicate auth is needed
	mockServer := &mockProbeServer{
		StatusCode: http.StatusMethodNotAllowed,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, _, _, summary, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if authRequired {
		t.Error("expected authRequired=false for 405 (auth not required)")
	}

	expectedSummary := "probe returned 405; checking PRM for OAuth config"
	if summary != expectedSummary {
		t.Errorf("summary: got %q, want %q", summary, expectedSummary)
	}
}

func TestProbeMCP_403Forbidden(t *testing.T) {
	// Server returns 403 Forbidden - auth not required (different from 401)
	mockServer := &mockProbeServer{
		StatusCode: http.StatusForbidden,
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []TraceEntry
	_, _, _, summary, authRequired, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if authRequired {
		t.Error("expected authRequired=false for 403")
	}

	if summary != "auth not required" {
		t.Errorf("summary: got %q, want %q", summary, "auth not required")
	}
}

func TestProbeMCP_WithCustomHeaders(t *testing.T) {
	// Verify custom headers are sent
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
		Headers: []string{"X-Custom-Header: custom-value", "Authorization: Bearer token123"},
	}

	var trace []TraceEntry
	_, _, _, _, _, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header: got %q, want %q", receivedHeaders.Get("X-Custom-Header"), "custom-value")
	}

	if receivedHeaders.Get("Authorization") != "Bearer token123" {
		t.Errorf("Authorization: got %q, want %q", receivedHeaders.Get("Authorization"), "Bearer token123")
	}

	// Verify Accept header is set correctly
	if receivedHeaders.Get("Accept") != "text/event-stream" {
		t.Errorf("Accept: got %q, want %q", receivedHeaders.Get("Accept"), "text/event-stream")
	}
}

func TestProbeMCP_VerboseOutput(t *testing.T) {
	mockServer := &mockProbeServer{
		StatusCode:  http.StatusOK,
		ContentType: "text/event-stream",
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
		Verbose: true,
	}

	var trace []TraceEntry
	var verboseOutput []byte
	buf := &captureWriter{buf: &verboseOutput}

	_, _, _, _, _, err := probeMCP(client, config, &trace, buf)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	output := string(verboseOutput)

	// Check that verbose output contains expected elements
	if !containsSubstring(output, "Step 1: MCP probe") {
		t.Error("verbose output missing step heading")
	}

	if !containsSubstring(output, "GET") {
		t.Error("verbose output missing request method")
	}
}

// captureWriter is a simple io.Writer that captures output to a byte slice
type captureWriter struct {
	buf *[]byte
}

func (c *captureWriter) Write(p []byte) (n int, err error) {
	*c.buf = append(*c.buf, p...)
	return len(p), nil
}

func TestProbeMCP_MCPModeOff(t *testing.T) {
	// When MCP mode is off, should not generate MCP-specific findings
	mockServer := &mockProbeServer{
		StatusCode:  http.StatusOK,
		ContentType: "application/json", // Wrong content type
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := ScanConfig{
		Target:  server.URL,
		MCPMode: "off", // MCP mode disabled
	}

	var trace []TraceEntry
	_, _, findings, _, _, err := probeMCP(client, config, &trace, io.Discard)

	if err != nil {
		t.Fatalf("probeMCP failed: %v", err)
	}

	// Should NOT have MCP finding when mode is off
	for _, f := range findings {
		if f.Code == "MCP_GET_NOT_SSE" {
			t.Error("should not have MCP_GET_NOT_SSE finding when MCP mode is off")
		}
	}
}

func TestExtractSSEData(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple SSE with data prefix",
			input:    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1}\n\n",
			expected: `{"jsonrpc":"2.0","id":1}`,
		},
		{
			name:     "data without space after colon",
			input:    "event: message\ndata:{\"jsonrpc\":\"2.0\"}\n\n",
			expected: `{"jsonrpc":"2.0"}`,
		},
		{
			name:     "multiple data lines",
			input:    "data: {\"part1\":\ndata: \"value\"}\n\n",
			expected: "{\"part1\":\n\"value\"}",
		},
		{
			name:     "no data lines",
			input:    "event: ping\n\n",
			expected: "",
		},
		{
			name:     "real-world SSE response",
			input:    "event: message\ndata: {\"result\":{\"protocolVersion\":\"2025-06-18\"},\"id\":1,\"jsonrpc\":\"2.0\"}\n\n",
			expected: `{"result":{"protocolVersion":"2025-06-18"},"id":1,"jsonrpc":"2.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSSEData([]byte(tt.input))
			if tt.expected == "" {
				if result != nil {
					t.Errorf("expected nil, got %q", string(result))
				}
				return
			}
			if string(result) != tt.expected {
				t.Errorf("extractSSEData() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}
