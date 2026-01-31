package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockMCPServer creates a test HTTP server that implements the MCP protocol.
// It handles the initialize and tools/list JSON-RPC methods.
type mockMCPServer struct {
	// Tools to return from tools/list
	Tools []mcpToolDetail
	// SessionID to return in MCP-Session-Id header (optional)
	SessionID string
	// InitializeError if set, returns this error from initialize
	InitializeError *jsonRPCError
	// ToolsListError if set, returns this error from tools/list
	ToolsListError *jsonRPCError
	// RequireSessionID if true, tools/list requires a valid session ID
	RequireSessionID bool
	// ReceivedRequests tracks all requests received
	ReceivedRequests []jsonRPCRequest
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
		m.writeErrorResponse(w, req.ID, m.InitializeError)
		return
	}

	// Set session ID header if configured
	if m.SessionID != "" {
		w.Header().Set("MCP-Session-Id", m.SessionID)
	}

	result := map[string]any{
		"protocolVersion": mcpProtocolVersion,
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
		Tools: []mcpToolDetail{
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	// Call fetchMCPTools with a trace slice (required by addTrace)
	var trace []traceEntry
	tools, err := fetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("fetchMCPTools failed: %v", err)
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
		Tools: []mcpToolDetail{}, // Empty tools list
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	tools, err := fetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("fetchMCPTools failed: %v", err)
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	_, err := fetchMCPTools(client, config, &trace, io.Discard)
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	_, err := fetchMCPTools(client, config, &trace, io.Discard)
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	_, err := fetchMCPTools(client, config, &trace, io.Discard)
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
		Tools: []mcpToolDetail{
			{Name: "test-tool"},
		},
	}

	server := httptest.NewServer(mockServer)
	defer server.Close()

	client := &http.Client{}
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	tools, err := fetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("fetchMCPTools failed: %v", err)
	}

	if len(tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(tools))
	}
}

func TestFetchMCPTools_WithManyTools(t *testing.T) {
	// Create a server with many tools to test pagination-like behavior
	tools := make([]mcpToolDetail, 50)
	for i := 0; i < 50; i++ {
		tools[i] = mcpToolDetail{
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	result, err := fetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("fetchMCPTools failed: %v", err)
	}

	if len(result) != 50 {
		t.Errorf("expected 50 tools, got %d", len(result))
	}
}

func TestFetchMCPTools_ToolWithComplexSchema(t *testing.T) {
	mockServer := &mockMCPServer{
		Tools: []mcpToolDetail{
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
	config := scanConfig{
		Target:  server.URL,
		MCPMode: "best-effort",
	}

	var trace []traceEntry
	tools, err := fetchMCPTools(client, config, &trace, io.Discard)
	if err != nil {
		t.Fatalf("fetchMCPTools failed: %v", err)
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
