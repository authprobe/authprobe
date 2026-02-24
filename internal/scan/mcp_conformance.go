package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// checkInitializeOrdering verifies the server enforces initialize-before-other-methods.
// MCP 2025-11-25: Servers MUST reject requests before initialize completes.
// When authRequired is false (public server), severity is lowered to "info" since
// there's no security impact - tools are already publicly accessible.
func checkInitializeOrdering(client *http.Client, config ScanConfig, authRequired bool, trace *[]TraceEntry, stdout io.Writer) []Finding {
	preInitRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "tools/list",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, preInitRequest, "", trace, stdout, "Step 2: MCP initialize + tools/list (pre-init tools/list)")
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if payload != nil && payload.Error != nil {
		return nil
	}
	evidence := fmt.Sprintf("pre-init tools/list status %d", resp.StatusCode)
	if authRequired {
		return []Finding{newMCPFinding(config, "MCP_INITIALIZE_ORDERING_NOT_ENFORCED", evidence)}
	}
	return []Finding{newFindingWithSeverity("MCP_INITIALIZE_ORDERING_NOT_ENFORCED", evidence, "info")}
}

// checkJSONRPCNullID verifies the server rejects null request IDs.
// JSON-RPC 2.0 Section 4: Request id MUST be a String, Number, or omitted (for notifications).
func checkJSONRPCNullID(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return []Finding{newMCPFinding(config, "MCP_JSONRPC_ID_NULL_ACCEPTED", "null id probe marshal failed")}
	}
	resp, _, parsed, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (null id probe)", nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if parsed != nil && parsed.Error != nil {
		return nil
	}
	return []Finding{newMCPFinding(config, "MCP_JSONRPC_ID_NULL_ACCEPTED", fmt.Sprintf("null id probe status %d", resp.StatusCode))}
}

// checkJSONRPCNotificationWithID verifies the server rejects notifications that include an id.
// JSON-RPC 2.0 Section 4.1: Notifications MUST NOT include an id member.
func checkJSONRPCNotificationWithID(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "notifications/initialized",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return []Finding{newMCPFinding(config, "MCP_NOTIFICATION_WITH_ID_ACCEPTED", "notification id probe marshal failed")}
	}
	resp, _, parsed, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (notification id probe)", nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if parsed != nil && parsed.Error != nil {
		return nil
	}
	return []Finding{newMCPFinding(config, "MCP_NOTIFICATION_WITH_ID_ACCEPTED", fmt.Sprintf("notification id probe status %d", resp.StatusCode))}
}

// checkOriginValidation verifies the server validates Origin headers for CSRF protection.
// MCP 2025-11-25 Security: Servers SHOULD validate the Origin header.
func checkOriginValidation(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      90,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (origin probe)", func(req *http.Request) {
		req.Header.Set("Origin", "http://invalid.example")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil
	}
	return []Finding{newMCPFinding(config, "MCP_ORIGIN_NOT_VALIDATED", fmt.Sprintf("origin probe status %d", resp.StatusCode))}
}

// checkProtocolVersionHeader verifies the server validates MCP-Protocol-Version header.
// MCP 2025-11-25 Streamable HTTP: Servers SHOULD reject invalid protocol versions.
func checkProtocolVersionHeader(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      91,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (protocol version probe)", func(req *http.Request) {
		req.Header.Set("MCP-Protocol-Version", "invalid")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil
	}
	return []Finding{newMCPFinding(config, "MCP_PROTOCOL_VERSION_REJECTION_MISSING", fmt.Sprintf("protocol version probe status %d", resp.StatusCode))}
}

// checkSessionHeader verifies the server validates MCP-Session-Id header.
// MCP 2025-11-25 Streamable HTTP: Servers SHOULD return 404 for invalid session IDs.
func checkSessionHeader(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      92,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (session id probe)", func(req *http.Request) {
		req.Header.Set("MCP-Session-Id", "invalid-session")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return []Finding{newMCPFinding(config, "MCP_SESSION_ID_REJECTION_MISSING", fmt.Sprintf("session id probe status %d", resp.StatusCode))}
}

// checkPing verifies the server correctly implements the ping method.
// MCP 2025-11-25: ping MUST return an empty object result.
func checkPing(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	pingRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "ping",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, pingRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (ping)")
	if err != nil {
		return []Finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping error: %v", err))}
	}
	if resp.StatusCode != http.StatusOK || payload == nil || payload.Error != nil {
		return []Finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping status %d", resp.StatusCode))}
	}
	var result any
	if err := json.Unmarshal(payload.Result, &result); err != nil {
		return []Finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping result parse error: %v", err))}
	}
	// MCP 2025-11-25: ping result MUST be an empty object {}
	if obj, ok := result.(map[string]any); !ok || len(obj) != 0 {
		return []Finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", "ping result not empty object")}
	}
	return nil
}

// checkToolSchemas validates tool definitions per MCP 2025-11-25 spec.
func checkToolSchemas(config ScanConfig, raw json.RawMessage) []Finding {
	findings := []Finding{}
	if len(raw) == 0 {
		return findings
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return []Finding{newMCPFinding(config, "MCP_TOOLS_LIST_INVALID", fmt.Sprintf("tools/list parse error: %v", err))}
	}
	for _, tool := range result.Tools {
		// MCP 2025-11-25: Tools MUST include inputSchema for argument validation
		if len(tool.InputSchema) == 0 {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_MISSING", fmt.Sprintf("tool %q missing inputSchema", tool.Name)))
			continue
		}
		var schema any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema parse error", tool.Name)))
			continue
		}
		if schema == nil {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema null", tool.Name)))
			continue
		}
		if _, ok := schema.(map[string]any); !ok {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema not object", tool.Name)))
		}
	}
	return findings
}

func checkToolIcons(config ScanConfig, raw json.RawMessage) []Finding {
	findings := []Finding{}
	if len(raw) == 0 {
		return findings
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return findings
	}
	for _, tool := range result.Tools {
		for key, value := range tool.Annotations {
			if !strings.Contains(strings.ToLower(key), "icon") {
				continue
			}
			uri, ok := value.(string)
			if !ok || strings.TrimSpace(uri) == "" {
				continue
			}
			if !isSafeIconURI(uri) {
				findings = append(findings, newMCPFinding(config, "MCP_ICON_UNSAFE_SCHEME", fmt.Sprintf("tool %q icon %q", tool.Name, uri)))
			}
		}
	}
	return findings
}

func checkTasksSupport(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	tasksRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tasks/list",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, tasksRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (tasks/list)")
	if err != nil {
		return []Finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", fmt.Sprintf("tasks/list error: %v", err))}
	}
	if resp.StatusCode == http.StatusNotFound {
		return []Finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", "tasks/list returned 404")}
	}
	if payload != nil && payload.Error != nil && payload.Error.Code == -32601 {
		return []Finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", "tasks/list method not found")}
	}
	return validateJSONRPCResponse(config, payload, tasksRequest.ID, "tasks/list")
}
