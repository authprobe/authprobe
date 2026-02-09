package scan

// mcp.go - MCP protocol (JSON-RPC, Streamable HTTP) functions and types
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ MCP Initialize Flow                 │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ mcpInitializeAndListTools           │ Step 2: MCP initialize + tools/list JSON-RPC flow          │
// │ parseInitializeResult               │ Parse and validate MCP initialize response                 │
// │ hasWWWAuthenticate                  │ Check if WWW-Authenticate header is present                │
// │ jsonRPCErrorMessage                 │ Extract error message from JSON-RPC response               │
// │ sendInitializedNotification         │ Send notifications/initialized per MCP spec                │
// │ FetchMCPTools                       │ Perform MCP initialize + tools/list to get tool list       │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ MCP Conformance Checks              │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ checkInitializeOrdering             │ Verify server enforces initialize-before-other-methods     │
// │ checkJSONRPCNullID                  │ Verify server rejects null request IDs                     │
// │ checkJSONRPCNotificationWithID      │ Verify server rejects notifications with IDs               │
// │ checkOriginValidation               │ Verify server validates Origin header for CSRF             │
// │ checkProtocolVersionHeader          │ Verify server validates MCP-Protocol-Version header        │
// │ checkSessionHeader                  │ Verify server validates MCP-Session-Id header              │
// │ checkPing                           │ Verify server correctly implements ping method             │
// │ checkToolSchemas                    │ Validate tool inputSchema definitions                      │
// │ checkToolIcons                      │ Validate tool icon URI schemes                             │
// │ checkTasksSupport                   │ Verify tasks methods when capability advertised            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ JSON-RPC Helpers                    │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ postJSONRPC                         │ Send JSON-RPC request and parse response                   │
// │ postJSONRPCBytes                    │ Send raw JSON-RPC bytes with optional mutation             │
// │ formatJSONRPCError                  │ Format JSON-RPC error for display                          │
// │ extractSSEData                      │ Extract JSON data from SSE-formatted response              │
// │ extractToolNames                    │ Extract tool names from tools/list result                  │
// │ validateJSONRPCResponse             │ Validate JSON-RPC response for conformance                 │
// │ jsonRPCIDEqual                      │ Compare two JSON-RPC IDs for equality                      │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// mcpProtocolVersion is the MCP protocol version supported by authprobe.
const mcpProtocolVersion = "2025-11-25"

// JSON-RPC types for MCP communication.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP tools list result types.
type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type mcpToolsListDetailResult struct {
	Tools []MCPToolDetail `json:"tools"`
}

type MCPToolDetail struct {
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  map[string]any  `json:"annotations,omitempty"`
}

type mcpAuthObservation struct {
	Status                  int
	ErrorMessage            string
	WWWAuthenticatePresent  bool
	WWWAuthenticateObserved string
}

// mcpInitializeAndListTools performs the MCP JSON-RPC handshake and tool enumeration.
// Called by runMCPInitialize in funnel Step 2 ("MCP initialize + tools/list").
//
// This function executes the full MCP protocol sequence:
//  1. Pre-init ordering check: If auth is not required, sends tools/list before initialize
//     to test whether the server enforces correct JSON-RPC ordering (MCP compliance).
//  2. Initialize: Sends JSON-RPC "initialize" with client capabilities and parses the
//     server's protocol version, capabilities, and session ID from the response.
//  3. Initialized notification: Sends the required "notifications/initialized" message.
//  4. Protocol conformance checks: Validates null ID handling, notification-with-ID rejection,
//     Origin header validation, protocol version header, and session header enforcement.
//  5. Ping: If the server advertises ping capability, validates the ping response.
//  6. Tools/list: Sends "tools/list" to enumerate available tools, validates tool schemas
//     and icons, and checks tasks support if advertised.
//
// Inputs:
//   - client: HTTP client for making requests
//   - config: Scan configuration (target URL, MCP/RFC mode, verbose, headers, etc.)
//   - trace: Request/response trace log for debugging and evidence collection
//   - stdout: Writer for verbose output
//   - authRequired: true if auth was detected in earlier steps; controls whether 401/403
//     from initialize is treated as SKIP (expected) vs FAIL (unexpected)
//
// Outputs:
//   - string: Step status — "PASS", "FAIL", or "SKIP"
//   - string: Evidence summary (e.g., "initialize -> 200\ntools/list -> 200 (tools: foo, bar)")
//   - []Finding: MCP and JSON-RPC compliance findings discovered during the handshake
//   - *mcpAuthObservation: Non-nil if initialize returned 401/403, capturing the auth
//     challenge details (status, error message, WWW-Authenticate) for late auth discovery
func mcpInitializeAndListTools(client *http.Client, config ScanConfig, trace *[]TraceEntry, stdout io.Writer, authRequired bool) (string, string, []Finding, *mcpAuthObservation) {
	var evidence strings.Builder
	findings := []Finding{}
	var authObservation *mcpAuthObservation

	if !authRequired {
		findings = append(findings, checkInitializeOrdering(client, config, authRequired, trace, stdout)...)
	}

	initParams := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "authprobe",
			"version": "0.1",
		},
	}

	initRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  initParams,
	}

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, "", trace, stdout, "Step 2: MCP initialize + tools/list (initialize)")
	if err != nil {
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", fmt.Sprintf("initialize error: %v", err)))
		return "FAIL", fmt.Sprintf("initialize error: %v", err), findings, nil
	}
	fmt.Fprintf(&evidence, "initialize -> %d", initResp.StatusCode)
	if initPayload == nil {
		fmt.Fprint(&evidence, " (non-JSON response)")
	}
	if initPayload != nil && initPayload.Error != nil {
		fmt.Fprintf(&evidence, " (error: %s)", initPayload.Error.Message)
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		wwwAuthPresent, wwwAuthValue := hasWWWAuthenticate(initResp.Header.Values("WWW-Authenticate"))
		authObservation = &mcpAuthObservation{
			Status:                  initResp.StatusCode,
			ErrorMessage:            jsonRPCErrorMessage(initPayload),
			WWWAuthenticatePresent:  wwwAuthPresent,
			WWWAuthenticateObserved: wwwAuthValue,
		}
		if authRequired {
			fmt.Fprint(&evidence, " (auth required)")
			return "SKIP", strings.TrimSpace(evidence.String()), findings, authObservation
		}
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, nil
	}

	findings = append(findings, validateJSONRPCResponse(config, initPayload, initRequest.ID, "initialize")...)
	initResult, capabilities, sessionID, initResultFindings := parseInitializeResult(config, initPayload, initResp)
	findings = append(findings, initResultFindings...)

	notificationFindings, notificationEvidence := sendInitializedNotification(client, config, sessionID, trace, stdout)
	if notificationEvidence != "" {
		fmt.Fprintf(&evidence, "\n%s", notificationEvidence)
	}
	findings = append(findings, notificationFindings...)

	findings = append(findings, checkJSONRPCNullID(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkJSONRPCNotificationWithID(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkOriginValidation(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkProtocolVersionHeader(client, config, sessionID, trace, stdout)...)
	if sessionID != "" {
		findings = append(findings, checkSessionHeader(client, config, sessionID, trace, stdout)...)
	}

	if supportsPing(capabilities) {
		findings = append(findings, checkPing(client, config, sessionID, trace, stdout)...)
	}

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (tools/list)")
	if err != nil {
		fmt.Fprintf(&evidence, "\n")
		fmt.Fprintf(&evidence, "tools/list -> error: %v", err)
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	fmt.Fprintf(&evidence, "\n")
	fmt.Fprintf(&evidence, "tools/list -> %d", toolsResp.StatusCode)
	if toolsPayload == nil {
		fmt.Fprint(&evidence, " (non-JSON response)")
	}
	if toolsPayload != nil && toolsPayload.Error != nil {
		fmt.Fprintf(&evidence, " (error: %s)", toolsPayload.Error.Message)
	}
	if toolsResp.StatusCode == http.StatusUnauthorized || toolsResp.StatusCode == http.StatusForbidden {
		if authRequired {
			fmt.Fprint(&evidence, " (auth required)")
			return "SKIP", strings.TrimSpace(evidence.String()), findings, authObservation
		}
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	if toolsResp.StatusCode != http.StatusOK || toolsPayload == nil || toolsPayload.Error != nil {
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	findings = append(findings, validateJSONRPCResponse(config, toolsPayload, toolsRequest.ID, "tools/list")...)

	toolNames := extractToolNames(toolsPayload.Result)
	if len(toolNames) == 0 {
		fmt.Fprint(&evidence, " (tools: none)")
	} else {
		fmt.Fprintf(&evidence, " (tools: %s)", strings.Join(toolNames, ", "))
	}

	findings = append(findings, checkToolSchemas(config, toolsPayload.Result)...)
	findings = append(findings, checkToolIcons(config, toolsPayload.Result)...)
	if supportsTasks(capabilities) || tasksAdvertised(initResult) {
		findings = append(findings, checkTasksSupport(client, config, sessionID, trace, stdout)...)
	}

	status := "PASS"
	if hasHighSeverity(findings) {
		status = "FAIL"
	}
	return status, strings.TrimSpace(evidence.String()), findings, authObservation
}

// parseInitializeResult validates the MCP initialize response per MCP 2025-11-25 spec.
func parseInitializeResult(config ScanConfig, payload *jsonRPCResponse, resp *http.Response) (map[string]any, map[string]any, string, []Finding) {
	findings := []Finding{}
	// MCP 2025-11-25: Initialize response MUST include a result object
	if payload == nil || payload.Result == nil {
		findings = append(findings, newMCPFinding(config, "MCP_INITIALIZE_RESULT_INVALID", "initialize missing result object"))
		return nil, nil, "", findings
	}
	var result map[string]any
	if err := json.Unmarshal(payload.Result, &result); err != nil {
		findings = append(findings, newMCPFinding(config, "MCP_INITIALIZE_RESULT_INVALID", fmt.Sprintf("initialize result parse error: %v", err)))
		return nil, nil, "", findings
	}

	// MCP 2025-11-25: The result MUST include "protocolVersion" matching the spec version
	protocolVersion, ok := result["protocolVersion"].(string)
	if !ok || strings.TrimSpace(protocolVersion) == "" {
		findings = append(findings, newMCPFinding(config, "MCP_PROTOCOL_VERSION_MISSING", "initialize result missing protocolVersion"))
	} else if protocolVersion != mcpProtocolVersion {
		findings = append(findings, newMCPFinding(config, "MCP_PROTOCOL_VERSION_MISMATCH", fmt.Sprintf("protocolVersion %q != %q", protocolVersion, mcpProtocolVersion)))
	}

	// MCP 2025-11-25: "capabilities" MUST be an object if present
	capabilities, ok := result["capabilities"].(map[string]any)
	if !ok && result["capabilities"] != nil {
		findings = append(findings, newMCPFinding(config, "MCP_CAPABILITIES_INVALID", "initialize capabilities not an object"))
	}

	sessionID := ""
	if resp != nil {
		sessionID = strings.TrimSpace(resp.Header.Get("MCP-Session-Id"))
	}
	if sessionID == "" {
		if value, ok := result["sessionId"].(string); ok {
			sessionID = strings.TrimSpace(value)
		} else if value, ok := result["session_id"].(string); ok {
			sessionID = strings.TrimSpace(value)
		}
	}

	return result, capabilities, sessionID, findings
}

func hasWWWAuthenticate(values []string) (bool, string) {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true, value
		}
	}
	return false, ""
}

func jsonRPCErrorMessage(payload *jsonRPCResponse) string {
	if payload == nil || payload.Error == nil {
		return ""
	}
	return strings.TrimSpace(payload.Error.Message)
}

// sendInitializedNotification sends the notifications/initialized per MCP 2025-11-25.
func sendInitializedNotification(client *http.Client, config ScanConfig, sessionID string, trace *[]TraceEntry, stdout io.Writer) ([]Finding, string) {
	notification := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	resp, body, payload, err := postJSONRPC(client, config, config.Target, notification, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (notifications/initialized)")
	if err != nil {
		return []Finding{newMCPFinding(config, "MCP_NOTIFICATION_FAILED", fmt.Sprintf("notifications/initialized error: %v", err))}, ""
	}
	evidence := fmt.Sprintf("notifications/initialized -> %d", resp.StatusCode)
	findings := []Finding{}
	// MCP 2025-11-25: Notifications SHOULD return 202 Accepted with no body
	if resp.StatusCode != http.StatusAccepted {
		findings = append(findings, newMCPFinding(config, "MCP_NOTIFICATION_STATUS_INVALID", fmt.Sprintf("notifications/initialized status %d", resp.StatusCode)))
	}
	// JSON-RPC 2.0: Notifications MUST NOT return a response body
	if len(body) > 0 || payload != nil {
		findings = append(findings, newMCPFinding(config, "MCP_NOTIFICATION_BODY_PRESENT", "notifications/initialized returned a body"))
	}
	return findings, evidence
}

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
	// Public server: lower severity since tools are already publicly accessible
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

// FetchMCPTools performs MCP initialize + tools/list to retrieve the list of tools.
// This is used by cli.go to fetch tool details for the --mcp-tool flag.
func FetchMCPTools(client *http.Client, config ScanConfig, trace *[]TraceEntry, stdout io.Writer) ([]MCPToolDetail, error) {
	initParams := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "authprobe",
			"version": "0.1",
		},
	}

	initRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  initParams,
	}

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, "", trace, stdout, "MCP tool fetch (initialize)")
	if err != nil {
		return nil, err
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("initialize unauthorized: %d", initResp.StatusCode)
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", formatJSONRPCError(initResp, initPayload))
	}

	sessionID := ""
	if initResp != nil {
		sessionID = strings.TrimSpace(initResp.Header.Get("MCP-Session-Id"))
	}
	if sessionID == "" && initPayload != nil && initPayload.Result != nil {
		var initResult map[string]any
		if err := json.Unmarshal(initPayload.Result, &initResult); err == nil {
			if value, ok := initResult["sessionId"].(string); ok {
				sessionID = strings.TrimSpace(value)
			} else if value, ok := initResult["session_id"].(string); ok {
				sessionID = strings.TrimSpace(value)
			}
		}
	}

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, sessionID, trace, stdout, "MCP tool fetch (tools/list)")
	if err != nil {
		return nil, err
	}
	if toolsResp.StatusCode == http.StatusUnauthorized || toolsResp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("tools/list unauthorized: %d", toolsResp.StatusCode)
	}
	if toolsResp.StatusCode != http.StatusOK || toolsPayload == nil || toolsPayload.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", formatJSONRPCError(toolsResp, toolsPayload))
	}

	if len(toolsPayload.Result) == 0 {
		return nil, errors.New("tools/list returned empty result")
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(toolsPayload.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}
	return result.Tools, nil
}

// formatJSONRPCError formats a JSON-RPC error response for display.
func formatJSONRPCError(resp *http.Response, payload *jsonRPCResponse) string {
	if payload != nil && payload.Error != nil {
		return fmt.Sprintf("%d (%s)", resp.StatusCode, payload.Error.Message)
	}
	return fmt.Sprintf("%d", resp.StatusCode)
}

// postJSONRPC sends a JSON-RPC request and returns the response.
func postJSONRPC(client *http.Client, config ScanConfig, target string, payload jsonRPCRequest, sessionID string, trace *[]TraceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, *jsonRPCResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	return postJSONRPCBytes(client, config, target, body, sessionID, trace, stdout, verboseLabel, nil)
}

// postJSONRPCBytes sends raw JSON-RPC bytes and returns the response.
// The mutate function allows modifying the request before sending (e.g., for testing).
func postJSONRPCBytes(client *http.Client, config ScanConfig, target string, body []byte, sessionID string, trace *[]TraceEntry, stdout io.Writer, verboseLabel string, mutate func(*http.Request)) (*http.Response, []byte, *jsonRPCResponse, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if mcpModeEnabled(config.MCPMode) {
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		if sessionID != "" {
			req.Header.Set("MCP-Session-Id", sessionID)
		}
	}
	if err := applyHeaders(req, config.Headers); err != nil {
		return nil, nil, nil, err
	}
	if mutate != nil {
		mutate(req)
	}
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
		if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
			return nil, nil, nil, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return resp, respBody, nil, err
		}
	}
	addTrace(trace, req, resp, config.Redact, verboseLabel)

	var parsed jsonRPCResponse
	if len(respBody) > 0 {
		// Try parsing as plain JSON first
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			return resp, respBody, &parsed, nil
		}
		// If Content-Type is text/event-stream, try parsing as SSE
		contentType := resp.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "text/event-stream") {
			if jsonData := extractSSEData(respBody); jsonData != nil {
				if err := json.Unmarshal(jsonData, &parsed); err == nil {
					return resp, respBody, &parsed, nil
				}
			}
		}
	}
	return resp, respBody, nil, nil
}

// extractSSEData extracts JSON data from an SSE-formatted response.
// SSE format: "event: <type>\ndata: <json>\n\n"
// Multiple data lines are concatenated.
func extractSSEData(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	var dataLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data:"))
		}
	}
	if len(dataLines) == 0 {
		return nil
	}
	// Concatenate all data lines (SSE spec says multi-line data is joined with newlines)
	return []byte(strings.Join(dataLines, "\n"))
}

// extractToolNames extracts tool names from a JSON-RPC tools/list result.
func extractToolNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var result mcpToolsListResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		if tool.Name != "" {
			names = append(names, tool.Name)
		}
	}
	return names
}

// validateJSONRPCResponse checks a JSON-RPC response for conformance issues.
func validateJSONRPCResponse(config ScanConfig, payload *jsonRPCResponse, expectedID any, context string) []Finding {
	findings := []Finding{}
	if payload == nil {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s response not JSON", context)))
		return findings
	}
	if payload.JSONRPC != "2.0" {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s jsonrpc=%q", context, payload.JSONRPC)))
	}
	if expectedID != nil && !jsonRPCIDEqual(payload.ID, expectedID) {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_ID_MISMATCH", fmt.Sprintf("%s id=%v", context, payload.ID)))
	}
	resultPresent := payload.Result != nil
	errorPresent := payload.Error != nil
	if resultPresent == errorPresent {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s result/error shape invalid", context)))
	}
	if payload.Error != nil {
		if payload.Error.Message == "" {
			findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s error missing message", context)))
		}
	}
	return findings
}

// jsonRPCIDEqual compares two JSON-RPC IDs for equality.
// Handles type coercion between int, float64, and string representations.
func jsonRPCIDEqual(a, b any) bool {
	switch av := a.(type) {
	case float64:
		switch bv := b.(type) {
		case int:
			return av == float64(bv)
		case int64:
			return av == float64(bv)
		case float64:
			return av == bv
		case string:
			return fmt.Sprintf("%g", av) == bv
		}
	case int:
		switch bv := b.(type) {
		case int:
			return av == bv
		case int64:
			return int64(av) == bv
		case float64:
			return float64(av) == bv
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	}
	return a == b
}
