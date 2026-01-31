package cli

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
	Tools []mcpToolDetail `json:"tools"`
}

type mcpToolDetail struct {
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  map[string]any  `json:"annotations,omitempty"`
}

// fetchMCPTools performs MCP initialize + tools/list to retrieve the list of tools.
// This is used by cli.go to fetch tool details for the --mcp-tool flag.
func fetchMCPTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) ([]mcpToolDetail, error) {
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
func postJSONRPC(client *http.Client, config scanConfig, target string, payload jsonRPCRequest, sessionID string, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, *jsonRPCResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	return postJSONRPCBytes(client, config, target, body, sessionID, trace, stdout, verboseLabel, nil)
}

// postJSONRPCBytes sends raw JSON-RPC bytes and returns the response.
// The mutate function allows modifying the request before sending (e.g., for testing).
func postJSONRPCBytes(client *http.Client, config scanConfig, target string, body []byte, sessionID string, trace *[]traceEntry, stdout io.Writer, verboseLabel string, mutate func(*http.Request)) (*http.Response, []byte, *jsonRPCResponse, error) {
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
		if err := writeVerboseRequest(stdout, req); err != nil {
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
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return resp, respBody, nil, err
		}
	}
	addTrace(trace, req, resp)

	var parsed jsonRPCResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			return resp, respBody, &parsed, nil
		}
	}
	return resp, respBody, nil, nil
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
func validateJSONRPCResponse(config scanConfig, payload *jsonRPCResponse, expectedID any, context string) []finding {
	findings := []finding{}
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
