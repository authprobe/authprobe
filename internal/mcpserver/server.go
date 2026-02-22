package mcpserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authprobe/internal/scan"
)

const protocolVersion = "2025-11-25"

type Server struct {
	in      io.Reader
	out     io.Writer
	errOut  io.Writer
	scans   map[string]scan.ScanSummary
	reports map[string]scan.ScanReport
	now     func() time.Time
}

// New creates an MCP server instance with IO streams and in-memory scan caches.
// Inputs: stdin reader, stdout writer, stderr writer.
// Outputs: initialized *Server ready to serve requests.
func New(in io.Reader, out io.Writer, errOut io.Writer) *Server {
	return &Server{in: in, out: out, errOut: errOut, scans: map[string]scan.ScanSummary{}, reports: map[string]scan.ScanReport{}, now: time.Now}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs stdio JSON-RPC transport.
// Serve reads newline-delimited JSON-RPC requests from stdio and writes responses to stdout.
// Inputs: none (uses server in/out streams).
// Outputs: error when the input scan loop terminates unexpectedly.
func (s *Server) Serve() error {
	scanner := bufio.NewScanner(s.in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		resp, respond := s.processRawRequest([]byte(line))
		if respond {
			s.write(resp)
		}
	}
	return scanner.Err()
}

// ServeHTTP runs MCP JSON-RPC over HTTP POST.
// ServeHTTP handles JSON-RPC requests over HTTP POST for MCP tool access.
// Inputs: HTTP response writer and request.
// Outputs: HTTP response body/status (no return values).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp, respond := s.processRawRequest(body)
	w.Header().Set("Content-Type", "application/json")
	if !respond {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	b, _ := json.Marshal(resp)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// processRawRequest parses one JSON-RPC request and dispatches it to the handler.
// Inputs: raw JSON request bytes.
// Outputs: rpcResponse payload and respond=true when request has an id.
func (s *Server) processRawRequest(raw []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}, true
	}
	if strings.TrimSpace(req.JSONRPC) != "2.0" {
		return rpcResponse{JSONRPC: "2.0", ID: decodeID(req.ID), Error: &rpcError{Code: -32600, Message: "invalid request: jsonrpc must be 2.0"}}, true
	}
	if isNullID(req.ID) {
		return rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32600, Message: "invalid request: id must not be null"}}, true
	}
	if len(req.ID) > 0 && strings.HasPrefix(req.Method, "notifications/") {
		return rpcResponse{JSONRPC: "2.0", ID: decodeID(req.ID), Error: &rpcError{Code: -32600, Message: "invalid request: notifications must not include id"}}, true
	}
	resp := s.handle(req)
	return resp, len(req.ID) != 0
}

// handle routes an already-parsed JSON-RPC request to supported MCP methods.
// Inputs: rpcRequest with method and params.
// Outputs: rpcResponse containing result or JSON-RPC error.
func (s *Server) handle(req rpcRequest) rpcResponse {
	id := decodeID(req.ID)
	switch req.Method {
	case "initialize":
		return rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"protocolVersion": protocolVersion,
			"serverInfo":      map[string]any{"name": "authprobe", "version": "dev"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}}
	case "tools/list":
		return rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": toolDefinitions()}}
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid params"}}
		}
		result, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32000, Message: err.Error()}}
		}
		payload, _ := json.Marshal(result)
		return rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"content": []map[string]any{{"type": "text", "text": string(payload)}}, "structuredContent": result}}
	default:
		return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

// isNullID reports whether a raw JSON-RPC id is explicitly null.
// Inputs: raw JSON id bytes from request payload.
// Outputs: true when id equals JSON null.
func isNullID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null"))
}

// decodeID unmarshals a JSON-RPC id into a generic Go value.
// Inputs: raw JSON id bytes.
// Outputs: decoded id value (or nil when absent/invalid).
func decodeID(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	_ = json.Unmarshal(raw, &v)
	return v
}

// write serializes an rpcResponse and writes it as a single line to stdout.
// Inputs: rpcResponse object.
// Outputs: none (best-effort write to output stream).
func (s *Server) write(resp rpcResponse) {
	b, _ := json.Marshal(resp)
	_, _ = s.out.Write(append(b, '\n'))
}

// callTool executes one exposed MCP tool by name using provided arguments.
// Inputs: tool name and arguments map.
// Outputs: structured tool result map and optional error.
func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "authprobe_scan_http":
		return s.scanHTTP(args, "")
	case "authprobe_scan_http_authenticated":
		auth, _ := args["authorization"].(string)
		if strings.TrimSpace(auth) == "" {
			return nil, fmt.Errorf("authorization is required")
		}
		return s.scanHTTP(args, auth)
	case "authprobe_render_markdown":
		report, err := s.reportFromInput(args)
		if err != nil {
			return nil, err
		}
		return map[string]any{"markdown": scan.RenderMarkdown(report)}, nil
	case "authprobe_bundle_evidence":
		report, err := s.reportFromInput(args)
		if err != nil {
			return nil, err
		}
		summary := scan.SummaryFromReport(report)
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("authprobe-mcp-%d.zip", s.now().UnixNano()))
		if err := scan.WriteOutputs(report, summary, scan.ScanConfig{BundlePath: tmp}); err != nil {
			return nil, err
		}
		if data, err := os.ReadFile(tmp); err == nil && len(data) < 400_000 {
			return map[string]any{"bundle_base64": base64.StdEncoding.EncodeToString(data), "encoding": "base64_zip"}, nil
		}
		return map[string]any{"bundle_path": tmp, "redacted": true}, nil
	default:
		return nil, fmt.Errorf("unknown tool %s", name)
	}
}

// reportFromInput resolves a ScanReport from either scan_id cache or report_json payload.
// Inputs: tool arguments map containing scan_id or report_json.
// Outputs: ScanReport value and optional error when missing/invalid.
func (s *Server) reportFromInput(args map[string]any) (scan.ScanReport, error) {
	if id, _ := args["scan_id"].(string); id != "" {
		report, ok := s.reports[id]
		if !ok {
			return scan.ScanReport{}, fmt.Errorf("unknown scan_id")
		}
		return report, nil
	}
	raw, ok := args["report_json"]
	if !ok {
		return scan.ScanReport{}, fmt.Errorf("report_json or scan_id is required")
	}
	b, _ := json.Marshal(raw)
	var report scan.ScanReport
	if err := json.Unmarshal(b, &report); err != nil {
		return scan.ScanReport{}, err
	}
	return report, nil
}

// scanHTTP runs the scan funnel with optional Authorization and formats MCP tool output.
// Inputs: scan tool args and optional authorization header value.
// Outputs: structured scan response map and optional error.
func (s *Server) scanHTTP(args map[string]any, authorization string) (map[string]any, error) {
	target, _ := args["target_url"].(string)
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("target_url is required")
	}
	headers := toStringSlice(args["headers"])
	secrets := []string{}
	if authorization != "" {
		headers = append(headers, "Authorization: "+authorization)
		secrets = append(secrets, authorization)
	}
	cfg := scan.ScanConfig{Target: target, Headers: headers, Timeout: durationSeconds(args["timeout_seconds"], 8), MCPMode: enumArg(args["mcp_mode"], "best-effort"), RFCMode: enumArg(args["rfc_mode"], "best-effort"), AllowPrivateIssuers: boolArg(args["allow_private_issuers"]), Insecure: boolArg(args["insecure"]), NoFollowRedirects: boolArg(args["no_follow_redirects"]), Redact: true, Command: "authprobe mcp tool scan"}
	report, summary, err := scan.RunScanFunnel(cfg, io.Discard, io.Discard)
	if err != nil {
		return nil, err
	}
	scanID := fmt.Sprintf("scan_%d", s.now().UnixNano())
	s.reports[scanID] = report
	s.scans[scanID] = summary

	data, _ := json.Marshal(report)
	safeJSON := redactText(string(data), secrets)
	var reportObj map[string]any
	_ = json.Unmarshal([]byte(safeJSON), &reportObj)

	res := map[string]any{"status": "ok", "scan_id": scanID, "summary": map[string]any{"target": report.Target, "auth_required": report.AuthRequired, "primary_finding": report.PrimaryFinding.Code}, "scan": reportObj}
	if report.AuthRequired && authorization == "" {
		res["status"] = "auth_required"
		res["next_action"] = map[string]any{"type": "call_tool", "tool_name": "authprobe_scan_http_authenticated", "required_input": []string{"authorization"}, "hint": "Provide Authorization header value (e.g., 'Bearer <token>'). Tokens are redacted in output."}
	}
	return res, nil
}

// redactText replaces known secret values in text with [redacted].
// Inputs: source text and list of secret strings to scrub.
// Outputs: redacted text string.
func redactText(text string, secrets []string) string {
	out := text
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, "[redacted]")
		if strings.HasPrefix(strings.ToLower(secret), "bearer ") {
			out = strings.ReplaceAll(out, strings.TrimSpace(secret[7:]), "[redacted]")
		}
	}
	return out
}

// boolArg casts a dynamic argument to bool with false default.
// Inputs: arbitrary value.
// Outputs: bool value or false when type does not match.
func boolArg(v any) bool {
	b, _ := v.(bool)
	return b
}

// enumArg casts a dynamic argument to string with fallback default.
// Inputs: arbitrary value and default string.
// Outputs: non-empty string value.
func enumArg(v any, d string) string {
	s, _ := v.(string)
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// durationSeconds converts a numeric seconds argument to time.Duration.
// Inputs: arbitrary value and default seconds.
// Outputs: duration in seconds.
func durationSeconds(v any, d int) time.Duration {
	switch t := v.(type) {
	case float64:
		return time.Duration(int(t)) * time.Second
	case int:
		return time.Duration(t) * time.Second
	default:
		return time.Duration(d) * time.Second
	}
}

// toStringSlice converts an any-typed JSON array into []string values.
// Inputs: arbitrary value expected to be []any of strings.
// Outputs: string slice (or nil when type is incompatible).
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// toolDefinitions returns MCP tool metadata and input schemas exposed by this server.
// Inputs: none.
// Outputs: array of tool definition objects.
func toolDefinitions() []map[string]any {
	scanDesc := "Run unauthenticated scan first. If result.status is auth_required, show the message, ask user to authenticate in client, then call authprobe_scan_http_authenticated with Authorization header."
	return []map[string]any{
		{"name": "authprobe_scan_http", "description": scanDesc, "inputSchema": map[string]any{"type": "object", "required": []string{"target_url"}, "properties": commonProps(false)}},
		{"name": "authprobe_scan_http_authenticated", "description": "Run authenticated scan using provided Authorization header. Tokens are redacted in output.", "inputSchema": map[string]any{"type": "object", "required": []string{"target_url", "authorization"}, "properties": commonProps(true)}},
		{"name": "authprobe_render_markdown", "description": "Render markdown report from report_json or scan_id.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"scan_id": map[string]any{"type": "string"}, "report_json": map[string]any{"type": "object"}}}},
		{"name": "authprobe_bundle_evidence", "description": "Create redacted evidence bundle from report_json or scan_id.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"scan_id": map[string]any{"type": "string"}, "report_json": map[string]any{"type": "object"}}}},
	}
}

// commonProps builds shared JSON schema properties for scan tool inputs.
// Inputs: withAuth flag to include authorization field.
// Outputs: JSON-schema properties map.
func commonProps(withAuth bool) map[string]any {
	p := map[string]any{
		"target_url":            map[string]any{"type": "string"},
		"headers":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"timeout_seconds":       map[string]any{"type": "integer"},
		"rfc_mode":              map[string]any{"type": "string", "enum": []string{"off", "best-effort", "strict"}},
		"mcp_mode":              map[string]any{"type": "string", "enum": []string{"off", "best-effort", "strict"}},
		"allow_private_issuers": map[string]any{"type": "boolean"},
		"insecure":              map[string]any{"type": "boolean"},
		"no_follow_redirects":   map[string]any{"type": "boolean"},
	}
	if withAuth {
		p["authorization"] = map[string]any{"type": "string"}
	}
	return p
}

// encodeForTest marshals a value to compact JSON for tests/helpers.
// Inputs: arbitrary value.
// Outputs: JSON string (trimmed) with best-effort encoding.
func encodeForTest(v any) string {
	b, _ := json.Marshal(v)
	return string(bytes.TrimSpace(b))
}
