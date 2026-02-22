package mcpserver

import (
	"bufio"
	"bytes"
	"context"
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

type CredentialProvider interface {
	ResolveAuthorization(ctx context.Context, credentialRef string, targetURL string, issuer string, scopes []string) (string, error)
}

type envCredentialProvider struct{}

func (p envCredentialProvider) ResolveAuthorization(ctx context.Context, credentialRef string, targetURL string, issuer string, scopes []string) (string, error) {
	_ = ctx
	_ = targetURL
	_ = issuer
	_ = scopes
	credentialRef = strings.TrimSpace(credentialRef)
	if credentialRef == "" {
		return "", fmt.Errorf("credential_ref is required")
	}
	if filePath := strings.TrimSpace(os.Getenv("AUTHPROBE_MCP_CREDENTIALS_FILE")); filePath != "" {
		if data, err := os.ReadFile(filePath); err == nil {
			entries := map[string]string{}
			if err := json.Unmarshal(data, &entries); err == nil {
				if v := strings.TrimSpace(entries[credentialRef]); v != "" {
					return v, nil
				}
			}
		}
	}
	for _, item := range strings.Split(os.Getenv("AUTHPROBE_MCP_CREDENTIALS"), ";") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) == credentialRef {
			if value := strings.TrimSpace(parts[1]); value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("credential_ref %q was not resolvable in stub provider", credentialRef)
}

type Server struct {
	in                 io.Reader
	out                io.Writer
	errOut             io.Writer
	scans              map[string]scan.ScanSummary
	reports            map[string]scan.ScanReport
	now                func() time.Time
	credentialProvider CredentialProvider
}

func New(in io.Reader, out io.Writer, errOut io.Writer) *Server {
	return &Server{in: in, out: out, errOut: errOut, scans: map[string]scan.ScanSummary{}, reports: map[string]scan.ScanReport{}, now: time.Now, credentialProvider: envCredentialProvider{}}
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

func (s *Server) handle(req rpcRequest) rpcResponse {
	id := decodeID(req.ID)
	switch req.Method {
	case "initialize":
		return rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"protocolVersion": protocolVersion, "serverInfo": map[string]any{"name": "authprobe", "version": "dev"}, "capabilities": map[string]any{"tools": map[string]any{}}}}
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

func isNullID(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func decodeID(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	_ = json.Unmarshal(raw, &v)
	return v
}
func (s *Server) write(resp rpcResponse) {
	b, _ := json.Marshal(resp)
	_, _ = s.out.Write(append(b, '\n'))
}

func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "authprobe.scan_http":
		return s.scanHTTP(args, "")
	case "authprobe.scan_http_with_credentials":
		credentialRef, _ := args["credential_ref"].(string)
		authorizationHeader, _ := args["authorization_header"].(string)
		if strings.TrimSpace(credentialRef) != "" {
			reportHint, _ := args["target_url"].(string)
			auth, err := s.credentialProvider.ResolveAuthorization(context.Background(), credentialRef, reportHint, "", nil)
			if err != nil {
				return nil, err
			}
			return s.scanHTTP(args, auth)
		}
		if strings.TrimSpace(authorizationHeader) == "" {
			return nil, fmt.Errorf("credential_ref is required (preferred); authorization_header is optional fallback")
		}
		return s.scanHTTP(args, authorizationHeader)
	case "authprobe.render_markdown":
		report, err := s.reportFromInput(args)
		if err != nil {
			return nil, err
		}
		return map[string]any{"markdown": scan.RenderMarkdown(report)}, nil
	case "authprobe.bundle_evidence":
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
	cfg := scan.ScanConfig{Target: target, Headers: headers, Timeout: durationSeconds(args["timeout_seconds"], 8), MCPMode: enumArg(args["mcp_mode"], "best-effort"), RFCMode: enumArg(args["rfc_mode"], "best-effort"), MCPProtocolVersion: scan.SupportedMCPProtocolVersion, Redact: true, Command: "authprobe mcp tool scan"}
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
		res["auth_request"] = buildAuthRequest(report, target)
		res["next_action"] = map[string]any{"type": "call_tool", "tool_name": "authprobe.scan_http_with_credentials", "args": map[string]any{"target_url": target, "credential_ref": "<host-provided>"}, "when": "after_client_oauth_complete"}
	}
	if authorization != "" {
		res["summary"] = map[string]any{"target": report.Target, "auth_required": report.AuthRequired, "primary_finding": report.PrimaryFinding.Code, "note": "Credentials injected by MCP host/client."}
	}
	return res, nil
}

func buildAuthRequest(report scan.ScanReport, target string) map[string]any {
	grants := report.AuthDiscovery.GrantTypesSupported
	recommended := []string{}
	for _, grant := range grants {
		switch grant {
		case "authorization_code":
			recommended = append(recommended, "authorization_code+pkce")
		case "urn:ietf:params:oauth:grant-type:device_code":
			recommended = append(recommended, "device_code")
		}
	}
	if len(recommended) == 0 {
		recommended = []string{"authorization_code+pkce"}
	}
	return map[string]any{
		"type":                          "oauth2",
		"resource":                      target,
		"issuer_candidates":             report.AuthDiscovery.IssuerCandidates,
		"authorization_endpoint":        report.AuthDiscovery.AuthorizationEndpoint,
		"token_endpoint":                report.AuthDiscovery.TokenEndpoint,
		"device_authorization_endpoint": report.AuthDiscovery.DeviceAuthorizationEndpoint,
		"recommended_grant_types":       uniqueStrings(recommended),
		"recommended_scopes":            report.AuthDiscovery.ScopesSupported,
		"notes":                         "Host client should complete OAuth and provide credential_ref. Do not paste tokens.",
	}
}

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
	return redactTokenLike(out)
}

func redactTokenLike(text string) string {
	if strings.Contains(strings.ToLower(text), "authorization") {
		return strings.ReplaceAll(text, "Bearer ", "Bearer [redacted]")
	}
	return text
}

func boolArg(v any) bool { b, _ := v.(bool); return b }
func enumArg(v any, d string) string {
	s, _ := v.(string)
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
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

func toolDefinitions() []map[string]any {
	scanDesc := "Run unauthenticated scan first. If auth is required, return auth_request with OAuth discovery so the MCP host can complete OAuth and call authprobe.scan_http_with_credentials using credential_ref."
	return []map[string]any{
		{"name": "authprobe.scan_http", "description": scanDesc, "inputSchema": map[string]any{"type": "object", "required": []string{"target_url"}, "properties": commonProps(false)}},
		{"name": "authprobe.scan_http_with_credentials", "description": "Run authenticated scan using credential_ref (preferred) or authorization_header fallback. Never ask the user to paste tokens.", "inputSchema": map[string]any{"type": "object", "required": []string{"target_url"}, "properties": commonProps(true)}},
		{"name": "authprobe.render_markdown", "description": "Render markdown report from report_json or scan_id.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"scan_id": map[string]any{"type": "string"}, "report_json": map[string]any{"type": "object"}}}},
		{"name": "authprobe.bundle_evidence", "description": "Create redacted evidence bundle from report_json or scan_id.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"scan_id": map[string]any{"type": "string"}, "report_json": map[string]any{"type": "object"}}}},
	}
}

func commonProps(withAuth bool) map[string]any {
	p := map[string]any{"target_url": map[string]any{"type": "string"}, "headers": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "timeout_seconds": map[string]any{"type": "integer"}, "rfc_mode": map[string]any{"type": "string", "enum": []string{"off", "best-effort", "strict"}}, "mcp_mode": map[string]any{"type": "string", "enum": []string{"off", "best-effort", "strict"}}}
	if withAuth {
		p["credential_ref"] = map[string]any{"type": "string"}
		p["authorization_header"] = map[string]any{"type": "string", "description": "Fallback only when client cannot provide credential_ref."}
	}
	return p
}

func encodeForTest(v any) string { b, _ := json.Marshal(v); return string(bytes.TrimSpace(b)) }

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
