package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"authprobe/internal/scan"
)

const sessionTTL = 10 * time.Minute

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
	sessions           map[string]*scanSession
	mu                 sync.Mutex
	now                func() time.Time
	defaultAuthAssist  string
	credentialProvider CredentialProvider
}

type scanSession struct {
	ScanID              string
	TargetURL           string
	Headers             []string
	TimeoutSeconds      int
	MCPMode             string
	RFCMode             string
	AllowPrivateIssuers bool
	Insecure            bool
	NoFollowRedirects   bool
	LoginURL            string
	VerificationURI     string
	UserCode            string
	Issuer              string
	ClientID            string
	DeviceCode          string
	TokenEndpoint       string
	PollInterval        time.Duration
	TokenExpiresAt      time.Time
	SessionExpiresAt    time.Time
	AccessToken         string
}

type dcrRegistration struct {
	Issuer               string
	RegistrationEndpoint string
	ClientID             string
}

// New creates an MCP server instance with IO streams and in-memory scan caches.
// Inputs: stdin reader, stdout writer, stderr writer.
// Outputs: initialized *Server ready to serve requests.
func New(in io.Reader, out io.Writer, errOut io.Writer) *Server {
	defaultAssist := strings.TrimSpace(strings.ToLower(os.Getenv("AUTHPROBE_MCP_DEFAULT_AUTH_ASSIST")))
	if defaultAssist != "off" {
		defaultAssist = "auto"
	}
	return &Server{in: in, out: out, errOut: errOut, scans: map[string]scan.ScanSummary{}, reports: map[string]scan.ScanReport{}, sessions: map[string]*scanSession{}, now: time.Now, defaultAuthAssist: defaultAssist, credentialProvider: envCredentialProvider{}}
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

// isNullID reports whether a raw JSON-RPC id is explicitly null.
// Inputs: raw JSON id bytes from request payload.
// Outputs: true when id equals JSON null.
func isNullID(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

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

func durationSecondsInt(v any, d int) int {
	switch t := v.(type) {
	case float64:
		if int(t) > 0 {
			return int(t)
		}
	case int:
		if t > 0 {
			return t
		}
	}
	return d
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

func stringSliceAny(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func preferredAuthMethod(methods []string) string {
	if containsString(methods, "none") {
		return "none"
	}
	if len(methods) > 0 && strings.TrimSpace(methods[0]) != "" {
		return strings.TrimSpace(methods[0])
	}
	return "none"
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

func stringValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func newHTTPClient(timeout time.Duration, insecure bool, noFollow bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	if noFollow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	}
	return client
}
