package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// callTool executes one exposed MCP tool by name using provided arguments.
// Inputs: tool name and arguments map.
// Outputs: structured tool result map and optional error.
func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	s.evictExpiredSessions()
	switch name {
	case "authprobe.scan_http", "authprobe_scan_http":
		return s.scanHTTP(args, "")
	case "authprobe.scan_resume", "authprobe_scan_resume":
		return s.scanResume(args)
	case "authprobe.scan_http_with_credentials", "authprobe_scan_http_with_credentials":
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
	authAssist := resolveAuthAssist(args["auth_assist"], s.defaultAuthAssist)
	outputFormat := resolveOutputFormat(args["output_format"])
	secrets := []string{}
	if authorization != "" {
		headers = append(headers, "Authorization: "+authorization)
		secrets = append(secrets, authorization)
	}
	timeoutSeconds := durationSecondsInt(args["timeout_seconds"], 8)
	cfg := scan.NewBaseConfig(scan.BaseConfigInput{
		Target:              target,
		Command:             "authprobe mcp tool scan",
		Headers:             headers,
		Timeout:             time.Duration(timeoutSeconds) * time.Second,
		MCPProbeTimeout:     2 * time.Second,
		MCPMode:             enumArg(args["mcp_mode"], "best-effort"),
		MCPProtocolVersion:  scan.SupportedMCPProtocolVersion,
		RFCMode:             enumArg(args["rfc_mode"], "best-effort"),
		AllowPrivateIssuers: boolArg(args["allow_private_issuers"]),
		Insecure:            boolArg(args["insecure"]),
		NoFollowRedirects:   boolArg(args["no_follow_redirects"]),
		TraceFailure:        boolArg(args["trace_failure"]),
		Redact:              true,
	})
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
	var dcr *dcrRegistration
	dcrErr := ""
	res := map[string]any{
		"status":        "ok",
		"scan_id":       scanID,
		"summary":       map[string]any{"target": report.Target, "auth_required": report.AuthRequired, "primary_finding": report.PrimaryFinding.Code},
		"output_format": outputFormat,
	}
	if outputFormat == "json" {
		res["scan"] = reportObj
	} else {
		res["markdown"] = scan.RenderMarkdown(report)
	}
	if report.AuthRequired && authorization == "" {
		authAssistError := ""
		if authAssist == "auto" {
			dcr, err = s.runDCRRegistration(report, timeoutSeconds, cfg)
			if err != nil {
				dcrErr = err.Error()
			}
			assist, err := s.startAuthAssist(report, target, headers, timeoutSeconds, cfg, dcr)
			if err == nil {
				return assist, nil
			}
			authAssistError = err.Error()
		}
		res["status"] = "auth_required"
		res["auth_request"] = buildAuthRequest(report, target, dcr)
		res["next_action"] = map[string]any{
			"type": "info",
			"message": "Authorization is required. AuthProbe can continue automatically " +
				"when DCR + device flow are available.",
		}
		if authAssist == "auto" {
			if dcr != nil {
				res["auth_assist"] = map[string]any{
					"mode":                  "auto",
					"status":                "dcr_completed",
					"reason":                authAssistUnavailableReason(report, authAssistError),
					"issuer":                dcr.Issuer,
					"registration_endpoint": dcr.RegistrationEndpoint,
					"client_id":             dcr.ClientID,
				}
			} else {
				reason := authAssistUnavailableReason(report, authAssistError)
				if strings.TrimSpace(dcrErr) != "" {
					reason = reason + "; dcr unavailable: " + dcrErr
				}
				res["auth_assist"] = map[string]any{
					"mode":   "auto",
					"status": "unavailable",
					"reason": reason,
				}
			}
		}
	}
	if authorization != "" {
		res["summary"] = map[string]any{
			"target":          report.Target,
			"auth_required":   report.AuthRequired,
			"primary_finding": report.PrimaryFinding.Code,
			"note":            "Credentials injected by MCP host/client.",
		}
	}
	return res, nil
}

// buildAuthRequest constructs OAuth guidance payload from scan discovery data.
// Inputs: scan report, target resource URL, optional DCR registration result.
// Outputs: auth request object for MCP clients.
func buildAuthRequest(report scan.ScanReport, target string, dcr *dcrRegistration) map[string]any {
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
	req := map[string]any{
		"type":                          "oauth2",
		"resource":                      target,
		"issuer_candidates":             report.AuthDiscovery.IssuerCandidates,
		"authorization_endpoint":        report.AuthDiscovery.AuthorizationEndpoint,
		"token_endpoint":                report.AuthDiscovery.TokenEndpoint,
		"device_authorization_endpoint": report.AuthDiscovery.DeviceAuthorizationEndpoint,
		"recommended_grant_types":       uniqueStrings(recommended),
		"recommended_scopes":            report.AuthDiscovery.ScopesSupported,
		"notes": "Host client should complete OAuth and provide credential_ref. " +
			"Do not paste tokens.",
	}
	if dcr != nil {
		req["client_id"] = dcr.ClientID
		req["registration_endpoint"] = dcr.RegistrationEndpoint
		if strings.TrimSpace(dcr.Issuer) != "" {
			req["issuer"] = dcr.Issuer
		}
	}
	return req
}

// resolveAuthAssist normalizes auth_assist mode with auto as default behavior.
// Inputs: raw argument value and default mode.
// Outputs: one of "auto" or "off".
func resolveAuthAssist(raw any, defaultMode string) string {
	mode := strings.TrimSpace(strings.ToLower(enumArg(raw, defaultMode)))
	if mode == "off" {
		return "off"
	}
	if mode == "auto" {
		return "auto"
	}
	if strings.TrimSpace(strings.ToLower(defaultMode)) == "off" {
		return "off"
	}
	// Default to auto unless explicitly disabled.
	return "auto"
}

// resolveOutputFormat normalizes MCP output format with markdown default.
// Inputs: raw output_format argument.
// Outputs: one of "markdown" or "json".
func resolveOutputFormat(raw any) string {
	mode := strings.TrimSpace(strings.ToLower(enumArg(raw, "markdown")))
	if mode == "json" {
		return "json"
	}
	return "markdown"
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
	return redactTokenLike(out)
}

func redactTokenLike(text string) string {
	if strings.Contains(strings.ToLower(text), "authorization") {
		return strings.ReplaceAll(text, "Bearer ", "Bearer [redacted]")
	}
	return text
}

func (s *Server) evictExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.SessionExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// startAuthAssist begins OAuth auth-assist and creates a resumable scan session.
// report: scan report containing discovered OAuth endpoints.
// target: original MCP resource URL being scanned.
// headers: caller-supplied HTTP headers to reuse during resumed scan.
// timeoutSeconds: per-request timeout budget in seconds.
// cfg: scan execution config flags for HTTP and protocol behavior.
// dcr: optional pre-registered DCR client; nil triggers auto registration.
func (s *Server) startAuthAssist(
	report scan.ScanReport,
	target string,
	headers []string,
	timeoutSeconds int,
	cfg scan.ScanConfig,
	dcr *dcrRegistration,
) (map[string]any, error) {
	client := newHTTPClient(
		time.Duration(timeoutSeconds)*time.Second,
		cfg.Insecure,
		cfg.NoFollowRedirects,
	)
	if report.AuthDiscovery.DeviceAuthorizationEndpoint == "" || report.AuthDiscovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("missing device_authorization_endpoint or token_endpoint")
	}
	if dcr == nil {
		var err error
		dcr, err = s.runDCRRegistration(report, timeoutSeconds, cfg)
		if err != nil {
			return nil, err
		}
	}
	deviceEndpoint := report.AuthDiscovery.DeviceAuthorizationEndpoint
	values := url.Values{}
	values.Set("client_id", dcr.ClientID)
	devResp, err := postForm(client, deviceEndpoint, values, nil)
	if err != nil {
		return nil, err
	}
	deviceCode, _ := devResp["device_code"].(string)
	if deviceCode == "" {
		return nil, fmt.Errorf("device flow failed: missing device_code")
	}
	verificationComplete, _ := devResp["verification_uri_complete"].(string)
	verificationURI, _ := devResp["verification_uri"].(string)
	loginURL := verificationComplete
	if loginURL == "" {
		loginURL = verificationURI
	}
	if loginURL == "" {
		return nil, fmt.Errorf("device flow failed: missing verification URI")
	}
	interval := 5
	if v, ok := devResp["interval"].(float64); ok && int(v) > 0 {
		interval = int(v)
	}
	expiresIn := 600
	if v, ok := devResp["expires_in"].(float64); ok && int(v) > 0 {
		expiresIn = int(v)
	}
	scanID := fmt.Sprintf("scan_%d", s.now().UnixNano())
	sess := &scanSession{
		ScanID:              scanID,
		TargetURL:           target,
		Headers:             append([]string{}, headers...),
		TimeoutSeconds:      timeoutSeconds,
		MCPMode:             cfg.MCPMode,
		RFCMode:             cfg.RFCMode,
		AllowPrivateIssuers: cfg.AllowPrivateIssuers,
		Insecure:            cfg.Insecure,
		NoFollowRedirects:   cfg.NoFollowRedirects,
		LoginURL:            loginURL,
		VerificationURI:     verificationURI,
		UserCode:            stringValue(devResp["user_code"]),
		Issuer:              dcr.Issuer,
		ClientID:            dcr.ClientID,
		DeviceCode:          deviceCode,
		TokenEndpoint:       report.AuthDiscovery.TokenEndpoint,
		PollInterval:        time.Duration(interval) * time.Second,
		TokenExpiresAt:      s.now().Add(time.Duration(expiresIn) * time.Second),
		SessionExpiresAt:    s.now().Add(sessionTTL),
	}
	s.mu.Lock()
	s.sessions[scanID] = sess
	s.mu.Unlock()
	return map[string]any{
		"status":           "awaiting_user_auth",
		"scan_id":          scanID,
		"login_url":        loginURL,
		"verification_uri": verificationURI,
		"user_code":        sess.UserCode,
		"next_action": map[string]any{
			"type":      "call_tool",
			"tool_name": "authprobe_scan_resume",
			"args":      map[string]any{"scan_id": scanID},
		},
	}, nil
}

// runDCRRegistration performs dynamic client registration based on issuer metadata.
// Inputs: scan report, timeout seconds, and scan config flags.
// Outputs: registered client metadata or an error.
func (s *Server) runDCRRegistration(
	report scan.ScanReport,
	timeoutSeconds int,
	cfg scan.ScanConfig,
) (*dcrRegistration, error) {
	client := newHTTPClient(
		time.Duration(timeoutSeconds)*time.Second,
		cfg.Insecure,
		cfg.NoFollowRedirects,
	)
	issuer := ""
	if len(report.AuthDiscovery.IssuerCandidates) > 0 {
		issuer = report.AuthDiscovery.IssuerCandidates[0]
	}
	metadataCandidates := []string{}
	if issuer != "" {
		metadataCandidates = append(
			metadataCandidates,
			strings.TrimRight(issuer, "/")+"/.well-known/oauth-authorization-server",
		)
	}
	if strings.TrimSpace(report.AuthDiscovery.TokenEndpoint) != "" {
		tokenURL, err := url.Parse(report.AuthDiscovery.TokenEndpoint)
		if err == nil &&
			strings.TrimSpace(tokenURL.Scheme) != "" &&
			strings.TrimSpace(tokenURL.Host) != "" {
			base := tokenURL.Scheme + "://" + tokenURL.Host
			metadataCandidates = append(
				metadataCandidates,
				base+"/.well-known/oauth-authorization-server",
			)
			if issuer == "" {
				issuer = base
			}
		}
	}
	regEndpoint := ""
	var meta map[string]any
	for _, candidate := range uniqueStrings(metadataCandidates) {
		candidateMeta, err := fetchJSON(client, candidate)
		if err != nil {
			continue
		}
		if v, _ := candidateMeta["registration_endpoint"].(string); strings.TrimSpace(v) != "" {
			regEndpoint = v
			meta = candidateMeta
			break
		}
	}
	if regEndpoint == "" {
		return nil, fmt.Errorf("missing registration_endpoint")
	}
	if v, _ := meta["issuer"].(string); strings.TrimSpace(v) != "" {
		issuer = strings.TrimSpace(v)
	}
	payloads := buildDCRRegistrationPayloads(meta, report)
	errors := make([]string, 0, len(payloads))
	for _, regBody := range payloads {
		regResp, err := postFormOrJSON(client, regEndpoint, regBody, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		clientID, _ := regResp["client_id"].(string)
		if strings.TrimSpace(clientID) == "" {
			errors = append(errors, "registration failed: missing client_id")
			continue
		}
		return &dcrRegistration{
			Issuer:               issuer,
			RegistrationEndpoint: regEndpoint,
			ClientID:             clientID,
		}, nil
	}
	if len(errors) == 0 {
		errors = append(errors, "no registration payload candidates")
	}
	return nil, fmt.Errorf(
		"registration failed: %s",
		strings.Join(uniqueStrings(errors), "; "),
	)
}

// buildDCRRegistrationPayloads builds metadata-driven candidate DCR payloads.
// Inputs: auth server metadata and scan report auth discovery details.
// Outputs: ordered list of registration payload candidates.
func buildDCRRegistrationPayloads(meta map[string]any, report scan.ScanReport) []map[string]any {
	authMethods := stringSliceAny(meta["token_endpoint_auth_methods_supported"])
	grantTypes := stringSliceAny(meta["grant_types_supported"])
	responseTypes := stringSliceAny(meta["response_types_supported"])
	scopes := stringSliceAny(meta["scopes_supported"])
	authMethod := preferredAuthMethod(authMethods)
	scope := strings.Join(scopes, " ")

	supportsDevice := strings.TrimSpace(
		report.AuthDiscovery.DeviceAuthorizationEndpoint,
	) != "" || containsString(grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
	supportsAuthCode := containsString(grantTypes, "authorization_code") ||
		len(grantTypes) == 0
	if !supportsDevice && !supportsAuthCode {
		supportsAuthCode = true
	}

	payloads := []map[string]any{}
	if supportsDevice {
		deviceBody := map[string]any{
			"client_name":                "AuthProbe MCP",
			"token_endpoint_auth_method": authMethod,
			"grant_types": []string{
				"urn:ietf:params:oauth:grant-type:device_code",
			},
		}
		if scope != "" {
			deviceBody["scope"] = scope
		}
		payloads = append(payloads, deviceBody)
	}

	if supportsAuthCode {
		authCodeGrants := []string{"authorization_code"}
		if containsString(grantTypes, "refresh_token") {
			authCodeGrants = append(authCodeGrants, "refresh_token")
		}
		authCodeBody := map[string]any{
			"client_name":                "AuthProbe MCP",
			"token_endpoint_auth_method": authMethod,
			"grant_types":                authCodeGrants,
			"response_types":             []string{"code"},
			"redirect_uris":              []string{"https://example.com/callback"},
		}
		if containsString(responseTypes, "code") {
			authCodeBody["response_types"] = []string{"code"}
		}
		if scope != "" {
			authCodeBody["scope"] = scope
		}
		payloads = append(payloads, authCodeBody)
	}
	return payloads
}

// authAssistUnavailableReason maps startup failures into user-facing reason text.
// Inputs: scan report and auth-assist startup error text.
// Outputs: explanatory reason string.
func authAssistUnavailableReason(report scan.ScanReport, startErr string) string {
	if strings.TrimSpace(report.AuthDiscovery.DeviceAuthorizationEndpoint) == "" {
		return "issuer metadata does not advertise " +
			"device_authorization_endpoint (device flow unavailable in this MVP)"
	}
	if strings.TrimSpace(report.AuthDiscovery.TokenEndpoint) == "" {
		return "issuer metadata does not advertise token_endpoint"
	}
	if strings.Contains(startErr, "registration_endpoint") {
		return "issuer metadata does not advertise registration_endpoint required " +
			"for dynamic client registration"
	}
	if strings.TrimSpace(startErr) != "" {
		return "automatic auth-assist could not start: " + startErr
	}
	return "automatic auth-assist unavailable for this target"
}

// scanResume polls token issuance and resumes the scan once auth completes.
// Inputs: args map with required scan_id.
// Outputs: status/result payload and optional error.
func (s *Server) scanResume(args map[string]any) (map[string]any, error) {
	id, _ := args["scan_id"].(string)
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("scan_id is required")
	}
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown scan_id")
	}
	if s.now().After(sess.SessionExpiresAt) || s.now().After(sess.TokenExpiresAt) {
		return map[string]any{"status": "auth_required", "next_action": "scan session expired; start a new scan"}, nil
	}
	if sess.AccessToken == "" {
		client := newHTTPClient(
			time.Duration(sess.TimeoutSeconds)*time.Second,
			sess.Insecure,
			sess.NoFollowRedirects,
		)
		values := url.Values{}
		values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		values.Set("device_code", sess.DeviceCode)
		values.Set("client_id", sess.ClientID)
		tokenResp, err := postForm(client, sess.TokenEndpoint, values, nil)
		if err != nil {
			return nil, err
		}
		if errCode := stringValue(tokenResp["error"]); errCode != "" {
			switch errCode {
			case "authorization_pending":
				return map[string]any{
					"status":                "awaiting_user_auth",
					"scan_id":               id,
					"login_url":             sess.LoginURL,
					"remaining_ttl_seconds": int(time.Until(sess.SessionExpiresAt).Seconds()),
				}, nil
			case "slow_down":
				sess.PollInterval += time.Second
				return map[string]any{
					"status":                "awaiting_user_auth",
					"scan_id":               id,
					"login_url":             sess.LoginURL,
					"remaining_ttl_seconds": int(time.Until(sess.SessionExpiresAt).Seconds()),
				}, nil
			case "access_denied", "expired_token":
				return map[string]any{
					"status":      "auth_required",
					"scan_id":     id,
					"next_action": "authorization failed or expired; restart scan",
				}, nil
			}
		}
		token := stringValue(tokenResp["access_token"])
		if token == "" {
			return map[string]any{
				"status":                "awaiting_user_auth",
				"scan_id":               id,
				"login_url":             sess.LoginURL,
				"remaining_ttl_seconds": int(time.Until(sess.SessionExpiresAt).Seconds()),
			}, nil
		}
		sess.AccessToken = token
	}
	result, err := s.scanHTTP(
		map[string]any{
			"target_url":            sess.TargetURL,
			"headers":               toAnySlice(sess.Headers),
			"timeout_seconds":       sess.TimeoutSeconds,
			"mcp_mode":              sess.MCPMode,
			"rfc_mode":              sess.RFCMode,
			"allow_private_issuers": sess.AllowPrivateIssuers,
			"insecure":              sess.Insecure,
			"no_follow_redirects":   sess.NoFollowRedirects,
			"auth_assist":           "off",
		},
		"Bearer "+sess.AccessToken,
	)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	return result, nil
}

// toAnySlice converts []string to []any for JSON-like argument passing.
// Inputs: string slice.
// Outputs: []any with identical values.
func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

// stringValue returns a trimmed string when v is a string, else empty string.
// Inputs: arbitrary value.
// Outputs: trimmed string.
func stringValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// newHTTPClient creates an HTTP client with TLS/redirect behavior from flags.
// Inputs: timeout, insecure TLS flag, and no-follow-redirects flag.
// Outputs: configured *http.Client.
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

// fetchJSON performs GET and decodes a JSON object body.
// Inputs: HTTP client and endpoint URL.
// Outputs: decoded JSON object and optional error.
func fetchJSON(client *http.Client, endpoint string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed %d", resp.StatusCode)
	}
	return payload, nil
}

// postFormOrJSON posts JSON body and decodes JSON object response.
// Inputs: HTTP client, endpoint URL, JSON payload, and optional headers.
// Outputs: decoded JSON object and optional error.
func postFormOrJSON(client *http.Client, endpoint string, body map[string]any, headers map[string]string) (map[string]any, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed %d", resp.StatusCode)
	}
	return payload, nil
}

// postForm posts x-www-form-urlencoded body and decodes JSON object response.
// Inputs: HTTP client, endpoint URL, form values, and optional headers.
// Outputs: decoded JSON object and optional error.
func postForm(client *http.Client, endpoint string, values url.Values, headers map[string]string) (map[string]any, error) {
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 && stringValue(payload["error"]) == "" {
		return nil, fmt.Errorf("request failed %d", resp.StatusCode)
	}
	return payload, nil
}

// boolArg casts a dynamic argument to bool with false default.
// Inputs: arbitrary value.
// Outputs: bool value or false when type does not match.
func boolArg(v any) bool { b, _ := v.(bool); return b }

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
	scanDesc := "Run unauthenticated scan first. Output defaults to markdown. " +
		"auth_assist defaults to auto (DCR + OAuth device flow); set " +
		"auth_assist=off to disable."
	return []map[string]any{
		{
			"name":        "authprobe_scan_http",
			"description": scanDesc,
			"inputSchema": map[string]any{
				"type":       "object",
				"required":   []string{"target_url"},
				"properties": commonProps(false),
			},
		},
		{
			"name": "authprobe_scan_resume",
			"description": "Resume an auth_assist scan. Returns awaiting_user_auth " +
				"until authorization succeeds, then finishes scan.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"scan_id"},
				"properties": map[string]any{
					"scan_id": map[string]any{"type": "string"},
				},
			},
		},
		{
			"name": "authprobe_scan_http_with_credentials",
			"description": "Run authenticated scan using credential_ref (preferred) " +
				"or authorization_header fallback. Never ask the user to paste " +
				"tokens.",
			"inputSchema": map[string]any{
				"type":       "object",
				"required":   []string{"target_url"},
				"properties": commonProps(true),
			},
		},
		{
			"name":        "authprobe.render_markdown",
			"description": "Render markdown report from report_json or scan_id.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scan_id":     map[string]any{"type": "string"},
					"report_json": map[string]any{"type": "object"},
				},
			},
		},
		{
			"name":        "authprobe.bundle_evidence",
			"description": "Create redacted evidence bundle from report_json or scan_id.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scan_id":     map[string]any{"type": "string"},
					"report_json": map[string]any{"type": "object"},
				},
			},
		},
	}
}

// commonProps builds shared JSON schema properties for scan tool inputs.
// Inputs: withAuth flag to include auth fields.
// Outputs: JSON-schema properties map.
func commonProps(withAuth bool) map[string]any {
	p := map[string]any{
		"target_url": map[string]any{"type": "string"},
		"headers": map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "string"},
		},
		"timeout_seconds": map[string]any{"type": "integer"},
		"trace_failure":   map[string]any{"type": "boolean", "default": false},
		"output_format": map[string]any{
			"type":    "string",
			"enum":    []string{"markdown", "json"},
			"default": "markdown",
		},
		"auth_assist": map[string]any{
			"type":    "string",
			"enum":    []string{"off", "auto"},
			"default": "auto",
		},
		"allow_private_issuers": map[string]any{"type": "boolean"},
		"insecure":              map[string]any{"type": "boolean"},
		"no_follow_redirects":   map[string]any{"type": "boolean"},
		"rfc_mode": map[string]any{
			"type": "string",
			"enum": []string{"off", "best-effort", "strict"},
		},
		"mcp_mode": map[string]any{
			"type": "string",
			"enum": []string{"off", "best-effort", "strict"},
		},
	}
	if withAuth {
		p["credential_ref"] = map[string]any{"type": "string"}
		p["authorization_header"] = map[string]any{
			"type":        "string",
			"description": "Fallback only when client cannot provide credential_ref.",
		}
	}
	return p
}

// encodeForTest marshals a value to compact JSON for tests/helpers.
// Inputs: arbitrary value.
// Outputs: JSON string (trimmed) with best-effort encoding.
func encodeForTest(v any) string { b, _ := json.Marshal(v); return string(bytes.TrimSpace(b)) }

// uniqueStrings deduplicates non-empty strings while preserving first-seen order.
// Inputs: string slice.
// Outputs: unique string slice.
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

// stringSliceAny converts []any to trimmed []string values.
// Inputs: arbitrary value expected to be []any.
// Outputs: string slice or nil when type mismatch.
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

// containsString reports whether trimmed want exists in values.
// Inputs: candidate values and target string.
// Outputs: true when found.
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

// preferredAuthMethod picks the best token endpoint auth method for DCR.
// Inputs: supported auth methods from server metadata.
// Outputs: selected auth method string.
func preferredAuthMethod(methods []string) string {
	if containsString(methods, "none") {
		return "none"
	}
	if len(methods) > 0 && strings.TrimSpace(methods[0]) != "" {
		return strings.TrimSpace(methods[0])
	}
	return "none"
}
