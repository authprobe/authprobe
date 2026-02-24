package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authprobe/internal/scan"
)

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
	case "authprobe.render_markdown", "authprobe_render_markdown":
		report, err := s.reportFromInput(args)
		if err != nil {
			return nil, err
		}
		return map[string]any{"markdown": scan.RenderMarkdown(report)}, nil
	case "authprobe.bundle_evidence", "authprobe_bundle_evidence":
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

func resolveOutputFormat(raw any) string {
	mode := strings.TrimSpace(strings.ToLower(enumArg(raw, "markdown")))
	if mode == "json" {
		return "json"
	}
	return "markdown"
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
			"name":        "authprobe_render_markdown",
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
			"name":        "authprobe_bundle_evidence",
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
