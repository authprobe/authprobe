package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authprobe/internal/scan"
)

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
