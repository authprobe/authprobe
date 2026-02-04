package cli

// utils.go - Utility functions for scan operations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Content Type & Mode Checks          │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ parseJSONBody                       │ Parse JSON from response body bytes                        │
// │ isJSONContentType                   │ Check if content-type is JSON                              │
// │ isSSEContentType                    │ Check if content-type is Server-Sent Events                │
// │ rfcModeEnabled / rfcModeStrict      │ Check RFC conformance mode settings                        │
// │ mcpModeEnabled / mcpModeStrict      │ Check MCP conformance mode settings                        │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ URL & Network Helpers               │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ isHTTPSURL                          │ Check if URL uses HTTPS scheme                             │
// │ isRedirectStatus                    │ Check if HTTP status is a redirect (3xx)                   │
// │ resolveURL                          │ Resolve relative URL against base                          │
// │ buildPRMCandidates                  │ Build PRM discovery candidate URLs (RFC 9728)              │
// │ buildPathSuffixCandidate            │ Build path-suffix PRM URL                                  │
// │ buildMetadataURL                    │ Build authorization server metadata URL (RFC 8414)         │
// │ extractResourceMetadata             │ Extract resource_metadata from WWW-Authenticate            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Validation & Security               │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ validateFetchTarget                 │ Validate URL for SSRF protection                           │
// │ validateURLString                   │ Validate URL for RFC 3986 conformance                      │
// │ isDisallowedIP                      │ Check if IP is private/loopback (SSRF block)               │
// │ issuerPrivate                       │ Check if issuer URL points to private address              │
// │ isSafeIconURI                       │ Check if icon URI uses safe scheme (https/data)            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Finding Helpers                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ newFinding                          │ Create finding with auto severity/confidence               │
// │ newMCPFinding                       │ Create MCP finding (upgrades severity in strict mode)      │
// │ newFindingWithSeverity              │ Create finding with explicit severity                      │
// │ newFindingWithEvidence              │ Create finding with multiple evidence lines                │
// │ findingRFCExplanation               │ Get RFC explanation text for finding code                  │
// │ findingSeverity                     │ Get severity level for finding code                        │
// │ findingConfidence                   │ Get confidence level for finding code                      │
// │ choosePrimaryFinding                │ Select most important finding from list                    │
// │ severityRank                        │ Convert severity to numeric rank for comparison            │
// │ hasHighSeverity                     │ Check if any finding has high severity                     │
// │ shouldFail                          │ Determine if scan should exit with failure                 │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ HTTP & Header Helpers               │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ fetchJSON                           │ HTTP GET and parse response as JSON                        │
// │ fetchWithRedirects                  │ HTTP GET with redirect handling and SSRF checks            │
// │ postTokenProbe                      │ POST probe to token endpoint with invalid creds            │
// │ applySafeHeaders                    │ Apply headers filtering out sensitive ones                 │
// │ applyHeaders                        │ Apply all headers to request                               │
// │ findHeader                          │ Find header value (case-insensitive)                       │
// │ checkEndpointHostMismatch           │ Check if endpoint host matches issuer                      │
// │ addTrace                            │ Add HTTP request/response to trace log                     │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Capability Checks                   │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ supportsPing                        │ Check if MCP capabilities include ping                     │
// │ supportsTasks                       │ Check if MCP capabilities include tasks                    │
// │ tasksAdvertised                     │ Check if init result advertises tasks                      │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// fetchPolicyError represents a policy violation during fetch operations.
type fetchPolicyError struct {
	Code   string
	Detail string
}

func (e fetchPolicyError) Error() string {
	return e.Detail
}

// resolvedTarget returns the final URL after redirects, or the fallback if not available.
func resolvedTarget(resp *http.Response, fallback string) string {
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return fallback
}

// parseJSONBody parses a JSON response body.
func parseJSONBody(body []byte) (any, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// isJSONContentType checks if a content type is JSON.
func isJSONContentType(contentType string) bool {
	lower := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(lower, "application/json") || strings.Contains(lower, "+json")
}

// isSSEContentType checks if a content type is Server-Sent Events.
func isSSEContentType(contentType string) bool {
	lower := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(lower, "text/event-stream")
}

// rfcModeEnabled returns true if RFC conformance checking is enabled.
func rfcModeEnabled(mode string) bool {
	return mode != "off"
}

// rfcModeStrict returns true if RFC conformance checking is in strict mode.
func rfcModeStrict(mode string) bool {
	return strings.EqualFold(mode, "strict")
}

// mcpModeEnabled returns true if MCP conformance checking is enabled.
func mcpModeEnabled(mode string) bool {
	return mode != "off"
}

// mcpModeStrict returns true if MCP conformance checking is in strict mode.
func mcpModeStrict(mode string) bool {
	return strings.EqualFold(mode, "strict")
}

// isHTTPSURL checks if a URL uses HTTPS scheme.
func isHTTPSURL(parsed *url.URL) bool {
	return parsed != nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != ""
}

// isRedirectStatus checks if an HTTP status code indicates a redirect.
func isRedirectStatus(status int) bool {
	return status >= 300 && status <= 399
}

// containsString checks if a slice contains a target string.
func containsString(list []any, target string) bool {
	for _, entry := range list {
		value, ok := entry.(string)
		if !ok {
			continue
		}
		if value == target {
			return true
		}
	}
	return false
}

// findHeader finds a header value by name (case-insensitive).
func findHeader(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// max returns the larger of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// isTimeoutError checks if an error is a timeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isDisallowedIP checks if an IP address should be blocked for SSRF protection.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// isSafeIconURI checks if a URI is safe for icon references.
func isSafeIconURI(raw string) bool {
	if strings.HasPrefix(raw, "data:") {
		return true
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "https"
}

// hasHighSeverity checks if any finding has high severity.
func hasHighSeverity(findings []finding) bool {
	for _, f := range findings {
		if f.Severity == "high" {
			return true
		}
	}
	return false
}

// supportsPing checks if capabilities indicate ping support.
func supportsPing(capabilities map[string]any) bool {
	if capabilities == nil {
		return false
	}
	if value, ok := capabilities["ping"].(bool); ok {
		return value
	}
	if utilities, ok := capabilities["utilities"].(map[string]any); ok {
		if value, ok := utilities["ping"].(bool); ok {
			return value
		}
	}
	return false
}

// supportsTasks checks if capabilities indicate tasks support.
func supportsTasks(capabilities map[string]any) bool {
	if capabilities == nil {
		return false
	}
	if _, ok := capabilities["tasks"]; ok {
		return true
	}
	if experimental, ok := capabilities["experimental"].(map[string]any); ok {
		if _, ok := experimental["tasks"]; ok {
			return true
		}
	}
	return false
}

// tasksAdvertised checks if the init result advertises tasks.
func tasksAdvertised(initResult map[string]any) bool {
	if initResult == nil {
		return false
	}
	if caps, ok := initResult["capabilities"].(map[string]any); ok {
		if _, ok := caps["tasks"]; ok {
			return true
		}
		if experimental, ok := caps["experimental"].(map[string]any); ok {
			if _, ok := experimental["tasks"]; ok {
				return true
			}
		}
	}
	return false
}

// applySafeHeaders adds headers to a request, filtering out sensitive ones.
func applySafeHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := parseHeader(header)
		if err != nil {
			return err
		}
		lower := strings.ToLower(key)
		if lower == "host" {
			req.Host = value
			continue
		}
		if isSensitiveHeader(key) {
			continue
		}
		req.Header.Add(key, value)
	}
	return nil
}

// applyHeaders adds all headers to a request.
func applyHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := parseHeader(header)
		if err != nil {
			return err
		}
		req.Header.Add(key, value)
	}
	return nil
}

func isSensitiveHeader(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "cookie", "set-cookie", "proxy-authorization":
		return true
	default:
		return false
	}
}

func redactHeaderValue(key, value string, redact bool) string {
	if redact && isSensitiveHeader(key) {
		return "[redacted]"
	}
	return value
}

func sanitizeHeadersForTrace(headers http.Header, redact bool) map[string]string {
	redacted := map[string]string{}
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		redacted[key] = redactHeaderValue(key, value, redact)
	}
	return redacted
}

func isSensitiveField(key string) bool {
	lower := strings.ToLower(key)
	switch lower {
	case "access_token", "refresh_token", "id_token", "client_secret", "client_assertion", "assertion", "password", "token":
		return true
	default:
		return strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password")
	}
}

func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if isSensitiveField(key) {
				typed[key] = "[redacted]"
				continue
			}
			typed[key] = redactJSONValue(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = redactJSONValue(item)
		}
		return typed
	default:
		return value
	}
}

func redactBody(contentType string, body []byte, redact bool) []byte {
	if len(body) == 0 || !redact {
		return body
	}
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "application/json") || strings.Contains(lower, "+json") {
		var payload any
		if err := json.Unmarshal(body, &payload); err != nil {
			return body
		}
		payload = redactJSONValue(payload)
		redacted, err := json.Marshal(payload)
		if err != nil {
			return body
		}
		return redacted
	}
	if strings.Contains(lower, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return body
		}
		for key := range values {
			if isSensitiveField(key) {
				values.Set(key, "[redacted]")
			}
		}
		return []byte(values.Encode())
	}
	return body
}

// resolveURL resolves a reference URL against a base URL.
func resolveURL(base *url.URL, ref string) (*url.URL, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, err
	}
	if parsed.IsAbs() {
		return parsed, nil
	}
	return base.ResolveReference(parsed), nil
}

// buildPRMCandidates builds the list of Protected Resource Metadata (PRM) discovery candidates
// per RFC 9728. It returns up to three candidates in priority order:
//
//  1. resource_metadata: URL from WWW-Authenticate header (if provided)
//  2. root: /.well-known/oauth-protected-resource at the target host
//  3. path-suffix: /.well-known/oauth-protected-resource + target path (if target has a path)
//
// Example for target "https://api.example.com/mcp":
//
//	root:        https://api.example.com/.well-known/oauth-protected-resource
//	path-suffix: https://api.example.com/.well-known/oauth-protected-resource/mcp
//
// The second return value (hasPathSuffix) is true when the target has a non-trivial path,
// indicating that RFC 9728 requires the path-suffix endpoint to exist.
func buildPRMCandidates(target string, resourceMetadata string) ([]prmCandidate, bool, error) {
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, false, fmt.Errorf("invalid mcp url: %w", err)
	}

	candidates := []prmCandidate{}
	if resourceMetadata != "" {
		rmURL, err := resolveURL(parsedTarget, resourceMetadata)
		if err == nil {
			candidates = append(candidates, prmCandidate{URL: rmURL.String(), Source: "resource_metadata"})
		}
	}

	rootURL := parsedTarget.ResolveReference(&url.URL{Path: "/.well-known/oauth-protected-resource"})
	candidates = append(candidates, prmCandidate{URL: rootURL.String(), Source: "root"})

	pathSuffix, hasPathSuffix := buildPathSuffixCandidate(parsedTarget)
	if pathSuffix != "" && pathSuffix != rootURL.String() {
		candidates = append(candidates, prmCandidate{URL: pathSuffix, Source: "path-suffix"})
	}
	return candidates, hasPathSuffix, nil
}

// buildPathSuffixCandidate builds the path-suffix PRM candidate URL.
func buildPathSuffixCandidate(target *url.URL) (string, bool) {
	path := target.EscapedPath()
	hasPathSuffix := (path != "" && path != "/") || target.RawQuery != ""
	if !hasPathSuffix {
		return "", false
	}
	trimmed := strings.TrimSuffix(path, "/")
	if trimmed == "" || trimmed == "/" {
		trimmed = ""
	}
	targetCopy := *target
	targetCopy.Path = "/.well-known/oauth-protected-resource" + trimmed
	targetCopy.RawQuery = ""
	targetCopy.Fragment = ""
	return targetCopy.String(), hasPathSuffix
}

// extractResourceMetadata extracts resource_metadata from WWW-Authenticate headers.
func extractResourceMetadata(headers []string) (string, bool) {
	re := regexp.MustCompile(`resource_metadata\s*=\s*"([^"]+)"|resource_metadata\s*=\s*([^,\s]+)`)
	for _, header := range headers {
		matches := re.FindStringSubmatch(header)
		if len(matches) > 1 && matches[1] != "" {
			return matches[1], true
		}
		if len(matches) > 2 && matches[2] != "" {
			return matches[2], true
		}
	}
	return "", false
}

// buildRFC8414DiscoveryURL builds the authorization server metadata URL per RFC 8414.
// RFC 8414 requires inserting the well-known segment after the host and before the issuer path:
// {scheme}://{host}/.well-known/oauth-authorization-server{issuer_path}
func buildRFC8414DiscoveryURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" {
		return "", errIssuerQueryFragment
	}
	if !parsed.IsAbs() {
		return "", errIssuerNotAbsolute
	}
	if parsed.Host == "" {
		return "", errIssuerMissingHost
	}
	if strings.Contains(parsed.Path, "/.well-known/") {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	issuerPath := parsed.EscapedPath()
	if issuerPath == "" || issuerPath == "/" {
		issuerPath = ""
	} else if strings.HasSuffix(issuerPath, "/") {
		issuerPath = strings.TrimSuffix(issuerPath, "/")
	}
	discovery := url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   "/.well-known/oauth-authorization-server" + issuerPath,
	}
	return discovery.String(), nil
}

// buildMetadataURL builds the authorization server metadata URL (best-effort).
func buildMetadataURL(issuer string) string {
	metadataURL, err := buildRFC8414DiscoveryURL(issuer)
	if err != nil {
		return issuer
	}
	return metadataURL
}

var (
	errIssuerQueryFragment = errors.New("issuer has query or fragment")
	errIssuerNotAbsolute   = errors.New("issuer is not an absolute URL")
	errIssuerMissingHost   = errors.New("issuer is missing host")
)

// canonicalizeIssuerIdentifier normalizes issuer identifiers for RFC 8414 matching.
// It follows RFC 3986/7230 case rules and normalizes HTTPS root issuers so
// https://host and https://host/ compare equal, while keeping non-root paths exact.
func canonicalizeIssuerIdentifier(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errIssuerQueryFragment
	}
	if !parsed.IsAbs() {
		return "", errIssuerNotAbsolute
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errIssuerMissingHost
	}
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = ""
	}
	canonical := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}
	return canonical.String(), nil
}

// issuerPrivate checks if an issuer URL points to a private/local address.
func issuerPrivate(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isDisallowedIP(ip)
}

// validateFetchTarget validates a URL for SSRF protection.
func validateFetchTarget(config scanConfig, target string) error {
	if config.AllowPrivateIssuers {
		return nil
	}
	if !rfcModeEnabled(config.RFCMode) {
		return nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return nil
	}
	if host == "localhost" || strings.HasSuffix(strings.ToLower(host), ".local") {
		return fetchPolicyError{Code: "METADATA_SSRF_BLOCKED", Detail: fmt.Sprintf("blocked host %s", host)}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return fetchPolicyError{Code: "METADATA_SSRF_BLOCKED", Detail: fmt.Sprintf("blocked IP %s", ip.String())}
		}
	}
	return nil
}

// validateURLString validates a URL string for RFC 3986 conformance.
func validateURLString(raw string, label string, config scanConfig, allowRelative bool) []finding {
	if !rfcModeEnabled(config.RFCMode) {
		return nil
	}
	findings := []finding{}
	parsed, err := url.Parse(raw)
	if err != nil {
		findings = append(findings, newFinding("RFC3986_INVALID_URI", fmt.Sprintf("%s invalid URI %q (RFC 3986)", label, raw)))
		return findings
	}
	if !allowRelative && !parsed.IsAbs() {
		findings = append(findings, newFinding("RFC3986_ABSOLUTE_HTTPS_REQUIRED", fmt.Sprintf("%s not absolute: %q", label, raw)))
		return findings
	}
	if parsed.IsAbs() && !isHTTPSURL(parsed) {
		findings = append(findings, newFinding("RFC3986_ABSOLUTE_HTTPS_REQUIRED", fmt.Sprintf("%s not https: %q", label, raw)))
	}
	return findings
}

// checkEndpointHostMismatch checks if an endpoint host matches the issuer host.
func checkEndpointHostMismatch(findings *[]finding, endpoint string, issuerHost string, name string) {
	if endpoint == "" || issuerHost == "" {
		return
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return
	}
	endpointHost := parsedEndpoint.Hostname()
	if endpointHost == "" {
		return
	}
	if !strings.EqualFold(endpointHost, issuerHost) {
		*findings = append(*findings, newFinding("AUTH_SERVER_ENDPOINT_HOST_MISMATCH", fmt.Sprintf("%s host %q != issuer host %q", name, endpointHost, issuerHost)))
	}
}

// statusFromFindings determines the status based on findings.
func statusFromFindings(findings []finding, authRequired bool) string {
	if !authRequired {
		return "SKIP"
	}
	if len(findings) == 0 {
		return "PASS"
	}
	return "FAIL"
}

// newFinding creates a new finding with the given code and evidence.
func newFinding(code string, evidence string) finding {
	severity := findingSeverity(code)
	confidence := findingConfidence(code)
	f := finding{Code: code, Severity: severity, Confidence: confidence}
	if evidence != "" {
		f.Evidence = []string{evidence}
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

// newMCPFinding creates a new MCP finding, upgrading severity in strict mode.
func newMCPFinding(config scanConfig, code string, evidence string) finding {
	if mcpModeStrict(config.MCPMode) && isMCPStrictUpgrade(code) {
		return newFindingWithSeverity(code, evidence, "high")
	}
	return newFinding(code, evidence)
}

// newFindingWithSeverity creates a new finding with explicit severity.
func newFindingWithSeverity(code string, evidence string, severity string) finding {
	confidence := findingConfidence(code)
	f := finding{Code: code, Severity: severity, Confidence: confidence}
	if evidence != "" {
		f.Evidence = []string{evidence}
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

// isMCPStrictUpgrade checks if a code should be upgraded to high severity in strict mode.
func isMCPStrictUpgrade(code string) bool {
	switch code {
	case "MCP_NOTIFICATION_STATUS_INVALID",
		"MCP_NOTIFICATION_BODY_PRESENT",
		"MCP_ORIGIN_NOT_VALIDATED",
		"MCP_PROTOCOL_VERSION_MISMATCH",
		"MCP_PROTOCOL_VERSION_REJECTION_MISSING",
		"MCP_SESSION_ID_REJECTION_MISSING",
		"MCP_PING_INVALID_RESPONSE",
		"MCP_ICON_UNSAFE_SCHEME",
		"MCP_TASKS_METHOD_MISSING",
		"MCP_INITIALIZE_RESULT_INVALID",
		"MCP_CAPABILITIES_INVALID",
		"MCP_TOOLS_LIST_INVALID":
		return true
	default:
		return false
	}
}

// newFindingWithEvidence creates a new finding with multiple evidence lines.
func newFindingWithEvidence(code string, evidence []string) finding {
	severity := findingSeverity(code)
	confidence := findingConfidence(code)
	f := finding{Code: code, Severity: severity, Confidence: confidence}
	if len(evidence) > 0 {
		f.Evidence = evidence
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

// findingRFCExplanation returns the RFC explanation for a finding code.
func findingRFCExplanation(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE":
		return "RFC 9728 discovery expects a WWW-Authenticate header with resource_metadata for protected resources."
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		return "RFC 9728 defines the root /.well-known/oauth-protected-resource endpoint for PRM discovery."
	case "PRM_MISSING_AUTHORIZATION_SERVERS":
		return "RFC 9728 requires authorization_servers in protected resource metadata for OAuth discovery."
	case "PRM_RESOURCE_MISMATCH":
		return "RFC 9728 requires the PRM resource value to exactly match the protected resource URL."
	case "PRM_JWKS_URI_NOT_HTTPS":
		return "RFC 9728 requires jwks_uri to use HTTPS for protected resource metadata."
	case "PRM_RESOURCE_MISSING":
		return "RFC 9728 requires a resource value in protected resource metadata."
	case "PRM_HTTP_STATUS_NOT_200":
		return "RFC 9728 expects a 200 OK response from the PRM endpoint for valid metadata."
	case "PRM_CONTENT_TYPE_NOT_JSON":
		return "RFC 9728 requires the PRM response to be JSON (application/json)."
	case "PRM_NOT_JSON_OBJECT":
		return "RFC 9728 requires the PRM response body to be a JSON object."
	case "PRM_BEARER_METHODS_INVALID":
		return "RFC 9728 defines bearer_methods as a JSON array of strings."
	case "PRM_WELLKNOWN_PATH_SUFFIX_MISSING":
		return "RFC 9728 requires the path-suffix PRM endpoint when the protected resource has a path."
	case "RESOURCE_FRAGMENT_FORBIDDEN":
		return "RFC 8707 forbids resource identifiers with URI fragments."
	case "RFC3986_INVALID_URI":
		return "RFC 3986 requires valid URI syntax for endpoints and issuer identifiers."
	case "RFC3986_ABSOLUTE_HTTPS_REQUIRED":
		return "RFC 3986 and OAuth metadata require absolute HTTPS URLs for endpoints and issuers."
	case "AUTH_SERVER_ISSUER_QUERY_FRAGMENT":
		return "RFC 8414 requires issuer identifiers to omit query and fragment components."
	case "AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON":
		return "RFC 8414 requires authorization server metadata responses to be JSON."
	case "AUTH_SERVER_ISSUER_MISMATCH":
		return "RFC 8414 requires the metadata issuer to exactly match the issuer used for discovery."
	case "AUTH_SERVER_METADATA_UNREACHABLE":
		return "RFC 8414 requires authorization server metadata to be retrievable at the well-known location."
	case "AUTH_SERVER_METADATA_INVALID":
		return "RFC 8414 defines required metadata fields such as issuer, authorization_endpoint, and token_endpoint."
	case "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		return "Issuer metadata resolution was blocked by local policy for private or disallowed addresses."
	case "HEADER_STRIPPED_BY_PROXY_SUSPECTED":
		return "The discovery header was missing, but metadata was still reachable, which can indicate proxy header stripping."
	case "AUTH_SERVER_ENDPOINT_HOST_MISMATCH":
		return "RFC 8414 expects metadata endpoints to align with the issuer host."
	case "AUTH_SERVER_PKCE_S256_MISSING":
		return "RFC 7636 requires support for the S256 code_challenge_method."
	case "AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH":
		return "RFC 8707 requires protected_resources to include the resource identifier when provided."
	case "JWKS_FETCH_ERROR":
		return "RFC 7517 requires a valid JWKS at jwks_uri when present in metadata."
	case "JWKS_INVALID":
		return "RFC 7517 requires a JWKS JSON object with a non-empty keys array."
	case "TOKEN_RESPONSE_NOT_JSON_RISK":
		return "RFC 6749 error responses from the token endpoint are expected to be JSON."
	case "TOKEN_HTTP200_ERROR_PAYLOAD_RISK":
		return "RFC 6749 requires error responses to use appropriate HTTP status codes."
	case "AUTH_SERVER_ROOT_WELLKNOWN_PROBE_FAILED":
		return "Some clients probe the root /.well-known/oauth-authorization-server for legacy compatibility; failures can indicate VS Code compatibility risks."
	case "SCOPES_WHITESPACE_RISK":
		return "Scope strings are parsed literally; leading or trailing whitespace can cause repeated login prompts."
	case "MCP_INITIALIZE_FAILED":
		return "MCP servers should accept the initialize JSON-RPC request and return a valid JSON response per the MCP specification."
	case "MCP_TOOLS_LIST_FAILED":
		return "MCP servers should respond to tools/list with a valid JSON result enumerating tools per the MCP specification."
	case "MCP_PROBE_TIMEOUT":
		return "MCP spec: \"The server MUST either return Content-Type: text/event-stream for GET requests or else return 405 Method Not Allowed.\" Timing out before headers indicates non-compliance."
	case "MCP_GET_NOT_SSE":
		return "MCP streamable HTTP requires GET requests to return Server-Sent Events (text/event-stream) or a 405 Method Not Allowed."
	case "MCP_JSONRPC_ID_NULL_ACCEPTED":
		return "MCP JSON-RPC requires request IDs to be strings or numbers; null IDs must be rejected."
	case "MCP_NOTIFICATION_WITH_ID_ACCEPTED":
		return "MCP JSON-RPC notifications must omit the id member."
	case "MCP_JSONRPC_RESPONSE_ID_MISMATCH":
		return "MCP JSON-RPC responses must echo the request id."
	case "MCP_JSONRPC_RESPONSE_INVALID":
		return "MCP JSON-RPC responses must include jsonrpc: \"2.0\" and exactly one of result or error."
	case "MCP_PROTOCOL_VERSION_MISSING":
		return "MCP initialize responses must include protocolVersion for explicit version negotiation."
	case "MCP_INITIALIZE_ORDERING_NOT_ENFORCED":
		return "MCP servers must require initialize before other requests such as tools/list."
	case "MCP_PROTOCOL_VERSION_MISMATCH":
		return "MCP version negotiation should be explicit and consistent with the requested protocolVersion."
	case "MCP_NOTIFICATION_STATUS_INVALID":
		return "MCP streamable HTTP responses to notifications should return 202 Accepted with no body."
	case "MCP_NOTIFICATION_BODY_PRESENT":
		return "MCP streamable HTTP notifications should not return a response body."
	case "MCP_NOTIFICATION_FAILED":
		return "MCP servers should accept notifications/initialized after initialize completes."
	case "MCP_ORIGIN_NOT_VALIDATED":
		return "MCP servers should validate Origin to mitigate DNS rebinding and return 403 for invalid origins."
	case "MCP_PROTOCOL_VERSION_REJECTION_MISSING":
		return "MCP servers that enforce MCP-Protocol-Version should respond with 400 for invalid values."
	case "MCP_SESSION_ID_REJECTION_MISSING":
		return "MCP servers that enforce MCP-Session-Id should respond with 404 for invalid session IDs."
	case "MCP_PING_INVALID_RESPONSE":
		return "When implemented, ping must return an empty JSON object promptly."
	case "MCP_INITIALIZE_RESULT_INVALID":
		return "MCP initialize results must be JSON objects with protocolVersion and capabilities."
	case "MCP_CAPABILITIES_INVALID":
		return "MCP initialize capabilities must be a JSON object."
	case "MCP_TOOL_INPUT_SCHEMA_MISSING":
		return "MCP tool inputSchema must be present and be a JSON Schema object."
	case "MCP_TOOL_INPUT_SCHEMA_INVALID":
		return "MCP tool inputSchema must be a parseable JSON Schema object."
	case "MCP_TOOLS_LIST_INVALID":
		return "MCP tools/list results must be JSON objects with a tools array."
	case "MCP_TASKS_METHOD_MISSING":
		return "When tasks capability is advertised, the corresponding tasks methods must exist."
	case "MCP_ICON_UNSAFE_SCHEME":
		return "MCP icon metadata should use safe URI schemes such as https: or data:."
	case "METADATA_SSRF_BLOCKED":
		return "Metadata fetch blocked by local SSRF protections; issuer metadata should be on a permitted host."
	case "METADATA_REDIRECT_BLOCKED":
		return "Metadata fetch redirected to a disallowed location and was blocked by policy."
	case "METADATA_REDIRECT_LIMIT":
		return "Metadata fetch exceeded the redirect limit before reaching the issuer metadata."
	case "DCR_ENDPOINT_OPEN":
		return "RFC 7591 recommends protecting the registration endpoint with an initial access token to prevent unauthorized client registration."
	case "DCR_HTTP_REDIRECT_ACCEPTED":
		return "RFC 6749 Section 3.1.2.1 recommends HTTPS for redirect URIs in production to protect authorization codes and tokens."
	case "DCR_LOCALHOST_REDIRECT_ACCEPTED":
		return "Localhost redirect URIs are common in development but may indicate insufficient validation in production."
	case "DCR_DANGEROUS_URI_ACCEPTED":
		return "Registration endpoints should reject dangerous URI schemes like javascript: or file: to prevent security vulnerabilities."
	case "DCR_EMPTY_REDIRECT_URIS_ACCEPTED":
		return "RFC 7591 requires redirect_uris for web application clients; empty arrays may indicate missing validation."
	default:
		return ""
	}
}

// findingSeverity returns the severity level for a finding code.
func findingSeverity(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE",
		"DISCOVERY_ROOT_WELLKNOWN_404",
		"PRM_MISSING_AUTHORIZATION_SERVERS",
		"PRM_RESOURCE_MISMATCH",
		"PRM_JWKS_URI_NOT_HTTPS",
		"PRM_RESOURCE_MISSING",
		"PRM_HTTP_STATUS_NOT_200",
		"PRM_CONTENT_TYPE_NOT_JSON",
		"PRM_NOT_JSON_OBJECT",
		"PRM_BEARER_METHODS_INVALID",
		"RFC3986_INVALID_URI",
		"RFC3986_ABSOLUTE_HTTPS_REQUIRED",
		"RESOURCE_FRAGMENT_FORBIDDEN",
		"AUTH_SERVER_ISSUER_QUERY_FRAGMENT",
		"AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON",
		"AUTH_SERVER_ISSUER_MISMATCH",
		"METADATA_SSRF_BLOCKED",
		"METADATA_REDIRECT_BLOCKED",
		"METADATA_REDIRECT_LIMIT",
		"JWKS_FETCH_ERROR",
		"JWKS_INVALID",
		"AUTH_SERVER_METADATA_UNREACHABLE",
		"AUTH_SERVER_METADATA_INVALID",
		"MCP_INITIALIZE_FAILED",
		"MCP_TOOLS_LIST_FAILED",
		"MCP_PROBE_TIMEOUT",
		"MCP_GET_NOT_SSE",
		"MCP_JSONRPC_ID_NULL_ACCEPTED",
		"MCP_INITIALIZE_ORDERING_NOT_ENFORCED",
		"MCP_NOTIFICATION_WITH_ID_ACCEPTED",
		"MCP_JSONRPC_RESPONSE_ID_MISMATCH",
		"MCP_JSONRPC_RESPONSE_INVALID",
		"MCP_PROTOCOL_VERSION_MISSING",
		"MCP_INITIALIZE_RESULT_INVALID",
		"MCP_TOOLS_LIST_INVALID",
		"MCP_TASKS_METHOD_MISSING",
		"MCP_TOOL_INPUT_SCHEMA_MISSING",
		"MCP_TOOL_INPUT_SCHEMA_INVALID",
		"DCR_ENDPOINT_OPEN",
		"DCR_HTTP_REDIRECT_ACCEPTED",
		"DCR_DANGEROUS_URI_ACCEPTED":
		return "high"
	case "PRM_WELLKNOWN_PATH_SUFFIX_MISSING",
		"HEADER_STRIPPED_BY_PROXY_SUSPECTED",
		"AUTH_SERVER_ISSUER_PRIVATE_BLOCKED",
		"SCOPES_WHITESPACE_RISK",
		"TOKEN_RESPONSE_NOT_JSON_RISK",
		"TOKEN_HTTP200_ERROR_PAYLOAD_RISK",
		"MCP_NOTIFICATION_STATUS_INVALID",
		"MCP_PROTOCOL_VERSION_MISMATCH",
		"MCP_PROTOCOL_VERSION_REJECTION_MISSING",
		"MCP_SESSION_ID_REJECTION_MISSING",
		"MCP_PING_INVALID_RESPONSE",
		"MCP_CAPABILITIES_INVALID",
		"DCR_LOCALHOST_REDIRECT_ACCEPTED",
		"DCR_EMPTY_REDIRECT_URIS_ACCEPTED":
		return "medium"
	case "AUTH_SERVER_ENDPOINT_HOST_MISMATCH",
		"AUTH_SERVER_PKCE_S256_MISSING",
		"AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH",
		"AUTH_SERVER_ROOT_WELLKNOWN_PROBE_FAILED",
		"MCP_NOTIFICATION_BODY_PRESENT",
		"MCP_NOTIFICATION_FAILED",
		"MCP_ORIGIN_NOT_VALIDATED",
		"MCP_ICON_UNSAFE_SCHEME":
		return "low"
	default:
		return "low"
	}
}

// findingConfidence returns the confidence level for a finding code.
func findingConfidence(code string) float64 {
	switch code {
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		// 0.92: Strong inference (0.85-0.95 range per PRD)
		return 0.92
	case "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		// 0.85: Strong inference (0.85-0.95 range per PRD)
		return 0.85
	case "HEADER_STRIPPED_BY_PROXY_SUSPECTED":
		// 0.9: Strong inference (0.85-0.95 range per PRD)
		return 0.9
	case "TOKEN_RESPONSE_NOT_JSON_RISK",
		"TOKEN_HTTP200_ERROR_PAYLOAD_RISK":
		// 0.7: Heuristic risk pattern (0.60-0.80 range per PRD)
		return 0.7
	case "MCP_PROBE_TIMEOUT":
		// 0.8: Heuristic risk pattern (0.60-0.80 range per PRD)
		return 0.8
	case "SCOPES_WHITESPACE_RISK":
		// 0.85: Heuristic lint (0.80-0.90 range per PRD)
		return 0.85
	default:
		// 1.00: Direct deterministic evidence (per PRD)
		return 1.00
	}
}

// choosePrimaryFinding selects the most important finding from a list.
func choosePrimaryFinding(findings []finding) finding {
	if len(findings) == 0 {
		return finding{}
	}
	sorted := make([]finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		si := severityRank(sorted[i].Severity)
		sj := severityRank(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		if sorted[i].Confidence != sorted[j].Confidence {
			return sorted[i].Confidence > sorted[j].Confidence
		}
		return sorted[i].Code < sorted[j].Code
	})
	return sorted[0]
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(severity string) int {
	switch severity {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// addTrace adds an HTTP request/response to the trace log.
func addTrace(trace *[]traceEntry, req *http.Request, resp *http.Response, redact bool) {
	*trace = append(*trace, traceEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Method:    req.Method,
		URL:       req.URL.String(),
		Status:    resp.StatusCode,
		Headers:   sanitizeHeadersForTrace(resp.Header, redact),
	})
}

// shouldFail determines if the scan should exit with failure based on findings.
func shouldFail(primary finding, failOn string) bool {
	if primary.Code == "" {
		return false
	}
	threshold := severityRank(strings.ToLower(failOn))
	if threshold == 0 {
		return false
	}
	return severityRank(primary.Severity) >= threshold
}

const maxMetadataRedirects = 5

// fetchJSON performs an HTTP GET and parses the response body as JSON.
func fetchJSON(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, any, error) {
	resp, body, err := fetchWithRedirects(client, config, target, trace, stdout, verboseLabel)
	if err != nil {
		return resp, nil, err
	}
	var payload any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			payload = nil
		}
	}
	return resp, payload, nil
}

// fetchWithRedirects performs metadata fetches with redirect handling and policy checks (SSRF, RFC 9110).
func fetchWithRedirects(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
	current := target
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
	}
	for redirects := 0; ; redirects++ {
		if err := validateFetchTarget(config, current); err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequest(http.MethodGet, current, nil)
		if err != nil {
			return nil, nil, err
		}
		if err := applyHeaders(req, config.Headers); err != nil {
			return nil, nil, err
		}
		if config.Verbose {
			if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
				return nil, nil, err
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			return resp, nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if config.Verbose {
			if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
				return resp, body, err
			}
		}
		addTrace(trace, req, resp, config.Redact)
		if !isRedirectStatus(resp.StatusCode) || config.NoFollowRedirects {
			return resp, body, nil
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("missing Location for redirect from %s", current)}
		}
		next, err := resolveURL(req.URL, location)
		if err != nil {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("invalid redirect Location %q", location)}
		}
		if rfcModeEnabled(config.RFCMode) {
			if !next.IsAbs() {
				return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("redirect Location not absolute: %q", location)}
			}
			if rfcModeEnabled(config.RFCMode) && !isHTTPSURL(next) {
				if rfcModeStrict(config.RFCMode) {
					return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("redirect Location not https: %q", location)}
				}
			}
		}
		if redirects >= maxMetadataRedirects {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_LIMIT", Detail: fmt.Sprintf("redirect limit exceeded for %s", target)}
		}
		current = next.String()
	}
}

// postTokenProbe sends a probe request to the token endpoint with invalid credentials.
func postTokenProbe(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid")
	form.Set("redirect_uri", "https://invalid.example/callback")
	form.Set("client_id", "authprobe")

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if err := applySafeHeaders(req, config.Headers); err != nil {
		return nil, nil, err
	}
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
		if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
			return nil, nil, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return resp, body, err
		}
	}
	addTrace(trace, req, resp, config.Redact)
	return resp, body, nil
}
