package scan

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
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Validation & Security               │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ isDisallowedIP                      │ Check if IP is private/loopback (SSRF block)               │
// │ isSafeIconURI                       │ Check if icon URI uses safe scheme (https/data)            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Header & Capability Helpers         │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ containsString                      │ Check if slice contains a target string                    │
// │ findHeader                          │ Find header value (case-insensitive)                       │
// │ applySafeHeaders                    │ Apply headers filtering out sensitive ones                 │
// │ applyHeaders                        │ Apply all headers to request                               │
// │ isSensitiveHeader                   │ Check if header name is sensitive                          │
// │ supportsPing                        │ Check if MCP capabilities include ping                     │
// │ supportsTasks                       │ Check if MCP capabilities include tasks                    │
// │ tasksAdvertised                     │ Check if init result advertises tasks                      │
// │ statusFromFindings                  │ Determine status based on findings                         │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type fetchPolicyError struct {
	Code   string
	Detail string
}

func (e fetchPolicyError) Error() string {
	return e.Detail
}

func resolvedTarget(resp *http.Response, fallback string) string {
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return fallback
}

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

func isJSONContentType(contentType string) bool {
	lower := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(lower, "application/json") || strings.Contains(lower, "+json")
}

func isSSEContentType(contentType string) bool {
	lower := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(lower, "text/event-stream")
}

func rfcModeEnabled(mode string) bool {
	return mode != "off"
}

func rfcModeStrict(mode string) bool {
	return strings.EqualFold(mode, "strict")
}

func mcpModeEnabled(mode string) bool {
	return mode != "off"
}

func mcpModeStrict(mode string) bool {
	return strings.EqualFold(mode, "strict")
}

func isHTTPSURL(parsed *url.URL) bool {
	return parsed != nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != ""
}

func isRedirectStatus(status int) bool {
	return status >= 300 && status <= 399
}

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

func findHeader(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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

func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

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

func hasHighSeverity(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == "high" {
			return true
		}
	}
	return false
}

func hasSeverityAtLeast(findings []Finding, severity string) bool {
	threshold := severityRank(strings.ToLower(severity))
	if threshold == 0 {
		return false
	}
	for _, f := range findings {
		if severityRank(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

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

func applySafeHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := ParseHeader(header)
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

func applyHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := ParseHeader(header)
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

func statusFromFindings(findings []Finding, authRequired bool) string {
	if !authRequired {
		return "SKIP"
	}
	if len(findings) == 0 {
		return "PASS"
	}
	return "FAIL"
}
