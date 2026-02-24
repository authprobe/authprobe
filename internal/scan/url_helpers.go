package scan

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	errIssuerQueryFragment = errors.New("issuer has query or fragment")
	errIssuerNotAbsolute   = errors.New("issuer is not an absolute URL")
	errIssuerMissingHost   = errors.New("issuer is missing host")
)

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

func canonicalizeResourceURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	if parsed.Path != "/" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}
	return parsed.String()
}

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

func buildIssuerDiscoveryCandidates(issuer string) ([]string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	if parsed.RawQuery != "" {
		return nil, errIssuerQueryFragment
	}
	parsed.Fragment = ""
	if !parsed.IsAbs() {
		return nil, errIssuerNotAbsolute
	}
	if parsed.Host == "" {
		return nil, errIssuerMissingHost
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	issuerPath := normalizeIssuerPath(parsed.EscapedPath())
	candidates := []string{
		(&url.URL{
			Scheme: parsed.Scheme,
			Host:   parsed.Host,
			Path:   "/.well-known/oauth-authorization-server" + issuerPath,
		}).String(),
		(&url.URL{
			Scheme: parsed.Scheme,
			Host:   parsed.Host,
			Path:   "/.well-known/openid-configuration" + issuerPath,
		}).String(),
		(&url.URL{
			Scheme: parsed.Scheme,
			Host:   parsed.Host,
			Path:   issuerPath + "/.well-known/openid-configuration",
		}).String(),
	}
	return candidates, nil
}

func normalizeIssuerPath(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	return strings.TrimSuffix(path, "/")
}

func buildMetadataURL(issuer string) string {
	metadataURL, err := buildRFC8414DiscoveryURL(issuer)
	if err != nil {
		return issuer
	}
	return metadataURL
}

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

func issuerMatchesWithTolerance(expected string, actual string) (bool, string, error) {
	expectedCanonical, err := canonicalizeIssuerIdentifier(expected)
	if err != nil {
		return false, "", err
	}
	actualCanonical, err := canonicalizeIssuerIdentifier(actual)
	if err != nil {
		return false, "", err
	}
	if actualCanonical == expectedCanonical {
		return true, "", nil
	}
	expectedURL, err := url.Parse(expectedCanonical)
	if err != nil {
		return false, "", err
	}
	actualURL, err := url.Parse(actualCanonical)
	if err != nil {
		return false, "", err
	}
	if issuerHostAndPathFamilyMatch(expectedURL, actualURL) {
		return true, fmt.Sprintf("WARN: metadata issuer %q not exact match for %q; accepted due to host/path family match", actual, expected), nil
	}
	return false, "", nil
}

func issuerHostAndPathFamilyMatch(expected *url.URL, actual *url.URL) bool {
	if !strings.EqualFold(expected.Hostname(), actual.Hostname()) {
		return false
	}
	if expected.Scheme != "" && actual.Scheme != "" && !strings.EqualFold(expected.Scheme, actual.Scheme) {
		return false
	}
	expectedPath := normalizeIssuerPath(expected.EscapedPath())
	actualPath := normalizeIssuerPath(actual.EscapedPath())
	expectedSegs := issuerPathSegments(expectedPath)
	actualSegs := issuerPathSegments(actualPath)
	if hasPathSegmentPrefix(expectedSegs, actualSegs) || hasPathSegmentPrefix(actualSegs, expectedSegs) {
		return true
	}
	if len(expectedSegs) == len(actualSegs) && len(expectedSegs) >= 2 {
		if expectedSegs[len(expectedSegs)-1] == actualSegs[len(actualSegs)-1] {
			return true
		}
	}
	return false
}

func issuerPathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func hasPathSegmentPrefix(path []string, prefix []string) bool {
	if len(prefix) == 0 || len(path) == 0 {
		return false
	}
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return false
		}
	}
	return true
}

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

func validateFetchTarget(config ScanConfig, target string) error {
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

func validateURLString(raw string, label string, config ScanConfig, allowRelative bool) []Finding {
	if !rfcModeEnabled(config.RFCMode) {
		return nil
	}
	findings := []Finding{}
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
		if config.AllowPrivateIssuers && isLocalOrPrivateURL(parsed) {
			return findings
		}
		findings = append(findings, newFinding("RFC3986_ABSOLUTE_HTTPS_REQUIRED", fmt.Sprintf("%s not https: %q", label, raw)))
	}
	return findings
}

func isLocalOrPrivateURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
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

func checkEndpointHostMismatch(findings *[]Finding, endpoint string, issuerHost string, name string) {
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
