package scan

// probe.go - OAuth discovery probe steps: types, MCP probe, and PRM fetch
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ probeMCP                            │ Step 1: Probe MCP endpoint for 401 + WWW-Authenticate      │
// │ fetchPRMMatrix                      │ Step 3: Fetch Protected Resource Metadata (RFC 9728)       │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ScanConfig struct {
	Target              string
	Command             string // Original command for display
	Headers             []string
	Timeout             time.Duration
	MCPProbeTimeout     time.Duration
	Verbose             bool
	Explain             bool
	LLMExplain          bool
	OpenAIAPIKey        string
	AnthropicAPIKey     string
	LLMMaxTokens        int    // Max output tokens for LLM explanation (default: 700)
	FailOn              string // Severity threshold for exit code 2: none, low, medium, high
	MCPMode             string
	MCPProtocolVersion  string // Effective MCP protocol version to send on requests (defaults to SupportedMCPProtocolVersion)
	RFCMode             string // Applies to all RFC checks: off, best-effort, strict
	AllowPrivateIssuers bool
	Insecure            bool // Skip TLS certificate verification (dev only)
	NoFollowRedirects   bool // Stop at first response, don't follow HTTP redirects
	Redact              bool
	TraceFailure        bool // Include verbose output of failed steps in report
	JSONPath            string
	MDPath              string
	TraceASCIIPath      string
	BundlePath          string
	OutputDir           string
}

const githubURL = "https://github.com/authprobe/authprobe"

type ScanReport struct {
	Command         string               `json:"command"`
	Target          string               `json:"target"`
	MCPMode         string               `json:"mcp_mode"`
	RFCMode         string               `json:"rfc_mode"`
	AuthRequired    bool                 `json:"auth_required"`
	Timestamp       string               `json:"timestamp"`
	Github          string               `json:"github"`
	PRMOK           bool                 `json:"prm_ok"`
	OAuthDiscovery  bool                 `json:"oauth_discovery_viable"`
	AuthzMetadataOK bool                 `json:"authz_server_metadata_ok"`
	AuthDiscovery   AuthDiscoverySummary `json:"auth_discovery"`
	Steps           []ScanStep           `json:"steps"`
	Findings        []Finding            `json:"findings"`
	PrimaryFinding  Finding              `json:"primary_finding"`
}

type AuthDiscoverySummary struct {
	IssuerCandidates            []string `json:"issuer_candidates,omitempty"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint               string   `json:"token_endpoint,omitempty"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint,omitempty"`
	GrantTypesSupported         []string `json:"grant_types_supported,omitempty"`
	ScopesSupported             []string `json:"scopes_supported,omitempty"`
}

type ScanStep struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type ScanSummary struct {
	Stdout string
	MD     string
	JSON   []byte
	Trace  []TraceEntry
}

type TraceEntry struct {
	Timestamp       string            `json:"ts"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Status          int               `json:"status"`
	StatusLine      string            `json:"status_line,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

type prmResult struct {
	AuthorizationServers []string
	Resource             string
	MetadataFound        bool
	PRMOK                bool
	RootWellKnown404     bool
	HasPathSuffix        bool
	OAuthDiscovery       bool
}

// probeMCP probes an MCP endpoint to determine authentication requirements (Step 1).
//
// This function sends a GET request with Accept: text/event-stream to trigger the
// MCP Streamable HTTP handshake and discover OAuth configuration via RFC 9728.
//
// Inputs:
//   - client: HTTP client for making requests
//   - config: Scan configuration (target URL, headers, verbose mode, etc.)
//   - trace: Request/response trace log for debugging and evidence collection
//   - stdout: Writer for verbose output
//
// Outputs (in order):
//   - resourceMetadata: URL from WWW-Authenticate resource_metadata param (empty if not found)
//   - resolvedTarget: The target URL after any redirects (for constructing PRM URLs)
//   - []Finding: MCP/RFC compliance findings (e.g., MCP_GET_NOT_SSE, DISCOVERY_NO_WWW_AUTHENTICATE)
//   - summary: Human-readable summary of the probe result
//   - authRequired: true if 401 received (auth definitely required),
//     false if 405/200 received (auth status unknown, caller should check PRM)
//   - error: Non-nil only for fatal errors (network failures, invalid config)
//
// Response handling:
//   - 401 Unauthorized: Auth required. Extract resource_metadata from WWW-Authenticate header.
//   - 405 Method Not Allowed: Server doesn't support GET/SSE. Auth status unknown; check PRM.
//     Step 2 will send POST requests (initialize, tools/list) per MCP spec, which may
//     reveal auth requirements (401/403) that GET couldn't detect.
//   - 200 OK: Auth not required (public endpoint). Validates SSE content-type per MCP spec.
//   - Timeout: Returns MCP_PROBE_TIMEOUT Finding (servers must respond promptly per MCP spec).
func probeMCP(client *http.Client, config ScanConfig, trace *[]TraceEntry, stdout io.Writer) (string, string, []Finding, string, bool, error) {
	findings := []Finding{}
	// Create a GET request to the target MCP endpoint
	req, err := http.NewRequest(http.MethodGet, config.Target, nil)
	if err != nil {
		return "", "", nil, "", false, err
	}
	req.Header.Set("Accept", "text/event-stream")
	// Apply any custom headers specified by the user
	if err := applyHeaders(req, config.Headers); err != nil {
		return "", "", nil, "", false, err
	}
	// If verbose mode is enabled, write the request details to stdout
	if config.Verbose {
		writeVerboseHeading(stdout, "Step 1: MCP probe (401 + WWW-Authenticate)")
		if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
			return "", "", nil, "", false, err
		}
	}
	// Execute the HTTP request
	requestClient := client
	if config.MCPProbeTimeout > 0 {
		requestClient = &http.Client{Timeout: config.MCPProbeTimeout, Transport: client.Transport, CheckRedirect: client.CheckRedirect}
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			evidence := "probe timed out waiting for response headers; MCP spec requires SSE headers or a 405 for GET Accept: text/event-stream"
			return "", config.Target, []Finding{newFinding("MCP_PROBE_TIMEOUT", evidence)}, evidence, true, nil
		}
		return "", "", nil, "", false, err
	}
	defer resp.Body.Close()
	_, _ = drainBody(&resp.Body)

	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return "", "", nil, "", false, err
		}
	}

	// Add this request/response pair to the trace for later analysis
	addTrace(trace, req, resp, config.Redact, "401 + WWW-Authenticate discovery")

	// MCP 2025-11-25 Streamable HTTP: A GET request with Accept: text/event-stream
	// MUST return Content-Type: text/event-stream for SSE streaming.
	// If the server returns 200 OK but with a different content type, it's non-conformant.
	if mcpModeEnabled(config.MCPMode) {
		if resp.StatusCode == http.StatusOK {
			contentType := resp.Header.Get("Content-Type")
			if !isSSEContentType(contentType) {
				findings = append(findings, newMCPFinding(config, "MCP_GET_NOT_SSE", fmt.Sprintf("GET content-type %q", contentType)))
			}
		}
	}

	if resp.StatusCode != http.StatusUnauthorized {
		// 405 Method Not Allowed means the server doesn't support GET/SSE, but doesn't indicate auth is required.
		// We'll check PRM to determine if OAuth is configured.
		if resp.StatusCode == http.StatusMethodNotAllowed {
			return "", resolvedTarget(resp, config.Target), findings, fmt.Sprintf("probe returned %d; checking PRM for OAuth config", resp.StatusCode), false, nil
		}
		return "", resolvedTarget(resp, config.Target), findings, "auth not required", false, nil
	}

	resourceMetadata, ok := extractResourceMetadata(resp.Header.Values("WWW-Authenticate"))
	// RFC 9728 Section 5.1: When a protected resource receives a request without
	// valid credentials, it SHOULD include a WWW-Authenticate header with a
	// "resource_metadata" parameter pointing to the OAuth Protected Resource Metadata URL.
	// This enables clients to discover how to obtain authorization.
	if !ok {
		return "", resolvedTarget(resp, config.Target), findings, "missing WWW-Authenticate/resource_metadata", true, nil
	}
	// Success: we have a 401 with resource_metadata, indicating proper MCP OAuth discovery
	return resourceMetadata, resolvedTarget(resp, config.Target), findings, "401 with resource_metadata", true, nil
}

// fetchPRMMatrix retrieves OAuth Protected Resource Metadata (RFC 9728) from well-known endpoints.
// Called by runPRMFetch in funnel Step 3 ("Protected Resource Metadata (RFC 9728)").
//
// This function probes multiple PRM candidates to discover OAuth configuration:
//   - Root endpoint: /.well-known/oauth-protected-resource
//   - Path-suffix endpoint: /.well-known/oauth-protected-resource/<path>
//   - Direct URL from WWW-Authenticate resource_metadata parameter (if provided)
//
// Inputs:
//   - client: HTTP client for making requests
//   - config: Scan configuration (target URL, RFC mode, timeouts, etc.)
//   - resourceMetadata: URL from WWW-Authenticate resource_metadata param (empty if not provided)
//   - resolvedTarget: The resolved target URL after any redirects from Step 1
//   - trace: Request/response trace log for debugging and evidence collection
//   - stdout: Writer for verbose output
//   - authRequiredFromProbe: true if Step 1 returned 401 (auth definitely required),
//     false if Step 1 returned 405/200 (auth status unknown, checking PRM to determine)
//
// Outputs:
//   - prmResult: Best matching PRM with Resource, AuthorizationServers, and MetadataFound flag
//   - []Finding: RFC compliance findings (e.g., PRM_RESOURCE_MISMATCH, PRM_MISSING_AUTHORIZATION_SERVERS)
//   - string: Evidence summary (URLs probed and their HTTP status codes)
//   - error: Non-nil only for fatal errors (not HTTP 404s)
//
// Behavior:
//   - When authRequiredFromProbe=true (401 from Step 1): 404 from PRM is flagged as a Finding
//   - When authRequiredFromProbe=false (405 from Step 1): 404 from PRM is normal (no OAuth configured)
//   - If valid PRM is found with authorization_servers, the caller should set authRequired=true
//   - Prefers exact resource match; falls back to first usable PRM if no exact match
func fetchPRMMatrix(client *http.Client, config ScanConfig, resourceMetadata string, resolvedTarget string, trace *[]TraceEntry, stdout io.Writer, authRequiredFromProbe bool) (prmResult, []Finding, string, error) {
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		return prmResult{}, nil, "", err
	}
	expectedResource := config.Target
	// Normalize resource identifiers so trailing-slash differences can be treated as equivalent.
	expectedCanonical := canonicalizeResourceURL(expectedResource)

	findings := []Finding{}
	// RFC 3986: Validate URL syntax conformance
	if rfcModeEnabled(config.RFCMode) {
		if urlFindings := validateURLString(config.Target, "resource", config, false); len(urlFindings) > 0 {
			findings = append(findings, urlFindings...)
		}
		// RFC 8707 Section 2: Resource identifiers MUST NOT include a fragment component
		if parsedTarget, err := url.Parse(config.Target); err == nil && parsedTarget.Fragment != "" {
			if rfcModeEnabled(config.RFCMode) {
				findings = append(findings, newFinding("RESOURCE_FRAGMENT_FORBIDDEN", fmt.Sprintf("resource %q includes fragment (RFC 8707)", config.Target)))
			}
		}
	}
	var evidence strings.Builder
	var bestPRM prmResult
	var fallbackPRM prmResult
	fallbackSet := false
	metadataFound := false
	prmOK := false
	rootWellKnown404 := false
	// Track exact-match candidates so we can prefer a strict match when present.
	exactMatchFound := false
	// Gate PRM resource comparison findings on RFC mode (same behavior as other PRM checks).
	shouldReportPRMFindings := config.RFCMode != "off"
	type prmResourceObservation struct {
		source    string
		resource  string
		canonical string
	}
	// Collect resource values to evaluate matrix consistency after probing all candidates.
	resourceObservations := []prmResourceObservation{}
	// Walk through PRM candidates built by buildPRMCandidates: root well-known, path-suffix well-known, and resource_metadata hint URL.
	for _, candidate := range candidates {
		reportFindings := config.RFCMode != "off"
		if hasPathSuffix {
			reportFindings = candidate.Source == "path-suffix"
		}
		if rfcModeEnabled(config.RFCMode) {
			if urlFindings := validateURLString(candidate.URL, fmt.Sprintf("prm(%s)", candidate.Source), config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		resp, payload, err := fetchJSON(client, config, candidate.URL, trace, stdout, "Step 3: PRM fetch matrix")
		if err != nil {
			if reportFindings {
				var policyErr fetchPolicyError
				if errors.As(err, &policyErr) {
					findings = append(findings, newFinding(policyErr.Code, fmt.Sprintf("%s fetch blocked: %s", candidate.Source, policyErr.Detail)))
				} else {
					findings = append(findings, newFinding("PRM_HTTP_STATUS_NOT_200", fmt.Sprintf("%s fetch error: %v", candidate.Source, err)))
				}
			}
			continue
		}
		status := resp.StatusCode
		fmt.Fprintf(&evidence, "%s -> %d\n", candidate.URL, status)
		// RFC 9728 Section 4: The PRM document MUST be available at the well-known endpoint
		// Only flag 404 as a failure if auth was required from Step 1 (401 response)
		// If Step 1 returned 405, 404 from PRM just means no OAuth is configured
		if status == http.StatusNotFound && candidate.Source == "root" {
			rootWellKnown404 = true
		}
		if status == http.StatusNotFound && candidate.Source == "root" && authRequiredFromProbe {
			findings = append(findings, newFinding("DISCOVERY_ROOT_WELLKNOWN_404", "root PRM endpoint returned 404"))
		}
		if status == http.StatusNotFound && candidate.Source == "path-suffix" && reportFindings && authRequiredFromProbe {
			findings = append(findings, newFinding("PRM_WELLKNOWN_PATH_SUFFIX_MISSING", "path-suffix PRM endpoint returned 404"))
		}
		if status != http.StatusOK && reportFindings && authRequiredFromProbe {
			findings = append(findings, newFinding("PRM_HTTP_STATUS_NOT_200", fmt.Sprintf("%s status %d", candidate.Source, status)))
			continue
		}
		if status != http.StatusOK {
			continue
		}
		// RFC 9728 Section 4: The PRM document MUST be served with Content-Type: application/json
		if reportFindings {
			contentType := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				findings = append(findings, newFinding("PRM_CONTENT_TYPE_NOT_JSON", fmt.Sprintf("%s content-type %q", candidate.Source, contentType)))
				continue
			}
		}
		// RFC 9728 Section 4: The PRM response MUST be a JSON object
		obj, ok := payload.(map[string]any)
		if !ok {
			if reportFindings {
				findings = append(findings, newFinding("PRM_NOT_JSON_OBJECT", fmt.Sprintf("%s response not JSON object", candidate.Source)))
			}
			continue
		}
		metadataFound = true
		prm := prmResult{}
		// RFC 9728 Section 4.1: The "resource" field MUST be present and match the protected resource
		if resourceValue, ok := obj["resource"].(string); ok {
			prm.Resource = resourceValue
			if reportFindings && !hasPathSuffix && resourceValue == "" {
				findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource empty", candidate.Source)))
			}
		} else if reportFindings && !hasPathSuffix {
			findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource missing", candidate.Source)))
		}
		resourceMatches := prm.Resource != "" && canonicalizeResourceURL(prm.Resource) == expectedCanonical
		if resourceMatches {
			switch candidate.Source {
			case "resource_metadata", "path-suffix":
				prmOK = true
			case "root":
				if !hasPathSuffix {
					prmOK = true
				}
			}
		}
		if reportFindings {
			// RFC 8707 Section 2: Resource identifiers MUST NOT include a fragment component
			if rfcModeEnabled(config.RFCMode) {
				if parsedResource, err := url.Parse(prm.Resource); err == nil && parsedResource.Fragment != "" {
					findings = append(findings, newFinding("RESOURCE_FRAGMENT_FORBIDDEN", fmt.Sprintf("%s resource %q includes fragment (RFC 8707)", candidate.Source, prm.Resource)))
				}
			}
		}
		if prm.Resource != "" {
			// Capture canonicalized forms for trailing-slash tolerant comparisons.
			resourceObservations = append(resourceObservations, prmResourceObservation{
				source:    candidate.Source,
				resource:  prm.Resource,
				canonical: canonicalizeResourceURL(prm.Resource),
			})
		}
		// RFC 9728 Section 4.1: "authorization_servers" is an array of issuer URLs
		if servers, ok := obj["authorization_servers"].([]any); ok {
			for _, entry := range servers {
				if value, ok := entry.(string); ok && value != "" {
					prm.AuthorizationServers = append(prm.AuthorizationServers, value)
				}
			}
		}
		// RFC 9728 Section 4.1: The PRM MUST include authorization_servers for OAuth discovery
		if len(prm.AuthorizationServers) == 0 && reportFindings && !hasPathSuffix {
			findings = append(findings, newFinding("PRM_MISSING_AUTHORIZATION_SERVERS", fmt.Sprintf("%s authorization_servers missing", candidate.Source)))
		}
		if reportFindings {
			// RFC 9728 Section 4.1: bearer_methods_supported values MUST be "header" or "body"
			if methods, ok := obj["bearer_methods_supported"].([]any); ok {
				for _, entry := range methods {
					value, ok := entry.(string)
					if !ok {
						findings = append(findings, newFinding("PRM_BEARER_METHODS_INVALID", fmt.Sprintf("%s bearer method not string", candidate.Source)))
						continue
					}
					switch value {
					case "header", "body", "query":
						continue
					default:
						findings = append(findings, newFinding("PRM_BEARER_METHODS_INVALID", fmt.Sprintf("%s bearer method %q invalid", candidate.Source, value)))
					}
				}
			}
			if jwksURI, ok := obj["jwks_uri"].(string); ok && jwksURI != "" {
				if parsedJWKS, err := url.Parse(jwksURI); err == nil && parsedJWKS.IsAbs() && !isHTTPSURL(parsedJWKS) {
					findings = append(findings, newFinding("PRM_JWKS_URI_NOT_HTTPS", fmt.Sprintf("%s jwks_uri %q not https", candidate.Source, jwksURI)))
				}
				if urlFindings := validateURLString(jwksURI, "jwks_uri", config, false); len(urlFindings) > 0 {
					findings = append(findings, urlFindings...)
				}
			}
		}

		if prm.Resource == expectedResource {
			// Prefer the strict exact match (especially path-suffix) when it is available.
			if !exactMatchFound || (hasPathSuffix && candidate.Source == "path-suffix") {
				bestPRM = prm
			}
			// Note that we've seen an exact resource match.
			exactMatchFound = true
		} else if hasPathSuffix {
			if !fallbackSet && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
				fallbackPRM = prm
				fallbackSet = true
			}
		} else if bestPRM.AuthorizationServers == nil && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
			bestPRM = prm
		}
	}
	if shouldReportPRMFindings && len(resourceObservations) > 0 {
		// Group observations by canonicalized resource to detect substantive mismatches.
		canonicalGroups := make(map[string][]prmResourceObservation)
		for _, obs := range resourceObservations {
			canonicalGroups[obs.canonical] = append(canonicalGroups[obs.canonical], obs)
		}
		var evidence []string
		if len(canonicalGroups) > 1 {
			// Multiple canonicalized resources means a real mismatch across PRM variants.
			evidence = append(evidence, fmt.Sprintf("expected resource %q", expectedResource))
			for _, obs := range resourceObservations {
				evidence = append(evidence, fmt.Sprintf("%s resource %q", obs.source, obs.resource))
			}
			findings = append(findings, newFindingWithEvidence("PRM_RESOURCE_MISMATCH", evidence))
		} else {
			var onlyCanonical string
			for canonical := range canonicalGroups {
				onlyCanonical = canonical
			}
			if onlyCanonical == expectedCanonical {
				// Canonicalized match but differing literal strings => trailing-slash compatibility warning.
				needsWarning := false
				for _, obs := range resourceObservations {
					if obs.resource != expectedResource {
						needsWarning = true
						break
					}
				}
				if needsWarning {
					evidence = append(evidence, "PRM resource differs only by trailing slash; strict clients may break.")
					for _, obs := range resourceObservations {
						evidence = append(evidence, fmt.Sprintf("%s resource %q", obs.source, obs.resource))
					}
					findings = append(findings, newFindingWithEvidence("PRM_RESOURCE_TRAILING_SLASH", evidence))
				}
			} else {
				// Single canonicalized value that doesn't match the expected resource => mismatch.
				evidence = append(evidence, fmt.Sprintf("expected resource %q", expectedResource))
				for _, obs := range resourceObservations {
					evidence = append(evidence, fmt.Sprintf("%s resource %q", obs.source, obs.resource))
				}
				findings = append(findings, newFindingWithEvidence("PRM_RESOURCE_MISMATCH", evidence))
			}
		}
	}
	// Fall back to the first usable PRM if the exact match is missing.
	if hasPathSuffix && !exactMatchFound && fallbackSet {
		bestPRM = fallbackPRM
	}
	bestPRM.MetadataFound = metadataFound
	bestPRM.PRMOK = prmOK
	bestPRM.RootWellKnown404 = rootWellKnown404
	bestPRM.HasPathSuffix = hasPathSuffix
	bestPRM.OAuthDiscovery = metadataFound
	if authRequiredFromProbe && resourceMetadata == "" && len(bestPRM.AuthorizationServers) > 0 {
		findings = append(findings, newFinding("HEADER_STRIPPED_BY_PROXY_SUSPECTED", "missing WWW-Authenticate; PRM still discoverable"))
	}

	return bestPRM, findings, strings.TrimSpace(evidence.String()), nil
}

type prmCandidate struct {
	URL    string
	Source string
}

type authServerMetadataResult struct {
	TokenEndpoints              []string
	RegistrationEndpoints       []string
	AuthorizationEndpoints      []string
	DeviceAuthorizationEndpoint string
	GrantTypesSupported         []string
	ScopesSupported             []string
}
