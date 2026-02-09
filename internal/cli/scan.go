package cli

// scan.go - Core scan logic for MCP and OAuth discovery probes
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Main Scan Steps                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ probeMCP                            │ Step 1: Probe MCP endpoint for 401 + WWW-Authenticate      │
// │ fetchPRMMatrix                      │ Step 3: Fetch Protected Resource Metadata (RFC 9728)       │
// │ fetchAuthServerMetadata             │ Step 4: Fetch authorization server metadata (RFC 8414)     │
// │ probeTokenEndpointReadiness         │ Step 5: Probe token endpoint for readiness heuristics      │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ MCP Initialize Flow                 │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ mcpInitializeAndListTools           │ Step 2: MCP initialize + tools/list JSON-RPC flow          │
// │ parseInitializeResult               │ Parse and validate MCP initialize response                 │
// │ sendInitializedNotification         │ Send notifications/initialized per MCP spec                │
// │ fetchMCPTools                       │ Perform MCP initialize + tools/list to get tool list       │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ MCP Conformance Checks              │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ checkInitializeOrdering             │ Verify server enforces initialize-before-other-methods     │
// │ checkJSONRPCNullID                  │ Verify server rejects null request IDs                     │
// │ checkJSONRPCNotificationWithID      │ Verify server rejects notifications with IDs               │
// │ checkOriginValidation               │ Verify server validates Origin header for CSRF             │
// │ checkProtocolVersionHeader          │ Verify server validates MCP-Protocol-Version header        │
// │ checkSessionHeader                  │ Verify server validates MCP-Session-Id header              │
// │ checkPing                           │ Verify server correctly implements ping method             │
// │ checkToolSchemas                    │ Validate tool inputSchema definitions                      │
// │ checkToolIcons                      │ Validate tool icon URI schemes                             │
// │ checkTasksSupport                   │ Verify tasks methods when capability advertised            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ JSON-RPC Helpers                    │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ postJSONRPC                         │ Send JSON-RPC request and parse response                   │
// │ postJSONRPCBytes                    │ Send raw JSON-RPC bytes with optional mutation             │
// │ formatJSONRPCError                  │ Format JSON-RPC error for display                          │
// │ extractToolNames                    │ Extract tool names from tools/list result                  │
// │ validateJSONRPCResponse             │ Validate JSON-RPC response for conformance                 │
// │ jsonRPCIDEqual                      │ Compare two JSON-RPC IDs for equality                      │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type scanConfig struct {
	Target              string
	Command             string // Original command for display
	Headers             []string
	Timeout             time.Duration
	Verbose             bool
	Explain             bool
	LLMExplain          bool
	OpenAIAPIKey        string
	AnthropicAPIKey     string
	FailOn              string // Severity threshold for exit code 2: none, low, medium, high
	MCPMode             string
	RFCMode             string // Applies to all RFC checks: off, best-effort, strict
	AllowPrivateIssuers bool
	Insecure            bool // Skip TLS certificate verification (dev only)
	NoFollowRedirects   bool // Stop at first response, don't follow HTTP redirects
	Redact              bool
	JSONPath            string
	MDPath              string
	TraceASCIIPath      string
	BundlePath          string
	OutputDir           string
}

type scanReport struct {
	Command         string     `json:"command"`
	Target          string     `json:"target"`
	MCPMode         string     `json:"mcp_mode"`
	RFCMode         string     `json:"rfc_mode"`
	Timestamp       string     `json:"timestamp"`
	PRMOK           bool       `json:"prm_ok"`
	OAuthDiscovery  bool       `json:"oauth_discovery_viable"`
	AuthzMetadataOK bool       `json:"authz_server_metadata_ok"`
	Steps           []scanStep `json:"steps"`
	Findings        []finding  `json:"findings"`
	PrimaryFinding  finding    `json:"primary_finding"`
}

type scanStep struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type scanSummary struct {
	Stdout string
	MD     string
	JSON   []byte
	Trace  []traceEntry
}

type traceEntry struct {
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

type mcpAuthObservation struct {
	Status                  int
	ErrorMessage            string
	WWWAuthenticatePresent  bool
	WWWAuthenticateObserved string
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
//   - []finding: MCP/RFC compliance findings (e.g., MCP_GET_NOT_SSE, DISCOVERY_NO_WWW_AUTHENTICATE)
//   - summary: Human-readable summary of the probe result
//   - authRequired: true if 401 received (auth definitely required),
//     false if 405/200 received (auth status unknown, caller should check PRM)
//   - error: Non-nil only for fatal errors (network failures, invalid config)
//
// Response handling:
//   - 401 Unauthorized: Auth required. Extract resource_metadata from WWW-Authenticate header.
//   - 405 Method Not Allowed: Server doesn't support GET/SSE. Auth status unknown; check PRM.
//   - 200 OK: Auth not required (public endpoint). Validates SSE content-type per MCP spec.
//   - Timeout: Returns MCP_PROBE_TIMEOUT finding (servers must respond promptly per MCP spec).
func probeMCP(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) (string, string, []finding, string, bool, error) {
	findings := []finding{}
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
	resp, err := client.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			evidence := "probe timed out waiting for response headers; MCP spec requires SSE headers or a 405 for GET Accept: text/event-stream"
			return "", config.Target, []finding{newFinding("MCP_PROBE_TIMEOUT", evidence)}, evidence, true, nil
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
//   - []finding: RFC compliance findings (e.g., PRM_RESOURCE_MISMATCH, PRM_MISSING_AUTHORIZATION_SERVERS)
//   - string: Evidence summary (URLs probed and their HTTP status codes)
//   - error: Non-nil only for fatal errors (not HTTP 404s)
//
// Behavior:
//   - When authRequiredFromProbe=true (401 from Step 1): 404 from PRM is flagged as a finding
//   - When authRequiredFromProbe=false (405 from Step 1): 404 from PRM is normal (no OAuth configured)
//   - If valid PRM is found with authorization_servers, the caller should set authRequired=true
//   - Prefers exact resource match; falls back to first usable PRM if no exact match
func fetchPRMMatrix(client *http.Client, config scanConfig, resourceMetadata string, resolvedTarget string, trace *[]traceEntry, stdout io.Writer, authRequiredFromProbe bool) (prmResult, []finding, string, error) {
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		return prmResult{}, nil, "", err
	}
	expectedResource := config.Target
	// Normalize resource identifiers so trailing-slash differences can be treated as equivalent.
	expectedCanonical := canonicalizeResourceURL(expectedResource)

	findings := []finding{}
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
	TokenEndpoints        []string
	RegistrationEndpoints []string
}

// fetchAuthServerMetadata retrieves Authorization Server Metadata via RFC 8414 and OIDC discovery (Step 4).
//
// For each issuer in PRM's authorization_servers, this function fetches the OAuth metadata
// from RFC 8414 or OIDC discovery endpoints and validates RFC compliance.
//
// Inputs:
//   - client: HTTP client for making requests
//   - config: Scan configuration (RFC mode, SSRF settings, verbose mode, etc.)
//   - prm: Protected Resource Metadata from Step 3 (contains authorization_servers list)
//   - trace: Request/response trace log for debugging and evidence collection
//   - stdout: Writer for verbose output
//
// Outputs:
//   - []finding: RFC compliance findings for each issuer:
//   - AUTH_SERVER_ISSUER_MISMATCH: metadata issuer != expected issuer (MUST violation)
//   - AUTH_SERVER_METADATA_INVALID: missing required fields or invalid format
//   - AUTH_SERVER_PKCE_S256_MISSING: no S256 support (SHOULD violation)
//   - JWKS_INVALID: malformed JWKS at jwks_uri
//   - string: Evidence summary (metadata URLs probed and HTTP status codes)
//   - authServerMetadataResult: Contains TokenEndpoints and RegistrationEndpoints for Steps 5-6
//
// Validations performed per RFC 8414:
//   - Issuer identifier has no query/fragment components
//   - Metadata response is 200 OK with application/json content-type
//   - Metadata issuer MUST match the expected issuer (tolerant host/path family match allowed for known variants)
//   - Required fields: issuer, authorization_endpoint, token_endpoint
//   - PKCE S256 support (code_challenge_methods_supported)
//   - JWKS validity if jwks_uri is present
//
// Security:
//   - SSRF protection blocks private/loopback issuers unless --allow-private-issuers is set
func fetchAuthServerMetadata(client *http.Client, config scanConfig, prm prmResult, trace *[]traceEntry, stdout io.Writer) ([]finding, string, authServerMetadataResult, bool) {
	findings := []finding{}
	var evidence strings.Builder
	result := authServerMetadataResult{}
	anySuccess := false
	for _, issuer := range prm.AuthorizationServers {
		if issuer == "" {
			continue
		}
		if rfcModeEnabled(config.RFCMode) {
			if urlFindings := validateURLString(issuer, "issuer", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFCMode) {
			if parsedIssuer, err := url.Parse(issuer); err == nil {
				if parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" {
					findings = append(findings, newFinding("AUTH_SERVER_ISSUER_QUERY_FRAGMENT", fmt.Sprintf("issuer %q has query/fragment (RFC 8414)", issuer)))
				}
			}
		}
		if !config.AllowPrivateIssuers {
			if blocked := issuerPrivate(issuer); blocked {
				findings = append(findings, newFinding("AUTH_SERVER_ISSUER_PRIVATE_BLOCKED", fmt.Sprintf("blocked issuer %s", issuer)))
				continue
			}
		}
		candidates, err := buildIssuerDiscoveryCandidates(issuer)
		if err != nil {
			code := "AUTH_SERVER_METADATA_INVALID"
			if errors.Is(err, errIssuerQueryFragment) {
				code = "AUTH_SERVER_ISSUER_QUERY_FRAGMENT"
			}
			findings = append(findings, newFinding(code, fmt.Sprintf("issuer %q invalid: %v", issuer, err)))
			continue
		}

		issuerEvidence := []string{fmt.Sprintf("issuer: %s", issuer)}
		warnings := []string{}
		success := false
		successViaOIDC := false
		policyBlocked := false
		hadNetworkError := false
		hadServerError := false
		hadInvalid := false

		for idx, metadataURL := range candidates {
			resp, payload, err := fetchJSON(client, config, metadataURL, trace, stdout, "Step 4: Auth server metadata")
			if err != nil {
				var policyErr fetchPolicyError
				if errors.As(err, &policyErr) {
					findings = append(findings, newFinding(policyErr.Code, fmt.Sprintf("issuer %s blocked: %s", issuer, policyErr.Detail)))
					issuerEvidence = append(issuerEvidence, fmt.Sprintf("%s -> blocked: %s", metadataURL, policyErr.Detail))
					policyBlocked = true
					break
				}
				issuerEvidence = append(issuerEvidence, fmt.Sprintf("%s -> fetch error: %v", metadataURL, err))
				hadNetworkError = true
				continue
			}

			issuerEvidence = append(issuerEvidence, fmt.Sprintf("%s -> %d", metadataURL, resp.StatusCode))
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
				continue
			}
			if resp.StatusCode >= http.StatusInternalServerError {
				hadServerError = true
				continue
			}
			if resp.StatusCode != http.StatusOK {
				hadInvalid = true
				continue
			}
			if rfcModeEnabled(config.RFCMode) {
				contentType := resp.Header.Get("Content-Type")
				if !strings.HasPrefix(contentType, "application/json") {
					hadInvalid = true
					continue
				}
			}
			obj, ok := payload.(map[string]any)
			if !ok {
				hadInvalid = true
				continue
			}
			if rfcModeEnabled(config.RFCMode) {
				issuerValue, ok := obj["issuer"].(string)
				if !ok || issuerValue == "" {
					hadInvalid = true
					continue
				}
				matches, warning, err := issuerMatchesWithTolerance(issuer, issuerValue)
				if err != nil {
					code := "AUTH_SERVER_METADATA_INVALID"
					if errors.Is(err, errIssuerQueryFragment) {
						code = "AUTH_SERVER_ISSUER_QUERY_FRAGMENT"
					}
					findings = append(findings, newFinding(code, fmt.Sprintf("metadata issuer %q invalid: %v", issuerValue, err)))
					hadInvalid = true
					continue
				}
				if !matches {
					findings = append(findings, newFindingWithEvidence("AUTH_SERVER_ISSUER_MISMATCH", []string{
						fmt.Sprintf("issuer mismatch: metadata issuer %q, expected %q", issuerValue, issuer),
					}))
					hadInvalid = true
					continue
				}
				if warning != "" {
					warnings = append(warnings, warning)
				}
			}
			authorizationEndpoint, ok := obj["authorization_endpoint"].(string)
			if !ok || authorizationEndpoint == "" {
				hadInvalid = true
				continue
			}
			tokenEndpoint, ok := obj["token_endpoint"].(string)
			if !ok || tokenEndpoint == "" {
				hadInvalid = true
				continue
			}
			registrationEndpoint, _ := obj["registration_endpoint"].(string)
			if rfcModeEnabled(config.RFCMode) {
				if urlFindings := validateURLString(authorizationEndpoint, "authorization_endpoint", config, false); len(urlFindings) > 0 {
					findings = append(findings, urlFindings...)
				}
				if urlFindings := validateURLString(tokenEndpoint, "token_endpoint", config, false); len(urlFindings) > 0 {
					findings = append(findings, urlFindings...)
				}
				parsedIssuer, err := url.Parse(issuer)
				if err == nil {
					issuerHost := parsedIssuer.Hostname()
					if issuerHost != "" {
						checkEndpointHostMismatch(&findings, authorizationEndpoint, issuerHost, "authorization_endpoint")
						checkEndpointHostMismatch(&findings, tokenEndpoint, issuerHost, "token_endpoint")
					}
				}
				if methods, ok := obj["code_challenge_methods_supported"].([]any); ok {
					if !containsString(methods, "S256") {
						findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing S256", issuer)))
					}
				} else {
					findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing code_challenge_methods_supported", issuer)))
				}
				if prm.Resource != "" {
					if protectedResources, ok := obj["protected_resources"].([]any); ok && len(protectedResources) > 0 {
						if !containsString(protectedResources, prm.Resource) {
							findings = append(findings, newFinding("AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH", fmt.Sprintf("resource %q not in protected_resources", prm.Resource)))
						}
					}
				}
				if jwksURI, ok := obj["jwks_uri"].(string); ok && jwksURI != "" {
					if urlFindings := validateURLString(jwksURI, "jwks_uri", config, false); len(urlFindings) > 0 {
						findings = append(findings, urlFindings...)
					}
					jwksResp, jwksPayload, err := fetchJSON(client, config, jwksURI, trace, stdout, "Step 4: Auth server metadata")
					if err != nil {
						var policyErr fetchPolicyError
						if errors.As(err, &policyErr) {
							findings = append(findings, newFinding(policyErr.Code, fmt.Sprintf("jwks blocked: %s", policyErr.Detail)))
						} else {
							findings = append(findings, newFinding("JWKS_FETCH_ERROR", fmt.Sprintf("%s fetch error: %v", jwksURI, err)))
						}
					} else if jwksResp.StatusCode != http.StatusOK {
						findings = append(findings, newFinding("JWKS_FETCH_ERROR", fmt.Sprintf("%s status %d", jwksURI, jwksResp.StatusCode)))
					} else if jwksObj, ok := jwksPayload.(map[string]any); !ok {
						findings = append(findings, newFinding("JWKS_INVALID", fmt.Sprintf("%s not JSON object", jwksURI)))
					} else if keys, ok := jwksObj["keys"].([]any); !ok || len(keys) == 0 {
						findings = append(findings, newFinding("JWKS_INVALID", fmt.Sprintf("%s missing keys array", jwksURI)))
					}
				}
			}

			result.TokenEndpoints = append(result.TokenEndpoints, tokenEndpoint)
			if registrationEndpoint != "" {
				result.RegistrationEndpoints = append(result.RegistrationEndpoints, registrationEndpoint)
			}
			success = true
			anySuccess = true
			if idx > 0 {
				successViaOIDC = true
			}
			break
		}

		if successViaOIDC {
			issuerEvidence = append(issuerEvidence, "Authorization server metadata discovered via OIDC discovery endpoint.")
		}
		for _, warning := range warnings {
			issuerEvidence = append(issuerEvidence, warning)
		}
		for _, line := range issuerEvidence {
			fmt.Fprintf(&evidence, "%s\n", line)
		}

		if success || policyBlocked {
			continue
		}
		if hadNetworkError || hadServerError {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_UNREACHABLE", fmt.Sprintf("%s metadata fetch failed", issuer)))
			continue
		}
		if hadInvalid {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s metadata invalid", issuer)))
			continue
		}
		findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s metadata discovery failed", issuer)))
	}
	return findings, strings.TrimSpace(evidence.String()), result, anySuccess
}

func mcpInitializeAndListTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer, authRequired bool) (string, string, []finding, *mcpAuthObservation) {
	var evidence strings.Builder
	findings := []finding{}
	var authObservation *mcpAuthObservation

	if !authRequired {
		findings = append(findings, checkInitializeOrdering(client, config, authRequired, trace, stdout)...)
	}

	initParams := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "authprobe",
			"version": "0.1",
		},
	}

	initRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  initParams,
	}

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, "", trace, stdout, "Step 2: MCP initialize + tools/list (initialize)")
	if err != nil {
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", fmt.Sprintf("initialize error: %v", err)))
		return "FAIL", fmt.Sprintf("initialize error: %v", err), findings, nil
	}
	fmt.Fprintf(&evidence, "initialize -> %d", initResp.StatusCode)
	if initPayload == nil {
		fmt.Fprint(&evidence, " (non-JSON response)")
	}
	if initPayload != nil && initPayload.Error != nil {
		fmt.Fprintf(&evidence, " (error: %s)", initPayload.Error.Message)
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		wwwAuthPresent, wwwAuthValue := hasWWWAuthenticate(initResp.Header.Values("WWW-Authenticate"))
		authObservation = &mcpAuthObservation{
			Status:                  initResp.StatusCode,
			ErrorMessage:            jsonRPCErrorMessage(initPayload),
			WWWAuthenticatePresent:  wwwAuthPresent,
			WWWAuthenticateObserved: wwwAuthValue,
		}
		if authRequired {
			fmt.Fprint(&evidence, " (auth required)")
			return "SKIP", strings.TrimSpace(evidence.String()), findings, authObservation
		}
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, nil
	}

	findings = append(findings, validateJSONRPCResponse(config, initPayload, initRequest.ID, "initialize")...)
	initResult, capabilities, sessionID, initResultFindings := parseInitializeResult(config, initPayload, initResp)
	findings = append(findings, initResultFindings...)

	notificationFindings, notificationEvidence := sendInitializedNotification(client, config, sessionID, trace, stdout)
	if notificationEvidence != "" {
		fmt.Fprintf(&evidence, "\n%s", notificationEvidence)
	}
	findings = append(findings, notificationFindings...)

	findings = append(findings, checkJSONRPCNullID(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkJSONRPCNotificationWithID(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkOriginValidation(client, config, sessionID, trace, stdout)...)
	findings = append(findings, checkProtocolVersionHeader(client, config, sessionID, trace, stdout)...)
	if sessionID != "" {
		findings = append(findings, checkSessionHeader(client, config, sessionID, trace, stdout)...)
	}

	if supportsPing(capabilities) {
		findings = append(findings, checkPing(client, config, sessionID, trace, stdout)...)
	}

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (tools/list)")
	if err != nil {
		fmt.Fprintf(&evidence, "\n")
		fmt.Fprintf(&evidence, "tools/list -> error: %v", err)
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	fmt.Fprintf(&evidence, "\n")
	fmt.Fprintf(&evidence, "tools/list -> %d", toolsResp.StatusCode)
	if toolsPayload == nil {
		fmt.Fprint(&evidence, " (non-JSON response)")
	}
	if toolsPayload != nil && toolsPayload.Error != nil {
		fmt.Fprintf(&evidence, " (error: %s)", toolsPayload.Error.Message)
	}
	if toolsResp.StatusCode == http.StatusUnauthorized || toolsResp.StatusCode == http.StatusForbidden {
		if authRequired {
			fmt.Fprint(&evidence, " (auth required)")
			return "SKIP", strings.TrimSpace(evidence.String()), findings, authObservation
		}
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	if toolsResp.StatusCode != http.StatusOK || toolsPayload == nil || toolsPayload.Error != nil {
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings, authObservation
	}
	findings = append(findings, validateJSONRPCResponse(config, toolsPayload, toolsRequest.ID, "tools/list")...)

	toolNames := extractToolNames(toolsPayload.Result)
	if len(toolNames) == 0 {
		fmt.Fprint(&evidence, " (tools: none)")
	} else {
		fmt.Fprintf(&evidence, " (tools: %s)", strings.Join(toolNames, ", "))
	}

	findings = append(findings, checkToolSchemas(config, toolsPayload.Result)...)
	findings = append(findings, checkToolIcons(config, toolsPayload.Result)...)
	if supportsTasks(capabilities) || tasksAdvertised(initResult) {
		findings = append(findings, checkTasksSupport(client, config, sessionID, trace, stdout)...)
	}

	status := "PASS"
	if hasHighSeverity(findings) {
		status = "FAIL"
	}
	return status, strings.TrimSpace(evidence.String()), findings, authObservation
}

// parseInitializeResult validates the MCP initialize response per MCP 2025-11-25 spec.
func parseInitializeResult(config scanConfig, payload *jsonRPCResponse, resp *http.Response) (map[string]any, map[string]any, string, []finding) {
	findings := []finding{}
	// MCP 2025-11-25: Initialize response MUST include a result object
	if payload == nil || payload.Result == nil {
		findings = append(findings, newMCPFinding(config, "MCP_INITIALIZE_RESULT_INVALID", "initialize missing result object"))
		return nil, nil, "", findings
	}
	var result map[string]any
	if err := json.Unmarshal(payload.Result, &result); err != nil {
		findings = append(findings, newMCPFinding(config, "MCP_INITIALIZE_RESULT_INVALID", fmt.Sprintf("initialize result parse error: %v", err)))
		return nil, nil, "", findings
	}

	// MCP 2025-11-25: The result MUST include "protocolVersion" matching the spec version
	protocolVersion, ok := result["protocolVersion"].(string)
	if !ok || strings.TrimSpace(protocolVersion) == "" {
		findings = append(findings, newMCPFinding(config, "MCP_PROTOCOL_VERSION_MISSING", "initialize result missing protocolVersion"))
	} else if protocolVersion != mcpProtocolVersion {
		findings = append(findings, newMCPFinding(config, "MCP_PROTOCOL_VERSION_MISMATCH", fmt.Sprintf("protocolVersion %q != %q", protocolVersion, mcpProtocolVersion)))
	}

	// MCP 2025-11-25: "capabilities" MUST be an object if present
	capabilities, ok := result["capabilities"].(map[string]any)
	if !ok && result["capabilities"] != nil {
		findings = append(findings, newMCPFinding(config, "MCP_CAPABILITIES_INVALID", "initialize capabilities not an object"))
	}

	sessionID := ""
	if resp != nil {
		sessionID = strings.TrimSpace(resp.Header.Get("MCP-Session-Id"))
	}
	if sessionID == "" {
		if value, ok := result["sessionId"].(string); ok {
			sessionID = strings.TrimSpace(value)
		} else if value, ok := result["session_id"].(string); ok {
			sessionID = strings.TrimSpace(value)
		}
	}

	return result, capabilities, sessionID, findings
}

func hasWWWAuthenticate(values []string) (bool, string) {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true, value
		}
	}
	return false, ""
}

func jsonRPCErrorMessage(payload *jsonRPCResponse) string {
	if payload == nil || payload.Error == nil {
		return ""
	}
	return strings.TrimSpace(payload.Error.Message)
}

// sendInitializedNotification sends the notifications/initialized per MCP 2025-11-25.
func sendInitializedNotification(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) ([]finding, string) {
	notification := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	resp, body, payload, err := postJSONRPC(client, config, config.Target, notification, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (notifications/initialized)")
	if err != nil {
		return []finding{newMCPFinding(config, "MCP_NOTIFICATION_FAILED", fmt.Sprintf("notifications/initialized error: %v", err))}, ""
	}
	evidence := fmt.Sprintf("notifications/initialized -> %d", resp.StatusCode)
	findings := []finding{}
	// MCP 2025-11-25: Notifications SHOULD return 202 Accepted with no body
	if resp.StatusCode != http.StatusAccepted {
		findings = append(findings, newMCPFinding(config, "MCP_NOTIFICATION_STATUS_INVALID", fmt.Sprintf("notifications/initialized status %d", resp.StatusCode)))
	}
	// JSON-RPC 2.0: Notifications MUST NOT return a response body
	if len(body) > 0 || payload != nil {
		findings = append(findings, newMCPFinding(config, "MCP_NOTIFICATION_BODY_PRESENT", "notifications/initialized returned a body"))
	}
	return findings, evidence
}

// checkInitializeOrdering verifies the server enforces initialize-before-other-methods.
// MCP 2025-11-25: Servers MUST reject requests before initialize completes.
// When authRequired is false (public server), severity is lowered to "info" since
// there's no security impact - tools are already publicly accessible.
func checkInitializeOrdering(client *http.Client, config scanConfig, authRequired bool, trace *[]traceEntry, stdout io.Writer) []finding {
	preInitRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "tools/list",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, preInitRequest, "", trace, stdout, "Step 2: MCP initialize + tools/list (pre-init tools/list)")
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if payload != nil && payload.Error != nil {
		return nil
	}
	evidence := fmt.Sprintf("pre-init tools/list status %d", resp.StatusCode)
	if authRequired {
		return []finding{newMCPFinding(config, "MCP_INITIALIZE_ORDERING_NOT_ENFORCED", evidence)}
	}
	// Public server: lower severity since tools are already publicly accessible
	return []finding{newFindingWithSeverity("MCP_INITIALIZE_ORDERING_NOT_ENFORCED", evidence, "info")}
}

// checkJSONRPCNullID verifies the server rejects null request IDs.
// JSON-RPC 2.0 Section 4: Request id MUST be a String, Number, or omitted (for notifications).
func checkJSONRPCNullID(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return []finding{newMCPFinding(config, "MCP_JSONRPC_ID_NULL_ACCEPTED", "null id probe marshal failed")}
	}
	resp, _, parsed, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (null id probe)", nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if parsed != nil && parsed.Error != nil {
		return nil
	}
	return []finding{newMCPFinding(config, "MCP_JSONRPC_ID_NULL_ACCEPTED", fmt.Sprintf("null id probe status %d", resp.StatusCode))}
}

// checkJSONRPCNotificationWithID verifies the server rejects notifications that include an id.
// JSON-RPC 2.0 Section 4.1: Notifications MUST NOT include an id member.
func checkJSONRPCNotificationWithID(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "notifications/initialized",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return []finding{newMCPFinding(config, "MCP_NOTIFICATION_WITH_ID_ACCEPTED", "notification id probe marshal failed")}
	}
	resp, _, parsed, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (notification id probe)", nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if parsed != nil && parsed.Error != nil {
		return nil
	}
	return []finding{newMCPFinding(config, "MCP_NOTIFICATION_WITH_ID_ACCEPTED", fmt.Sprintf("notification id probe status %d", resp.StatusCode))}
}

// checkOriginValidation verifies the server validates Origin headers for CSRF protection.
// MCP 2025-11-25 Security: Servers SHOULD validate the Origin header.
func checkOriginValidation(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      90,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (origin probe)", func(req *http.Request) {
		req.Header.Set("Origin", "http://invalid.example")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil
	}
	return []finding{newMCPFinding(config, "MCP_ORIGIN_NOT_VALIDATED", fmt.Sprintf("origin probe status %d", resp.StatusCode))}
}

// checkProtocolVersionHeader verifies the server validates MCP-Protocol-Version header.
// MCP 2025-11-25 Streamable HTTP: Servers SHOULD reject invalid protocol versions.
func checkProtocolVersionHeader(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      91,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (protocol version probe)", func(req *http.Request) {
		req.Header.Set("MCP-Protocol-Version", "invalid")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil
	}
	return []finding{newMCPFinding(config, "MCP_PROTOCOL_VERSION_REJECTION_MISSING", fmt.Sprintf("protocol version probe status %d", resp.StatusCode))}
}

// checkSessionHeader verifies the server validates MCP-Session-Id header.
// MCP 2025-11-25 Streamable HTTP: Servers SHOULD return 404 for invalid session IDs.
func checkSessionHeader(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      92,
		"method":  "tools/list",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	resp, _, _, err := postJSONRPCBytes(client, config, config.Target, body, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (session id probe)", func(req *http.Request) {
		req.Header.Set("MCP-Session-Id", "invalid-session")
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return []finding{newMCPFinding(config, "MCP_SESSION_ID_REJECTION_MISSING", fmt.Sprintf("session id probe status %d", resp.StatusCode))}
}

// checkPing verifies the server correctly implements the ping method.
// MCP 2025-11-25: ping MUST return an empty object result.
func checkPing(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	pingRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "ping",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, pingRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (ping)")
	if err != nil {
		return []finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping error: %v", err))}
	}
	if resp.StatusCode != http.StatusOK || payload == nil || payload.Error != nil {
		return []finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping status %d", resp.StatusCode))}
	}
	var result any
	if err := json.Unmarshal(payload.Result, &result); err != nil {
		return []finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", fmt.Sprintf("ping result parse error: %v", err))}
	}
	// MCP 2025-11-25: ping result MUST be an empty object {}
	if obj, ok := result.(map[string]any); !ok || len(obj) != 0 {
		return []finding{newMCPFinding(config, "MCP_PING_INVALID_RESPONSE", "ping result not empty object")}
	}
	return nil
}

// checkToolSchemas validates tool definitions per MCP 2025-11-25 spec.
func checkToolSchemas(config scanConfig, raw json.RawMessage) []finding {
	findings := []finding{}
	if len(raw) == 0 {
		return findings
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return []finding{newMCPFinding(config, "MCP_TOOLS_LIST_INVALID", fmt.Sprintf("tools/list parse error: %v", err))}
	}
	for _, tool := range result.Tools {
		// MCP 2025-11-25: Tools MUST include inputSchema for argument validation
		if len(tool.InputSchema) == 0 {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_MISSING", fmt.Sprintf("tool %q missing inputSchema", tool.Name)))
			continue
		}
		var schema any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema parse error", tool.Name)))
			continue
		}
		if schema == nil {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema null", tool.Name)))
			continue
		}
		if _, ok := schema.(map[string]any); !ok {
			findings = append(findings, newMCPFinding(config, "MCP_TOOL_INPUT_SCHEMA_INVALID", fmt.Sprintf("tool %q inputSchema not object", tool.Name)))
		}
	}
	return findings
}

func checkToolIcons(config scanConfig, raw json.RawMessage) []finding {
	findings := []finding{}
	if len(raw) == 0 {
		return findings
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return findings
	}
	for _, tool := range result.Tools {
		for key, value := range tool.Annotations {
			if !strings.Contains(strings.ToLower(key), "icon") {
				continue
			}
			uri, ok := value.(string)
			if !ok || strings.TrimSpace(uri) == "" {
				continue
			}
			if !isSafeIconURI(uri) {
				findings = append(findings, newMCPFinding(config, "MCP_ICON_UNSAFE_SCHEME", fmt.Sprintf("tool %q icon %q", tool.Name, uri)))
			}
		}
	}
	return findings
}

func checkTasksSupport(client *http.Client, config scanConfig, sessionID string, trace *[]traceEntry, stdout io.Writer) []finding {
	tasksRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tasks/list",
	}
	resp, _, payload, err := postJSONRPC(client, config, config.Target, tasksRequest, sessionID, trace, stdout, "Step 2: MCP initialize + tools/list (tasks/list)")
	if err != nil {
		return []finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", fmt.Sprintf("tasks/list error: %v", err))}
	}
	if resp.StatusCode == http.StatusNotFound {
		return []finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", "tasks/list returned 404")}
	}
	if payload != nil && payload.Error != nil && payload.Error.Code == -32601 {
		return []finding{newMCPFinding(config, "MCP_TASKS_METHOD_MISSING", "tasks/list method not found")}
	}
	return validateJSONRPCResponse(config, payload, tasksRequest.ID, "tasks/list")
}

func probeTokenEndpointReadiness(client *http.Client, config scanConfig, tokenEndpoints []string, trace *[]traceEntry, stdout io.Writer) ([]finding, string) {
	findings := []finding{}
	var evidence strings.Builder
	for _, endpoint := range tokenEndpoints {
		if endpoint == "" {
			continue
		}
		resp, body, err := postTokenProbe(client, config, endpoint, trace, stdout, "Step 5: Token endpoint readiness (heuristics)")
		if err != nil {
			fmt.Fprintf(&evidence, "%s -> error: %v\n", endpoint, err)
			continue
		}
		fmt.Fprintf(&evidence, "%s -> %d\n", endpoint, resp.StatusCode)

		contentType := resp.Header.Get("Content-Type")
		payload, parseErr := parseJSONBody(body)
		if !isJSONContentType(contentType) || parseErr != nil {
			findings = append(findings, newFinding("TOKEN_RESPONSE_NOT_JSON_RISK", fmt.Sprintf("token content-type %q", contentType)))
		}

		if resp.StatusCode == http.StatusOK {
			if payloadMap, ok := payload.(map[string]any); ok {
				if _, ok := payloadMap["error"]; ok {
					findings = append(findings, newFinding("TOKEN_HTTP200_ERROR_PAYLOAD_RISK", "token response 200 with error payload"))
				}
			}
		}
	}
	return findings, strings.TrimSpace(evidence.String())
}

// probeDCREndpoints probes Dynamic Client Registration endpoints (RFC 7591).
// Tests for: open registration, input validation, and security posture.
func probeDCREndpoints(client *http.Client, config scanConfig, registrationEndpoints []string, trace *[]traceEntry, stdout io.Writer) ([]finding, string) {
	findings := []finding{}
	var evidence strings.Builder
	for _, endpoint := range registrationEndpoints {
		if endpoint == "" {
			continue
		}
		// Test 1: Probe with empty request to check if endpoint is protected
		emptyResp, _, err := postDCRProbe(client, config, endpoint, map[string]any{}, trace, stdout, "Step 6: Dynamic client registration (empty probe)")
		if err != nil {
			fmt.Fprintf(&evidence, "%s -> error: %v\n", endpoint, err)
			continue
		}
		fmt.Fprintf(&evidence, "%s -> %d", endpoint, emptyResp.StatusCode)

		switch emptyResp.StatusCode {
		case http.StatusCreated, http.StatusOK:
			// Endpoint is open - this is a security concern
			findings = append(findings, newFinding("DCR_ENDPOINT_OPEN", fmt.Sprintf("%s accepts unauthenticated registration", endpoint)))
			fmt.Fprint(&evidence, " (OPEN - no auth required)")

			// Test 2: Check input validation with suspicious redirect_uris
			findings = append(findings, testDCRInputValidation(client, config, endpoint, trace, stdout)...)
		case http.StatusUnauthorized, http.StatusForbidden:
			// Endpoint is protected - expected for secure DCR
			fmt.Fprint(&evidence, " (protected)")
		case http.StatusBadRequest:
			// Endpoint requires valid input - likely protected or validates input
			fmt.Fprint(&evidence, " (validates input)")
		default:
			fmt.Fprintf(&evidence, " (unexpected status)")
		}
		fmt.Fprintln(&evidence)
	}
	return findings, strings.TrimSpace(evidence.String())
}

// testDCRInputValidation tests DCR endpoint input validation with suspicious values.
func testDCRInputValidation(client *http.Client, config scanConfig, endpoint string, trace *[]traceEntry, stdout io.Writer) []finding {
	findings := []finding{}

	// Test: HTTP redirect URI (should be rejected per RFC 6749 Section 3.1.2.1)
	httpPayload := map[string]any{
		"redirect_uris": []string{"http://evil.example.com/callback"},
		"client_name":   "authprobe-test-http",
	}
	httpResp, _, err := postDCRProbe(client, config, endpoint, httpPayload, trace, stdout, "Step 6: Dynamic client registration (http redirect test)")
	if err == nil && (httpResp.StatusCode == http.StatusCreated || httpResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_HTTP_REDIRECT_ACCEPTED", "registration accepted http:// redirect URI"))
	}

	// Test: localhost redirect URI (common in dev, risky in prod)
	localhostPayload := map[string]any{
		"redirect_uris": []string{"http://localhost:8080/callback"},
		"client_name":   "authprobe-test-localhost",
	}
	localhostResp, _, err := postDCRProbe(client, config, endpoint, localhostPayload, trace, stdout, "Step 6: Dynamic client registration (localhost test)")
	if err == nil && (localhostResp.StatusCode == http.StatusCreated || localhostResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_LOCALHOST_REDIRECT_ACCEPTED", "registration accepted localhost redirect URI"))
	}

	// Test: Dangerous URI schemes (file://, javascript:)
	dangerousPayload := map[string]any{
		"redirect_uris": []string{"javascript:alert(1)"},
		"client_name":   "authprobe-test-dangerous",
	}
	dangerousResp, _, err := postDCRProbe(client, config, endpoint, dangerousPayload, trace, stdout, "Step 6: Dynamic client registration (dangerous URI test)")
	if err == nil && (dangerousResp.StatusCode == http.StatusCreated || dangerousResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_DANGEROUS_URI_ACCEPTED", "registration accepted javascript: or file: URI scheme"))
	}

	// Test: Empty redirect_uris array (should be rejected)
	emptyRedirectPayload := map[string]any{
		"redirect_uris": []string{},
		"client_name":   "authprobe-test-empty-redirects",
	}
	emptyRedirectResp, _, err := postDCRProbe(client, config, endpoint, emptyRedirectPayload, trace, stdout, "Step 6: Dynamic client registration (empty redirects test)")
	if err == nil && (emptyRedirectResp.StatusCode == http.StatusCreated || emptyRedirectResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_EMPTY_REDIRECT_URIS_ACCEPTED", "registration accepted empty redirect_uris array"))
	}

	return findings
}

// postDCRProbe sends a POST request to a DCR endpoint with JSON payload.
func postDCRProbe(client *http.Client, config scanConfig, endpoint string, payload map[string]any, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return resp, respBody, err
		}
	}
	addTrace(trace, req, resp, config.Redact, verboseLabel)

	return resp, respBody, nil
}

// mcpProtocolVersion is the MCP protocol version supported by authprobe.
const mcpProtocolVersion = "2025-11-25"

// JSON-RPC types for MCP communication.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP tools list result types.
type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type mcpToolsListDetailResult struct {
	Tools []mcpToolDetail `json:"tools"`
}

type mcpToolDetail struct {
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  map[string]any  `json:"annotations,omitempty"`
}

// fetchMCPTools performs MCP initialize + tools/list to retrieve the list of tools.
// This is used by cli.go to fetch tool details for the --mcp-tool flag.
func fetchMCPTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) ([]mcpToolDetail, error) {
	initParams := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "authprobe",
			"version": "0.1",
		},
	}

	initRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  initParams,
	}

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, "", trace, stdout, "MCP tool fetch (initialize)")
	if err != nil {
		return nil, err
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("initialize unauthorized: %d", initResp.StatusCode)
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", formatJSONRPCError(initResp, initPayload))
	}

	sessionID := ""
	if initResp != nil {
		sessionID = strings.TrimSpace(initResp.Header.Get("MCP-Session-Id"))
	}
	if sessionID == "" && initPayload != nil && initPayload.Result != nil {
		var initResult map[string]any
		if err := json.Unmarshal(initPayload.Result, &initResult); err == nil {
			if value, ok := initResult["sessionId"].(string); ok {
				sessionID = strings.TrimSpace(value)
			} else if value, ok := initResult["session_id"].(string); ok {
				sessionID = strings.TrimSpace(value)
			}
		}
	}

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, sessionID, trace, stdout, "MCP tool fetch (tools/list)")
	if err != nil {
		return nil, err
	}
	if toolsResp.StatusCode == http.StatusUnauthorized || toolsResp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("tools/list unauthorized: %d", toolsResp.StatusCode)
	}
	if toolsResp.StatusCode != http.StatusOK || toolsPayload == nil || toolsPayload.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", formatJSONRPCError(toolsResp, toolsPayload))
	}

	if len(toolsPayload.Result) == 0 {
		return nil, errors.New("tools/list returned empty result")
	}
	var result mcpToolsListDetailResult
	if err := json.Unmarshal(toolsPayload.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}
	return result.Tools, nil
}

// formatJSONRPCError formats a JSON-RPC error response for display.
func formatJSONRPCError(resp *http.Response, payload *jsonRPCResponse) string {
	if payload != nil && payload.Error != nil {
		return fmt.Sprintf("%d (%s)", resp.StatusCode, payload.Error.Message)
	}
	return fmt.Sprintf("%d", resp.StatusCode)
}

// postJSONRPC sends a JSON-RPC request and returns the response.
func postJSONRPC(client *http.Client, config scanConfig, target string, payload jsonRPCRequest, sessionID string, trace *[]traceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, *jsonRPCResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	return postJSONRPCBytes(client, config, target, body, sessionID, trace, stdout, verboseLabel, nil)
}

// postJSONRPCBytes sends raw JSON-RPC bytes and returns the response.
// The mutate function allows modifying the request before sending (e.g., for testing).
func postJSONRPCBytes(client *http.Client, config scanConfig, target string, body []byte, sessionID string, trace *[]traceEntry, stdout io.Writer, verboseLabel string, mutate func(*http.Request)) (*http.Response, []byte, *jsonRPCResponse, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if mcpModeEnabled(config.MCPMode) {
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		if sessionID != "" {
			req.Header.Set("MCP-Session-Id", sessionID)
		}
	}
	if err := applyHeaders(req, config.Headers); err != nil {
		return nil, nil, nil, err
	}
	if mutate != nil {
		mutate(req)
	}
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
		if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
			return nil, nil, nil, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return resp, respBody, nil, err
		}
	}
	addTrace(trace, req, resp, config.Redact, verboseLabel)

	var parsed jsonRPCResponse
	if len(respBody) > 0 {
		// Try parsing as plain JSON first
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			return resp, respBody, &parsed, nil
		}
		// If Content-Type is text/event-stream, try parsing as SSE
		contentType := resp.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "text/event-stream") {
			if jsonData := extractSSEData(respBody); jsonData != nil {
				if err := json.Unmarshal(jsonData, &parsed); err == nil {
					return resp, respBody, &parsed, nil
				}
			}
		}
	}
	return resp, respBody, nil, nil
}

// extractSSEData extracts JSON data from an SSE-formatted response.
// SSE format: "event: <type>\ndata: <json>\n\n"
// Multiple data lines are concatenated.
func extractSSEData(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	var dataLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data:"))
		}
	}
	if len(dataLines) == 0 {
		return nil
	}
	// Concatenate all data lines (SSE spec says multi-line data is joined with newlines)
	return []byte(strings.Join(dataLines, "\n"))
}

// extractToolNames extracts tool names from a JSON-RPC tools/list result.
func extractToolNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var result mcpToolsListResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		if tool.Name != "" {
			names = append(names, tool.Name)
		}
	}
	return names
}

// validateJSONRPCResponse checks a JSON-RPC response for conformance issues.
func validateJSONRPCResponse(config scanConfig, payload *jsonRPCResponse, expectedID any, context string) []finding {
	findings := []finding{}
	if payload == nil {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s response not JSON", context)))
		return findings
	}
	if payload.JSONRPC != "2.0" {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s jsonrpc=%q", context, payload.JSONRPC)))
	}
	if expectedID != nil && !jsonRPCIDEqual(payload.ID, expectedID) {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_ID_MISMATCH", fmt.Sprintf("%s id=%v", context, payload.ID)))
	}
	resultPresent := payload.Result != nil
	errorPresent := payload.Error != nil
	if resultPresent == errorPresent {
		findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s result/error shape invalid", context)))
	}
	if payload.Error != nil {
		if payload.Error.Message == "" {
			findings = append(findings, newMCPFinding(config, "MCP_JSONRPC_RESPONSE_INVALID", fmt.Sprintf("%s error missing message", context)))
		}
	}
	return findings
}

// jsonRPCIDEqual compares two JSON-RPC IDs for equality.
// Handles type coercion between int, float64, and string representations.
func jsonRPCIDEqual(a, b any) bool {
	switch av := a.(type) {
	case float64:
		switch bv := b.(type) {
		case int:
			return av == float64(bv)
		case int64:
			return av == float64(bv)
		case float64:
			return av == bv
		case string:
			return fmt.Sprintf("%g", av) == bv
		}
	case int:
		switch bv := b.(type) {
		case int:
			return av == bv
		case int64:
			return int64(av) == bv
		case float64:
			return float64(av) == bv
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	}
	return a == b
}
