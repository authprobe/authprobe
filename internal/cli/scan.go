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
	BundlePath          string
	OutputDir           string
}

type scanReport struct {
	Command        string     `json:"command"`
	Target         string     `json:"target"`
	MCPMode        string     `json:"mcp_mode"`
	RFCMode        string     `json:"rfc_mode"`
	Timestamp      string     `json:"timestamp"`
	Steps          []scanStep `json:"steps"`
	Findings       []finding  `json:"findings"`
	PrimaryFinding finding    `json:"primary_finding"`
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
	Timestamp string            `json:"ts"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type prmResult struct {
	AuthorizationServers []string
	Resource             string
}

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
	addTrace(trace, req, resp, config.Redact)

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
		findings = append(findings, newFinding("DISCOVERY_NO_WWW_AUTHENTICATE", "missing resource_metadata in WWW-Authenticate"))
		return "", resolvedTarget(resp, config.Target), findings, "missing WWW-Authenticate/resource_metadata", true, nil
	}
	// Success: we have a 401 with resource_metadata, indicating proper MCP OAuth discovery
	return resourceMetadata, resolvedTarget(resp, config.Target), findings, "401 with resource_metadata", true, nil
}

// fetchPRMMatrix retrieves protected resource metadata across discovery candidates.
func fetchPRMMatrix(client *http.Client, config scanConfig, resourceMetadata string, resolvedTarget string, trace *[]traceEntry, stdout io.Writer, authRequiredFromProbe bool) (prmResult, []finding, string, error) {
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		return prmResult{}, nil, "", err
	}
	expectedResource := config.Target

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
	pathSuffixOK := false
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
		if reportFindings {
			// RFC 9728 Section 4.1: The "resource" value MUST match the protected resource identifier
			if prm.Resource != "" && prm.Resource != expectedResource {
				findings = append(findings, newFinding("PRM_RESOURCE_MISMATCH", fmt.Sprintf("%s resource %q != %q", candidate.Source, prm.Resource, expectedResource)))
			}
			// RFC 8707 Section 2: Resource identifiers MUST NOT include a fragment component
			if rfcModeEnabled(config.RFCMode) {
				if parsedResource, err := url.Parse(prm.Resource); err == nil && parsedResource.Fragment != "" {
					findings = append(findings, newFinding("RESOURCE_FRAGMENT_FORBIDDEN", fmt.Sprintf("%s resource %q includes fragment (RFC 8707)", candidate.Source, prm.Resource)))
				}
			}
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

		if hasPathSuffix {
			if candidate.Source == "path-suffix" && prm.Resource == expectedResource {
				bestPRM = prm
				pathSuffixOK = true
			} else if !fallbackSet && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
				fallbackPRM = prm
				fallbackSet = true
			}
		} else if bestPRM.AuthorizationServers == nil && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
			bestPRM = prm
		}
	}
	if hasPathSuffix && !pathSuffixOK && fallbackSet {
		bestPRM = fallbackPRM
	}
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

// fetchAuthServerMetadata retrieves authorization server metadata per RFC 8414.
func fetchAuthServerMetadata(client *http.Client, config scanConfig, prm prmResult, trace *[]traceEntry, stdout io.Writer) ([]finding, string, authServerMetadataResult) {
	findings := []finding{}
	var evidence strings.Builder
	result := authServerMetadataResult{}
	for _, issuer := range prm.AuthorizationServers {
		if issuer == "" {
			continue
		}
		// RFC 3986: Validate issuer URL syntax
		if rfcModeEnabled(config.RFCMode) {
			if urlFindings := validateURLString(issuer, "issuer", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		// RFC 8414 Section 2: The issuer identifier MUST NOT contain query or fragment components
		if rfcModeEnabled(config.RFCMode) {
			if parsedIssuer, err := url.Parse(issuer); err == nil {
				if parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" {
					findings = append(findings, newFinding("AUTH_SERVER_ISSUER_QUERY_FRAGMENT", fmt.Sprintf("issuer %q has query/fragment (RFC 8414)", issuer)))
				}
			}
		}
		// SSRF protection: Block requests to private/loopback IP ranges
		if !config.AllowPrivateIssuers {
			if blocked := issuerPrivate(issuer); blocked {
				findings = append(findings, newFinding("AUTH_SERVER_ISSUER_PRIVATE_BLOCKED", fmt.Sprintf("blocked issuer %s", issuer)))
				continue
			}
		}
		metadataURL := buildMetadataURL(issuer)
		resp, payload, err := fetchJSON(client, config, metadataURL, trace, stdout, "Step 4: Auth server metadata")
		if err != nil {
			var policyErr fetchPolicyError
			if errors.As(err, &policyErr) {
				findings = append(findings, newFinding(policyErr.Code, fmt.Sprintf("issuer %s blocked: %s", issuer, policyErr.Detail)))
			} else {
				findings = append(findings, newFinding("AUTH_SERVER_METADATA_UNREACHABLE", fmt.Sprintf("%s fetch error: %v", issuer, err)))
			}
			continue
		}
		fmt.Fprintf(&evidence, "%s -> %d\n", metadataURL, resp.StatusCode)
		// RFC 8414 Section 3: The metadata endpoint MUST return 200 OK
		if resp.StatusCode != http.StatusOK {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s status %d", issuer, resp.StatusCode)))
			continue
		}
		// RFC 8414 Section 3: The response MUST have Content-Type: application/json
		if rfcModeEnabled(config.RFCMode) {
			contentType := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				findings = append(findings, newFinding("AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON", fmt.Sprintf("%s content-type %q", issuer, contentType)))
				continue
			}
		}
		// RFC 8414 Section 3: The response body MUST be a JSON object
		obj, ok := payload.(map[string]any)
		if !ok {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s response not JSON object", issuer)))
			continue
		}
		// RFC 8414 Section 2: The "issuer" value MUST be identical to the issuer identifier
		if rfcModeEnabled(config.RFCMode) {
			if issuerValue, ok := obj["issuer"].(string); ok {
				if issuerValue != issuer {
					findings = append(findings, newFindingWithEvidence("AUTH_SERVER_ISSUER_MISMATCH", []string{
						fmt.Sprintf("issuer mismatch: metadata issuer %q, expected %q", issuerValue, issuer),
					}))
					continue
				}
			} else {
				findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing issuer", issuer)))
				continue
			}
		}
		// RFC 8414 Section 2: "authorization_endpoint" is REQUIRED
		authorizationEndpoint, ok := obj["authorization_endpoint"].(string)
		if !ok || authorizationEndpoint == "" {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing authorization_endpoint", issuer)))
			continue
		}
		// RFC 8414 Section 2: "token_endpoint" is REQUIRED (except for implicit-only servers)
		tokenEndpoint, ok := obj["token_endpoint"].(string)
		if !ok || tokenEndpoint == "" {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing token_endpoint", issuer)))
			continue
		}
		// RFC 7591 Section 3: "registration_endpoint" is OPTIONAL - used for Dynamic Client Registration
		registrationEndpoint, _ := obj["registration_endpoint"].(string)
		if rfcModeEnabled(config.RFCMode) {
			if urlFindings := validateURLString(authorizationEndpoint, "authorization_endpoint", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFCMode) {
			if urlFindings := validateURLString(tokenEndpoint, "token_endpoint", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFCMode) {
			parsedIssuer, err := url.Parse(issuer)
			if err == nil {
				issuerHost := parsedIssuer.Hostname()
				if issuerHost != "" {
					checkEndpointHostMismatch(&findings, authorizationEndpoint, issuerHost, "authorization_endpoint")
					checkEndpointHostMismatch(&findings, tokenEndpoint, issuerHost, "token_endpoint")
				}
			}
		}
		// RFC 7636 Section 4.2: Servers SHOULD support "S256" for PKCE
		// MCP OAuth requires PKCE with S256 for public clients
		if rfcModeEnabled(config.RFCMode) {
			if methods, ok := obj["code_challenge_methods_supported"].([]any); ok {
				if !containsString(methods, "S256") {
					findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing S256", issuer)))
				}
			} else {
				findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing code_challenge_methods_supported", issuer)))
			}
		}
		// RFC 8414 Section 2: If present, protected_resources SHOULD include the resource
		if rfcModeEnabled(config.RFCMode) && prm.Resource != "" {
			if protectedResources, ok := obj["protected_resources"].([]any); ok && len(protectedResources) > 0 {
				if !containsString(protectedResources, prm.Resource) {
					findings = append(findings, newFinding("AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH", fmt.Sprintf("resource %q not in protected_resources", prm.Resource)))
				}
			}
		}
		// RFC 7517: Validate JWKS endpoint if present
		if rfcModeEnabled(config.RFCMode) {
			if jwksURI, ok := obj["jwks_uri"].(string); ok && jwksURI != "" {
				if urlFindings := validateURLString(jwksURI, "jwks_uri", config, false); len(urlFindings) > 0 {
					findings = append(findings, urlFindings...)
				}
				// RFC 7517 Section 5: JWKS MUST be a JSON object with a "keys" array
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
	}
	return findings, strings.TrimSpace(evidence.String()), result
}

func mcpInitializeAndListTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer, authRequired bool) (string, string, []finding) {
	var evidence strings.Builder
	findings := []finding{}

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
		return "FAIL", fmt.Sprintf("initialize error: %v", err), findings
	}
	fmt.Fprintf(&evidence, "initialize -> %d", initResp.StatusCode)
	if initPayload == nil {
		fmt.Fprint(&evidence, " (non-JSON response)")
	}
	if initPayload != nil && initPayload.Error != nil {
		fmt.Fprintf(&evidence, " (error: %s)", initPayload.Error.Message)
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		if authRequired {
			fmt.Fprint(&evidence, " (auth required)")
			return "SKIP", strings.TrimSpace(evidence.String()), findings
		}
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		findings = append(findings, newFinding("MCP_INITIALIZE_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings
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
		return "FAIL", strings.TrimSpace(evidence.String()), findings
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
			return "SKIP", strings.TrimSpace(evidence.String()), findings
		}
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings
	}
	if toolsResp.StatusCode != http.StatusOK || toolsPayload == nil || toolsPayload.Error != nil {
		findings = append(findings, newFinding("MCP_TOOLS_LIST_FAILED", strings.TrimSpace(evidence.String())))
		return "FAIL", strings.TrimSpace(evidence.String()), findings
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
	return status, strings.TrimSpace(evidence.String()), findings
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
	addTrace(trace, req, resp, config.Redact)

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
	addTrace(trace, req, resp, config.Redact)

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
