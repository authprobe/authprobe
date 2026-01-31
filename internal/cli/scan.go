package cli

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
	Headers             []string
	Timeout             time.Duration
	Verbose             bool
	Explain             bool
	FailOn              string // Severity threshold for exit code 2: none, low, medium, high
	MCPMode             string
	RFCMode             string // Applies to all RFC checks: off, best-effort, strict
	AllowPrivateIssuers bool
	Insecure            bool // Skip TLS certificate verification (dev only)
	NoFollowRedirects   bool // Stop at first response, don't follow HTTP redirects
	JSONPath            string
	MDPath              string
	BundlePath          string
	OutputDir           string
}

type scanReport struct {
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
		if err := writeVerboseRequest(stdout, req); err != nil {
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
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return "", "", nil, "", false, err
		}
	}

	// Add this request/response pair to the trace for later analysis
	addTrace(trace, req, resp)

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
		if resp.StatusCode == http.StatusMethodNotAllowed {
			return "", resolvedTarget(resp, config.Target), findings, fmt.Sprintf("probe returned %d; continuing discovery", resp.StatusCode), true, nil
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
func fetchPRMMatrix(client *http.Client, config scanConfig, resourceMetadata string, resolvedTarget string, trace *[]traceEntry, stdout io.Writer) (prmResult, []finding, string, error) {
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
		if status == http.StatusNotFound && candidate.Source == "root" && !hasPathSuffix {
			findings = append(findings, newFinding("DISCOVERY_ROOT_WELLKNOWN_404", "root PRM endpoint returned 404"))
		}
		if status != http.StatusOK && reportFindings {
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

	return bestPRM, findings, strings.TrimSpace(evidence.String()), nil
}

type prmCandidate struct {
	URL    string
	Source string
}

type authServerMetadataResult struct {
	TokenEndpoints []string
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
	}
	return findings, strings.TrimSpace(evidence.String()), result
}

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

const maxMetadataRedirects = 5

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
			if err := writeVerboseRequest(stdout, req); err != nil {
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
			if err := writeVerboseResponse(stdout, resp); err != nil {
				return resp, body, err
			}
		}
		addTrace(trace, req, resp)
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

func mcpInitializeAndListTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer, authRequired bool) (string, string, []finding) {
	var evidence strings.Builder
	findings := []finding{}

	if !authRequired {
		findings = append(findings, checkInitializeOrdering(client, config, trace, stdout)...)
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
func checkInitializeOrdering(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) []finding {
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
	return []finding{newMCPFinding(config, "MCP_INITIALIZE_ORDERING_NOT_ENFORCED", fmt.Sprintf("pre-init tools/list status %d", resp.StatusCode))}
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
		if err := writeVerboseRequest(stdout, req); err != nil {
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
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return resp, body, err
		}
	}
	addTrace(trace, req, resp)
	return resp, body, nil
}
