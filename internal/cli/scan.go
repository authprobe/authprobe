package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type scanConfig struct {
	Target              string
	Profile             string
	Headers             []string
	Timeout             time.Duration
	Verbose             bool
	Explain             bool
	ShowTrace           bool
	FailOn              string
	RFC9728Mode         string
	RFC3986Mode         string
	RFC8414Mode         string
	RFC8707Mode         string
	RFC9207Mode         string
	RFC6750Mode         string
	RFC7517Mode         string
	RFC7519Mode         string
	RFC7636Mode         string
	RFC6749Mode         string
	RFC1918Mode         string
	RFC6890Mode         string
	RFC9110Mode         string
	AllowPrivateIssuers bool
	NoFollowRedirects   bool
	JSONPath            string
	MDPath              string
	BundlePath          string
	OutputDir           string
}

type scanReport struct {
	Target         string     `json:"target"`
	Profile        string     `json:"profile"`
	RFC9728Mode    string     `json:"rfc9728_mode"`
	RFC3986Mode    string     `json:"rfc3986_mode"`
	RFC8414Mode    string     `json:"rfc8414_mode"`
	RFC8707Mode    string     `json:"rfc8707_mode"`
	RFC9207Mode    string     `json:"rfc9207_mode"`
	RFC6750Mode    string     `json:"rfc6750_mode"`
	RFC7517Mode    string     `json:"rfc7517_mode"`
	RFC7519Mode    string     `json:"rfc7519_mode"`
	RFC7636Mode    string     `json:"rfc7636_mode"`
	RFC6749Mode    string     `json:"rfc6749_mode"`
	RFC1918Mode    string     `json:"rfc1918_mode"`
	RFC6890Mode    string     `json:"rfc6890_mode"`
	RFC9110Mode    string     `json:"rfc9110_mode"`
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

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
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

func runScanFunnel(config scanConfig, stdout io.Writer) (scanReport, scanSummary, error) {
	report := scanReport{
		Target:      config.Target,
		Profile:     config.Profile,
		RFC9728Mode: config.RFC9728Mode,
		RFC3986Mode: config.RFC3986Mode,
		RFC8414Mode: config.RFC8414Mode,
		RFC8707Mode: config.RFC8707Mode,
		RFC9207Mode: config.RFC9207Mode,
		RFC6750Mode: config.RFC6750Mode,
		RFC7517Mode: config.RFC7517Mode,
		RFC7519Mode: config.RFC7519Mode,
		RFC7636Mode: config.RFC7636Mode,
		RFC6749Mode: config.RFC6749Mode,
		RFC1918Mode: config.RFC1918Mode,
		RFC6890Mode: config.RFC6890Mode,
		RFC9110Mode: config.RFC9110Mode,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	client := &http.Client{Timeout: config.Timeout}
	if config.NoFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	trace := []traceEntry{}
	findings := []finding{}
	steps := []scanStep{}

	step1 := scanStep{ID: 1, Name: "MCP probe (401 + WWW-Authenticate)"}
	resourceMetadata, step1Findings, step1Evidence, authRequired, err := probeMCP(client, config, &trace, stdout)
	if err != nil {
		return report, scanSummary{}, err
	}
	step1Trace := append([]traceEntry(nil), trace...)
	findings = append(findings, step1Findings...)
	step1.Status = statusFromFindings(step1Findings, authRequired)
	step1.Detail = step1Evidence
	steps = append(steps, step1)

	step2 := scanStep{ID: 2, Name: "MCP initialize + tools/list"}
	step2Status, step2Detail, step2Findings := mcpInitializeAndListTools(client, config, &trace, stdout, authRequired)
	step2.Status = step2Status
	step2.Detail = step2Detail
	findings = append(findings, step2Findings...)
	steps = append(steps, step2)

	if !authRequired {
		steps = append(steps, scanStep{ID: 3, Name: "PRM fetch matrix", Status: "SKIP", Detail: "auth not required"})
		steps = append(steps, scanStep{ID: 4, Name: "Auth server metadata", Status: "SKIP", Detail: "auth not required"})
		steps = append(steps, scanStep{ID: 5, Name: "Token endpoint readiness (heuristics)", Status: "SKIP", Detail: "auth not required"})
		report.Steps = steps
		report.Findings = findings
		report.PrimaryFinding = choosePrimaryFinding(findings)
		summary := buildSummary(report)
		if config.Explain {
			explanation := buildScanExplanation(config, resourceMetadata, prmResult{}, authRequired)
			if explanation != "" {
				summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + explanation + "\n"
			}
		}
		if config.ShowTrace {
			traceView := buildProbeTraceASCII(step1Trace, config.Target, resourceMetadata, step1Evidence, authRequired)
			if traceView != "" {
				summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + traceView + "\n"
			}
		}
		summary.Trace = trace
		if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
			return report, scanSummary{}, err
		}
		return report, summary, nil
	}

	step3 := scanStep{ID: 3, Name: "PRM fetch matrix"}
	prmResult, step3Findings, step3Evidence, err := fetchPRMMatrix(client, config, resourceMetadata, &trace, stdout)
	if err != nil {
		return report, scanSummary{}, err
	}
	findings = append(findings, step3Findings...)
	step3.Status = statusFromFindings(step3Findings, true)
	step3.Detail = step3Evidence
	steps = append(steps, step3)

	step4 := scanStep{ID: 4, Name: "Auth server metadata"}
	authMetadata := authServerMetadataResult{}
	if len(prmResult.AuthorizationServers) == 0 {
		step4.Status = "SKIP"
		step4.Detail = "no authorization_servers in PRM"
	} else {
		step4Findings, step4Evidence, metadata := fetchAuthServerMetadata(client, config, prmResult, &trace, stdout)
		authMetadata = metadata
		findings = append(findings, step4Findings...)
		step4.Status = statusFromFindings(step4Findings, true)
		step4.Detail = step4Evidence
	}
	steps = append(steps, step4)

	step5 := scanStep{ID: 5, Name: "Token endpoint readiness (heuristics)"}
	if len(authMetadata.TokenEndpoints) == 0 {
		step5.Status = "SKIP"
		step5.Detail = "no token_endpoint in metadata"
	} else {
		step5Findings, step5Evidence := probeTokenEndpointReadiness(client, config, authMetadata.TokenEndpoints, &trace, stdout)
		findings = append(findings, step5Findings...)
		step5.Status = statusFromFindings(step5Findings, true)
		step5.Detail = step5Evidence
	}
	steps = append(steps, step5)

	report.Steps = steps
	report.Findings = findings
	report.PrimaryFinding = choosePrimaryFinding(findings)
	summary := buildSummary(report)
	if config.Explain {
		explanation := buildScanExplanation(config, resourceMetadata, prmResult, authRequired)
		if explanation != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + explanation + "\n"
		}
	}
	if config.ShowTrace {
		traceView := buildProbeTraceASCII(step1Trace, config.Target, resourceMetadata, step1Evidence, authRequired)
		if traceView != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + traceView + "\n"
		}
	}
	summary.Trace = trace
	if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
		return report, scanSummary{}, err
	}
	return report, summary, nil
}

type prmResult struct {
	AuthorizationServers []string
	Resource             string
}

func probeMCP(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) (string, []finding, string, bool, error) {
	// Create a GET request to the target MCP endpoint
	req, err := http.NewRequest(http.MethodGet, config.Target, nil)
	if err != nil {
		return "", nil, "", false, err
	}
	req.Header.Set("Accept", "text/event-stream")
	// Apply any custom headers specified by the user
	if err := applyHeaders(req, config.Headers); err != nil {
		return "", nil, "", false, err
	}
	// If verbose mode is enabled, write the request details to stdout
	if config.Verbose {
		if err := writeVerboseRequest(stdout, req); err != nil {
			return "", nil, "", false, err
		}
	}
	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			evidence := "probe timed out waiting for response headers; MCP spec requires SSE headers or a 405 for GET Accept: text/event-stream"
			return "", []finding{newFinding("MCP_PROBE_TIMEOUT", evidence)}, evidence, true, nil
		}
		return "", nil, "", false, err
	}
	defer resp.Body.Close()
	_, _ = drainBody(&resp.Body)

	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return "", nil, "", false, err
		}
	}

	// Add this request/response pair to the trace for later analysis
	addTrace(trace, req, resp)

	if resp.StatusCode != http.StatusUnauthorized {
		if resp.StatusCode == http.StatusMethodNotAllowed {
			return "", nil, fmt.Sprintf("probe returned %d; continuing discovery", resp.StatusCode), true, nil
		}
		return "", nil, "auth not required", false, nil
	}

	resourceMetadata, ok := extractResourceMetadata(resp.Header.Values("WWW-Authenticate"))
	if !ok {
		// Missing resource_metadata is a finding - the server requires auth but doesn't provide discovery info
		return "", []finding{newFinding("DISCOVERY_NO_WWW_AUTHENTICATE", "missing resource_metadata in WWW-Authenticate")}, "missing WWW-Authenticate/resource_metadata", true, nil
	}
	// Success: we have a 401 with resource_metadata, indicating proper MCP OAuth discovery
	return resourceMetadata, nil, "401 with resource_metadata", true, nil
}

func fetchPRMMatrix(client *http.Client, config scanConfig, resourceMetadata string, trace *[]traceEntry, stdout io.Writer) (prmResult, []finding, string, error) {
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		return prmResult{}, nil, "", err
	}

	findings := []finding{}
	if rfcModeEnabled(config.RFC3986Mode) {
		if urlFindings := validateURLString(config.Target, "resource", config, false); len(urlFindings) > 0 {
			findings = append(findings, urlFindings...)
		}
		if parsedTarget, err := url.Parse(config.Target); err == nil && parsedTarget.Fragment != "" {
			if rfcModeEnabled(config.RFC8707Mode) {
				findings = append(findings, newFinding("RESOURCE_FRAGMENT_FORBIDDEN", fmt.Sprintf("resource %q includes fragment (RFC 8707)", config.Target)))
			}
		}
	}
	var evidence strings.Builder
	var bestPRM prmResult
	pathSuffixSeen := false
	pathSuffixOK := false
	for _, candidate := range candidates {
		reportFindings := config.RFC9728Mode != "off"
		if hasPathSuffix {
			reportFindings = candidate.Source == "path-suffix"
		}
		if candidate.Source == "path-suffix" {
			pathSuffixSeen = true
		}
		if rfcModeEnabled(config.RFC3986Mode) {
			if urlFindings := validateURLString(candidate.URL, fmt.Sprintf("prm(%s)", candidate.Source), config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		resp, payload, err := fetchJSON(client, config, candidate.URL, trace, stdout)
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
		if reportFindings {
			contentType := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				findings = append(findings, newFinding("PRM_CONTENT_TYPE_NOT_JSON", fmt.Sprintf("%s content-type %q", candidate.Source, contentType)))
				continue
			}
		}
		obj, ok := payload.(map[string]any)
		if !ok {
			if reportFindings {
				findings = append(findings, newFinding("PRM_NOT_JSON_OBJECT", fmt.Sprintf("%s response not JSON object", candidate.Source)))
			}
			continue
		}
		prm := prmResult{}
		if resourceValue, ok := obj["resource"].(string); ok {
			prm.Resource = resourceValue
			if reportFindings && !hasPathSuffix && resourceValue == "" {
				findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource empty", candidate.Source)))
			}
		} else if reportFindings && !hasPathSuffix {
			findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource missing", candidate.Source)))
		}
		if reportFindings {
			if prm.Resource != "" && prm.Resource != config.Target {
				findings = append(findings, newFinding("PRM_RESOURCE_MISMATCH", fmt.Sprintf("%s resource %q != %q", candidate.Source, prm.Resource, config.Target)))
			}
			if rfcModeEnabled(config.RFC8707Mode) {
				if parsedResource, err := url.Parse(prm.Resource); err == nil && parsedResource.Fragment != "" {
					findings = append(findings, newFinding("RESOURCE_FRAGMENT_FORBIDDEN", fmt.Sprintf("%s resource %q includes fragment (RFC 8707)", candidate.Source, prm.Resource)))
				}
			}
		}
		if servers, ok := obj["authorization_servers"].([]any); ok {
			for _, entry := range servers {
				if value, ok := entry.(string); ok && value != "" {
					prm.AuthorizationServers = append(prm.AuthorizationServers, value)
				}
			}
		}
		if len(prm.AuthorizationServers) == 0 && reportFindings && !hasPathSuffix {
			findings = append(findings, newFinding("PRM_MISSING_AUTHORIZATION_SERVERS", fmt.Sprintf("%s authorization_servers missing", candidate.Source)))
		}
		if reportFindings {
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
			if candidate.Source == "path-suffix" && prm.Resource == config.Target {
				bestPRM = prm
				pathSuffixOK = true
			}
		} else if bestPRM.AuthorizationServers == nil && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
			bestPRM = prm
		}
	}
	if hasPathSuffix && (pathSuffixSeen && !pathSuffixOK) {
		findings = append(findings, newFinding("PRM_WELLKNOWN_PATH_SUFFIX_MISSING", "path-suffix PRM endpoint missing or mismatched"))
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

func fetchAuthServerMetadata(client *http.Client, config scanConfig, prm prmResult, trace *[]traceEntry, stdout io.Writer) ([]finding, string, authServerMetadataResult) {
	findings := []finding{}
	var evidence strings.Builder
	result := authServerMetadataResult{}
	for _, issuer := range prm.AuthorizationServers {
		if issuer == "" {
			continue
		}
		if rfcModeEnabled(config.RFC3986Mode) {
			if urlFindings := validateURLString(issuer, "issuer", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFC8414Mode) {
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
		metadataURL := buildMetadataURL(issuer)
		resp, payload, err := fetchJSON(client, config, metadataURL, trace, stdout)
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
		if resp.StatusCode != http.StatusOK {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s status %d", issuer, resp.StatusCode)))
			continue
		}
		if rfcModeEnabled(config.RFC8414Mode) {
			contentType := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				findings = append(findings, newFinding("AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON", fmt.Sprintf("%s content-type %q", issuer, contentType)))
				continue
			}
		}
		obj, ok := payload.(map[string]any)
		if !ok {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s response not JSON object", issuer)))
			continue
		}
		if rfcModeEnabled(config.RFC8414Mode) {
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
		authorizationEndpoint, ok := obj["authorization_endpoint"].(string)
		if !ok || authorizationEndpoint == "" {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing authorization_endpoint", issuer)))
			continue
		}
		tokenEndpoint, ok := obj["token_endpoint"].(string)
		if !ok || tokenEndpoint == "" {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing token_endpoint", issuer)))
			continue
		}
		if rfcModeEnabled(config.RFC3986Mode) {
			if urlFindings := validateURLString(authorizationEndpoint, "authorization_endpoint", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFC3986Mode) {
			if urlFindings := validateURLString(tokenEndpoint, "token_endpoint", config, false); len(urlFindings) > 0 {
				findings = append(findings, urlFindings...)
			}
		}
		if rfcModeEnabled(config.RFC8414Mode) {
			parsedIssuer, err := url.Parse(issuer)
			if err == nil {
				issuerHost := parsedIssuer.Hostname()
				if issuerHost != "" {
					checkEndpointHostMismatch(&findings, authorizationEndpoint, issuerHost, "authorization_endpoint")
					checkEndpointHostMismatch(&findings, tokenEndpoint, issuerHost, "token_endpoint")
				}
			}
		}
		if rfcModeEnabled(config.RFC7636Mode) {
			if methods, ok := obj["code_challenge_methods_supported"].([]any); ok {
				if !containsString(methods, "S256") {
					findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing S256", issuer)))
				}
			} else {
				findings = append(findings, newFinding("AUTH_SERVER_PKCE_S256_MISSING", fmt.Sprintf("%s missing code_challenge_methods_supported", issuer)))
			}
		}
		if rfcModeEnabled(config.RFC8707Mode) && prm.Resource != "" {
			if protectedResources, ok := obj["protected_resources"].([]any); ok && len(protectedResources) > 0 {
				if !containsString(protectedResources, prm.Resource) {
					findings = append(findings, newFinding("AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH", fmt.Sprintf("resource %q not in protected_resources", prm.Resource)))
				}
			}
		}
		if rfcModeEnabled(config.RFC7517Mode) {
			if jwksURI, ok := obj["jwks_uri"].(string); ok && jwksURI != "" {
				if urlFindings := validateURLString(jwksURI, "jwks_uri", config, false); len(urlFindings) > 0 {
					findings = append(findings, urlFindings...)
				}
				jwksResp, jwksPayload, err := fetchJSON(client, config, jwksURI, trace, stdout)
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

func fetchJSON(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer) (*http.Response, any, error) {
	resp, body, err := fetchWithRedirects(client, config, target, trace, stdout)
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

func fetchWithRedirects(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer) (*http.Response, []byte, error) {
	current := target
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
		if rfcModeEnabled(config.RFC9110Mode) {
			if !next.IsAbs() {
				return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("redirect Location not absolute: %q", location)}
			}
			if rfcModeEnabled(config.RFC3986Mode) && !isHTTPSURL(next) {
				if rfcModeStrict(config.RFC9110Mode) {
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

	initParams := map[string]any{
		"protocolVersion": "2024-11-05",
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

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, trace, stdout)
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

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, trace, stdout)
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

	toolNames := extractToolNames(toolsPayload.Result)
	if len(toolNames) == 0 {
		fmt.Fprint(&evidence, " (tools: none)")
	} else {
		fmt.Fprintf(&evidence, " (tools: %s)", strings.Join(toolNames, ", "))
	}

	return "PASS", strings.TrimSpace(evidence.String()), findings
}

func fetchMCPTools(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) ([]mcpToolDetail, error) {
	initParams := map[string]any{
		"protocolVersion": "2024-11-05",
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

	initResp, _, initPayload, err := postJSONRPC(client, config, config.Target, initRequest, trace, stdout)
	if err != nil {
		return nil, err
	}
	if initResp.StatusCode == http.StatusUnauthorized || initResp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("initialize unauthorized: %d", initResp.StatusCode)
	}
	if initResp.StatusCode != http.StatusOK || initPayload == nil || initPayload.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", formatJSONRPCError(initResp, initPayload))
	}

	toolsRequest := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	toolsResp, _, toolsPayload, err := postJSONRPC(client, config, config.Target, toolsRequest, trace, stdout)
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

func formatJSONRPCError(resp *http.Response, payload *jsonRPCResponse) string {
	if payload != nil && payload.Error != nil {
		return fmt.Sprintf("%d (%s)", resp.StatusCode, payload.Error.Message)
	}
	return fmt.Sprintf("%d", resp.StatusCode)
}

func postJSONRPC(client *http.Client, config scanConfig, target string, payload jsonRPCRequest, trace *[]traceEntry, stdout io.Writer) (*http.Response, []byte, *jsonRPCResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if err := applyHeaders(req, config.Headers); err != nil {
		return nil, nil, nil, err
	}
	if config.Verbose {
		if err := writeVerboseRequest(stdout, req); err != nil {
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
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return resp, respBody, nil, err
		}
	}
	addTrace(trace, req, resp)

	var parsed jsonRPCResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			return resp, respBody, &parsed, nil
		}
	}
	return resp, respBody, nil, nil
}

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

func probeTokenEndpointReadiness(client *http.Client, config scanConfig, tokenEndpoints []string, trace *[]traceEntry, stdout io.Writer) ([]finding, string) {
	findings := []finding{}
	var evidence strings.Builder
	for _, endpoint := range tokenEndpoints {
		if endpoint == "" {
			continue
		}
		resp, body, err := postTokenProbe(client, config, endpoint, trace, stdout)
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

func postTokenProbe(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer) (*http.Response, []byte, error) {
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

func applySafeHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := parseHeader(header)
		if err != nil {
			return err
		}
		lower := strings.ToLower(key)
		switch lower {
		case "authorization", "cookie", "proxy-authorization":
			continue
		case "host":
			req.Host = value
			continue
		}
		req.Header.Add(key, value)
	}
	return nil
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

type fetchPolicyError struct {
	Code   string
	Detail string
}

func (e fetchPolicyError) Error() string {
	return e.Detail
}

func rfcModeEnabled(mode string) bool {
	return mode != "off"
}

func rfcModeStrict(mode string) bool {
	return strings.EqualFold(mode, "strict")
}

func isHTTPSURL(parsed *url.URL) bool {
	return parsed != nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != ""
}

func isRedirectStatus(status int) bool {
	return status >= 300 && status <= 399
}

func validateFetchTarget(config scanConfig, target string) error {
	if config.AllowPrivateIssuers {
		return nil
	}
	if !rfcModeEnabled(config.RFC1918Mode) && !rfcModeEnabled(config.RFC6890Mode) {
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

func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func validateURLString(raw string, label string, config scanConfig, allowRelative bool) []finding {
	if !rfcModeEnabled(config.RFC3986Mode) {
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

func buildMetadataURL(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return issuer
	}
	if strings.Contains(parsed.Path, "/.well-known/") {
		return parsed.String()
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	parsed.Path = strings.TrimSuffix(path, "/") + "/.well-known/oauth-authorization-server"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
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

func statusFromFindings(findings []finding, authRequired bool) string {
	if !authRequired {
		return "SKIP"
	}
	if len(findings) == 0 {
		return "PASS"
	}
	return "FAIL"
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
	case "MCP_INITIALIZE_FAILED":
		return "MCP servers should accept the initialize JSON-RPC request and return a valid JSON response per the MCP specification."
	case "MCP_TOOLS_LIST_FAILED":
		return "MCP servers should respond to tools/list with a valid JSON result enumerating tools per the MCP specification."
	case "MCP_PROBE_TIMEOUT":
		return "MCP spec: \"The server MUST either return Content-Type: text/event-stream for GET requests or else return 405 Method Not Allowed.\" Timing out before headers indicates non-compliance."
	case "METADATA_SSRF_BLOCKED":
		return "Metadata fetch blocked by local SSRF protections; issuer metadata should be on a permitted host."
	case "METADATA_REDIRECT_BLOCKED":
		return "Metadata fetch redirected to a disallowed location and was blocked by policy."
	case "METADATA_REDIRECT_LIMIT":
		return "Metadata fetch exceeded the redirect limit before reaching the issuer metadata."
	default:
		return ""
	}
}

func findingSeverity(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE",
		"DISCOVERY_ROOT_WELLKNOWN_404",
		"PRM_MISSING_AUTHORIZATION_SERVERS",
		"PRM_RESOURCE_MISMATCH",
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
		"MCP_PROBE_TIMEOUT":
		return "high"
	case "PRM_WELLKNOWN_PATH_SUFFIX_MISSING",
		"AUTH_SERVER_ISSUER_PRIVATE_BLOCKED",
		"TOKEN_RESPONSE_NOT_JSON_RISK",
		"TOKEN_HTTP200_ERROR_PAYLOAD_RISK":
		return "medium"
	case "AUTH_SERVER_ENDPOINT_HOST_MISMATCH",
		"AUTH_SERVER_PKCE_S256_MISSING",
		"AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH":
		return "low"
	default:
		return "low"
	}
}

func findingConfidence(code string) float64 {
	switch code {
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		// 0.92: Strong inference (0.85-0.95 range per PRD)
		// A 404 on the root PRM endpoint is a strong indicator of misconfiguration,
		// but not definitive because:
		// - The server might implement path-suffix endpoints instead (RFC 9728 allows this)
		// - The endpoint might be at a different location
		// - Some servers may intentionally not expose the root endpoint
		return 0.92
	case "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		// 0.85: Strong inference (0.85-0.95 range per PRD)
		// Blocking private issuers is a safety/policy decision, not a technical failure.
		// Lower confidence because:
		// - Private issuers might be intentional (internal services, localhost development)
		// - It's a security measure, not necessarily indicating a problem
		// - The user can override with --allow-private-issuers if needed
		return 0.85
	case "TOKEN_RESPONSE_NOT_JSON_RISK",
		"TOKEN_HTTP200_ERROR_PAYLOAD_RISK":
		// 0.7: Heuristic risk pattern (0.60-0.80 range per PRD)
		// These are behavioral heuristics, not definitive failures:
		// - Token endpoints may legitimately use form-encoded responses (RFC 6749 allows this)
		// - HTTP 200 with error payloads might be a valid pattern for some servers
		// - These are "RISK" findings - warnings about potential issues, not certain problems
		// Lower confidence reflects that these are inferred from behavior patterns
		return 0.7
	case "MCP_PROBE_TIMEOUT":
		// 0.8: Heuristic risk pattern (0.60-0.80 range per PRD)
		// Timeouts have lower confidence because they could indicate:
		// - Transient network issues (not a configuration problem)
		// - Temporary server unavailability
		// - Actual MCP configuration issues (SSE headers not sent, wrong endpoint)
		// The uncertainty between transient vs. persistent issues warrants lower confidence
		return 0.8
	default:
		// 1.00: Direct deterministic evidence (per PRD)
		// Most findings have full confidence because they're based on:
		// - Direct HTTP status code mismatches
		// - Missing required fields in JSON responses
		// - Exact value mismatches (e.g., resource URL)
		// - Invalid content types or formats
		// These are objective, verifiable facts with no ambiguity
		return 1.00
	}
}

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

func buildSummary(report scanReport) scanSummary {
	var out strings.Builder
	fmt.Fprintf(&out, "Scanning: %s\n", report.Target)
	fmt.Fprintln(&out, "Funnel")
	maxLabel := 0
	maxStatus := 0
	for _, step := range report.Steps {
		label := fmt.Sprintf("  [%d] %s", step.ID, step.Name)
		if len(label) > maxLabel {
			maxLabel = len(label)
		}
		if len(step.Status) > maxStatus {
			maxStatus = len(step.Status)
		}
	}
	for _, step := range report.Steps {
		label := fmt.Sprintf("  [%d] %s", step.ID, step.Name)
		fmt.Fprintf(&out, "%-*s  %-*s\n", maxLabel, label, maxStatus, step.Status)
		if strings.TrimSpace(step.Detail) != "" {
			detailLines := summarizeStepDetail(step.Detail, 6, 96-6)
			for _, line := range detailLines {
				fmt.Fprintf(&out, "      %s\n", line)
			}
		}
	}
	if report.PrimaryFinding.Code != "" {
		fmt.Fprintf(&out, "\nPrimary finding (%s): %s (confidence %.2f)\n", strings.ToUpper(report.PrimaryFinding.Severity), report.PrimaryFinding.Code, report.PrimaryFinding.Confidence)
		if len(report.PrimaryFinding.Evidence) > 0 {
			fmt.Fprintln(&out, "  Evidence:")
			for _, line := range report.PrimaryFinding.Evidence {
				for _, wrapped := range wrapText(line, 96-6) {
					fmt.Fprintf(&out, "      %s\n", wrapped)
				}
			}
		}
	}
	stdout := out.String()

	md := renderMarkdown(report)
	jsonBytes, _ := json.MarshalIndent(report, "", "  ")

	return scanSummary{Stdout: stdout, MD: md, JSON: jsonBytes}
}

func buildProbeTraceASCII(entries []traceEntry, target string, resourceMetadata string, evidence string, authRequired bool) string {
	if len(entries) == 0 {
		return ""
	}
	entry := entries[0]
	for _, candidate := range entries {
		if candidate.Method == http.MethodGet && candidate.URL == target {
			entry = candidate
			break
		}
	}
	var out strings.Builder
	fmt.Fprintln(&out, "Trace (step 1: MCP probe)")
	fmt.Fprintf(&out, "  --> %s %s\n", entry.Method, entry.URL)
	statusText := http.StatusText(entry.Status)
	if statusText == "" {
		statusText = "unknown"
	}
	fmt.Fprintf(&out, "  <-- %d %s\n", entry.Status, statusText)
	if value, ok := findHeader(entry.Headers, "WWW-Authenticate"); ok {
		fmt.Fprintf(&out, "      WWW-Authenticate: %s\n", value)
	}
	if resourceMetadata != "" {
		fmt.Fprintf(&out, "      resource_metadata: %s\n", resourceMetadata)
	} else {
		fmt.Fprintln(&out, "      resource_metadata: (none)")
	}
	if evidence != "" {
		fmt.Fprintf(&out, "      outcome: %s\n", evidence)
	}
	fmt.Fprintf(&out, "      auth_required: %t\n", authRequired)
	return strings.TrimSpace(out.String())
}

func findHeader(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func summarizeStepDetail(detail string, maxTools int, maxWidth int) []string {
	lines := strings.Split(strings.TrimSpace(detail), "\n")
	var summarized []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = summarizeToolsList(line, maxTools)
		summarized = append(summarized, wrapText(line, maxWidth)...)
	}
	if len(summarized) == 0 {
		return []string{""}
	}
	return summarized
}

func summarizeToolsList(detail string, maxTools int) string {
	const marker = "tools:"
	start := strings.Index(detail, marker)
	if start == -1 {
		return detail
	}
	start += len(marker)
	rest := detail[start:]
	end := strings.Index(rest, ")")
	if end == -1 {
		return detail
	}
	list := strings.TrimSpace(rest[:end])
	if list == "" {
		return detail
	}
	tools := strings.Split(list, ",")
	for i := range tools {
		tools[i] = strings.TrimSpace(tools[i])
	}
	if len(tools) <= maxTools {
		return detail
	}
	compact := strings.Join(tools[:maxTools], ", ")
	compact = fmt.Sprintf("%s, +%d more", compact, len(tools)-maxTools)
	prefix := strings.TrimRight(detail[:start], " ")
	suffix := rest[end:]
	return fmt.Sprintf("%s %s%s", prefix, compact, suffix)
}

func wrapText(text string, width int) []string {
	if width <= 0 || len(text) <= width {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}
	var lines []string
	var current strings.Builder
	for _, word := range words {
		if current.Len() == 0 {
			current.WriteString(word)
			continue
		}
		if current.Len()+1+len(word) > width {
			lines = append(lines, current.String())
			current.Reset()
			current.WriteString(word)
			continue
		}
		current.WriteByte(' ')
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func buildScanExplanation(config scanConfig, resourceMetadata string, prmResult prmResult, authRequired bool) string {
	var out strings.Builder
	fmt.Fprintln(&out, "Explain (RFC 9728 rationale)")
	if !authRequired {
		fmt.Fprintln(&out, "1) MCP probe")
		fmt.Fprintln(&out, "- AuthProbe did not receive a 401 response that indicates authentication is required, so RFC 9728 PRM discovery is skipped.")
		return out.String()
	}

	fmt.Fprintln(&out, "1) MCP probe")
	fmt.Fprintf(&out, "- AuthProbe sends an unauthenticated GET to %s.\n", config.Target)
	fmt.Fprintln(&out, "- RFC 9728 discovery hinges on a 401 with WWW-Authenticate that includes resource_metadata.")
	if resourceMetadata != "" {
		fmt.Fprintf(&out, "- resource_metadata hint: %s\n", resourceMetadata)
	} else {
		fmt.Fprintln(&out, "- resource_metadata hint: (none)")
	}

	fmt.Fprintln(&out, "\n2) MCP initialize + tools/list")
	fmt.Fprintln(&out, "- AuthProbe sends an MCP initialize request followed by tools/list to enumerate server tools.")

	fmt.Fprintln(&out, "\n3) Protected Resource Metadata (PRM) discovery")
	fmt.Fprintln(&out, "- RFC 9728 defines PRM URLs by inserting /.well-known/oauth-protected-resource between the host and path.")
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		fmt.Fprintf(&out, "- Unable to build PRM candidates: %v\n", err)
	} else {
		for _, candidate := range candidates {
			fmt.Fprintf(&out, "- %s (%s)\n", candidate.URL, candidate.Source)
		}
		if hasPathSuffix {
			fmt.Fprintln(&out, "- Because the resource has a path, the path-suffix PRM endpoint is required by RFC 9728.")
		}
	}
	fmt.Fprintln(&out, "- PRM responses must be JSON objects with a resource that exactly matches the target URL.")
	fmt.Fprintln(&out, "- authorization_servers is required for OAuth discovery; it lists issuer URLs.")

	fmt.Fprintln(&out, "\n4) Authorization server metadata")
	if len(prmResult.AuthorizationServers) == 0 {
		fmt.Fprintln(&out, "- No authorization_servers found in PRM, so AuthProbe skips metadata fetches.")
	} else {
		fmt.Fprintln(&out, "- For each issuer, AuthProbe fetches <issuer>/.well-known/oauth-authorization-server (RFC 8414).")
		for _, issuer := range prmResult.AuthorizationServers {
			metadataURL := buildMetadataURL(issuer)
			fmt.Fprintf(&out, "- issuer: %s\n", issuer)
			fmt.Fprintf(&out, "- metadata: %s\n", metadataURL)
		}
	}

	fmt.Fprintln(&out, "\n5) Token endpoint readiness (heuristics)")
	fmt.Fprintln(&out, "- AuthProbe sends a safe, invalid grant request to the token endpoint to observe error response behavior.")
	fmt.Fprintln(&out, "- It flags non-JSON responses or HTTP 200 responses that still contain error payloads.")

	return out.String()
}

func renderMarkdown(report scanReport) string {
	var md strings.Builder
	fmt.Fprintf(&md, "# AuthProbe report\n\n")
	fmt.Fprintf(&md, "Scanning: %s\n\n", report.Target)
	fmt.Fprintf(&md, "- Target: %s\n", report.Target)
	fmt.Fprintf(&md, "- Profile: %s\n", report.Profile)
	fmt.Fprintf(&md, "- RFC9728: %s\n", report.RFC9728Mode)
	fmt.Fprintf(&md, "- RFC3986: %s\n", report.RFC3986Mode)
	fmt.Fprintf(&md, "- RFC8414: %s\n", report.RFC8414Mode)
	fmt.Fprintf(&md, "- RFC8707: %s\n", report.RFC8707Mode)
	fmt.Fprintf(&md, "- RFC9207: %s\n", report.RFC9207Mode)
	fmt.Fprintf(&md, "- RFC6750: %s\n", report.RFC6750Mode)
	fmt.Fprintf(&md, "- RFC7517: %s\n", report.RFC7517Mode)
	fmt.Fprintf(&md, "- RFC7519: %s\n", report.RFC7519Mode)
	fmt.Fprintf(&md, "- RFC7636: %s\n", report.RFC7636Mode)
	fmt.Fprintf(&md, "- RFC6749: %s\n", report.RFC6749Mode)
	fmt.Fprintf(&md, "- RFC1918: %s\n", report.RFC1918Mode)
	fmt.Fprintf(&md, "- RFC6890: %s\n", report.RFC6890Mode)
	fmt.Fprintf(&md, "- RFC9110: %s\n", report.RFC9110Mode)
	fmt.Fprintf(&md, "- Timestamp: %s\n\n", report.Timestamp)
	fmt.Fprintf(&md, "## Funnel\n\n")
	for _, step := range report.Steps {
		fmt.Fprintf(&md, "- [%d] %s: **%s**", step.ID, step.Name, step.Status)
		if step.Detail != "" {
			fmt.Fprintf(&md, " (%s)", step.Detail)
		}
		fmt.Fprintln(&md)
	}
	if report.PrimaryFinding.Code != "" {
		fmt.Fprintf(&md, "\n## Primary finding\n\n")
		fmt.Fprintf(&md, "- Code: %s\n", report.PrimaryFinding.Code)
		fmt.Fprintf(&md, "- Severity: %s\n", report.PrimaryFinding.Severity)
		fmt.Fprintf(&md, "- Confidence: %.2f\n", report.PrimaryFinding.Confidence)
		if len(report.PrimaryFinding.Evidence) > 0 {
			fmt.Fprintf(&md, "- Evidence:\n")
			for _, line := range report.PrimaryFinding.Evidence {
				fmt.Fprintf(&md, "  - %s\n", line)
			}
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintf(&md, "\n## All findings\n\n")
		for _, item := range report.Findings {
			fmt.Fprintf(&md, "- %s (%s, %.2f)\n", item.Code, item.Severity, item.Confidence)
			for _, line := range item.Evidence {
				fmt.Fprintf(&md, "  - %s\n", line)
			}
		}
	}
	return md.String()
}

func writeOutputs(report scanReport, summary scanSummary, config scanConfig) error {
	outputDir := config.OutputDir
	jsonPath := resolveOutputPath(config.JSONPath, outputDir)
	mdPath := resolveOutputPath(config.MDPath, outputDir)
	bundlePath := resolveOutputPath(config.BundlePath, outputDir)

	if config.JSONPath == "-" {
		if _, err := os.Stdout.Write(summary.JSON); err != nil {
			return err
		}
	} else if jsonPath != "" {
		if err := ensureParentDir(jsonPath); err != nil {
			return err
		}
		if err := os.WriteFile(jsonPath, summary.JSON, 0o644); err != nil {
			return err
		}
	}
	if mdPath != "" {
		if err := ensureParentDir(mdPath); err != nil {
			return err
		}
		if err := os.WriteFile(mdPath, []byte(summary.MD), 0o644); err != nil {
			return err
		}
	}
	if bundlePath != "" {
		if err := writeBundle(bundlePath, summary); err != nil {
			return err
		}
	}
	return nil
}

func resolveOutputPath(path string, dir string) string {
	if path == "" {
		return ""
	}
	if dir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func writeBundle(path string, summary scanSummary) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	if err := writeZipFile(zipWriter, "report.json", summary.JSON); err != nil {
		return err
	}
	if err := writeZipFile(zipWriter, "report.md", []byte(summary.MD)); err != nil {
		return err
	}
	traceBytes := buildTraceJSONL(summary.Trace)
	if err := writeZipFile(zipWriter, "trace.jsonl", traceBytes); err != nil {
		return err
	}
	meta := map[string]string{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeZipFile(zipWriter, "meta.json", metaBytes); err != nil {
		return err
	}
	return nil
}

func writeZipFile(zipWriter *zip.Writer, name string, payload []byte) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(payload)
	return err
}

func addTrace(trace *[]traceEntry, req *http.Request, resp *http.Response) {
	headers := map[string]string{}
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	*trace = append(*trace, traceEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Method:    req.Method,
		URL:       req.URL.String(),
		Status:    resp.StatusCode,
		Headers:   headers,
	})
}

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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildTraceJSONL(entries []traceEntry) []byte {
	var buffer bytes.Buffer
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
