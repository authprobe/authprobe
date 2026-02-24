package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

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
//   - []Finding: RFC compliance findings for each issuer:
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
func fetchAuthServerMetadata(client *http.Client, config ScanConfig, prm prmResult, trace *[]TraceEntry, stdout io.Writer) ([]Finding, string, authServerMetadataResult, bool) {
	findings := []Finding{}
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
			result.AuthorizationEndpoints = append(result.AuthorizationEndpoints, authorizationEndpoint)
			if registrationEndpoint != "" {
				result.RegistrationEndpoints = append(result.RegistrationEndpoints, registrationEndpoint)
			}
			if deviceEndpoint, _ := obj["device_authorization_endpoint"].(string); deviceEndpoint != "" && result.DeviceAuthorizationEndpoint == "" {
				result.DeviceAuthorizationEndpoint = deviceEndpoint
			}
			if grants, ok := obj["grant_types_supported"].([]any); ok {
				for _, grant := range grants {
					if grantStr, ok := grant.(string); ok && grantStr != "" {
						result.GrantTypesSupported = append(result.GrantTypesSupported, grantStr)
					}
				}
			}
			if scopes, ok := obj["scopes_supported"].([]any); ok {
				for _, scope := range scopes {
					if scopeStr, ok := scope.(string); ok && scopeStr != "" {
						result.ScopesSupported = append(result.ScopesSupported, scopeStr)
					}
				}
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

func probeTokenEndpointReadiness(client *http.Client, config ScanConfig, tokenEndpoints []string, trace *[]TraceEntry, stdout io.Writer) ([]Finding, string) {
	findings := []Finding{}
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
func probeDCREndpoints(client *http.Client, config ScanConfig, registrationEndpoints []string, trace *[]TraceEntry, stdout io.Writer) ([]Finding, string) {
	findings := []Finding{}
	var evidence strings.Builder
	for _, endpoint := range registrationEndpoints {
		if endpoint == "" {
			continue
		}
		emptyResp, _, err := postDCRProbe(client, config, endpoint, map[string]any{}, trace, stdout, "Step 6: Dynamic client registration (empty probe)")
		if err != nil {
			fmt.Fprintf(&evidence, "%s -> error: %v\n", endpoint, err)
			continue
		}
		fmt.Fprintf(&evidence, "%s -> %d", endpoint, emptyResp.StatusCode)

		switch emptyResp.StatusCode {
		case http.StatusCreated, http.StatusOK:
			findings = append(findings, newFinding("DCR_ENDPOINT_OPEN", fmt.Sprintf("%s accepts unauthenticated registration", endpoint)))
			fmt.Fprint(&evidence, " (OPEN - no auth required)")

			findings = append(findings, testDCRInputValidation(client, config, endpoint, trace, stdout)...)
		case http.StatusUnauthorized, http.StatusForbidden:
			fmt.Fprint(&evidence, " (protected)")
		case http.StatusBadRequest:
			fmt.Fprint(&evidence, " (validates input)")
		default:
			fmt.Fprintf(&evidence, " (unexpected status)")
		}
		fmt.Fprintln(&evidence)
	}
	return findings, strings.TrimSpace(evidence.String())
}

func testDCRInputValidation(client *http.Client, config ScanConfig, endpoint string, trace *[]TraceEntry, stdout io.Writer) []Finding {
	findings := []Finding{}

	httpPayload := map[string]any{
		"redirect_uris": []string{"http://evil.example.com/callback"},
		"client_name":   "authprobe-test-http",
	}
	httpResp, _, err := postDCRProbe(client, config, endpoint, httpPayload, trace, stdout, "Step 6: Dynamic client registration (http redirect test)")
	if err == nil && (httpResp.StatusCode == http.StatusCreated || httpResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_HTTP_REDIRECT_ACCEPTED", "registration accepted http:// redirect URI"))
	}

	localhostPayload := map[string]any{
		"redirect_uris": []string{"http://localhost:8080/callback"},
		"client_name":   "authprobe-test-localhost",
	}
	localhostResp, _, err := postDCRProbe(client, config, endpoint, localhostPayload, trace, stdout, "Step 6: Dynamic client registration (localhost test)")
	if err == nil && (localhostResp.StatusCode == http.StatusCreated || localhostResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_LOCALHOST_REDIRECT_ACCEPTED", "registration accepted localhost redirect URI"))
	}

	dangerousPayload := map[string]any{
		"redirect_uris": []string{"javascript:alert(1)"},
		"client_name":   "authprobe-test-dangerous",
	}
	dangerousResp, _, err := postDCRProbe(client, config, endpoint, dangerousPayload, trace, stdout, "Step 6: Dynamic client registration (dangerous URI test)")
	if err == nil && (dangerousResp.StatusCode == http.StatusCreated || dangerousResp.StatusCode == http.StatusOK) {
		findings = append(findings, newFinding("DCR_DANGEROUS_URI_ACCEPTED", "registration accepted javascript: or file: URI scheme"))
	}

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

func postDCRProbe(client *http.Client, config ScanConfig, endpoint string, payload map[string]any, trace *[]TraceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
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
