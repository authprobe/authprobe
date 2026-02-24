package scan

import (
	"fmt"
	"sort"
	"strings"
)

func newFinding(code string, evidence string) Finding {
	severity := findingSeverity(code)
	confidence := findingConfidence(code)
	f := Finding{Code: code, Severity: severity, Confidence: confidence}
	if evidence != "" {
		f.Evidence = []string{evidence}
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

func newMCPFinding(config ScanConfig, code string, evidence string) Finding {
	if mcpModeStrict(config.MCPMode) && isMCPStrictUpgrade(code) {
		return newFindingWithSeverity(code, evidence, "high")
	}
	return newFinding(code, evidence)
}

func newFindingWithSeverity(code string, evidence string, severity string) Finding {
	confidence := findingConfidence(code)
	f := Finding{Code: code, Severity: severity, Confidence: confidence}
	if evidence != "" {
		f.Evidence = []string{evidence}
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

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

func newFindingWithEvidence(code string, evidence []string) Finding {
	severity := findingSeverity(code)
	confidence := findingConfidence(code)
	f := Finding{Code: code, Severity: severity, Confidence: confidence}
	if len(evidence) > 0 {
		f.Evidence = evidence
	}
	if explanation := findingRFCExplanation(code); explanation != "" {
		f.Evidence = append(f.Evidence, explanation)
	}
	return f
}

func buildAuthDiscoveryUnavailableFinding(observation mcpAuthObservation, prmEvidence string) Finding {
	evidence := []string{fmt.Sprintf("initialize -> %d", observation.Status)}
	if strings.TrimSpace(observation.ErrorMessage) != "" {
		evidence = append(evidence, fmt.Sprintf("initialize error: %s", strings.TrimSpace(observation.ErrorMessage)))
	}
	if observation.WWWAuthenticatePresent {
		value := strings.TrimSpace(observation.WWWAuthenticateObserved)
		if value == "" {
			value = "(present)"
		}
		evidence = append(evidence, fmt.Sprintf("WWW-Authenticate: %s", value))
	} else {
		evidence = append(evidence, "WWW-Authenticate: (missing)")
	}
	if strings.TrimSpace(prmEvidence) != "" {
		for _, line := range strings.Split(prmEvidence, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			evidence = append(evidence, line)
		}
	}
	return newFindingWithEvidence("AUTH_REQUIRED_BUT_NOT_ADVERTISED", evidence)
}

func findingRFCExplanation(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE":
		return "RFC 9728 discovery expects a WWW-Authenticate header with resource_metadata for protected resources."
	case "AUTH_REQUIRED_BUT_NOT_ADVERTISED":
		return "Auth appears required but OAuth discovery was not advertised. Next steps: add WWW-Authenticate + PRM for OAuth/MCP discovery, or document the required non-OAuth auth (e.g., SigV4)."
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		return "RFC 9728 defines the root /.well-known/oauth-protected-resource endpoint; for path-based resources, the path-suffix PRM or resource_metadata hint is sufficient for standards-compliant discovery."
	case "OAUTH_DISCOVERY_UNAVAILABLE":
		return "OAuth discovery failed because no PRM endpoint returned valid metadata for this resource."
	case "PRM_MISSING_AUTHORIZATION_SERVERS":
		return "RFC 9728 requires authorization_servers in protected resource metadata for OAuth discovery."
	case "PRM_RESOURCE_MISMATCH":
		return "RFC 9728 requires the PRM resource value to exactly match the protected resource URL."
	case "PRM_RESOURCE_TRAILING_SLASH":
		return "PRM resource identifiers that differ only by a trailing slash can break strict clients; treat as a compatibility warning."
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
		return "Authorization server metadata responses must be JSON (RFC 8414 or OIDC discovery)."
	case "AUTH_SERVER_ISSUER_MISMATCH":
		return "RFC 8414 requires the metadata issuer to exactly match the issuer used for discovery."
	case "AUTH_SERVER_METADATA_UNREACHABLE":
		return "Authorization server metadata should be retrievable at RFC 8414 or OIDC discovery well-known locations."
	case "AUTH_SERVER_METADATA_INVALID":
		return "RFC 8414 and OIDC discovery define required metadata fields such as issuer, authorization_endpoint, and token_endpoint."
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
	case "VERSION_MISMATCH":
		return "AuthProbe always scans with MCP protocol version 2025-11-25; mismatches mean the server likely does not support that version fully."
	case "MCP_PROTOCOL_VERSION_NEGOTIATION_NOT_APPLIED":
		return "MCP clients must honor the negotiated protocolVersion returned by initialize; failures indicate version negotiation was not applied."
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

func findingSeverity(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE",
		"AUTH_REQUIRED_BUT_NOT_ADVERTISED",
		"DISCOVERY_ROOT_WELLKNOWN_404",
		"OAUTH_DISCOVERY_UNAVAILABLE",
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
		"MCP_PROTOCOL_VERSION_NEGOTIATION_NOT_APPLIED",
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
		"VERSION_MISMATCH",
		"PRM_RESOURCE_TRAILING_SLASH",
		"MCP_NOTIFICATION_BODY_PRESENT",
		"MCP_NOTIFICATION_FAILED",
		"MCP_ORIGIN_NOT_VALIDATED",
		"MCP_ICON_UNSAFE_SCHEME":
		return "low"
	default:
		return "low"
	}
}

func findingConfidence(code string) float64 {
	switch code {
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		return 0.92
	case "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		return 0.85
	case "HEADER_STRIPPED_BY_PROXY_SUSPECTED":
		return 0.9
	case "TOKEN_RESPONSE_NOT_JSON_RISK",
		"TOKEN_HTTP200_ERROR_PAYLOAD_RISK":
		return 0.7
	case "MCP_PROBE_TIMEOUT":
		return 0.8
	case "SCOPES_WHITESPACE_RISK":
		return 0.85
	default:
		return 1.00
	}
}

func choosePrimaryFinding(findings []Finding) Finding {
	if len(findings) == 0 {
		return Finding{}
	}
	var candidates []Finding
	for _, item := range findings {
		if severityRank(item.Severity) >= severityRank("high") {
			candidates = append(candidates, item)
		}
	}
	if len(candidates) == 0 {
		return Finding{}
	}
	sorted := make([]Finding, len(candidates))
	copy(sorted, candidates)
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

// ShouldFail determines if the scan should exit with failure based on findings.
func ShouldFail(primary Finding, failOn string) bool {
	if primary.Code == "" {
		return false
	}
	threshold := severityRank(strings.ToLower(failOn))
	if threshold == 0 {
		return false
	}
	return severityRank(primary.Severity) >= threshold
}
