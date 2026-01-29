# AuthProbe funnel overview

This document explains how AuthProbe stages its scan, what each step checks, and which RFCs inform the expectations.

## 1) Discovery (MCP → OAuth bootstrap)

**What is scanned**
- AuthProbe sends a probe request to the MCP endpoint and inspects the response code and headers.

**What is expected**
- `401 Unauthorized` and a `WWW-Authenticate` header containing `resource_metadata`.

**Failure codes**
- `MCP_PROBE_TIMEOUT`: probe timed out waiting for response headers.
- `DISCOVERY_NO_WWW_AUTHENTICATE`: 401 without `resource_metadata`.

**Relevant RFC**
- **RFC 9728**: discovery via `WWW-Authenticate` + `resource_metadata` for protected resources.

## 2) MCP initialize + tools/list

**What is scanned**
- AuthProbe sends JSON-RPC `initialize` and `tools/list` requests to confirm the server is responsive after discovery.

**What is expected**
- `200 OK` + JSON responses for both calls.

**Failure codes**
- `MCP_INITIALIZE_FAILED`
- `MCP_TOOLS_LIST_FAILED`

**Relevant RFC**
- Not RFC-based; this is MCP protocol readiness validation.

## 3) Protected Resource Metadata (PRM) discovery

**What is scanned**
- PRM URLs are built and fetched (root and/or path-suffix). The responses are validated for status, JSON, and fields.

**What is expected**
- `200 OK`
- `Content-Type: application/json`
- JSON object containing:
  - `resource` matching the MCP endpoint URL.
  - `authorization_servers` list.

**Failure codes**
- Fetch/HTTP:
  - `DISCOVERY_ROOT_WELLKNOWN_404`
  - `PRM_HTTP_STATUS_NOT_200`
  - `PRM_CONTENT_TYPE_NOT_JSON`
  - `PRM_NOT_JSON_OBJECT`
- Content:
  - `PRM_RESOURCE_MISSING`
  - `PRM_RESOURCE_MISMATCH`
  - `PRM_MISSING_AUTHORIZATION_SERVERS`
  - `PRM_BEARER_METHODS_INVALID`
  - `PRM_WELLKNOWN_PATH_SUFFIX_MISSING`
- Resource URI checks:
  - `RFC3986_INVALID_URI`
  - `RFC3986_ABSOLUTE_HTTPS_REQUIRED`
  - `RESOURCE_FRAGMENT_FORBIDDEN`

**Relevant RFCs**
- **RFC 9728**: PRM location + required fields.
- **RFC 3986**: URI validity / HTTPS requirements.
- **RFC 8707**: protected resource URI fragment rules.

## 4) Authorization server metadata

**What is scanned**
- For each `authorization_servers` entry, AuthProbe fetches `<issuer>/.well-known/oauth-authorization-server` and validates the metadata.

**What is expected**
- `200 OK`, JSON body.
- Required fields:
  - `issuer` (must match discovery issuer)
  - `authorization_endpoint`
  - `token_endpoint`
- Optional (when enabled):
  - `code_challenge_methods_supported` includes `S256`.
  - `protected_resources` includes the resource.
  - `jwks_uri` resolves to a valid JWKS.

**Failure codes**
- Metadata fetch/format:
  - `AUTH_SERVER_METADATA_UNREACHABLE`
  - `AUTH_SERVER_METADATA_INVALID`
  - `AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON`
  - `AUTH_SERVER_ISSUER_MISMATCH`
  - `AUTH_SERVER_ISSUER_QUERY_FRAGMENT`
  - `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`
- Required fields:
  - `AUTH_SERVER_METADATA_INVALID` (missing issuer/authorization_endpoint/token_endpoint)
- Optional checks:
  - `AUTH_SERVER_PKCE_S256_MISSING`
  - `AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH`
  - `AUTH_SERVER_ENDPOINT_HOST_MISMATCH`
  - `JWKS_FETCH_ERROR`
  - `JWKS_INVALID`
- Legacy compatibility probe (VS Code profile):
  - `AUTH_SERVER_ROOT_WELLKNOWN_PROBE_FAILED`

**Relevant RFCs**
- **RFC 8414**: authorization server metadata.
- **RFC 3986**: issuer/endpoint URI checks.
- **RFC 7636**: PKCE `S256`.
- **RFC 8707**: protected resources matching.
- **RFC 7517**: JWKS.

## 5) Token endpoint readiness (heuristics)

**What is scanned**
- AuthProbe sends a safe invalid grant request to observe token endpoint behavior.

**What is expected**
- JSON error response (content-type JSON).
- HTTP status should not be `200` with an OAuth error payload.

**Failure codes**
- `TOKEN_RESPONSE_NOT_JSON_RISK`
- `TOKEN_HTTP200_ERROR_PAYLOAD_RISK`

**Relevant RFC**
- Not strictly RFC-based; this is a compatibility/heuristic check.

## 6) Redirect and SSRF safety checks (infra/routing)

**What is scanned**
- Redirect handling and SSRF-style safety checks for metadata fetches.

**What is expected**
- Valid absolute redirects when redirect policy is strict.
- No private/loopback disallowed targets if SSRF protections are enforced.

**Failure codes**
- `METADATA_REDIRECT_BLOCKED`
- `METADATA_REDIRECT_LIMIT`
- `METADATA_SSRF_BLOCKED`

**Relevant RFCs**
- **RFC 9110**: redirect handling policy.
- SSRF blocking is local policy (not an RFC requirement).

## Failure-code cheat sheet

This cheat sheet maps AuthProbe findings to the funnel step, expectation, and RFC (when applicable).

| Code | Step | Expectation | RFC |
| --- | --- | --- | --- |
| `MCP_PROBE_TIMEOUT` | Discovery | MCP probe should return headers promptly (SSE headers or a 405 for GET Accept: text/event-stream). | MCP protocol behavior |
| `DISCOVERY_NO_WWW_AUTHENTICATE` | Discovery | `401` must include `WWW-Authenticate` with `resource_metadata`. | RFC 9728 |
| `MCP_INITIALIZE_FAILED` | MCP initialize + tools/list | `initialize` returns `200` with JSON. | MCP protocol |
| `MCP_TOOLS_LIST_FAILED` | MCP initialize + tools/list | `tools/list` returns `200` with JSON. | MCP protocol |
| `DISCOVERY_ROOT_WELLKNOWN_404` | PRM discovery | Root PRM should be reachable when path-suffix isn’t required. | RFC 9728 |
| `PRM_HTTP_STATUS_NOT_200` | PRM discovery | PRM endpoint returns `200 OK`. | RFC 9728 |
| `PRM_CONTENT_TYPE_NOT_JSON` | PRM discovery | PRM response `Content-Type` must be JSON. | RFC 9728 |
| `PRM_NOT_JSON_OBJECT` | PRM discovery | PRM response must be a JSON object. | RFC 9728 |
| `PRM_RESOURCE_MISSING` | PRM discovery | PRM must include a `resource` value. | RFC 9728 |
| `PRM_RESOURCE_MISMATCH` | PRM discovery | PRM `resource` must match the MCP endpoint. | RFC 9728 |
| `PRM_MISSING_AUTHORIZATION_SERVERS` | PRM discovery | PRM must include `authorization_servers`. | RFC 9728 |
| `PRM_BEARER_METHODS_INVALID` | PRM discovery | `bearer_methods_supported` values must be valid strings. | RFC 9728 |
| `PRM_WELLKNOWN_PATH_SUFFIX_MISSING` | PRM discovery | Path-suffix PRM required when resource has a path. | RFC 9728 |
| `RFC3986_INVALID_URI` | PRM/auth metadata | URLs must parse as valid URIs. | RFC 3986 |
| `RFC3986_ABSOLUTE_HTTPS_REQUIRED` | PRM/auth metadata | URLs must be absolute HTTPS. | RFC 3986 |
| `RESOURCE_FRAGMENT_FORBIDDEN` | PRM discovery | `resource` must not include fragment. | RFC 8707 |
| `AUTH_SERVER_ISSUER_QUERY_FRAGMENT` | Auth server metadata | Issuer must not include query/fragment. | RFC 8414 |
| `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED` | Auth server metadata | Issuer cannot be private when SSRF protections are enabled. | Local policy |
| `AUTH_SERVER_METADATA_UNREACHABLE` | Auth server metadata | Metadata endpoint must be reachable. | RFC 8414 |
| `AUTH_SERVER_METADATA_INVALID` | Auth server metadata | Metadata must be `200` JSON with required fields. | RFC 8414 |
| `AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON` | Auth server metadata | Metadata response must be JSON. | RFC 8414 |
| `AUTH_SERVER_ISSUER_MISMATCH` | Auth server metadata | Metadata `issuer` must equal discovery issuer. | RFC 8414 |
| `AUTH_SERVER_ENDPOINT_HOST_MISMATCH` | Auth server metadata | Metadata endpoints should align with issuer host. | RFC 8414 |
| `AUTH_SERVER_PKCE_S256_MISSING` | Auth server metadata | `code_challenge_methods_supported` should include `S256`. | RFC 7636 |
| `AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH` | Auth server metadata | `protected_resources` should include the resource. | RFC 8707 |
| `JWKS_FETCH_ERROR` | Auth server metadata | `jwks_uri` must be reachable. | RFC 7517 |
| `JWKS_INVALID` | Auth server metadata | JWKS must be valid JSON with `keys`. | RFC 7517 |
| `AUTH_SERVER_ROOT_WELLKNOWN_PROBE_FAILED` | Auth server metadata (VS Code) | Legacy root metadata probe should succeed for compatibility. | Legacy compatibility |
| `TOKEN_RESPONSE_NOT_JSON_RISK` | Token readiness | Token endpoint should respond with JSON. | OAuth best practice |
| `TOKEN_HTTP200_ERROR_PAYLOAD_RISK` | Token readiness | Token endpoint should not return `200` with `error`. | OAuth best practice |
| `METADATA_REDIRECT_BLOCKED` | Redirect safety | Redirects must be absolute HTTPS when strict. | RFC 9110 |
| `METADATA_REDIRECT_LIMIT` | Redirect safety | Redirect chains must stay within limit. | RFC 9110 |
| `METADATA_SSRF_BLOCKED` | Redirect safety | Metadata hosts must not be private. | Local policy |
