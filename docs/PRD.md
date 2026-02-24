# AuthProbe v0.1 PRD

**Product:** AuthProbe  
**Summary:** MCP OAuth diagnostics in minutes (discovery → metadata → token readiness → auth header checks)  
Developer-first CLI for debugging broken MCP OAuth flows, with proof-grade evidence and clear next-step guidance.

---

## 1) Executive summary

AuthProbe is a CLI that pinpoints *where* MCP OAuth breaks (and *why*), then provides deterministic findings and verification commands.

---

## 2) Target users and job-to-be-done

### Primary user (v0.1)
A developer building or integrating a **remote MCP server with OAuth** who is currently blocked by:
- OAuth discovery issues (`/.well-known/*`, `WWW-Authenticate`, `resource_metadata`)
- PRM shape/canonical resource mismatches
- auth server metadata inconsistencies
- token endpoint quirks that cause client incompatibility
- proxy/ingress “it’s not my code” problems (header stripping, path prefixes)

### Job-to-be-done
> “Tell me exactly what’s wrong with my MCP OAuth setup, with evidence, and tell me what to do next.”

---

## 3) Goals (v0.1)

1) **Time-to-root-cause < 2 minutes** for common failures  
2) **One primary finding** per scan (decisive, evidence-backed)  
3) **CI-ready**: stable finding codes, exit codes, severity gating, machine-readable outputs  
4) **Redaction-by-default** for anything sensitive (tokens, cookies, secrets)

### RFC 9728 conformance (v0.1)
AuthProbe should validate **OAuth Protected Resource Metadata** behavior per RFC 9728 in a way that’s useful to developers:
- Default: **best-effort** conformance checks (fail on key MUST violations; warn on SHOULD/best-practice gaps).
- Optional: **strict** mode for CI gates and “spec-hardening” work.

### MCP 2025-11-25 spec conformance (best-effort by default)
AuthProbe should validate key behaviors from the MCP 2025-11-25 specification (especially **Streamable HTTP** and JSON-RPC lifecycle):
- Default: **best-effort** checks (fail on key MUST violations; warn on SHOULD/best-practice gaps).
- Optional: **strict** mode for CI gates and “interop hardening”.

---

## 4) Non-goals (explicitly out of scope for v0.1)

- Browser-based OAuth login automation (Authorization Code + PKCE end-to-end)  
- Running as a permanent reverse proxy/gateway  
- Full runtime observability agent  
- Managed SaaS scanner  
- Provider-specific deep integrations (Okta/Entra/Keycloak packs)

These are Phase 2+ .

---

## 5) Product surface (CLI)

### Canonical commands (must ship)
- `authprobe scan <mcp_url>`

### Helper flags (small, but recommended)
- `authprobe scan --explain` (print RFC rationale for each scan step)

---

## 6) Scan funnel (what `scan` does)

AuthProbe runs a staged funnel with deterministic step IDs. Each step emits PASS/FAIL/SKIP with evidence references.

### Steps (v0.1)
**Step 1: MCP probe**
- Request MCP endpoint with no token
- Expect either:
  - auth enabled: 401 with usable `WWW-Authenticate` + `resource_metadata=...`
  - auth not required: skip auth checks

**Step 2: PRM fetch matrix**
- Fetch PRM from:
  - `resource_metadata` URL (if provided)
  - root candidate: `/.well-known/oauth-protected-resource`
  - path-suffix candidate: `/.well-known/oauth-protected-resource/<mcp_path>`
- Validate PRM JSON fields (especially `authorization_servers`), and validate canonical `resource` value.
- Additionally, compute RFC 9728 **well-known URL(s)** from the protected resource identifier and probe:
  - `/.well-known/oauth-protected-resource` (root)
  - `/.well-known/oauth-protected-resource/<path>` (path-suffix, when the resource has a path)
- Enforce RFC 9728 anti-impersonation rule: the PRM `resource` **must exactly match** the protected resource identifier used to construct/fetch metadata (code-point equality; no Unicode normalization).

**Step 3: Authorization server metadata**
- From PRM `authorization_servers`, fetch metadata (RFC 8414 / OIDC-style discovery).
- Validate presence and parse of key endpoints (authorization/token, etc.).

**Step 4: Token endpoint readiness heuristics**
- Without full login, perform safe “readiness” checks:
  - content-type behaviors (JSON vs form-encoded) on error paths
  - detect “HTTP 200 but error payload” patterns
- This step outputs risk findings rather than claiming full end-to-end validity.

**Step 5: Dynamic Client Registration (RFC 7591)**
- If `registration_endpoint` is present in authorization server metadata:
  - Probe endpoint accessibility (protected vs open)
  - Test input validation with suspicious redirect URIs
  - Check for dangerous URI scheme acceptance (http://, javascript:, file://)
  - Verify empty redirect_uris array rejection
- Findings indicate security posture of DCR configuration.

**(Optional Step 6: Authenticated MCP call)**
- Only if user provides a bearer token via `--bearer-token` (optional, may be deferred if not needed for v0.1):
  - Make one MCP call with `Authorization: Bearer <token>` and classify 401 results.

---

## 6.1) RFC 9728 checks (OAuth Protected Resource Metadata)

AuthProbe should implement explicit RFC 9728 checks for:
- **Well-known URL construction** (root and path-suffix variants)
- **PRM HTTP semantics** (`200 OK`, JSON object body, correct content-type)
- **Required/optional fields and constraints**
- **Anti-impersonation** (`resource` equality rules)
- **TLS and SSRF guardrails** when following `authorization_servers`

### `--rfc` modes
- `off`: skip RFC-specific checks (only core MCP/OAuth checks).
- `best-effort` (default): fail on key MUST violations; warn on SHOULD/best-practice gaps.
- `strict`: fail on all MUST violations + escalate key SHOULD gaps to failures (CI-friendly).

### Private issuer safety (SSRF guardrail)
When fetching authorization server metadata from `authorization_servers`, AuthProbe must avoid accidental SSRF:
- By default, block **private/loopback/link-local** issuer targets.
- Allow override for enterprise/internal deployments via `--allow-private-issuers`.

## 6.2) MCP 2025-11-25 spec checks (Streamable HTTP + JSON-RPC)

AuthProbe should implement best-effort checks derived from the MCP 2025-11-25 specification with a focus on interoperability and client drift. These checks should be **safe** (no secrets) and **deterministic**.

### `--mcp` modes
- `off`: skip MCP-spec conformance checks (only OAuth/RFC9728 checks).
- `best-effort` (default): fail on key MUST violations; warn on SHOULD/best-practice gaps.
- `strict`: hard-fail additional deviations (CI-friendly).

### Areas to validate (high value)

**A) JSON-RPC base rules**
- Invalid `id` (null) must be rejected; notifications must not include `id`.
- Responses must echo request `id` and use correct `result`/`error` shapes.

**B) Lifecycle**
- `initialize` must occur first; client must send `notifications/initialized` after `initialize` response.
- Version negotiation must be consistent and explicit.

**C) Streamable HTTP transport**
- POST must include correct `Accept` headers (`application/json` and `text/event-stream`).
- POST body must be a single JSON-RPC message.
- Notification/response bodies accepted by server should return `202 Accepted` with no body.
- GET must use `Accept: text/event-stream`; server must reply with SSE or `405 Method Not Allowed`.
- If server requires `MCP-Protocol-Version` and/or `MCP-Session-Id`, behavior on missing/invalid must match spec (`400`/`404` as applicable).
- Server should validate `Origin` header (DNS rebinding defense) and return `403` on invalid origins.

**D) Utilities (when implemented)**
- `ping` returns `{}` promptly.
- Cancellation and progress token semantics are consistent (no regressions).

**E) Tools/Tasks/Schema hygiene**
- Tool `inputSchema` must be a JSON Schema object (not null) and parseable.
- If tasks capability is advertised, the corresponding methods exist and taskSupport rules are enforced.

**F) Icon metadata safety (best-effort)**
- Icon URIs should use safe schemes (`https:` or `data:`); warn on unsafe schemes.

---

## 7) Finding codes (v0.1 must-have)

Finding codes are stable identifiers. Each finding includes:
- severity (low/medium/high)
- confidence (0–1)
- evidence (sanitized)
- next-step references (verification commands and supporting context)

### Discovery & PRM
1) `DISCOVERY_NO_WWW_AUTHENTICATE`  
401 returned but missing/invalid `WWW-Authenticate` header or missing `resource_metadata`.

2) `DISCOVERY_ROOT_WELLKNOWN_404`  
`GET /.well-known/oauth-protected-resource` is 404/unreachable.

3) `PRM_MISSING_AUTHORIZATION_SERVERS`  
PRM JSON reachable but missing `authorization_servers`.

4) `PRM_RESOURCE_MISMATCH`  
PRM `resource` doesn’t match actual MCP endpoint (e.g., points to origin/root).

### Auth server metadata
5) `AUTH_SERVER_METADATA_UNREACHABLE`  
Auth server metadata endpoint cannot be fetched.

6) `AUTH_SERVER_METADATA_INVALID`  
Auth server metadata fetched but invalid/missing critical endpoints.

### Token endpoint readiness (heuristics)
7) `TOKEN_RESPONSE_NOT_JSON_RISK`  
Token endpoint behavior suggests form-encoded responses likely; warn when client expects JSON.

8) `TOKEN_HTTP200_ERROR_PAYLOAD_RISK`  
Token endpoint returns HTTP 200 with `error` payload patterns; warn.

### Infra / environment
9) `HEADER_STRIPPED_BY_PROXY_SUSPECTED`  
Behavior suggests `WWW-Authenticate` or required headers are removed by a proxy/WAF chain.

10) `MULTI_INSTANCE_STATE_RISK` *(warning-level in v0.1)*  
Signals stateful proxy flows would fail under multi-replica without shared storage/sticky routing.

### RFC 9728 conformance (additional finding codes)

**PRM / well-known construction**
11) `PRM_WELLKNOWN_PATH_SUFFIX_MISSING`  
Path-suffix PRM endpoint (e.g., `/.well-known/oauth-protected-resource/<path>`) is missing/unreachable when the protected resource identifier contains a path.

**PRM HTTP semantics**
12) `PRM_HTTP_STATUS_NOT_200`  
PRM endpoint returned a non-200 HTTP status where metadata is expected.

13) `PRM_CONTENT_TYPE_NOT_JSON`  
PRM endpoint did not return `application/json`.

14) `PRM_NOT_JSON_OBJECT`  
PRM response body is not a JSON object.

**PRM field constraints**
15) `PRM_RESOURCE_MISSING`  
PRM response missing required `resource` parameter.

16) `PRM_JWKS_URI_NOT_HTTPS`  
PRM `jwks_uri` is present but not `https:`.

17) `PRM_BEARER_METHODS_INVALID`  
PRM `bearer_methods_supported` contains values outside `{header, body, query}`.

18) `PRM_SIGNING_ALG_NONE_FORBIDDEN`  
PRM `resource_signing_alg_values_supported` contains the forbidden value `none`.

**Best-practice warnings (best-effort; strict may fail)**
19) `PRM_CACHE_CONTROL_MISSING`  
PRM response lacks explicit caching directives (`Cache-Control`), which can cause unnecessary load and inconsistent client behavior.

**SSRF / safety**
20) `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`  
Authorization server issuer resolves to a private/loopback/link-local target and was blocked (use `--allow-private-issuers` to override).

### MCP 2025-11-25 conformance (additional finding codes)

**JSON-RPC correctness**
21) `JSONRPC_ID_NULL_FORBIDDEN`  
A JSON-RPC request used `id: null` (forbidden); server/client behavior should reject per spec.

22) `JSONRPC_NOTIFICATION_HAS_ID`  
A notification included an `id` (forbidden).

23) `JSONRPC_RESPONSE_ID_MISMATCH`  
Response `id` does not match the request `id`.

24) `JSONRPC_ERROR_SHAPE_INVALID`  
Error response missing required JSON-RPC `error.code` (int) or `error.message` (string).

**Lifecycle**
25) `LIFECYCLE_INITIALIZE_NOT_FIRST`  
Non-initialize request observed before initialize completes.

26) `PROTOCOL_VERSION_NEGOTIATION_INVALID`  
`initialize` protocol version negotiation behavior inconsistent/invalid.

**Streamable HTTP**
27) `HTTP_ACCEPT_HEADER_INCOMPLETE`  
Missing required `Accept` values (`application/json` and `text/event-stream`) for POST.

28) `HTTP_POST_BODY_NOT_SINGLE_JSONRPC`  
POST body is not a single JSON-RPC message object.

29) `HTTP_202_REQUIRED_FOR_NOTIFICATION_RESPONSE`  
Server accepted a notification/response POST but did not return `202 Accepted` with empty body.

30) `HTTP_GET_NOT_SSE_OR_405`  
GET did not return `text/event-stream` and was not `405 Method Not Allowed`.

31) `HTTP_PROTOCOL_VERSION_HEADER_MISSING`  
Missing required `MCP-Protocol-Version` on subsequent requests.

32) `HTTP_PROTOCOL_VERSION_UNSUPPORTED`  
Server rejected a protocol version in a way that does not match the spec’s HTTP semantics (expect `400`).

33) `SESSION_ID_NON_ASCII`  
`MCP-Session-Id` contains non-visible-ASCII characters.

34) `SESSION_ID_REQUIRED_BUT_NOT_ENFORCED`  
Server behavior suggests session id is required but error handling is inconsistent.

35) `HTTP_ORIGIN_NOT_VALIDATED`  
Server accepts requests with invalid `Origin` without returning `403` (DNS rebinding defense gap).

**Utilities**
36) `PING_RESULT_NOT_EMPTY_OBJECT`  
`ping` returned a non-empty result (should be `{}`).

**Tools/Tasks/Schema**
37) `TOOL_INPUT_SCHEMA_NULL_FORBIDDEN`  
`tools/list` returned a tool with null/absent `inputSchema` where schema is required.

38) `TOOL_INPUT_SCHEMA_INVALID`  
`inputSchema` is not a valid JSON Schema object (parse/shape failure).

39) `TASKS_CAPABILITY_DECLARED_BUT_METHOD_MISSING`  
Server declares tasks capability but required task methods are missing/unimplemented.

40) `TOOL_TASK_SUPPORT_REQUIRED_NOT_ENFORCED`  
Tool advertises task support `required` but server accepts non-task execution (or vice-versa).

**Icons (best-effort)**
41) `ICON_URI_UNSAFE_SCHEME`  
Icon URI uses unsafe/unsupported scheme (e.g., `javascript:`, `file:`).

**SSE resumability (best-effort)**
42) `SSE_LAST_EVENT_ID_RESUME_VIOLATION`  
Server violates resumption semantics with `Last-Event-ID` (replay/broadcast mismatch).

### Dynamic Client Registration (RFC 7591)

43) `DCR_ENDPOINT_OPEN`  
Registration endpoint accepts unauthenticated requests; should require initial access token.

44) `DCR_HTTP_REDIRECT_ACCEPTED`  
Registration endpoint accepts http:// (non-TLS) redirect URIs in production.

45) `DCR_LOCALHOST_REDIRECT_ACCEPTED`  
Registration endpoint accepts localhost redirect URIs (risky in production).

46) `DCR_DANGEROUS_URI_ACCEPTED`  
Registration endpoint accepts dangerous URI schemes (javascript:, file:).

47) `DCR_EMPTY_REDIRECT_URIS_ACCEPTED`  
Registration endpoint accepts empty redirect_uris array.

---

## 7.1) Severity and confidence rules (v0.1)

AuthProbe findings must be consistent and CI-friendly. Each finding includes:
- **severity**: low / medium / high
- **confidence**: 0.00–1.00 based on direct evidence

### Default severity mapping
**HIGH**
- `DISCOVERY_NO_WWW_AUTHENTICATE`
- `DISCOVERY_ROOT_WELLKNOWN_404`
- `PRM_MISSING_AUTHORIZATION_SERVERS`
- `PRM_RESOURCE_MISMATCH`
- `PRM_RESOURCE_MISSING`
- `PRM_HTTP_STATUS_NOT_200` (when metadata is expected)
- `PRM_CONTENT_TYPE_NOT_JSON`
- `PRM_NOT_JSON_OBJECT`
- `PRM_JWKS_URI_NOT_HTTPS`
- `PRM_BEARER_METHODS_INVALID`
- `PRM_SIGNING_ALG_NONE_FORBIDDEN`
- `AUTH_SERVER_METADATA_UNREACHABLE`
- `AUTH_SERVER_METADATA_INVALID`

**MEDIUM**
- `HEADER_STRIPPED_BY_PROXY_SUSPECTED`
- `PRM_WELLKNOWN_PATH_SUFFIX_MISSING`
- `TOKEN_RESPONSE_NOT_JSON_RISK`
- `TOKEN_HTTP200_ERROR_PAYLOAD_RISK`
- `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`
- `MULTI_INSTANCE_STATE_RISK`

**LOW**
- `PRM_CACHE_CONTROL_MISSING`

### Confidence guidelines (examples)
- **1.00**: direct deterministic mismatch (HTTP status, content-type, required field missing, exact `resource` inequality).
- **0.85–0.95**: strong inference from repeated probes (header stripping suspected).
- **0.60–0.80**: heuristic risk patterns (token endpoint readiness warnings).

**Primary finding selection rule (unchanged):** choose the highest-severity finding; tie-break by highest confidence.

### MCP 2025-11-25 severity mapping additions

**HIGH**
- `JSONRPC_ID_NULL_FORBIDDEN`
- `JSONRPC_NOTIFICATION_HAS_ID`
- `JSONRPC_RESPONSE_ID_MISMATCH`
- `JSONRPC_ERROR_SHAPE_INVALID`
- `LIFECYCLE_INITIALIZE_NOT_FIRST`
- `PROTOCOL_VERSION_NEGOTIATION_INVALID`
- `HTTP_ACCEPT_HEADER_INCOMPLETE`
- `HTTP_POST_BODY_NOT_SINGLE_JSONRPC`
- `HTTP_202_REQUIRED_FOR_NOTIFICATION_RESPONSE`
- `HTTP_GET_NOT_SSE_OR_405`
- `HTTP_PROTOCOL_VERSION_HEADER_MISSING`
- `HTTP_PROTOCOL_VERSION_UNSUPPORTED`
- `SESSION_ID_NON_ASCII`
- `HTTP_ORIGIN_NOT_VALIDATED`
- `TOOL_INPUT_SCHEMA_NULL_FORBIDDEN`
- `TOOL_INPUT_SCHEMA_INVALID`
- `TASKS_CAPABILITY_DECLARED_BUT_METHOD_MISSING`
- `TOOL_TASK_SUPPORT_REQUIRED_NOT_ENFORCED`

**MEDIUM**
- `PING_RESULT_NOT_EMPTY_OBJECT`
- `SESSION_ID_REQUIRED_BUT_NOT_ENFORCED`
- `ICON_URI_UNSAFE_SCHEME`
- `SSE_LAST_EVENT_ID_RESUME_VIOLATION`

### RFC 7591 Dynamic Client Registration severity mapping

**HIGH**
- `DCR_ENDPOINT_OPEN`
- `DCR_HTTP_REDIRECT_ACCEPTED`
- `DCR_DANGEROUS_URI_ACCEPTED`

**MEDIUM**
- `DCR_LOCALHOST_REDIRECT_ACCEPTED`
- `DCR_EMPTY_REDIRECT_URIS_ACCEPTED`

---

## 8) Outputs and artifacts

### Stdout (developer-first)
- Funnel view + primary finding + 3-line evidence + next best action

### Files
- `--md report.md` (human, PR/issue friendly)
- `--json report.json` (machine, stable schema)
- `--bundle evidence.zip` containing:
  - `trace.jsonl` (sanitized HTTP transcript)
  - `report.json`
  - `report.md`
  - `meta.json` (tool version, timestamp, settings)

### Exit codes
- `0` = no findings at/above `--fail-on`
- `2` = findings at/above `--fail-on`
- `3` = tool/runtime error (invalid args, unreachable host, etc.)

---

## 9) Security & privacy (v0.1 constraints)

- Never store or emit full tokens/cookies/secrets in logs or bundles.
- Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`) should be redacted or token-fingerprinted in outputs.

---

## 10) Acceptance criteria (definition of done)

### `scan`
- Prints funnel with PASS/FAIL/SKIP per step
- Selects exactly ONE primary finding (highest severity, highest confidence)
- Includes >= 3 evidence lines (request + status + key header presence)
- Produces valid markdown + JSON outputs consistent with stdout
- `--bundle` creates zip with required files and redaction applied

---

## 11) Test plan (fixtures-first)

### Fixture format
Each fixture includes:
- `trace.jsonl` (sanitized transcript)
- `expected_report.json`
- (optional) `expected_stdout.txt`

### Minimum fixture cases (v0.1)
**Discovery / well-known**
1) `root_prm_404_path_prm_200` → expects `DISCOVERY_ROOT_WELLKNOWN_404`
2) `missing_www_authenticate` → expects `DISCOVERY_NO_WWW_AUTHENTICATE`
3) `prm_missing_authorization_servers` → expects `PRM_MISSING_AUTHORIZATION_SERVERS`
4) `resource_mismatch_points_to_origin` → expects `PRM_RESOURCE_MISMATCH`

**Token readiness heuristics**
5) `token_form_encoded_risk` → expects `TOKEN_RESPONSE_NOT_JSON_RISK`
6) `token_http200_error_payload` → expects `TOKEN_HTTP200_ERROR_PAYLOAD_RISK`

**Proxy/infra**
7) `header_stripping_suspected` → expects `HEADER_STRIPPED_BY_PROXY_SUSPECTED`

**RFC 9728 conformance**
8) `path_suffix_prm_missing` → expects `PRM_WELLKNOWN_PATH_SUFFIX_MISSING`
9) `prm_jwks_uri_not_https` → expects `PRM_JWKS_URI_NOT_HTTPS`
10) `issuer_private_blocked` → expects `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`

### Test requirements
- `go test ./...` must pass
- Finding selection order must be deterministic

---

## 12) Release packaging (v0.1)

Must ship:
1) GitHub Releases with binaries:
- `authprobe_<os>_<arch>`
- `checksums.txt`
2) Docker image:
- `ghcr.io/<org>/authprobe:<version>`
3) Homebrew tap (recommended, not mandatory):
- `brew install authprobe`
4) GitHub Action (thin wrapper):
- downloads release binary
- runs `scan` or `matrix`
- uploads report artifacts

---

## 14) Milestones (build sequence)

1) Repo scaffold + CLI wiring + exact `--help` outputs  
2) Scan funnel steps + finding engine + JSON schema  
3) Markdown renderer + bundle exporter  
4) Fixtures + golden tests  
5) Release packaging (binaries + docker + action)

---

## 15) Appendix A — Exact `--help` outputs (v0.1)

### `authprobe scan --help`
```text
authprobe scan: Diagnose MCP OAuth by running a staged probe (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe scan <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
  -H, --header <k:v>       Add a request header (repeatable).
                           Example: -H "Host: internal.example.com"

      --timeout <sec>      Overall scan timeout in seconds. Default: 8

      --mcp <mode>         MCP 2025-11-25 conformance checks (JSON-RPC + Streamable HTTP).
                           Options: off, best-effort, strict
                           Default: best-effort

      --rfc <mode>         RFC conformance checks (9728, 8414, 3986, 8707, 7636, etc.).
                           Options: off, best-effort, strict
                           Default: best-effort

      --allow-private-issuers
                           Allow fetching authorization server metadata from private/loopback/link-local issuers.
                           (Use only in trusted networks.)

      --insecure           Allow invalid TLS certificates (dev only).
      --no-follow-redirects
                           Do not follow HTTP redirects.

      --fail-on <level>    Exit non-zero if findings at/above this severity exist.
                           Options: none, low, medium, high
                           Default: high

OUTPUTS:
      --json <path>        Write structured JSON report to file. Use "-" for stdout.
      --md <path>          Write Markdown report to file. Use "-" for stdout.
      --bundle <path>      Write sanitized evidence bundle (zip) to file.
      --output-dir <dir>   Write all requested outputs into a directory.

DIAGNOSTICS:
  -v, --verbose            Verbose logs (includes request/response headers + bodies).
  -e, --explain            Print an RFC rationale for each scan step.
  -l, --tool-list          Print MCP tool names with their titles (from tools/list).
  -d, --tool-detail <name> Print a single MCP tool's full JSON definition.

EXAMPLES:
  authprobe scan https://mcp.example.com/mcp
  authprobe scan https://mcp.example.com/mcp --json -
  authprobe scan https://mcp.example.com/mcp --md report.md --json report.json
  authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com" --fail-on medium
  authprobe scan https://mcp.example.com/mcp --bundle evidence.zip
  authprobe scan https://mcp.example.com/mcp --rfc strict
  authprobe scan https://mcp.example.com/mcp --mcp strict
```

## 16) Appendix B — Golden example (report shape expectations)

A golden Markdown report must include:
- Target, timestamp
- funnel table (steps)
- primary finding with severity/confidence
- evidence block with sanitized request/response facts
- next-step references + verification commands
- verify command(s)

(Use the golden example from the design discussion as the fixture reference.)

---

## Appendix C — OAuth Metadata URL Verification (RFC-driven)

**Version:** 0.1  
**Last updated:** January 26, 2026

### Problem statement

When a client consumes **Protected Resource Metadata (RS)** and **Authorization Server Metadata (AS)**, it receives a cluster of URLs it may later call (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, etc.). If these URLs are accepted without verification, the client is exposed to **impersonation**, **mix-up**, and **SSRF** risk. This appendix defines a compact set of **RFC-backed semantic verification checks** to convert discovered URLs into trustworthy runtime configuration (and to keep “random strings from the internet” from becoming production traffic routers).

### Goals

- Provide deterministic, spec-aligned validation for RS metadata (**RFC 9728**) and AS metadata (**RFC 8414**), including **issuer/resource binding** rules.
- Harden any metadata-driven HTTP fetch against **SSRF** and misrouting while staying compatible with real-world providers (including legitimate **cross-host endpoints**).
- Produce a machine-readable validation report per discovered URL/field with **Fail / Warn / Info** outcomes.

### Non-goals

- Proving business ownership of a domain beyond standard TLS validation.
- Blocking cross-host endpoints by default (many large providers legitimately use different hosts).
- Performing high-risk active tests that require real client credentials or user interaction.

### Inputs and artifacts

- RS metadata from `/.well-known/oauth-protected-resource` (**RFC 9728**)
- AS metadata from `/.well-known/oauth-authorization-server` (**RFC 8414**)
- Optional: authorization responses including `iss` parameter (**RFC 9207**)
- Optional: JWT-based tokens requiring JWKS + claim validation (**RFC 7517 / RFC 7519**)

### Example (motivating edge case)

A common real-world mismatch is a trailing slash in a discovered issuer identifier:

- RS metadata lists: `https://accounts.google.com/`
- AS metadata returns: `issuer: https://accounts.google.com`

**RFC 8414** defines how to construct the well-known URL (including removing a terminating slash in specific cases) and requires strict issuer equality after retrieval.

**Issuer and resource comparisons MUST use code-point equality with no Unicode normalization.**

### Normative references (RFCs)

| RFC | What we use it for | Link |
|---|---|---|
| RFC 9728 | OAuth 2.0 Protected Resource Metadata (RS metadata, SSRF, string operations) | `https://www.rfc-editor.org/rfc/rfc9728` |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata (AS discovery, issuer binding, string ops) | `https://www.rfc-editor.org/rfc/rfc8414.html` |
| RFC 9207 | OAuth 2.0 Authorization Server Issuer Identification (`iss` parameter; mix-up defense) | `https://datatracker.ietf.org/doc/html/rfc9207` |
| RFC 8707 | Resource Indicators for OAuth 2.0 (`resource` parameter; audience restriction posture) | `https://datatracker.ietf.org/doc/html/rfc8707` |
| RFC 6750 | Bearer Token Usage (Authorization header; query/body caveats) | `https://datatracker.ietf.org/doc/html/rfc6750` |
| RFC 7636 | PKCE (S256 preferred; mitigates code interception) | `https://datatracker.ietf.org/doc/html/rfc7636` |
| RFC 7517 | JSON Web Key (JWK) / JWK Set (`jwks_uri`; keys array) | `https://datatracker.ietf.org/doc/html/rfc7517` |
| RFC 7519 | JSON Web Token (JWT) (`aud`/`exp` semantics when tokens are JWTs) | `https://datatracker.ietf.org/doc/html/rfc7519` |
| RFC 3986 | URI Generic Syntax (parsing; components; absolute URI rules) | `https://datatracker.ietf.org/doc/html/rfc3986` |
| RFC 1918 | Private IPv4 address ranges (SSRF blocking input) | `https://datatracker.ietf.org/doc/html/rfc1918` |
| RFC 6890 | Special-Purpose Address Registries (loopback, link-local, etc.) | `https://datatracker.ietf.org/doc/html/rfc6890` |
| RFC 9110 | HTTP Semantics (redirect handling; Location header) | `https://www.rfc-editor.org/rfc/rfc9110.html` |
| RFC 6749 | The OAuth 2.0 Authorization Framework (baseline endpoint + error model) | `https://datatracker.ietf.org/doc/html/rfc6749` |

### Verification cases

Each case maps directly to an RFC requirement or an RFC-called-out security consideration.

- **Fail**: hard error; must not proceed.
- **Warn**: log + surface; proceed allowed.
- **Info**: optional diagnostics.

#### Fail-fast (MUST) cases

| Case | Applies to | Verification | RFC rationale |
|---|---|---|---|
| F-01 | All discovered URLs | Parse per RFC 3986; reject invalid URI syntax. Require absolute HTTPS URLs for issuer identifiers, protected resource identifiers, and any endpoints we will call. | RFC 3986; RFC 8414; RFC 9728 |
| F-02 | Issuer + resource identifiers | Reject identifiers containing query/fragment where prohibited: issuer MUST have no query/fragment; resource indicators MUST NOT include fragment. | RFC 8414 (issuer); RFC 9207 (iss); RFC 8707 (resource: no fragment) |
| F-03 | AS well-known URL construction | When forming `/.well-known/oauth-authorization-server`, remove a terminating `/` from an issuer that has a path component before inserting `/.well-known/`. | RFC 8414 §3.1 |
| F-04 | RS well-known URL construction | When forming `/.well-known/oauth-protected-resource`, remove a terminating `/` following the host before inserting `/.well-known/` when the resource identifier contains a path or query component. | RFC 9728 §3.1 |
| F-05 | AS metadata response | Require HTTP 200 and `Content-Type: application/json`; JSON must parse to an object. | RFC 8414 §3.2 |
| F-06 | RS metadata response | Require HTTP 200 and `Content-Type: application/json`; JSON must parse to an object. | RFC 9728 §3.2 |
| F-07 | Issuer binding (AS metadata) | Require returned `issuer` to be identical to the issuer used to form the metadata URL; otherwise discard metadata. | RFC 8414 §3.3 + §4 |
| F-08 | Resource binding (RS metadata) | Require returned `resource` to be identical to the resource identifier used to form the metadata URL (or the URL used to call the RS when metadata URL came from `WWW-Authenticate`); otherwise discard metadata. | RFC 9728 §3.3 + §6 |
| F-09 | String equality rules | All security-relevant comparisons (issuer, resource, `iss`, etc.) use code-point equality; do not apply Unicode normalization. | RFC 8414 §4; RFC 9728 §6; RFC 9207 §2.4 (refers to RFC 3986 string comparison) |
| F-10 | Network fetch hardening | SSRF defenses for all metadata-driven fetches: block internal/special-purpose IP ranges; protect against DNS rebinding; cap redirects; reject redirects to disallowed targets. | RFC 9728 §7.7; RFC 1918; RFC 6890 |
| F-11 | TLS requirements | Enforce TLS and validate certificates for all metadata URLs and endpoints; fail closed on TLS errors. | RFC 9728 §7.1; RFC 8414 §6.1 |
| F-12 | Bearer token transport | Enforce `bearer_methods_supported` from RS metadata. If only `header` is allowed, MUST NOT send token via query or body. Never use more than one bearer method per request. | RFC 9728 (`bearer_methods_supported`); RFC 6750 §2 |
| F-13 | Redirect handling (metadata fetches) | Follow redirects only for safe GET/HEAD and only to absolute HTTPS `Location` URIs that still pass SSRF policy. | RFC 9110; RFC 9728 §7.7 |
| F-14 | JWKS (if validating JWTs) | If tokens are JWTs, fetch `jwks_uri` and require a valid JWK Set with `keys` array; reject malformed sets. | RFC 7517 §2 |
| F-15 | JWT claim checks (if JWTs used) | Validate signature; reject if `aud` (when present) does not include this client/service, and reject if `exp` is in the past. | RFC 7519 §4.1.3 and §4.1.4 |
| F-16 | Mix-up defense (multi-issuer clients) | If `iss` is present in authorization responses, decode and compare to expected issuer; reject on mismatch. Ensure issuer identifiers are unique across configured ASs. | RFC 9207 §2.4 and §4 |

#### Warn-only (SHOULD) cases

| Case | Applies to | Verification | RFC rationale |
|---|---|---|---|
| W-01 | OAuth endpoints vs issuer | Warn if endpoints are on a different host/registrable domain than issuer (common for large providers). Treat as phishing/misrouting signal, not a hard block. | RFC 8414 §6.2 (impersonation risks); RFC 9207 (mix-up context) |
| W-02 | PKCE posture | Warn if `code_challenge_methods_supported` is missing `S256`. Prefer S256; treat `plain` as legacy. | RFC 7636 (S256 vs plain threat model); RFC 8414 (`code_challenge_methods_supported`) |
| W-03 | Scopes hygiene | Warn if caller requests scopes not required for the target resource; encourage least-privilege. | RFC 9728 §7.2 |
| W-04 | Audience restriction posture | Warn if client operates across multiple resources but does not use Resource Indicators to request audience-restricted tokens. | RFC 8707 §2; RFC 9728 §7.4 |
| W-05 | Protected resources cross-check | If AS metadata includes `protected_resources`, cross-check it against RS metadata for consistency when enumerations are used. | RFC 9728 §4 (protected_resources + cross-check guidance) |

#### Optional (INFO) probes

| Case | Applies to | Verification | RFC rationale |
|---|---|---|---|
| I-01 | Endpoint sanity probes | Optional: send non-sensitive, intentionally-invalid requests (e.g., missing params) to check endpoints behave like OAuth endpoints (expect OAuth-style errors, not generic 200 pages). | RFC 6749 (error responses) |
| I-02 | Metadata caching | Optional: honor HTTP caching headers with bounded TTL to reduce latency and repeated network calls. | RFC 9110 (HTTP semantics) |

### Output format

The validator should emit a per-artifact report with:

1. Field name  
2. URL value  
3. Result (**Fail / Warn / Info**)  
4. Short reason string  
5. RFC references (one or more)

Downstream tooling can gate execution on **Fail** results.

### Success metrics

- **Zero** acceptance of metadata with issuer/resource mismatch (per RFC 8414 / RFC 9728).
- SSRF hardening: **no** fetches to internal/special-purpose ranges; **no** redirect-based bypasses.
- High compatibility: major providers (Google, Microsoft, Okta, etc.) validate without host-coincidence false positives (**Warn-only**).

---

## Roadmap

### Phase 1: DCR Authentication Support

| ID   | Feature                       | Description                                                                              | Status  |
|------|-------------------------------|------------------------------------------------------------------------------------------|---------|
| R-01 | DCR with initial access token | Add `--dcr-token` flag to authenticate DCR requests. AuthProbe sends `Authorization:     | Planned |
|      |                               | Bearer <token>` to the registration endpoint when provided, enabling testing of          |         |
|      |                               | protected DCR endpoints. Also support `AUTHPROBE_DCR_TOKEN` environment variable for     |         |
|      |                               | CI/CD.                                                                                   |         |
| R-02 | Client Credentials Flow       | Add `--client-id` and `--client-secret` flags to obtain access tokens via OAuth 2.0      | Planned |
|      |                               | Client Credentials grant (RFC 6749 Section 4.4). No user interaction required.           |         |
|      |                               | AuthProbe POSTs to token endpoint with `grant_type=client_credentials` and uses the      |         |
|      |                               | returned token for authenticated MCP calls. Ideal for CI/CD and service accounts.        |         |
| R-03 | DCR grant_types validation    | Detect servers that incorrectly reject valid DCR requests due to overly strict           | Planned |
|      |                               | grant_types validation. RFC 7591 allows clients to register with only                    |         |
|      |                               | `authorization_code`; requiring `refresh_token` is non-compliant.<br><br>                |         |
|      |                               | **Symptom:** Client registration fails with "invalid grant_types" even though            |         |
|      |                               | the request is RFC-compliant.<br><br>                                                    |         |
|      |                               | **Test case:**<br>                                                                       |         |
|      |                               | `POST /register` with `{"grant_types": ["authorization_code"]}`<br>                      |         |
|      |                               | Expected: 201 Created<br>                                                                |         |
|      |                               | Failure: 400 because `refresh_token` not included<br><br>                                |         |
|      |                               | **Finding:** `DCR_GRANT_TYPES_OVERLY_STRICT` (MEDIUM) - server rejects valid             |         |
|      |                               | authorization_code-only registration, blocking zero-touch MCP client onboarding.         |         |
