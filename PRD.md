# AuthProbe v0.1 PRD

**Product:** AuthProbe  
**Summary:** MCP OAuth diagnostics in minutes (discovery → metadata → token readiness → auth header checks)  
Developer-first CLI for debugging broken MCP OAuth flows, with proof-grade evidence and copy/paste remediation.

---

## 1) Executive summary

AuthProbe is a CLI that pinpoints *where* MCP OAuth breaks (and *why*) across common client behaviors (e.g., VS Code vs Inspector-style), then generates deterministic remediation snippets and verification commands.

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
> “Tell me exactly what’s wrong with my MCP OAuth setup, with evidence, and give me the fastest safe fix.”

---

## 3) Goals (v0.1)

1) **Time-to-root-cause < 2 minutes** for common failures  
2) **One primary finding** per scan (decisive, evidence-backed)  
3) **Client compatibility matrix** across 3 profiles (generic, vscode, inspector)  
4) **Deterministic fixes** for the most frequent failure modes (fastapi/nginx/envoy/generic)  
5) **CI-ready**: stable finding codes, exit codes, severity gating, machine-readable outputs  
6) **Redaction-by-default** for anything sensitive (tokens, cookies, secrets)

### RFC 9728 conformance (v0.1)
AuthProbe should validate **OAuth Protected Resource Metadata** behavior per RFC 9728 in a way that’s useful to developers:
- Default: **best-effort** conformance checks (fail on key MUST violations; warn on SHOULD/best-practice gaps).
- Optional: **strict** mode for CI gates and “spec-hardening” work.

---

## 4) Non-goals (explicitly out of scope for v0.1)

- Browser-based OAuth login automation (Authorization Code + PKCE end-to-end)  
- Running as a permanent reverse proxy/gateway  
- Full runtime observability agent  
- Managed SaaS scanner  
- Provider-specific deep integrations (Okta/Entra/Keycloak packs)

These are Phase 2+ after CLI adoption.

---

## 5) Product surface (CLI)

### Canonical commands (must ship)
- `authprobe scan <mcp_url>`
- `authprobe matrix <mcp_url>`
- `authprobe fix <FINDING_CODE> --target <fastapi|nginx|envoy|generic>`

### Helper commands (small, but recommended)
- `authprobe profiles`
- `authprobe explain <FINDING_CODE>`

### Profiles (minimum set)
- `generic` — spec-forward baseline
- `vscode` — root `/.well-known` sensitivity and common direct discovery behavior
- `inspector` — probe-first / header-driven discovery tolerance

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

**(Optional Step 5: Authenticated MCP call)**
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

### `--rfc9728` modes
- `off`: skip RFC 9728-specific checks (only core MCP/OAuth checks).
- `best-effort` (default): fail on key MUST violations; warn on SHOULD/best-practice gaps.
- `strict`: fail on all MUST violations + escalate key SHOULD gaps to failures (CI-friendly).

### Private issuer safety (SSRF guardrail)
When fetching authorization server metadata from `authorization_servers`, AuthProbe must avoid accidental SSRF:
- By default, block **private/loopback/link-local** issuer targets.
- Allow override for enterprise/internal deployments via `--allow-private-issuers`.

---

## 7) Finding codes (v0.1 must-have)

Finding codes are stable identifiers. Each finding includes:
- severity (low/medium/high)
- confidence (0–1)
- evidence (sanitized)
- remediation references (snippet IDs and verify commands)

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
Token endpoint behavior suggests form-encoded responses likely; warn when profile expects JSON.

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

---

## 8) Remediation generator (v0.1)

`authprobe fix <FINDING_CODE> --target <...>` outputs deterministic snippets and steps.

### Minimum remediation coverage for v0.1
- `DISCOVERY_ROOT_WELLKNOWN_404`
  - FastAPI shim route (serve PRM at root)
  - Nginx rewrite snippet
  - Envoy route guidance
- `DISCOVERY_NO_WWW_AUTHENTICATE`
  - How to emit `WWW-Authenticate` correctly
  - Nginx/Envoy header forwarding guidance
- `PRM_MISSING_AUTHORIZATION_SERVERS`
  - Minimal valid PRM template
- `PRM_RESOURCE_MISMATCH`
  - Guidance + example corrected PRM `resource`
- `HEADER_STRIPPED_BY_PROXY_SUSPECTED`
  - Nginx/Envoy header allow/forward snippet + verification steps
- `PRM_HTTP_STATUS_NOT_200`, `PRM_CONTENT_TYPE_NOT_JSON`, `PRM_NOT_JSON_OBJECT`, `PRM_RESOURCE_MISSING`
  - “Minimal valid PRM” template + debugging checklist
- `PRM_JWKS_URI_NOT_HTTPS`, `PRM_BEARER_METHODS_INVALID`, `PRM_SIGNING_ALG_NONE_FORBIDDEN`
  - Field constraint explanation + corrected examples
- `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`
  - Explain SSRF guardrail + `--allow-private-issuers` override (with caution)

Every fix output MUST include:
- snippet ID (e.g., `fix/nginx/prm_root_rewrite.conf`)
- when to use it
- verify command (always ends with `authprobe scan ...`)

---

## 9) Outputs and artifacts

### Stdout (developer-first)
- Funnel view + primary finding + 3-line evidence + next best action

### Files
- `--md report.md` (human, PR/issue friendly)
- `--json report.json` (machine, stable schema)
- `--sarif report.sarif` (optional for GitHub code scanning)
- `--bundle evidence.zip` containing:
  - `trace.jsonl` (sanitized HTTP transcript)
  - `report.json`
  - `report.md`
  - `meta.json` (tool version, profile, timestamp, settings)

### Exit codes
- `0` = no findings at/above `--fail-on`
- `2` = findings at/above `--fail-on`
- `3` = tool/runtime error (invalid args, unreachable host, etc.)

---

## 10) Security & privacy (v0.1 constraints)

- Redaction ON by default.
- Never store or emit full tokens/cookies/secrets in logs or bundles.
- `--no-redact` exists only for local debugging and is flagged as unsafe.

Redaction rules (baseline):
- `Authorization`, `Cookie`, `Set-Cookie` → removed or token-fingerprinted
- bodies → only shape-level info (content-type, key presence), no raw credentials

---

## 11) Acceptance criteria (definition of done)

### `scan`
- Prints funnel with PASS/FAIL/SKIP per step
- Selects exactly ONE primary finding (highest severity, highest confidence)
- Includes >= 3 evidence lines (request + status + key header presence)
- Produces valid markdown + JSON outputs consistent with stdout
- `--bundle` creates zip with required files and redaction applied

### `matrix`
- Runs scan per profile and prints compact comparison
- Includes: result, failing step, primary finding per profile
- Supports `--format table|md|json`
- Exit respects `--fail-on`

### `fix`
- For each supported finding code + target, generates deterministic snippet
- `--explain` adds rationale and verification commands

---

## 12) Test plan (fixtures-first)

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
- Golden file tests must validate report stability
- Finding selection order must be deterministic

---

## 13) Release packaging (v0.1)

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
4) Profiles + matrix orchestration  
5) Fix generator for top codes (fastapi/nginx/envoy/generic)  
6) Fixtures + golden tests  
7) Release packaging (binaries + docker + action)

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
  -p, --profile <name>     Client behavior profile to simulate.
                           Options: generic, vscode, inspector
                           Default: generic

  -H, --header <k:v>       Add a request header (repeatable).
                           Example: -H "Host: internal.example.com"

      --proxy <url>        HTTP(S) proxy for outbound requests.
                           Example: --proxy http://127.0.0.1:8080

      --timeout <sec>      Overall scan timeout in seconds. Default: 60
      --connect-timeout <sec>
                           Connection timeout in seconds. Default: 10
      --retries <n>        Retry failed GETs for metadata endpoints. Default: 1

      --rfc9728 <mode>     RFC 9728 conformance checks for protected resource metadata.
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
      --json <path>        Write structured JSON report to file.
      --md <path>          Write Markdown report to file.
      --sarif <path>       Write SARIF report (GitHub code scanning) to file.
      --bundle <path>      Write sanitized evidence bundle (zip) to file.
      --output-dir <dir>   Write all requested outputs into a directory.

DIAGNOSTICS:
      --verbose            Verbose logs (includes request timeline; still redacted).
      --no-redact          Disable redaction (NOT recommended; for local debugging only).

EXAMPLES:
  authprobe scan https://mcp.example.com/mcp
  authprobe scan https://mcp.example.com/mcp --profile vscode --md report.md --json report.json
  authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com" --fail-on medium
  authprobe scan https://mcp.example.com/mcp --bundle evidence.zip
  authprobe scan https://mcp.example.com/mcp --rfc9728 strict
```

### `authprobe matrix --help`
```text
authprobe matrix: Compare MCP OAuth compatibility across multiple client profiles and show where behavior diverges.

USAGE:
  authprobe matrix <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
      --profiles <list>    Comma-separated list of profiles to run.
                           Options: generic, vscode, inspector
                           Default: generic,vscode,inspector

  -H, --header <k:v>       Add a request header (repeatable).
      --proxy <url>        HTTP(S) proxy for outbound requests.
      --timeout <sec>      Overall timeout per profile in seconds. Default: 60

      --rfc9728 <mode>     RFC 9728 conformance checks for protected resource metadata.
                           Options: off, best-effort, strict
                           Default: best-effort

      --allow-private-issuers
                           Allow fetching authorization server metadata from private/loopback/link-local issuers.
                           (Use only in trusted networks.)

      --insecure           Allow invalid TLS certificates (dev only).
      --no-follow-redirects
                           Do not follow HTTP redirects.

      --fail-on <level>    Exit non-zero if any profile has findings at/above this severity.
                           Options: none, low, medium, high
                           Default: high

OUTPUTS:
      --format <fmt>       Output format for stdout.
                           Options: table, md, json
                           Default: table

      --json <path>        Write structured JSON matrix to file.
      --md <path>          Write Markdown matrix to file.
      --bundle <path>      Write sanitized evidence bundle (zip) containing per-profile traces.

DIAGNOSTICS:
      --verbose            Verbose logs (includes request timeline; still redacted).

EXAMPLES:
  authprobe matrix https://mcp.example.com/mcp
  authprobe matrix https://mcp.example.com/mcp --profiles vscode,inspector --format md
  authprobe matrix https://mcp.example.com/mcp --json matrix.json --bundle matrix-evidence.zip
```

### `authprobe fix --help`
```text
authprobe fix: Generate remediation snippets for a specific finding code.

USAGE:
  authprobe fix <FINDING_CODE> [flags]

ARGUMENTS:
  <FINDING_CODE>           Finding code from `authprobe scan` or `authprobe matrix`.
                           Example: DISCOVERY_ROOT_WELLKNOWN_404

FLAGS:
  -t, --target <name>      Target environment to generate a snippet for.
                           Options: fastapi, starlette, nginx, envoy, cloudflare, generic
                           Default: generic

      --out <path>         Write the snippet to a file (stdout by default).
      --explain            Include rationale and verification steps.
      --smart              Use Smart Fix mode (LLM-assisted) to tailor the snippet.
                           Requires --smart-endpoint or AUTH_PROBE_SMART_ENDPOINT env var.

      --smart-endpoint <url>
                           URL for Smart Fix backend (optional; advanced).
      --context <path>     Optional path to config/context file (YAML/JSON/text) used by --smart.
                           Example: ingress.yaml, nginx.conf, values.yaml

EXAMPLES:
  authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target fastapi
  authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx --explain
  authprobe fix HEADER_STRIPPED_BY_PROXY_SUSPECTED --target envoy --out envoy-snippet.yaml
  authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx --smart --context ingress.yaml
```

---

## 16) Appendix B — Golden example (report shape expectations)

A golden Markdown report must include:
- Target, profile, timestamp
- funnel table (steps)
- primary finding with severity/confidence
- evidence block with sanitized request/response facts
- remediation snippet references + generation commands
- verify command(s)

(Use the golden example from the design discussion as the fixture reference.)
