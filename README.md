# `authprobe` — MCP OAuth Diagnostics

[![CI Build](https://github.com/authprobe/authprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/authprobe/authprobe/actions/workflows/go.yml)
[![Security Status](https://snyk.io/test/github/authprobe/authprobe/badge.svg)](https://snyk.io/test/github/authprobe/authprobe)
[![Join Discord](https://img.shields.io/badge/Join-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/ZYRjaZEsNV)
[![Open in GitHub Codespaces](https://img.shields.io/badge/Open%20in-GitHub%20Codespaces-2f363d?logo=github&logoColor=white)](https://github.com/codespaces/new?hide_repo_select=true&repo=authprobe/authprobe)


`authprobe` pinpoints **MCP OAuth** failures.

MCP + OAuth breaks for mundane reasons like missing headers, wrong content types, malformed metadata. `authprobe scan <mcp_url>` walks the discovery flow and reports exactly where it diverges from spec.

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                               AuthProbe Scan Funnel                                  │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  [1] Discovery ──► [2] MCP Init ──► [3] PRM ──► [4] Auth Server ──► [5] Token ──► [6] DCR
│        │                │              │              │                │           │ │
│        ▼                ▼              ▼              ▼                ▼           ▼ │
│     401 + WWW-     initialize +    Fetch PRM     Fetch issuer       POST        DCR  │
│     Authenticate   tools/list      metadata      metadata          probe       probe │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

See [docs/funnel.md](docs/funnel.md) for the full breakdown of what gets checked and why.

Specs involved: [MCP](https://modelcontextprotocol.io/specification), [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728), [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517), [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986), [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110).

---

## Quickstart

### Install (binary)
Download the latest release binary from GitHub Releases and put it on your PATH.

### Install (Docker)
```bash
docker pull ghcr.io/authprobe/authprobe:latest
docker run --rm ghcr.io/authprobe/authprobe:latest scan https://mcp.example.com/mcp
docker run --rm ghcr.io/authprobe/authprobe:latest scan \
	https://compute.googleapis.com/mcp --openai-api-key=<key>

```

### Install (Clone Repository)
```bash
git clone https://github.com/authprobe/authprobe.git && \
      cd authprobe && \
      go run cmd/authprobe/main.go scan https://mcp.example.com/mcp
```

### Check version
```bash
authprobe --version
authprobe 0.4.0 (commit 92d5fada10399cd96da6521536ed746464592c93, built 2026-02-09T05:48:13Z)
```

### Isolating Failure using `authprobe`

AuthProbe helps you isolate failures by capturing network traces for failed probe steps and optionally using an LLM to explain RFC compliance gaps.

#### Run Basic Scan

```bash
authprobe scan https://mcp.example.com/mcp
```

#### Get an RFC-based explanation of the failure

```bash
authprobe scan https://mcp.example.com/mcp --explain
```

#### Get verbose output for failure

Shows the complete trace of request/response that went on the wire to help understand failure

```bash
authprobe scan https://mcp.example.com/mcp --explain --trace-failure
```

#### Have a LLM model explain failure

Use a LLM to request analysis of failure. `llm-max-tokens` defaults to `600` if a value isn't provided

```bash
export OPENAI_API_KEY=<key>
authprobe scan https://mcp.example.com/mcp --explain --trace-failure --llm-max-tokens=1080
```

To use Anthropic

```bash
export ANTHROPIC_API_KEY=<key>
authprobe scan https://mcp.example.com/mcp --explain --trace-failure --llm-max-tokens=1080
```

## What you get

The scan produces a funnel view output and an LLM explanation of spec
expectations if an Anthropic or OpenAI API key is provided.

### 1) Funnel view (what broke, where)
```text

$ go run cmd/authprobe/main.go scan https://aws-mcp.us-east-1.api.aws/mcp --trace-failure
Command:   authprobe scan --trace-failure https://aws-mcp.us-east-1.api.aws/mcp
Scanning:  https://aws-mcp.us-east-1.api.aws/mcp
Scan time: Feb 09, 2026 04:44:41 UTC
Github:    https://github.com/authprobe/authprobe

Funnel
  [1] MCP probe (401 + WWW-Authenticate)      [-] SKIP
        probe returned 405; checking PRM for OAuth config

  [2] MCP initialize + tools/list             [X] FAIL
        initialize -> 401 (error: Authentication failed: Unable to verify your
        user identity. Please ensure you are properly authenticated and try
        again.)

  [3] PRM fetch matrix                        [X] FAIL
        https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource
        -> 405
        https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource/mcp
        -> 405
        PRM unreachable or unusable; OAuth discovery unavailable

  [4] Auth server metadata                    [-] SKIP
        no authorization_servers in PRM

  [5] Token endpoint readiness (heuristics)   [-] SKIP
        no token_endpoint in metadata

  [6] Dynamic client registration (RFC 7591)  [-] SKIP
        no registration_endpoint in metadata

Primary Finding (HIGH): AUTH_REQUIRED_BUT_NOT_ADVERTISED (confidence 1.00)
  Evidence:
      initialize -> 401
      initialize error: Authentication failed: Unable to verify your user identity. Please
      ensure you are properly authenticated and try again.
      WWW-Authenticate: (missing)
      https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource -> 405
      https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource/mcp -> 405
      PRM unreachable or unusable; OAuth discovery unavailable
      Auth appears required but OAuth discovery was not advertised. Next steps: add
      WWW-Authenticate + PRM for OAuth/MCP discovery, or document the required non-OAuth auth
      (e.g., SigV4).

┌─────────────────────┤ RFC RATIONALE ├──────────────────────┐
Explain (RFC 9728 rationale)
1) MCP probe
- AuthProbe sends an unauthenticated GET to https://aws-mcp.us-east-1.api.aws/mcp.
- RFC 9728 discovery hinges on a 401 with WWW-Authenticate that includes resource_metadata.
- resource_metadata hint: (none)

2) MCP initialize + tools/list
- AuthProbe sends an MCP initialize request followed by tools/list to enumerate server tools.

3) Protected Resource Metadata (PRM) discovery
- RFC 9728 defines PRM URLs by inserting /.well-known/oauth-protected-resource between the host and path.
- https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource (root)
- https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource/mcp (path-suffix)
- Because the resource has a path, the path-suffix PRM endpoint is required by RFC 9728.
- PRM responses must be JSON objects with a resource that matches the target URL; trailing-slash mismatches are warned for compatibility.
- authorization_servers is required for OAuth discovery; it lists issuer URLs.

4) Authorization server metadata
- No authorization_servers found in PRM, so AuthProbe skips metadata fetches.

5) Token endpoint readiness (heuristics)
- AuthProbe sends a safe, invalid grant request to the token endpoint to observe error response behavior.
- It flags non-JSON responses or HTTP 200 responses that still contain error payloads.

┌───────────────────────┤ CALL TRACE ├───────────────────────┐
Call Trace Using: https://github.com/authprobe/authprobe

  ┌────────────┐                                                    ┌────────────┐
  │ authprobe  │                                                    │ MCP Server │
  └─────┬──────┘                                                    └─────┬──────┘
        │                                                                 │
        │ ╔═══ Step 1: MCP probe                    ═══════╪═══════════════════╗
        │  GET https://aws-mcp.us-east-1.api.aws/mcp
        │  Reason: 401 + WWW-Authenticate discovery
        │    Accept:  text/event-stream
        │    Host:    aws-mcp.us-east-1.api.aws
        ├─────────────────────────────────────────────────────────────────►│
        │  405 Method Not Allowed
        │    Allow:           POST
        │    Content-Length:  102
        │    Date:            Mon, 09 Feb 2026 04:44:41 GMT
        │    Server:          CloudFront
        │    Via:             1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
        │    X-Amz-Cf-Id:     hFriapAaoBgVX_B09D4MbK1-SDPg9l6VwvOw67mrScOeCh5N2ywTWA==
        │    X-Amz-Cf-Pop:    SFO53-P7
        │    X-Cache:         LambdaGeneratedResponse from cloudfront
        │◄─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │ ╔═══ Step 2: MCP initialize               ═══════╪═══════════════════╗
        │  POST https://aws-mcp.us-east-1.api.aws/mcp
        │  Reason: Step 2: MCP initialize + tools/list (pre-init tools/list)
        │    Accept:                application/json, text/event-stream
        │    Content-Type:          application/json
        │    Host:                  aws-mcp.us-east-1.api.aws
        │    Mcp-Protocol-Version:  2025-11-25
        ├─────────────────────────────────────────────────────────────────►│
        │  401 Unauthorized
        │    Content-Length:  194
        │    Date:            Mon, 09 Feb 2026 04:44:41 GMT
        │    Server:          CloudFront
        │    Via:             1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
        │    X-Amz-Cf-Id:     b-ejOK7BHXqcZ_OFbQHqbli8XnA6ZqH160dnpSlKzCbYcuMBG7aLJQ==
        │    X-Amz-Cf-Pop:    SFO53-P7
        │    X-Cache:         LambdaGeneratedResponse from cloudfront
        │◄─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │  POST https://aws-mcp.us-east-1.api.aws/mcp
        │  Reason: Step 2: MCP initialize + tools/list (initialize)
        │    Accept:                application/json, text/event-stream
        │    Content-Type:          application/json
        │    Host:                  aws-mcp.us-east-1.api.aws
        │    Mcp-Protocol-Version:  2025-11-25
        ├─────────────────────────────────────────────────────────────────►│
        │  401 Unauthorized
        │    Content-Length:  194
        │    Date:            Mon, 09 Feb 2026 04:44:41 GMT
        │    Server:          CloudFront
        │    Via:             1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
        │    X-Amz-Cf-Id:     OfTZxhdf7sBGylO_uwnubF6Ug8I6t2hhJtNf3Y2cKY9JJFDKQf8Umg==
        │    X-Amz-Cf-Pop:    SFO53-P7
        │    X-Cache:         LambdaGeneratedResponse from cloudfront
        │◄─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │ ╔═══ Step 3: PRM Discovery                ═══════╪═══════════════════╗
        │  GET https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource
        │  Reason: Step 3: PRM fetch matrix
        │    Accept:  application/json
        │    Host:    aws-mcp.us-east-1.api.aws
        ├─────────────────────────────────────────────────────────────────►│
        │  405 Method Not Allowed
        │    Allow:           POST
        │    Content-Length:  102
        │    Date:            Mon, 09 Feb 2026 04:44:41 GMT
        │    Server:          CloudFront
        │    Via:             1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
        │    X-Amz-Cf-Id:     T7wqge7EjJ7fawHJ8BfpaQtcdWqrxMyChNc0o4-_ljt2fNo-1mf_HA==
        │    X-Amz-Cf-Pop:    SFO53-P7
        │    X-Cache:         LambdaGeneratedResponse from cloudfront
        │◄─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │  GET https://aws-mcp.us-east-1.api.aws/.well-known/oauth-protected-resource/mcp
                │  Reason: Step 3: PRM fetch matrix
        │    Accept:  application/json
        │    Host:    aws-mcp.us-east-1.api.aws
        ├─────────────────────────────────────────────────────────────────►│
        │  405 Method Not Allowed
        │    Allow:           POST
        │    Content-Length:  102
        │    Date:            Mon, 09 Feb 2026 04:44:41 GMT
        │    Server:          CloudFront
        │    Via:             1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
        │    X-Amz-Cf-Id:     2M5Zpj2fh9-HHFROy6R7AsPxt-IesLDAZJ88YUTB89QHcI3cIDEZBw==
        │    X-Amz-Cf-Pop:    SFO53-P7
        │    X-Cache:         LambdaGeneratedResponse from cloudfront
        │◄─────────────────────────────────────────────────────────────────┤
        ▼                                                                  ▼

┌───────────────┤ FAILED TEST VERBOSE OUTPUT ├───────────────┐
== Step 2: MCP initialize + tools/list (initialize) ==
> POST /mcp HTTP/1.1
> Host: aws-mcp.us-east-1.api.aws
> Accept: application/json, text/event-stream
> Content-Type: application/json
> Mcp-Protocol-Version: 2025-11-25
>
> {"id":1,"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"authprobe","version":"0.1"},"protocolVersion":"2025-11-25"}}
< HTTP/2.0 401 Unauthorized
< Content-Length: 194
< Date: Mon, 09 Feb 2026 04:44:41 GMT
< Server: CloudFront
< Via: 1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
< X-Amz-Cf-Id: j6vZ5X5OT7GHbC1CYUDbNgj8UoBSjaVMxgfv1v5TFAeUdxyZFeLf7g==
< X-Amz-Cf-Pop: SFO53-P7
< X-Cache: LambdaGeneratedResponse from cloudfront
<
< {"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-32001,"message":"Authentication failed: Unable to verify your user identity. Please ensure you are properly authenticated and try again."}}

== Step 3: PRM fetch matrix ==
> GET /.well-known/oauth-protected-resource HTTP/1.1
> Host: aws-mcp.us-east-1.api.aws
> Accept: application/json
>
> (empty body)
< HTTP/2.0 405 Method Not Allowed
< Allow: POST
< Content-Length: 102
< Date: Mon, 09 Feb 2026 04:44:41 GMT
< Server: CloudFront
< Via: 1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
< X-Amz-Cf-Id: D-2GdRq0lEgNouiYU-ZtnS7O4f0Qcc_mv2o6wKnk9UrYdjtRhTWPRQ==
< X-Amz-Cf-Pop: SFO53-P7
< X-Cache: LambdaGeneratedResponse from cloudfront
<
< {"jsonrpc":"2.0","id":"","result":null,"error":{"code":-32600,"message":"HTTP method not supported."}}

== Step 3: PRM fetch matrix ==
> GET /.well-known/oauth-protected-resource/mcp HTTP/1.1
> Host: aws-mcp.us-east-1.api.aws
> Accept: application/json
>
> (empty body)
< HTTP/2.0 405 Method Not Allowed
< Allow: POST
< Content-Length: 102
< Date: Mon, 09 Feb 2026 04:44:41 GMT
< Server: CloudFront
< Via: 1.1 6269ff653a8a0b71d436afa999909318.cloudfront.net (CloudFront)
< X-Amz-Cf-Id: j4naZq2teP4ZUsfzCQM2hohEVUBCPpahdMOzbzUaBbe2pa3Lc214hg==
< X-Amz-Cf-Pop: SFO53-P7
< X-Cache: LambdaGeneratedResponse from cloudfront
<
< {"jsonrpc":"2.0","id":"","result":null,"error":{"code":-32600,"message":"HTTP method not supported."}}

┌────────────────────┤ LLM EXPLANATION ├─────────────────────┐
### Summary of the Primary Finding: AUTH_REQUIRED_BUT_NOT_ADVERTISED (High Severity)

The scan indicates that the AWS MCP server at
`https://aws-mcp.us-east-1.api.aws/mcp` requires authentication
for the `initialize` call (returns HTTP 401 Unauthorized), but it
fails to properly advertise the authentication scheme(s).
Crucially, the server does **not** provide a `WWW-Authenticate`
header in the 401 response, and the OAuth discovery endpoints
(Protected Resource Metadata or PRM) are unavailable (returning
HTTP 405 Method Not Allowed). This combination violates key
requirements for OAuth-protected resources per MCP 2025-11-25
and RFC 9728, and results in interoperability and client
implementation issues.

---

## Detailed Explanation / Compliance Analysis

### 1. Auth Required But Not Advertised

#### Evidence:
- **Step [2]** shows the MCP `initialize` method returns
  **401 Unauthorized** with the error
  `"Authentication failed: Unable to verify your user identity"`.
- The response **lacks a `WWW-Authenticate` header**.
- The PRM endpoints
  (`/.well-known/oauth-protected-resource` and subpath) return
  **405 Method Not Allowed**
  (not the expected 200 OK with metadata).
- OAuth discovery configuration via PRM is therefore
  **unavailable** or **unreachable**.

---

### 2. Relevant Specification Requirements

#### MCP 2025-11-25 (MCP Spec for OAuth)
- Section 4.4 (Authentication and OAuth Discovery) requires:
  - When an endpoint requires authentication, the server
    **MUST** respond with a `401 Unauthorized` status
    **including** a `WWW-Authenticate` header indicating the
    authentication scheme(s).
  - The client relies on this header to understand how to
    authenticate (e.g., Bearer tokens as per RFC 6750).
- Section 5 (OAuth Discovery) requires:
  - The OAuth Protected Resource Metadata (PRM) endpoint
    **MUST** exist and respond with a `200 OK` and a JSON
    document describing the OAuth configuration
    (see RFC 8414, RFC 9728).
  - This metadata enables clients to perform OAuth
    discovery — learn the authorization, token endpoints,
    and supported features.
- When OAuth discovery is not provided, the MCP server
  **MUST** document the non-OAuth authentication mechanism
  clearly so clients can interact correctly.

#### RFC 9728 (OAuth Metadata for Resource Servers)
- Defines that the **protected resource** must expose OAuth
  metadata at a well-known URI
  (e.g., `/.well-known/oauth-protected-resource`).
- The resource server **MUST** respond to a GET request to
  this URI with **200 OK** and a JSON payload containing
  OAuth metadata.
- The 405 (Method Not Allowed) response here violates this.

#### RFC 8414 (OAuth 2.0 Authorization Server Metadata)
- Sets expectations for OAuth discovery metadata endpoints
  (authorization server side).
- By analogy and extension in MCP, clients expect metadata
  for resource servers per RFC 9728.

#### HTTP Semantics (RFC 7235 - Authentication)
- A `401 Unauthorized` response **MUST** include a
  `WWW-Authenticate` header indicating the authentication
  challenge.
- Servers omitting `WWW-Authenticate` in a 401 response
  violate this and leave clients guessing how to
  authenticate.

---

### 3. Why Is This a Valid and Justified Failure?

- The server requires authentication for the `initialize`
  method, but provides **no information to clients on how
  to authenticate**:
  - Missing `WWW-Authenticate` header after 401.
  - No exposed OAuth discovery metadata
    (missing / malformed PRM endpoint).
- This incomplete and non-compliant implementation breaks
  the fundamental client discovery and authentication flow
  defined in MCP and OAuth specs.
- `405` on the PRM endpoint is an invalid response because
  the metadata endpoint is **expected to support GET** and
  respond with valid metadata (RFC 9728).
- Consequently, clients cannot discover or execute OAuth
  authentication, causing interoperability failures.

---

### 4. Correct Server Behavior per Specifications

- **Handling 401 Unauthorized with OAuth** (MCP 2025-11-25, RFC 7235):
  Respond with HTTP 401 **including a `WWW-Authenticate` header**,
  e.g., `WWW-Authenticate: Bearer realm="aws-mcp",
  error="invalid_token",
  error_description="Invalid or missing token"`
- **Expose OAuth Discovery Metadata** (RFC 9728):
  Implement a valid PRM endpoint at
  `https://.../.well-known/oauth-protected-resource` returning
  **200 OK** with a JSON payload listing authorization servers,
  token endpoint URLs, supported scopes, token types, etc.
- **Support HTTP GET on PRM Endpoint**:
  PRM endpoint **must support the GET method** and return JSON
  metadata, not 405.
- **If Non-OAuth Auth is Used** (MCP 2025-11-25):
  Document the authentication mechanism clearly (e.g., AWS SigV4),
  and do **not** mislead clients by requiring OAuth authentication
  without discovery metadata or WWW-Authenticate. Servers can omit
  OAuth metadata but must include correct HTTP auth headers or
  documentation.







```

## Core commands

### `authprobe scan <mcp_url>`
Diagnose MCP OAuth by running a staged probe.

Common flags:
- `--help`
- `-H`, `--header <k:v>` (add request header, repeatable)
- `--timeout <sec>` (default: 8)
- `--mcp <mode>` (off, best-effort, strict MCP 2025-11-25 conformance checks)
- `--rfc <mode>` (off, best-effort, strict RFC conformance checks)
- `--allow-private-issuers` (bypass [SSRF protection](docs/ssrf-protection.md) for internal networks)
- `--insecure` (skip TLS certificate verification; for dev/testing with self-signed certs)
- `--no-follow-redirects` (stop at first response; useful for debugging redirect chains)
- `--fail-on <level>` (exit code 2 if findings at/above severity: none, low, medium, high; default: high)
- `-v`, `--verbose` (print request/response headers + bodies during scan)
- `--trace-failure` (include verbose output of failed probe steps in report)
- `--no-redact` (disable redaction in verbose logs and evidence bundles)
- `-e`, `--explain` (print RFC rationale for each scan step)
- `--openai-api-key <key>` (or set `OPENAI_API_KEY`; enables LLM explanations)
- `--anthropic-api-key <key>` (or set `ANTHROPIC_API_KEY`; enables LLM explanations; if both set, OpenAI is used)
- `--llm-max-tokens <n>` (max output tokens for LLM explanations; default: 700)
- `-l`, `--tool-list` (print MCP tool names)
- `-d`, `--tool-detail <name>` (print a single MCP tool's full JSON definition)
- Outputs: `--json`, `--md`, `--trace-ascii`, `--bundle`, `--output-dir` (use `-` for stdout, e.g., `--json -` or `--md -`)


Examples:
```bash
MCP_URL="https://mcp.example.com/mcp"

# Basic scan
authprobe scan $MCP_URL

# Custom header (e.g. internal hostname routing)
authprobe scan $MCP_URL -H "Host: internal.example.com"

# Strict RFC + MCP conformance checks
authprobe scan $MCP_URL --rfc strict --mcp strict

# Verbose output with failure traces
authprobe scan $MCP_URL --verbose --trace-failure

# RFC rationale for every probe step
authprobe scan $MCP_URL --explain

# LLM-powered explanation (OpenAI)
authprobe scan $MCP_URL --openai-api-key $OPENAI_API_KEY

# CI gate: fail if any medium-or-above finding
authprobe scan $MCP_URL --fail-on medium

# All outputs at once
authprobe scan $MCP_URL \
  --md report.md --json report.json \
  --trace-ascii trace.txt --bundle evidence.zip

# Stream JSON to jq
authprobe scan $MCP_URL --json - | jq '.findings'

# Full diagnostic run: strict checks, verbose, failure traces,
# LLM explanation, all outputs into a directory
authprobe scan $MCP_URL \
  --rfc strict --mcp strict \
  --verbose --trace-failure --explain \
  --openai-api-key $OPENAI_API_KEY \
  --output-dir ./scan-results

# Self-signed dev server, no redirects, relaxed failure threshold
authprobe scan $MCP_URL \
  --insecure --no-follow-redirects \
  --allow-private-issuers --fail-on none

# List available MCP tools
authprobe scan $MCP_URL --tool-list

# Inspect a specific tool definition
authprobe scan $MCP_URL --tool-detail "my_tool_name"
```

## Outputs (great for CI and GitHub issues)

### Markdown report
```bash
authprobe scan https://mcp.example.com/mcp --md report.md
```

### JSON report (stable schema)
```bash
authprobe scan https://mcp.example.com/mcp --json report.json
```

### Evidence bundle (sanitized)
```bash
authprobe scan https://mcp.example.com/mcp --bundle evidence.zip
```

Attach `report.md` or the evidence bundle to GitHub issues to make troubleshooting concrete.

---

## CI / GitHub Actions (recurring protection)
AuthProbe is designed to be a regression tripwire in CI.

Typical pattern:
- run `authprobe scan` against staging on PR
- fail the build if severity ≥ `high`
- upload `report.md` and `report.json` artifacts

### GitHub Action
Use the bundled action to run scans and upload artifacts:

```yaml
jobs:
  authprobe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: authprobe/authprobe@v0.1.0
        with:
          mcp_url: https://mcp.example.com/mcp
          args: --fail-on medium --rfc strict
```

Action inputs (all optional except `mcp_url`):

| Input              | Default                    | Description                                       |
|--------------------|----------------------------|---------------------------------------------------|
| `version`          | `latest`                   | Release version (e.g., `v0.1.0` or `latest`)      |
| `command`          | `scan`                     | AuthProbe command to run                           |
| `mcp_url`          | —                          | MCP endpoint URL (required when `command=scan`)    |
| `args`             | `""`                       | Additional CLI flags passed to AuthProbe           |
| `report_md`        | `authprobe-report.md`      | Markdown report output path (empty to skip)        |
| `report_json`      | `authprobe-report.json`    | JSON report output path (empty to skip)            |
| `bundle`           | `authprobe-evidence.zip`   | Evidence bundle output path (empty to skip)        |
| `upload_artifacts` | `true`                     | Upload reports as workflow artifacts                |

---

## FAQ

### Is MCP OAuth really that fragile?
It can be. Client discovery behaviors differ, infra strips headers, `.well-known` endpoints get mounted under prefixes, and auth server behavior varies by provider. AuthProbe exists to make that failure surface deterministic.

### Correctness
AuthProbe is under active development. We have manually verified
over 100 reported failures against the relevant RFCs to confirm
that the tool's output matches the specifications. That said,
there may be corner cases - unusual server configurations, edge
cases in spec interpretation, or uncommon protocol flows - where
findings are not fully accurate. If you spot one, please open an
issue with the scan output (`--json -` or `--bundle`).

---

## Contributing
Contributions that help the ecosystem most:
- Bug reports with scan output (`--json -` or `--bundle`)
- New test fixtures (sanitized real-world failure traces)
- Expanded RFC conformance checks or new finding codes
- Improved redaction, report stability, and output formatting
- Documentation fixes and additional usage examples

---

## Keywords (for humans and search)
MCP OAuth, Model Context Protocol authentication, MCP 2025-11-25,
Streamable HTTP, JSON-RPC 2.0, Server-Sent Events (SSE),
OAuth 2.0 discovery, OAuth proxy troubleshooting,
Protected Resource Metadata (PRM), `oauth-protected-resource`,
`.well-known`, `resource_metadata`, `authorization_servers`,
Dynamic Client Registration (DCR), PKCE S256,
OIDC discovery, JWKS, JWT,
`WWW-Authenticate`, Bearer token, `token_endpoint`,
RFC 9728, RFC 8414, RFC 6749, RFC 6750, RFC 7591,
RFC 7636, RFC 8707, RFC 7235, RFC 3986, RFC 9110,
MCP server authentication, MCP conformance testing,
SSRF protection, redaction, evidence bundle.

---
