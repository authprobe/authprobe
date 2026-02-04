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
	https://compute.googleapis.com/mcp --openai-api-key=$OPENAI_API_KEY ```

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```
---

## What you get

The scan produces a funnel view output and an LLM explanation of spec
expectations if an Anthropic or OpenAI API key is provided.

### 1) Funnel view (what broke, where)
```text
Command:   authprobe scan https://knowledge-mcp.global.api.aws Scanning:
https://knowledge-mcp.global.api.aws
Scan time: Feb 04, 2026 20:02:52 UTC

Funnel
  [1] MCP probe (401 + WWW-Authenticate)      [-] SKIP
        probe returned 405; checking PRM for OAuth config

  [2] MCP initialize + tools/list             [X] FAIL
        initialize -> 200
        notifications/initialized -> 202
        tools/list -> 200 (tools: aws___get_regional_availability,
        aws___list_regions, aws___read_documentation, aws___recommend, +1 more)

  [3] PRM fetch matrix                        [+] PASS
        https://knowledge-mcp.global.api.aws/.well-known/oauth-protected-resource
        -> 200
        no OAuth configuration found

  [4] Auth server metadata                    [-] SKIP
        auth not required

  [5] Token endpoint readiness (heuristics)   [-] SKIP
        auth not required

  [6] Dynamic client registration (RFC 7591)  [-] SKIP
        auth not required

Primary finding (HIGH): MCP_JSONRPC_ID_NULL_ACCEPTED (confidence 1.00)
Evidence:
      null id probe status 200
      MCP JSON-RPC requires request IDs to be strings or numbers; null IDs
      must be rejected.

LLM explanation
# Analysis of MCP_JSONRPC_ID_NULL_ACCEPTED

## Verdict: **FAILURE IS VALID AND JUSTIFIED**

## Specification Foundation

### JSON-RPC 2.0 Specification (Core Requirement)

**JSON-RPC 2.0 Section 4.1 - Request object:**
> **id**: An identifier established by the Client [...] It MUST contain a
> String, Number, or NULL value.

**JSON-RPC 2.0 Section 4.2 - Response object:**
> **id**: This member is REQUIRED. It MUST be the same as the value of the id
> member in the Request Object.

**JSON-RPC 2.0 Section 5.1 - Notification:**
> A Notification is a Request object **without an "id" member**. [...] The
> Server MUST NOT reply to a Notification, including those that are within a
> batch request.

**Critical distinction:** While JSON-RPC 2.0 allows `"id": null` in request
objects, the semantics are problematic. The specification states that if `id`
is null, it's technically a valid request (not a notification), and the server
MUST respond with a response object containing `"id": null`.

### MCP 2025-11-25 Specification

**MCP 2025-11-25 inherits JSON-RPC 2.0** as its transport layer, but adds clarifications:

**Section "JSON-RPC Messages":**
> MCP uses JSON-RPC 2.0 as its wire format. All messages are JSON-RPC 2.0 compliant.

**Section "Request Identification":**
> Request **id** field: MUST be a string or number (not null)
>
> Notifications: MUST NOT include an id field

This is the **key specification requirement** that applies here. MCP
explicitly narrows JSON-RPC 2.0's allowance of null IDs.

## Why the Failure is Valid

### 1. **MCP Explicitly Prohibits null IDs**

The MCP specification **intentionally restricts** the JSON-RPC 2.0 id space:

- **Allowed in MCP requests:** `string` | `number`
- **Forbidden in MCP requests:** `null`
- **Forbidden in MCP requests:** omitted (that creates a notification)

When the server at `https://knowledge-mcp.global.api.aws` accepted a request
with `"id": null` and returned a 200 response, it violated MCP's narrower
contract.

### 2. **Rationale for the MCP Restriction**

The MCP specification's prohibition of null IDs serves several purposes:

**a) Semantic Clarity:**
- In JSON-RPC 2.0, `"id": null` creates ambiguity: is this a request expecting
  a response, or an improperly formatted notification?
- MCP eliminates this: notifications have NO id field; requests have non-null
  ids

**b)
exit status 2

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
- `--openai-api-key <key>` (or set `OPENAI_API_KEY`; enables LLM explanations)
- `--anthropic-api-key <key>` (or set `ANTHROPIC_API_KEY`; enables LLM explanations)
- `--allow-private-issuers` (bypass [SSRF protection](docs/ssrf-protection.md) for internal networks)
- `--insecure` (skip TLS certificate verification; for dev/testing with self-signed certs)
- `--no-follow-redirects` (stop at first response; useful for debugging redirect chains)
- `--fail-on <level>` (exit code 2 if findings at/above severity: none, low, medium, high; default: high)
- `-v`, `--verbose` (print request/response headers + bodies during scan)
- `-e`, `--explain` (print RFC rationale for each scan step)
- `-l`, `--tool-list` (print MCP tool names)
- `-d`, `--tool-detail <name>` (print a single MCP tool's full JSON definition)
- Outputs: `--md`, `--json`, `--bundle`, `--output-dir` (use `-` for stdout, e.g., `--json -` or `--md -`)


Examples:
```bash
authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com"
authprobe scan https://mcp.example.com/mcp --md report.md --json report.json --bundle evidence.zip
authprobe scan https://mcp.example.com/mcp --json - | jq '.findings'
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
          args: --fail-on high
```

---

## FAQ

### “Is MCP OAuth really that fragile?”
It can be. Client discovery behaviors differ, infra strips headers, `.well-known` endpoints get mounted under prefixes, and auth server behavior varies by provider. AuthProbe exists to make that failure surface deterministic.

---

## Contributing
Contributions that help the ecosystem most:
- new fixtures (sanitized real-world failure traces)
- new deterministic guidance examples
- hardening redaction and report stability

---

## Keywords (for humans and search)
MCP OAuth, Model Context Protocol authentication, OAuth discovery, oauth-protected-resource, `.well-known`, `resource_metadata`, PRM, RFC 9728, RFC 8414, token endpoint parsing, MCP server authentication, OAuth proxy troubleshooting.

---
