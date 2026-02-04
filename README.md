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
docker run --rm ghcr.io/authprobe/authprobe:latest scan https://compute.googleapis.com/mcp --openai-api-key=$OPENAI_API_KEY
```

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```
---

## What you get

The scan produces a funnel view output and an LLM explanation of spec expectations if an Anthropic or OpenAI API key is provided.

### 1) Funnel view (what broke, where)
```text
Command:   authprobe scan https://api.githubcopilot.com/mcp/                                                                                                                                                                                                                [24/9382]
Scanning:  https://api.githubcopilot.com/mcp/
Scan time: Feb 04, 2026 07:00:55 UTC

Funnel
  [1] MCP probe (401 + WWW-Authenticate)      [+] PASS
        401 with resource_metadata

  [2] MCP initialize + tools/list             [-] SKIP                                                                                                                                                                                                                                       initialize -> 401 (non-JSON response) (auth required)

  [3] PRM fetch matrix                        [X] FAIL
        https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/
        -> 200
        https://api.githubcopilot.com/.well-known/oauth-protected-resource ->
        404
        https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp
        -> 200

  [4] Auth server metadata                    [X] FAIL
        https://github.com/login/oauth/.well-known/oauth-authorization-server ->
        404

  [5] Token endpoint readiness (heuristics)   [-] SKIP
        no token_endpoint in metadata

  [6] Dynamic client registration (RFC 7591)  [-] SKIP
        no registration_endpoint in metadata

Primary finding (HIGH): AUTH_SERVER_METADATA_INVALID (confidence 1.00)
  Evidence:
      https://github.com/login/oauth status 404
      RFC 8414 defines required metadata fields such as issuer, authorization_endpoint, and
      token_endpoint.

LLM explanation
# AUTH_SERVER_METADATA_INVALID Analysis

## Summary
**This failure is VALID and JUSTIFIED.** The authorization server metadata endpoint is returning a 404, which violates the OAuth 2.0 Authorization Server Metadata specification (RFC 8414).

## Specification Requirements

### RFC 8414 §3 - Authorization Server Metadata Discovery

RFC 8414 defines the well-known URI pattern for authorization server metadata discovery:

```
https://[authorization-server]/.well-known/oauth-authorization-server
```

The specification states:

> "Authorization servers supporting metadata MUST make a JSON document containing metadata available at a path formed by inserting a well-known URI string into the authorization server's issuer identifier between the host component and the path component, if any."

### MCP 2025-11-25 OAuth Integration

The MCP specification references RFC 9728 for OAuth integration, which in turn relies on RFC 8414 for authorization server discovery. Section on OAuth states:

> "MCP servers SHOULD support OAuth 2.0 for authentication when operating over HTTP transport."

The Protected Resource Metadata (from step 3) points to `https://github.com/login/oauth` as the authorization server via the `authorization_servers` array in the PRM document.

### RFC 9728 §3 - Authorization Server Discovery

RFC 9728 §3.1 states:

> "The protected resource metadata includes an 'authorization_servers' parameter that identifies the authorization servers that can issue access tokens for use with the protected resource."

Once the authorization server identifier is obtained, **RFC 8414 MUST be used to discover the authorization server's metadata**.

## What's Failing

The scan attempted to fetch:
```
https://github.com/login/oauth/.well-known/oauth-authorization-server
```

Result: **404 Not Found**

This means one of two things is wrong:

1. **Incorrect authorization server identifier in PRM**: The PRM document at `https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp` (step 3 shows this returned 200) contains `authorization_servers` array with `"https://github.com/login/oauth"`, but this is not the correct issuer identifier.

2. **Missing metadata endpoint**: GitHub has not implemented RFC 8414 metadata discovery at the expected location.

## Why This Matters

Without valid authorization server metadata, MCP clients cannot:

- **Discover the authorization endpoint** (RFC 8414 §2 - required field `authorization_endpoint`)
- **Discover the token endpoint** (RFC 8414 §2 - required field `token_endpoint`)
- **Determine supported grant types** (RFC 8414 §2 - optional field `grant_types_supported`)
- **Verify PKCE support** (RFC 8414 §2 - optional field `code_challenge_methods_supported`)
- **Determine supported scopes** (RFC 8414 §2 - optional field `scopes_supported`)

RFC
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
