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
```

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```
---

## What you get

### 1) Funnel view (what broke, where)
```text
Command:   authprobe scan https://compute.googleapis.com/mcp
Scanning:  https://compute.googleapis.com/mcp
Scan time: Feb 02, 2026 05:48:18 UTC

Funnel
  [1] MCP probe (401 + WWW-Authenticate)      [-] SKIP
        probe returned 405; checking PRM for OAuth config

  [2] MCP initialize + tools/list             [+] PASS
        initialize -> 200
        notifications/initialized -> 202
        tools/list -> 200 (tools: create_instance, delete_instance,
        start_instance, stop_instance, +25 more)

  [3] PRM fetch matrix                        [+] PASS
        https://compute.googleapis.com/.well-known/oauth-protected-resource ->
        404
        https://compute.googleapis.com/.well-known/oauth-protected-resource/mcp
        -> 200

  [4] Auth server metadata                    [X] FAIL
        https://accounts.google.com/.well-known/oauth-authorization-server ->
        200

  [5] Token endpoint readiness (heuristics)   [-] SKIP
        no token_endpoint in metadata

  [6] Dynamic client registration (RFC 7591)  [-] SKIP
        no registration_endpoint in metadata

Primary finding (HIGH): AUTH_SERVER_ISSUER_MISMATCH (confidence 1.00)
  Evidence:
      issuer mismatch: metadata issuer "https://accounts.google.com", expected
      "https://accounts.google.com/"
      RFC 8414 requires the metadata issuer to exactly match the issuer used for discovery.
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
