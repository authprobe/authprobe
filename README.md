# `authprobe` — MCP OAuth Diagnostics

[![Build Status](https://github.com/authprobe/authprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/authprobe/authprobe/actions/workflows/go.yml)
[![License](https://img.shields.io/github/license/authprobe/authprobe)](https://github.com/authprobe/authprobe/blob/main/LICENSE)
[![Security Status](https://snyk.io/test/github/authprobe/authprobe/badge.svg)](https://snyk.io/test/github/authprobe/authprobe)


`authprobe` is a tool that tells you *exactly why* **MCP OAuth** is broken.

Remote MCP servers + OAuth fail for boring reasons. Left unresolved, these may result in hours of debugging and broken implementations. `authprobe` helps identify and pinpoint the exact deviation from the spec.

`authprobe` focuses on the most failure-prone parts of MCP OAuth. Getting MCP OAuth working well means following a bunch of specs and handling all edge cases. Miss one spec detail and you can lose days chasing “nothing’s happening” bugs. You need a reliable way to pinpoint what’s actually wrong. Is it your MCP server or your OAuth setup ? `authprobe scan <https://mcp>` lets to find the gaps

For a detailed funnel breakdown (steps, expectations, RFCs, and failure codes), see [docs/funnel.md](docs/funnel.md).

Example scan output and funnel step map: [docs/scan-google-compute-mcp.md](docs/scan-google-compute-mcp.md).
Example scan **verbose** output and funnel step map: [docs/scan-google-compute-mcp.md](docs/scan-google-compute-mcp-verbose.md).

Relevant RFCs that make MCP OAuth complex:
- Model Context Protocol (MCP) Specification
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 8707 — Resource Indicators for OAuth 2.0
- RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients
- RFC 7517 — JSON Web Key (JWK)
- RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax
- RFC 9110 — HTTP Semantics

---

## Quickstart

### Install (binary)
Download the latest release binary from GitHub Releases and put it on your PATH.

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```
---

## What you get

### 1) Funnel view (what broke, where)
```text
$ authprobe scan https://staging.example.com/mcp

Funnel
  [1] MCP probe (401 + WWW-Authenticate) ............... PASS
  [2] MCP initialize + tools/list ...................... PASS
  [3] PRM fetch matrix ................................. FAIL (404)
  [4] Auth server metadata ............................. SKIP
  [5] Token endpoint readiness (heuristics) ............ SKIP

Primary finding (HIGH): DISCOVERY_ROOT_WELLKNOWN_404 (confidence 0.92)
Next steps: review the finding details and apply the suggested changes manually
```

## Core commands

### `authprobe scan <mcp_url>`
Diagnose MCP OAuth by running a staged probe.

Common flags:
- `--help`
- `--timeout <sec>`
- `--mcp <mode>` (off, best-effort, strict MCP 2025-11-25 conformance checks)
- `--rfc <mode>` (off, best-effort, strict RFC conformance checks)
- `--allow-private-issuers` (bypass [SSRF protection](docs/ssrf-protection.md) for internal networks)
- `--verbose` (print request/response headers + bodies during scan)
- `--explain` (print RFC rationale for each scan step)
- `--tool-list` / `--tool-detail <name>` (print MCP tool metadata)
- Outputs: `--md`, `--json`, `--sarif`, `--bundle`, `--output-dir` (use `--json -` for stdout-only JSON)


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
