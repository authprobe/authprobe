# AuthProbe — MCP OAuth Diagnostics

[![Build Status](https://github.com/authprobe/authprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/authprobe/authprobe/actions/workflows/go.yml)
[![License](https://img.shields.io/github/license/authprobe/authprobe)](https://github.com/authprobe/authprobe/blob/main/LICENSE)
[![Security Status](https://snyk.io/test/github/authprobe/authprobe/badge.svg)](https://snyk.io/test/github/authprobe/authprobe)


**AuthProbe** is a tool that tells you *exactly why* **MCP OAuth** is broken.

Remote MCP servers + OAuth fail for boring reasons. Left unresolved, these may result in hours of debugging and broken implementations. `authprobe` helps identify and pinpoint the exact deviation from the spec.

AuthProbe focuses on the most failure-prone parts of MCP OAuth. For a detailed funnel breakdown (steps, expectations, RFCs, and failure codes), see [docs/funnel.md](docs/funnel.md).

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

### 2) Ensure your MCP server works with different clients (Claude, VS Code, generic, Inspector)
Use `--profile` on `scan` to emulate client-specific discovery behavior.

VS Code profile highlights:
- Enforces strict PRM `resource` equality against the resolved MCP endpoint (post-redirect).
- Prefers path-suffix PRM discovery (`/.well-known/oauth-protected-resource/<path>`).
- Warns on legacy root auth-server well-known probe failures and whitespace in scopes.

---

## Core commands

### `authprobe scan <mcp_url>`
Diagnose MCP OAuth by running a staged probe.

Common flags:
- `--help`
- `--timeout <sec>`, `--connect-timeout <sec>`, `--retries <n>`
- `--verbose` (print request/response headers + bodies during scan)
- `--explain` (print RFC 9728 rationale for each scan step)
- `--tool-list` / `--tool-detail <name>` (print MCP tool metadata)
- Outputs: `--md`, `--json`, `--sarif`, `--bundle`, `--output-dir` (use `--json -` for stdout-only JSON)


Examples:
```bash
authprobe scan https://mcp.example.com/mcp --profile vscode
authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com"
authprobe scan https://mcp.example.com/mcp --md report.md --json report.json --bundle evidence.zip
authprobe scan https://mcp.example.com/mcp --json - | jq '.findings'
```

### `authprobe matrix <mcp_url>`
Run multiple client profiles and show divergences.

> Note: `matrix` is a stub in v0.1 and prints "not implemented".

Examples:
```bash
authprobe matrix https://mcp.example.com/mcp
authprobe matrix https://mcp.example.com/mcp --format md
```
---

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
- new client profiles
- new deterministic guidance examples
- hardening redaction and report stability

---

## Keywords (for humans and search)
MCP OAuth, Model Context Protocol authentication, OAuth discovery, oauth-protected-resource, `.well-known`, `resource_metadata`, PRM, RFC 9728, RFC 8414, token endpoint parsing, VS Code MCP, MCP Inspector, MCP server authentication, OAuth proxy troubleshooting.

---
