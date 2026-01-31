# `authprobe` — MCP OAuth Diagnostics

[![Build Status](https://github.com/authprobe/authprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/authprobe/authprobe/actions/workflows/go.yml)
[![License](https://img.shields.io/github/license/authprobe/authprobe)](https://github.com/authprobe/authprobe/blob/main/LICENSE)
[![Security Status](https://snyk.io/test/github/authprobe/authprobe/badge.svg)](https://snyk.io/test/github/authprobe/authprobe)


`authprobe` pinpoints **MCP OAuth** failures.

MCP + OAuth breaks for mundane reasons—missing headers, wrong content types, malformed metadata. `authprobe scan <mcp_url>` walks the discovery flow and reports exactly where it diverges from spec.

See [docs/funnel.md](docs/funnel.md) for the full breakdown of what gets checked and why.

Specs involved: [MCP](https://modelcontextprotocol.io/specification), [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728), [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517), [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986), [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110).

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
- Outputs: `--md`, `--json`, `--bundle`, `--output-dir` (use `--json -` for stdout-only JSON)


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
