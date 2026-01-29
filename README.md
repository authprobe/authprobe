# AuthProbe — MCP OAuth Diagnostics

[![Build Status](https://github.com/authprobe/authprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/authprobe/authprobe/actions/workflows/go.yml)
[![License](https://img.shields.io/github/license/authprobe/authprobe)](https://github.com/authprobe/authprobe/blob/main/LICENSE)
[![Security Status](https://snyk.io/test/github/authprobe/authprobe/badge.svg)](https://snyk.io/test/github/authprobe/authprobe)


**AuthProbe** is a tool that tells you *exactly why* **MCP OAuth** is broken.

Remote MCP servers + OAuth fail for boring reasons. Left unresolved, these may result in hours of debugging and broken implementations. `authprobe` helps identify and pinpoint the exact deviation from the spec.

Some boring problems that authprobe can check - `/.well-known/oauth-protected-resource` is missing at the **root**, `WWW-Authenticate` / `resource_metadata` headers are missing or stripped by a proxy, PRM (`oauth-protected-resource` JSON) is malformed or points to the wrong resource path, auth server metadata is inconsistent, token endpoints behave differently than clients expect (JSON vs form-encoded, HTTP 200 + error payload), different clients follow different discovery flows. This list will evolve as we add more checks

---

## Quickstart

### Install (binary)
Download the latest release binary from GitHub Releases and put it on your PATH.

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```

> `matrix` is a stub command in the current v0.1 CLI and will print a "not implemented" message.

---

## What you get

### 1) Funnel view (what broke, where)
```text
$ authprobe scan https://staging.example.com/mcp --profile vscode

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
- `--profile generic|vscode|inspector` (`-p` alias)
- `-H "Header: Value"` (repeatable)
- `--proxy http://127.0.0.1:8080`
- `--timeout <sec>`, `--connect-timeout <sec>`, `--retries <n>`
- `--fail-on none|low|medium|high`
- `--verbose` (print request/response headers + bodies during scan)
- `--explain` (print RFC 9728 rationale for each scan step)
- `--show-trace` (print MCP probe trace)
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

## What AuthProbe checks (MCP OAuth stages)

AuthProbe focuses on the most failure-prone parts of MCP OAuth:

For a detailed funnel breakdown (steps, expectations, RFCs, and failure codes), see [docs/funnel.md](docs/funnel.md).

### Discovery (MCP → OAuth bootstrap)
- Does the MCP endpoint respond with `401` and a usable `WWW-Authenticate` header?
- Is there a `resource_metadata=...` pointer for PRM?

### MCP initialize + tools/list
- Does the MCP server accept `initialize` and `tools/list` after probing?

### Protected Resource Metadata (PRM)
- Is `/.well-known/oauth-protected-resource` reachable at the root?
- Does the path-suffix variant exist when needed?
- Does PRM include `authorization_servers`?
- Is PRM `resource` canonical and pointing to the actual MCP endpoint path?

### Authorization server metadata
- Are metadata endpoints reachable and parseable?
- Are critical endpoints present (authorization, token, registration when applicable)?

### Token endpoint readiness (heuristics)
- Do token responses look JSON vs form-encoded?
- Are there provider quirks like HTTP 200 + `error` payload patterns?

### Infra risk flags
- Does behavior suggest header stripping by a proxy/WAF?
- Is this setup likely to break under multi-instance state (warning in v0.1)?

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

## Privacy & redaction
AuthProbe is **redaction-first**:
- tokens/cookies are removed or fingerprinted
- transcripts store shapes and headers needed for diagnosis
- `--no-redact` exists only for local debugging and is **not recommended**

---

## FAQ

### “Is MCP OAuth really that fragile?”
It can be. Client discovery behaviors differ, infra strips headers, `.well-known` endpoints get mounted under prefixes, and auth server behavior varies by provider. AuthProbe exists to make that failure surface deterministic.

### “Can it help if OAuth succeeds but requests are still 401?”
Yes — that’s usually token propagation vs token validation. v0.1 focuses on discovery/metadata/token readiness; later versions can add deeper token propagation checks and debug-proxy capture modes.

---

## Contributing
Contributions that help the ecosystem most:
- new fixtures (sanitized real-world failure traces)
- new client profiles
- new deterministic guidance examples
- hardening redaction and report stability

---

## Project status
AuthProbe is currently **experimental** while the feature set and output formats stabilize.

---

## Keywords (for humans and search)
MCP OAuth, Model Context Protocol authentication, OAuth discovery, oauth-protected-resource, `.well-known`, `resource_metadata`, PRM, RFC 9728, RFC 8414, token endpoint parsing, VS Code MCP, MCP Inspector, MCP server authentication, OAuth proxy troubleshooting.

---
