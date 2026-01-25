# AuthProbe — MCP OAuth Diagnostics (scan, matrix, fix)

**AuthProbe** is a fast CLI that tells you *exactly why* **MCP OAuth** is broken - and how to fix it.

It runs a staged probe (discovery → metadata → token readiness → auth header checks), compares behavior across common client styles (VS Code vs Inspector-ish), and generates **copy/paste remediation snippets** for the most common failure modes.

If you’ve ever stared at a mysterious `401`, a `/.well-known` 404, or an “OAuth succeeded but still unauthorized” loop… this is for you.

---

## Why AuthProbe exists

Remote MCP servers + OAuth fail for boring reasons:
- `/.well-known/oauth-protected-resource` is missing at the **root**
- `WWW-Authenticate` / `resource_metadata` headers are missing or stripped by a proxy
- PRM (`oauth-protected-resource` JSON) is malformed or points to the wrong resource path
- auth server metadata is inconsistent
- token endpoints behave differently than clients expect (JSON vs form-encoded, HTTP 200 + error payload)
- different clients follow different discovery flows
- Verify [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728/)

AuthProbe turns that chaos into a 1-page diagnosis with evidence and a concrete fix path.

---

## Quickstart

### Install (binary)
Download the latest release binary from GitHub Releases and put it on your PATH.

### Run a scan
```bash
authprobe scan https://mcp.example.com/mcp
```

### Compare client compatibility
```bash
authprobe matrix https://mcp.example.com/mcp
```

### Generate a fix snippet
```bash
authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx --explain
```

---

## What you get

### 1) Funnel view (what broke, where)
```text
$ authprobe scan https://staging.example.com/mcp --profile vscode

Funnel
  [1] MCP probe (401 + WWW-Authenticate) ............... PASS
  [2] PRM fetch (from resource_metadata) ............... PASS
  [3] PRM fetch (root /.well-known) .................... FAIL (404)
  [4] Auth server metadata ............................. SKIP

Primary finding (HIGH): DISCOVERY_ROOT_WELLKNOWN_404 (confidence 0.92)
Fix: authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx --explain
```

### 2) Compatibility matrix (works for X, fails for Y)
```text
$ authprobe matrix https://staging.example.com/mcp

| profile    | result | failing step | primary finding              |
|------------|--------|--------------|------------------------------|
| generic    | PASS   | -            | -                            |
| vscode     | FAIL   | PRM(root)    | DISCOVERY_ROOT_WELLKNOWN_404 |
| inspector  | PASS   | -            | -                            |
```

### 3) Deterministic fixes (copy/paste, no vibes)
AuthProbe ships with remediation generators for common MCP OAuth failures (FastAPI shims, Nginx/Envoy rewrites/forwarding rules, minimal PRM templates, etc.).

---

## Core commands

### `authprobe scan <mcp_url>`
Diagnose MCP OAuth by running a staged probe.

Common flags:
- `--profile generic|vscode|inspector`
- `-H "Header: Value"` (repeatable)
- `--proxy http://127.0.0.1:8080`
- `--fail-on none|low|medium|high`
- `--verbose` (print request/response headers + bodies during scan)
- Outputs: `--md`, `--json`, `--sarif`, `--bundle`

Examples:
```bash
authprobe scan https://mcp.example.com/mcp --profile vscode
authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com"
authprobe scan https://mcp.example.com/mcp --md report.md --json report.json --bundle evidence.zip
```

### `authprobe matrix <mcp_url>`
Run multiple client profiles and show divergences.

Examples:
```bash
authprobe matrix https://mcp.example.com/mcp
authprobe matrix https://mcp.example.com/mcp --profiles vscode,inspector --format md
```

### `authprobe fix <FINDING_CODE>`
Generate a remediation snippet for a finding.

Examples:
```bash
authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target fastapi --explain
authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx
authprobe fix HEADER_STRIPPED_BY_PROXY_SUSPECTED --target envoy --out envoy-snippet.yaml
```

---

## What AuthProbe checks (MCP OAuth stages)

AuthProbe focuses on the most failure-prone parts of MCP OAuth:

### Discovery (MCP → OAuth bootstrap)
- Does the MCP endpoint respond with `401` and a usable `WWW-Authenticate` header?
- Is there a `resource_metadata=...` pointer for PRM?

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

### “Does AuthProbe fix my system automatically?”
AuthProbe generates deterministic snippets and verify commands. It doesn’t mutate your infrastructure by itself.

### “Can it help if OAuth succeeds but requests are still 401?”
Yes — that’s usually token propagation vs token validation. v0.1 focuses on discovery/metadata/token readiness; later versions can add deeper token propagation checks and debug-proxy capture modes.

---

## Contributing
Contributions that help the ecosystem most:
- new fixtures (sanitized real-world failure traces)
- new client profiles
- new deterministic remediation snippets
- hardening redaction and report stability

---

## Keywords (for humans and search)
MCP OAuth, Model Context Protocol authentication, OAuth discovery, oauth-protected-resource, `.well-known`, `resource_metadata`, PRM, RFC 9728, RFC 8414, token endpoint parsing, VS Code MCP, MCP Inspector, MCP server authentication, OAuth proxy troubleshooting.

---
