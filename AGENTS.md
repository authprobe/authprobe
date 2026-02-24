# AGENTS.md

AuthProbe diagnoses broken MCP OAuth flows. Given an endpoint URL, it runs a
6-step HTTP probe funnel and produces a report with deterministic finding codes,
severity/confidence scores, and RFC references.

## Code Map

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture
document. Quick orientation:

```
cmd/authprobe/          → main.go entry point (injects build metadata, calls cli.Run)
internal/cli/           → CLI layer: flag parsing, command routing, output writing
internal/scan/          → Core scan engine: probes, funnel, findings, output formatting
internal/scan/llm/      → LLM provider adapters (OpenAI, Anthropic)
internal/mcpserver/     → Embedded MCP server (stdio + HTTP transports)
```

## Layer Boundaries

```
CLI (cli pkg)  ──► ScanConfig ──►  Scan Engine (scan pkg)
MCP Server (mcpserver pkg)  ──► ScanConfig ──►  Scan Engine (scan pkg)
```

- **CLI and MCP Server never make HTTP requests directly.** They construct a
  `ScanConfig` and call `scan.RunScanFunnel`.
- **Scan Engine never reads flags or os.Args.** It receives a `ScanConfig`.
- **Output rendering is pure formatting.** `output.go` consumes `ScanReport`
  and `ScanConfig` but never calls probes or makes HTTP requests.

## Invariants

These are non-negotiable. Violating any of them is a breaking change.

1. **Zero external dependencies.** `go.mod` has no `require` block. Do not add one.
2. **One primary finding per scan.** The report selects at most one primary finding.
3. **Finding codes are stable API.** Codes like `DISCOVERY_NO_WWW_AUTHENTICATE`
   appear in JSON reports, CI gates, and docs. Adding new codes is fine;
   changing or removing existing codes is breaking.
4. **Redaction by default.** Sensitive headers and JSON fields are redacted in
   all outputs unless `--no-redact` is explicitly passed.
5. **Per-scan state, no globals.** Each `RunScanFunnel` call creates a fresh
   `funnel` struct. No global mutable state.
6. **SSRF protection on by default.** Metadata-driven fetches block
   private/loopback/link-local targets unless `--allow-private-issuers`.

## Golden Principles

See [docs/core-beliefs.md](docs/core-beliefs.md) for rationale behind each.

- Parse and validate at the boundary (HTTP responses, CLI args)
- Prefer shared helpers (`newFinding`, `fetchJSON`, `doRequest`) over one-off code
- Tests should use `httptest.NewServer` — no real network calls in tests
- Keep files under 500 lines; split when they grow
- Every finding needs evidence lines explaining *why* it fired

## Key Documents

| Document | Purpose |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Code map, key types, layer boundaries |
| [docs/core-beliefs.md](docs/core-beliefs.md) | Golden principles with rationale |
| [docs/QUALITY.md](docs/QUALITY.md) | Quality grades per domain, known gaps |
| [docs/funnel.md](docs/funnel.md) | Scan funnel steps, skip conditions, failure codes |
| [docs/ssrf-protection.md](docs/ssrf-protection.md) | SSRF threat model and implementation |
| [docs/PRD.md](docs/PRD.md) | Product requirements, finding code catalog, severity rules |

## Making Changes

- Run `make lint` before committing to check architectural invariants.
- Run `make test` to run all tests.
- When adding a new finding code, add it to `docs/PRD.md` and the relevant step
  section in `docs/funnel.md`.
- When adding a new package under `internal/`, update the code map in
  `docs/ARCHITECTURE.md`.
- When modifying layer boundaries or invariants, update this file.

## Scan Funnel Quick Reference

```
Step 1: MCP probe        → GET endpoint, expect 401 + WWW-Authenticate
Step 2: MCP initialize   → JSON-RPC initialize + tools/list
Step 3: PRM fetch        → Protected Resource Metadata from well-known URLs
Step 4: Auth server meta → Authorization server metadata (RFC 8414 / OIDC)
Step 5: Token readiness  → Probe token endpoint with invalid grant
Step 6: DCR probe        → Dynamic client registration (RFC 7591)
```

Skip logic: Step 3 never skipped. Steps 4-6 skipped if auth not required.
See [docs/funnel.md](docs/funnel.md) for details.
