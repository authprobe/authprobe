# Architecture

This document describes the high-level architecture of AuthProbe.
If you want to familiarize yourself with the codebase, you are in the right place.

See also `docs/PRD.md` for the product requirements and finding code catalog.

## Bird's Eye View

AuthProbe diagnoses broken OAuth flows on remote MCP servers. Given an MCP
endpoint URL, it runs a staged "funnel" of HTTP probes -- discovery, metadata
fetch, token readiness, dynamic client registration -- and produces a report
with deterministic finding codes, severity/confidence scores, and RFC
references. No browser, no credentials, no side effects.

It ships as a single Go binary with two faces:

- **CLI** (`authprobe scan <url>`) for humans and CI pipelines.
- **MCP server** (`authprobe mcp`) that exposes the same scan engine as
  JSON-RPC tools, so AI agents can diagnose OAuth issues programmatically.

There are zero external Go dependencies (`go.mod` has no `require` block).

## Code Map

```
authprobe/
├── cmd/authprobe/       # main.go -- injects build metadata, calls cli.Run
├── internal/
│   ├── cli/             # CLI layer: flag parsing, command routing, output writing
│   ├── scan/            # Core scan engine: probes, funnel, output formatting
│   │   └── llm/         # LLM provider adapters (OpenAI, Anthropic)
│   └── mcpserver/       # Embedded MCP server (stdio + HTTP transports)
├── docs/PRD.md          # Product requirements, finding codes, severity rules
├── action.yml           # GitHub Action wrapper
└── Dockerfile
```

### `cmd/authprobe`

The entry point. `main.go` sets version/commit/date via `cli.SetVersionInfo`,
then delegates to `cli.Run`. Nothing else lives here.

### `internal/cli`

Parses `os.Args` and routes to `scan` or `mcp` subcommands. For `scan`, it
builds a `ScanConfig`, calls `scan.RunScanFunnel`, then writes outputs (JSON,
Markdown, trace, bundle) based on flags. The CLI layer never makes HTTP
requests directly -- it only constructs config and consumes the report.

Important files:

- `cli.go` -- command router and `runScan` orchestration
- `mcp.go` -- launches the embedded MCP server (stdio or HTTP)
- `help.go` -- help text constants (canonical `--help` output)
- `normalize.go` -- flag/argument normalization utilities

### `internal/scan`

The heart of the project. Contains the scan funnel, all probe logic, HTTP
utilities, output formatting, and finding construction.

Important files:

- `funnel.go` -- orchestrates the 6-step scan funnel; owns the `funnel` struct
  that carries HTTP client, config, accumulated trace entries, and findings
- `probe.go` -- implements OAuth discovery probes (Steps 1, 3-6): PRM fetch
  matrix, auth server metadata, token endpoint readiness, DCR probing
- `mcp.go` -- MCP protocol handling (Step 2): JSON-RPC `initialize`,
  `notifications/initialized`, `tools/list`, conformance checks
- `output.go` -- report rendering: stdout funnel view, Markdown, JSON, ASCII
  call trace, evidence bundle (zip)
- `utils.go` -- shared HTTP helpers, URL validation, SSRF protection, finding
  factory (`newFinding`), header redaction
- `verbose.go` -- verbose request/response formatting with redaction awareness
- `llm.go` -- builds prompts for LLM-powered explanations of scan results
- `stdio_gateway.go` -- HTTP-to-stdio bridge for scanning local MCP servers
  launched via `--stdio-command`
- `version_negotiation.go` -- MCP protocol version negotiation logic

### Stdio Gateway

The stdio gateway (`stdio_gateway.go`) bridges AuthProbe's HTTP-based scan flow
to local MCP servers that communicate via stdio JSON-RPC instead of HTTP.

When the user passes `--stdio-command`, `StartStdioGateway` spawns the command
as a child process, opens its stdin/stdout pipes, and starts a local HTTP server
on an ephemeral `127.0.0.1` port. Incoming HTTP POST requests are written as
newline-delimited JSON-RPC to the process's stdin; the response line read from
stdout is returned as the HTTP response body. GET requests return a minimal SSE
response for probe compatibility.

The gateway is transparent to the rest of the scan engine -- it produces a
`http://127.0.0.1:<port><path>` URL that the funnel treats like any remote MCP
endpoint. A `/debug` endpoint exposes request counts, recent stderr, and the
last request/response for troubleshooting. The gateway is torn down after the
scan via a cleanup function that shuts down the HTTP server and kills the child
process.

### `internal/mcpserver`

A self-contained JSON-RPC server that wraps the scan engine as MCP tools.
Supports both stdio (newline-delimited JSON-RPC) and HTTP POST transports.

The server exposes five tools:

- `authprobe.scan_http` -- unauthenticated scan
- `authprobe.scan_http_with_credentials` -- authenticated scan
- `authprobe.scan_resume` -- resume an in-progress OAuth device flow
- `authprobe.render_markdown` -- render a Markdown report from scan results
- `authprobe.bundle_evidence` -- create a redacted evidence zip

Scan results are cached by `scan_id` with session TTL management.

Important types: `Server`, `scanSession`.

## Key Types

Use symbol search to find these -- they are the load-bearing types:

- **`ScanConfig`** (scan package) -- everything needed to run a scan: target
  URL, headers, timeouts, mode flags, output paths. Flows from CLI to funnel.
- **`ScanReport`** (scan package) -- the final scan result: steps, findings,
  auth discovery summary, trace. Flows from funnel to output renderers.
- **`ScanStep`** (scan package) -- one step's outcome: ID, name, status
  (PASS/FAIL/SKIP), detail string.
- **`Finding`** (scan package) -- a diagnostic issue: code, severity,
  confidence, evidence lines. Finding codes are stable identifiers enumerated
  in `docs/PRD.md`.
- **`TraceEntry`** (scan package) -- an HTTP request/response pair captured
  during the scan, used for verbose output and evidence bundles.
- **`funnel`** (scan package, unexported) -- the scan orchestrator. Holds the
  HTTP client, config, accumulated steps/findings/trace, PRM result, and auth
  server metadata. Created per-scan, not reused.
- **`Server`** (mcpserver package) -- the MCP server. Holds tool definitions,
  scan cache, session map, and credential provider interface.

## The Scan Funnel

The funnel is a fixed sequence of 6 steps. Each step can PASS, FAIL, or SKIP.
Steps may be skipped when a prerequisite fails or when auth is required but no
token is available. The funnel always runs to completion -- it does not
short-circuit.

```
Step 1: MCP probe          GET the endpoint, expect 401 + WWW-Authenticate
Step 2: MCP initialize     JSON-RPC initialize + tools/list (skipped if auth required)
Step 3: PRM fetch matrix   Fetch Protected Resource Metadata from well-known URLs
Step 4: Auth server meta   Fetch authorization server metadata (RFC 8414 / OIDC)
Step 5: Token readiness    Probe token endpoint with invalid grant (heuristic)
Step 6: DCR probe          Probe dynamic client registration endpoint (RFC 7591)
```

After all steps run, `buildReport` aggregates findings and selects exactly one
**primary finding** (highest severity, then highest confidence). The report,
together with output config, drives rendering.

## Invariants

- **One primary finding per scan.** The scan always selects at most one primary
  finding. This is a product invariant -- users get a single decisive answer.

- **Finding codes are stable.** Codes like `DISCOVERY_NO_WWW_AUTHENTICATE` are
  public API. They appear in JSON reports, CI gates (`--fail-on`), and
  documentation. Adding codes is fine; changing or removing existing codes is a
  breaking change.

- **Redaction by default.** Sensitive headers (`Authorization`, `Cookie`,
  `Set-Cookie`) and JSON fields (`access_token`, `refresh_token`, `client_secret`)
  are redacted in all outputs unless `--no-redact` is explicitly passed. This is
  a security invariant -- no code path should emit raw secrets.

- **No external dependencies.** The `go.mod` has no `require` block. This is
  intentional -- it keeps the binary small, the supply chain minimal, and
  compilation fast. Think hard before adding one.

- **The funnel struct is per-scan and not reused.** Each `RunScanFunnel` call
  creates a fresh `funnel`. Probe functions accumulate state (findings, trace)
  on this struct. There is no global mutable state.

- **SSRF protection is on by default.** Metadata-driven fetches block
  private/loopback/link-local targets unless `--allow-private-issuers` is set.

## Boundaries

The project has three distinct layers with clean boundaries:

```
┌─────────────┐     ┌──────────────┐
│   CLI       │     │  MCP Server  │
│ (cli pkg)   │     │ (mcpserver)  │
└──────┬──────┘     └──────┬───────┘
       │                   │
       │   ScanConfig      │   ScanConfig
       │   ──────────►     │   ──────────►
       │                   │
       ▼                   ▼
┌──────────────────────────────────┐
│         Scan Engine              │
│         (scan pkg)               │
│                                  │
│  funnel → probes → findings      │
│  HTTP client (no global state)   │
│  output renderers                │
└──────────────────────────────────┘
```

- **CLI → Scan:** The CLI constructs a `ScanConfig` and calls
  `scan.RunScanFunnel`. It never touches HTTP directly. After the scan, it
  receives a `ScanReport` and writes outputs.

- **MCP Server → Scan:** The MCP server also calls `scan.RunScanFunnel` with a
  `ScanConfig`. It adds session management and scan caching on top, but the
  scan itself is identical to the CLI path.

- **Scan → HTTP:** All HTTP I/O is encapsulated in the `funnel` struct's
  client. Timeout, TLS, redirect policy, and custom headers are configured once
  at funnel creation. Probe functions use shared helpers from `utils.go`
  (`fetchJSON`, `doRequest`, etc.) rather than constructing requests directly.

- **Scan → Output:** Report rendering (`output.go`) consumes `ScanReport` and
  `ScanConfig` but does not call probes or make HTTP requests. It is a pure
  formatting layer.

## Cross-Cutting Concerns

**HTTP client configuration.** Timeout, TLS verification (`--insecure`),
redirect following (`--no-follow-redirects`), and custom headers (`-H`) are
configured once when the `funnel` is created. All probes share the same client.

**Redaction.** Implemented in `utils.go`. Applied to verbose output, trace
entries, and evidence bundles. Covers both HTTP headers and JSON body fields.

**Finding system.** Findings are the primary diagnostic output. Each has a
stable code, severity (high/medium/low), confidence (0.0-1.0), and evidence
lines. Severity and confidence are assigned by the probe that creates the
finding -- they are not computed from other data. The `newFinding` helper in
`utils.go` enforces the structure.

**LLM explanations.** Optional. When an API key is provided (`--openai-api-key`
or `--anthropic-api-key`), `llm.go` builds a prompt from the scan context and
findings, sends it to the provider via `scan/llm/`, and appends the explanation
to the report. The LLM adapters in `scan/llm/` are thin HTTP wrappers with no
shared state.

**Trace logging.** Every HTTP request/response pair is captured as a
`TraceEntry` during the scan. This powers verbose output (`-v`), the ASCII call
trace (`--trace-ascii`), failed-step traces (`--trace-failure`), and evidence
bundles (`--bundle`).
