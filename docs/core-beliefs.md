# Core Beliefs

These are the operating principles that guide every decision in authprobe.
They are not aspirational — they describe how the codebase works today and
how it should continue to work. When in doubt, refer back here.

## 1. Zero External Dependencies

`go.mod` has no `require` block. This keeps the binary small, the supply chain
minimal, compilation fast, and the entire codebase inspectable without chasing
upstream code. If you need functionality from a library, implement the minimal
subset needed in `internal/`.

**Why it matters for agents:** An agent can reason about the full codebase
without needing to understand opaque upstream behavior.

## 2. Redaction by Default

No code path emits raw secrets. Sensitive headers (`Authorization`, `Cookie`,
`Set-Cookie`) and JSON fields (`access_token`, `refresh_token`,
`client_secret`) are redacted in all outputs unless the user explicitly passes
`--no-redact`.

**Why it matters:** AuthProbe scans real OAuth endpoints. Users paste output
into bug reports, Slack threads, and CI logs. Leaking tokens is unacceptable.

## 3. One Primary Finding Per Scan

Each scan produces at most one primary finding — the highest severity, then
highest confidence issue. This gives users a single decisive answer rather
than a wall of diagnostics to triage.

**Why it matters:** The tool's value comes from clarity, not completeness.
Secondary findings are still available for deep dives.

## 4. Finding Codes Are Stable API

Codes like `DISCOVERY_NO_WWW_AUTHENTICATE` appear in JSON reports, CI gates
(`--fail-on`), documentation, and downstream integrations. Adding new codes
is safe; changing or removing existing codes is a breaking change.

**Why it matters:** Users build automation around these codes. Breaking them
breaks trust.

## 5. Per-Scan State, No Globals

Each `RunScanFunnel` call creates a fresh `funnel` struct. Probe functions
accumulate state (findings, trace entries) on this struct. There is no global
mutable state. This makes scans deterministic and safe to run concurrently.

**Why it matters for agents:** No hidden state means an agent can reason
about a scan in isolation without worrying about side effects from previous
runs.

## 6. SSRF Protection On by Default

Metadata-driven fetches block private, loopback, and link-local targets.
AuthProbe follows URLs from untrusted servers — without this, a malicious
MCP server could direct probes at internal infrastructure.

**Why it matters:** AuthProbe is a security diagnostic tool. It must not
become a security liability.

## 7. Parse and Validate at the Boundary

HTTP responses, CLI arguments, and JSON payloads are validated at the point
of entry. Probe functions operate on validated data. This prevents cascading
errors from malformed inputs and makes debugging straightforward.

**Why it matters for agents:** When an agent adds a new probe, the pattern
is clear: validate first, then act on structured data.

## 8. Prefer Shared Helpers Over One-Off Code

Use `newFinding`, `fetchJSON`, `doRequest`, `redactHeaders` from `utils.go`.
These helpers enforce consistent behavior (redaction, SSRF checks, error
handling) that would otherwise need to be reimplemented in every probe.

**Why it matters:** Centralizing invariants means fixing a bug or adding a
feature in one place applies everywhere.

## 9. Tests Use Fake Servers, Not the Network

All HTTP-dependent tests use `httptest.NewServer`. No test makes real network
calls. This keeps tests fast, deterministic, and runnable offline.

## 10. Keep Files Focused

When a file grows past ~500 lines, split it by responsibility. Large files
make it harder for both humans and agents to navigate and reason about scope.
