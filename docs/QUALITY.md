# Quality Scorecard

This document grades each domain and architectural layer, tracking coverage,
documentation, and known gaps. Update this when making significant changes.

Last reviewed: 2026-02-24

## Domain Grades

| Domain | Test Coverage | Doc Coverage | Grade | Known Gaps |
|---|---|---|---|---|
| **Scan Funnel** (funnel.go) | High | High | A | File at 614 lines |
| **MCP Probes** (mcp.go + mcp_conformance.go) | High | High | A- | mcp.go at 684 lines |
| **OAuth Probes** (probe.go + probe_auth.go) | High | High | A- | probe.go at 521 lines |
| **PRM Discovery** | High | High | A | — |
| **Auth Server Metadata** | High | High | A | — |
| **Token Readiness** | Medium | High | A- | — |
| **DCR Probing** | Medium | High | A- | — |
| **Output Rendering** (output.go) | Medium | Medium | A- | File at 637 lines |
| **HTTP Utilities** (http_helpers.go) | High | Medium | A- | — |
| **URL Helpers** (url_helpers.go) | High | Medium | A- | — |
| **Finding System** (findings.go) | High | High | A | — |
| **Redaction** (redact.go) | High | High | A | — |
| **SSRF Protection** | High | High | A | — |
| **CLI Layer** | Medium | High | A- | — |
| **MCP Server** (server.go + tools.go + auth_assist.go) | Medium | Medium | A- | Session TTL tested |
| **LLM Adapters** (llm/) | Medium | Medium | A- | Unit tests added; no integration tests (API keys required) |
| **Version Negotiation** | High | Medium | A- | — |
| **Stdio Gateway** | Medium | Medium | A- | Documentation added to ARCHITECTURE.md |

## Architectural Health

| Metric | Status | Notes |
|---|---|---|
| External dependencies | Green | Zero — `go.mod` has no `require` block |
| Layer boundary violations | Green | CLI/MCP Server never call HTTP directly |
| Global mutable state | Green | Only sentinel errors at package level |
| Finding code stability | Green | All documented codes present in source |
| SSRF protection | Green | Default-on, tested |
| Redaction | Green | Default-on, covers headers + JSON fields |
| CI pipeline | Green | Build + test + coverage on every PR |
| Invariant linting | Green | `make lint` checks mechanical invariants |
| File sizes | Yellow | 4 files between 500-700 lines; all others under 500 |

## Priority Improvements

1. **Further split remaining large files.** `mcp.go` (684), `output.go` (637),
   `funnel.go` (614), and `probe.go` (521) are above the 500-line guideline
   but contain cohesive logic that is hard to split further without fragmenting
   readability.
2. **LLM integration tests.** Add tests that use `httptest.NewServer` by
   making API URLs configurable (currently hardcoded constants).
3. **Output rendering doc coverage.** Add documentation for the output format
   internals (Markdown, ASCII trace, bundle zip structure).
