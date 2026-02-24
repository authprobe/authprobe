# Quality Scorecard

This document grades each domain and architectural layer, tracking coverage,
documentation, and known gaps. Update this when making significant changes.

Last reviewed: 2026-02-24

## Domain Grades

| Domain | Test Coverage | Doc Coverage | Grade | Known Gaps |
|---|---|---|---|---|
| **Scan Funnel** (funnel.go) | High | High | A | File at 614 lines, approaching split threshold |
| **MCP Probes** (mcp.go) | High | High | B+ | File at 950 lines, should be split |
| **OAuth Probes** (probe.go) | High | High | B+ | File at 952 lines, should be split |
| **PRM Discovery** | High | High | A | — |
| **Auth Server Metadata** | High | High | A | — |
| **Token Readiness** | Medium | High | A- | — |
| **DCR Probing** | Medium | High | A- | — |
| **Output Rendering** (output.go) | Medium | Medium | B | File at 637 lines |
| **HTTP Utilities** (utils.go) | High | Medium | B- | File at 1403 lines, needs splitting |
| **SSRF Protection** | High | High | A | — |
| **Redaction** | High | High | A | — |
| **CLI Layer** | Medium | High | A- | — |
| **MCP Server** (mcpserver/) | Medium | Medium | B | File at 1239 lines, needs splitting; session TTL not fully tested |
| **LLM Adapters** | Low | Low | C | No integration tests, minimal unit tests |
| **Version Negotiation** | High | Medium | A- | — |
| **Stdio Gateway** | Medium | Low | B- | Limited documentation |

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

## Priority Improvements

1. **Split large files.** `utils.go` (1403 lines), `mcpserver/server.go`
   (1239 lines), `mcp.go` (950 lines), and `probe.go` (952 lines) are well
   past the 500-line guideline.
2. **LLM adapter tests.** The `internal/scan/llm/` package has minimal test
   coverage. Add unit tests with mock HTTP responses.
3. **MCP Server session TTL.** Add tests for session expiration and cleanup.
4. **Stdio Gateway documentation.** Add a section to ARCHITECTURE.md or a
   standalone doc explaining the HTTP-to-stdio bridge.
