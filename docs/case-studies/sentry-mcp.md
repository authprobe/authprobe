# Sentry MCP: RFC 9728 compliance fixes from AuthProbe findings

## Context

For MCP servers that require OAuth, clients need standards-based discovery to find Protected Resource Metadata (PRM) and authorization server details. RFC 9728 conformance helps clients discover this information reliably across implementations.

## What AuthProbe found

In [getsentry/sentry-mcp PR #799](https://github.com/getsentry/sentry-mcp/pull/799), maintainers documented three RFC 9728 gaps identified while scanning `https://mcp.sentry.dev/mcp` with AuthProbe:

- An issue in PRM path handling for resource URLs that include a path segment.
- Inconsistent handling of trailing slashes in discovered metadata.
- Missing protocol scheme normalization in PRM comparison logic.

## What changed

Per [PR #799](https://github.com/getsentry/sentry-mcp/pull/799), Sentry MCP updated discovery behavior to address those gaps and improve RFC 9728 protected resource metadata compliance for `mcp.sentry.dev`.

## How to reproduce

```bash
authprobe scan https://mcp.sentry.dev/mcp --explain --trace-failure
```
