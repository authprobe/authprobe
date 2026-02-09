package cli

// help.go - Command help text constants
//
// Constants:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Constant                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ scanHelp                            │ Help text for the scan command                             │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

const scanHelp = `authprobe scan: Diagnose MCP OAuth by running a staged probe (discovery → metadata → token readiness → auth header checks).

Note: For path-based resources, resource-specific PRM (path-suffix) or resource_metadata hints are sufficient for standards-compliant discovery; the root PRM endpoint is a compatibility check.

USAGE:
  authprobe scan <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
  -H, --header <k:v>       Add a request header (repeatable).
                           Example: -H "Host: internal.example.com"

      --timeout <sec>      Overall scan timeout in seconds. Default: 8

      --mcp <mode>         MCP 2025-11-25 conformance checks (Streamable HTTP + JSON-RPC).
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc <mode>         RFC conformance checks (9728, 8414, 3986, 8707, 7636, etc.).
                           Options: off, best-effort, strict
                           Default: best-effort

      --allow-private-issuers
                           Allow fetching authorization server metadata from private/loopback/link-local issuers.
                           (Use only in trusted networks.)

      --insecure           Allow invalid TLS certificates (dev only).
      --no-follow-redirects
                           Do not follow HTTP redirects.

      --fail-on <level>    Exit non-zero if findings at/above this severity exist.
                           Options: none, low, medium, high
                           Default: high

OUTPUTS:
      --json <path>        Write structured JSON report to file. Use "-" for stdout.
      --md <path>          Write Markdown report to file. Use "-" for stdout.
      --trace-ascii <path> Write ASCII call trace to file. Use "-" for stdout.
      --bundle <path>      Write sanitized evidence bundle (zip) to file.
      --output-dir <dir>   Write all requested outputs into a directory.

DIAGNOSTICS:
  -v, --verbose            Verbose logs (includes request/response headers + bodies).
      --trace-failure      Include verbose output of failed probe steps in report.
      --no-redact          Disable redaction in verbose logs and evidence bundles.
  -e, --explain            Print an RFC rationale for each scan step.
      --openai-api-key     OpenAI API key (or set OPENAI_API_KEY). Enables LLM explanations.
      --anthropic-api-key  Anthropic API key (or set ANTHROPIC_API_KEY). Enables LLM explanations.
                           If both are set, OpenAI is used.
      --llm-max-tokens     Maximum output tokens for LLM explanations. Default: 700
  -l, --tool-list          Print MCP tool names with their titles (from tools/list).
  -d, --tool-detail <name> Print a single MCP tool's full JSON definition.

EXAMPLES:
  # Quick scan
  authprobe scan https://mcp.example.com/mcp

  # Re-run failed steps to capture their full trace
  authprobe scan https://mcp.example.com/mcp --trace-failure

  # See exactly what's on the wire (headers, bodies, status codes)
  authprobe scan https://mcp.example.com/mcp --verbose

  # Why did it fail? Get RFC rationale for every step
  authprobe scan https://mcp.example.com/mcp --explain

  # LLM-powered deep dive into compliance gaps
  authprobe scan https://mcp.example.com/mcp --openai-api-key $OPENAI_API_KEY

  # List available MCP tools on the server
  authprobe scan https://mcp.example.com/mcp --tool-list

For the latest version, full documentation, and all options visit:
  https://github.com/authprobe/authprobe
`

const rootHelp = `authprobe: MCP OAuth diagnostics in minutes (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe <command> [args]

COMMANDS:
  scan       Diagnose MCP OAuth by running a staged probe.

Use "authprobe <command> --help" for more information about a command.

For the latest version, full documentation, and all options visit:
  https://github.com/authprobe/authprobe
`
