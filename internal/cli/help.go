package cli

const scanHelp = `authprobe scan: Diagnose MCP OAuth by running a staged probe (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe scan <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
  -H, --header <k:v>       Add a request header (repeatable).
                           Example: -H "Host: internal.example.com"

      --proxy <url>        HTTP(S) proxy for outbound requests.
                           Example: --proxy http://127.0.0.1:8080

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
      --md <path>          Write Markdown report to file.
      --sarif <path>       Write SARIF report (GitHub code scanning) to file.
      --bundle <path>      Write sanitized evidence bundle (zip) to file.
      --output-dir <dir>   Write all requested outputs into a directory.

DIAGNOSTICS:
      --verbose            Verbose logs (includes request/response headers + bodies; still redacted).
      --no-redact          Disable redaction (NOT recommended; for local debugging only).
      --explain            Print an RFC 9728 rationale for each scan step.
      --show-trace         Print the MCP probe call trace in ASCII.
      --tool-list          Print MCP tool names with their titles (from tools/list).
      --tool-detail <name> Print a single MCP tool's full JSON definition.

EXAMPLES:
  authprobe scan https://mcp.example.com/mcp
  authprobe scan https://mcp.example.com/mcp --md report.md --json report.json
  authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com" --fail-on medium
  authprobe scan https://mcp.example.com/mcp --bundle evidence.zip
  authprobe scan https://mcp.example.com/mcp --rfc strict
`

const rootHelp = `authprobe: MCP OAuth diagnostics in minutes (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe <command> [args]

COMMANDS:
  scan       Diagnose MCP OAuth by running a staged probe.

Use "authprobe <command> --help" for more information about a command.
`
