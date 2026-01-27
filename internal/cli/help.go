package cli

const scanHelp = `authprobe scan: Diagnose MCP OAuth by running a staged probe (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe scan <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
  -p, --profile <name>     Client behavior profile to simulate.
                           Options: generic, vscode, inspector
                           Default: generic

  -H, --header <k:v>       Add a request header (repeatable).
                           Example: -H "Host: internal.example.com"

      --proxy <url>        HTTP(S) proxy for outbound requests.
                           Example: --proxy http://127.0.0.1:8080

      --timeout <sec>      Overall scan timeout in seconds. Default: 8
      --connect-timeout <sec>
                           Connection timeout in seconds. Default: 10
      --retries <n>        Retry failed GETs for metadata endpoints. Default: 1

      --rfc9728 <mode>     RFC 9728 conformance checks for protected resource metadata.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc3986 <mode>     RFC 3986 URI parsing + HTTPS checks for metadata URLs.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc8414 <mode>     RFC 8414 authorization server metadata checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc8707 <mode>     RFC 8707 resource indicator checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc9207 <mode>     RFC 9207 issuer identification checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc6750 <mode>     RFC 6750 bearer token method checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc7517 <mode>     RFC 7517 JWKS shape validation checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc7519 <mode>     RFC 7519 JWT claim validation checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc7636 <mode>     RFC 7636 PKCE posture checks.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc6749 <mode>     RFC 6749 OAuth endpoint behavior probes.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc1918 <mode>     RFC 1918 private-range SSRF protections.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc6890 <mode>     RFC 6890 special-purpose range SSRF protections.
                           Options: off, best-effort, strict
                           Default: best-effort
      --rfc9110 <mode>     RFC 9110 redirect handling checks for metadata fetches.
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
      --json <path>        Write structured JSON report to file.
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
  authprobe scan https://mcp.example.com/mcp --profile vscode --md report.md --json report.json
  authprobe scan https://mcp.example.com/mcp -H "Host: internal.example.com" --fail-on medium
  authprobe scan https://mcp.example.com/mcp --bundle evidence.zip
  authprobe scan https://mcp.example.com/mcp --rfc9728 strict
`

const matrixHelp = `authprobe matrix: Run scans across client profiles and compare findings.

USAGE:
  authprobe matrix <mcp_url> [flags]

ARGUMENTS:
  <mcp_url>                MCP endpoint URL (example: https://example.com/mcp)

FLAGS:
      --format <format>    Output format. Options: table, md, json
                           Default: table

      --fail-on <level>    Exit non-zero if findings at/above this severity exist.
                           Options: none, low, medium, high
                           Default: high

EXAMPLES:
  authprobe matrix https://mcp.example.com/mcp
  authprobe matrix https://mcp.example.com/mcp --format md
`

const fixHelp = `authprobe fix: Generate remediation snippets for a specific finding.

USAGE:
  authprobe fix <FINDING_CODE> --target <fastapi|nginx|envoy|generic> [flags]

ARGUMENTS:
  <FINDING_CODE>           Finding code to remediate (example: DISCOVERY_ROOT_WELLKNOWN_404)

FLAGS:
      --target <name>      Target environment for the snippet.
                           Options: fastapi, nginx, envoy, generic

      --explain            Include rationale and verification commands.

EXAMPLES:
  authprobe fix DISCOVERY_ROOT_WELLKNOWN_404 --target nginx
  authprobe fix PRM_RESOURCE_MISMATCH --target fastapi --explain
`

const rootHelp = `authprobe: MCP OAuth diagnostics in minutes (discovery → metadata → token readiness → auth header checks).

USAGE:
  authprobe <command> [args]

COMMANDS:
  scan       Diagnose MCP OAuth by running a staged probe.
  matrix     Run scans across client profiles and compare findings.
  fix        Generate remediation snippets for a specific finding.

Use "authprobe <command> --help" for more information about a command.
`
