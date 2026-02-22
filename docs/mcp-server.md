# AuthProbe MCP Server

Run AuthProbe as an MCP server for Claude Desktop/Cursor using stdio transport:

```json
{
  "mcpServers": {
    "authprobe": {
      "command": "authprobe",
      "args": ["mcp", "--transport", "stdio"]
    }
  }
}
```

## OAuth-assist flow (no token paste)

1. Call `authprobe.scan_http` with `auth_assist="auto"` (default).
2. If auth is required and the target supports DCR (RFC 7591) + device flow (RFC 8628), AuthProbe returns:
   - `status="awaiting_user_auth"`
   - `login_url`
   - `scan_id`
3. User authorizes in browser using the login URL.
4. Client calls `authprobe.scan_resume` with `scan_id`.
5. If still pending, response remains `awaiting_user_auth`; once authorized, scan resumes automatically and returns `status="ok"`.

## Security notes

- Tokens are never printed in MCP JSON output, markdown output, trace output, or bundles.
- Authorization header values are always redacted in outputs.
- Tokens are kept in memory only, scoped to scan session, and TTL-limited.
- If device flow or DCR is not supported by the issuer, AuthProbe returns `auth_required` guidance.
