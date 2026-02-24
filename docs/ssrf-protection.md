# SSRF Protection in AuthProbe

AuthProbe follows URLs discovered in OAuth metadata (`authorization_servers` in PRM, `token_endpoint`, `jwks_uri`, etc.). Without proper safeguards, a malicious or compromised MCP server could return metadata pointing to internal services, enabling **Server-Side Request Forgery (SSRF)** attacks.

## What is SSRF?

SSRF occurs when an attacker tricks a server-side application into making HTTP requests to an unintended location. In the context of MCP OAuth:

1. You scan an untrusted MCP endpoint: `authprobe scan https://evil-mcp.example.com/mcp`
2. The MCP server returns a `WWW-Authenticate` header pointing to malicious PRM
3. The PRM metadata contains: `"authorization_servers": ["http://169.254.169.254/latest/meta-data/"]`
4. Without protection, AuthProbe would fetch AWS instance metadata (or other internal services)

## Default Behavior (SSRF Protection ON)

By default, AuthProbe blocks requests to:

| Category | Blocked Ranges | RFC Reference |
|----------|----------------|---------------|
| **Private IPv4** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 |
| **Loopback** | `127.0.0.0/8`, `::1` | RFC 6890 |
| **Link-local** | `169.254.0.0/16`, `fe80::/10` | RFC 6890 |
| **Special hostnames** | `localhost`, `*.local` | — |
| **Multicast** | `224.0.0.0/4`, `ff00::/8` | RFC 6890 |

### Finding Codes

When AuthProbe blocks a request due to SSRF protection, it emits one of these findings:

- **`AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`** — The discovered authorization server issuer resolves to a private/internal address
- **`METADATA_SSRF_BLOCKED`** — A metadata fetch target (e.g., `jwks_uri`) resolves to a blocked address

Example output:
```
AUTH_SERVER_ISSUER_PRIVATE_BLOCKED: blocked issuer http://10.0.0.5/oauth
```

## Enterprise/Internal Deployments

For scanning MCP servers on internal networks where the authorization server is legitimately private, use the `--allow-private-issuers` flag:

```bash
authprobe scan https://internal-mcp.corp.local/mcp --allow-private-issuers
```

### When to Use `--allow-private-issuers`

✅ **Safe to use:**
- Scanning your own internal MCP servers
- Testing in development/staging environments
- Enterprise deployments with private OAuth infrastructure

❌ **Do NOT use:**
- Scanning untrusted or third-party MCP endpoints
- Automated scanning of user-provided URLs
- CI pipelines processing external inputs

## Implementation Details

AuthProbe performs SSRF checks at two levels:

1. **Issuer validation** (`issuerPrivate` function) — Checks the authorization server issuer URL before fetching metadata
2. **Fetch target validation** (`validateFetchTarget` function) — Performs DNS resolution and checks all resolved IPs before making any request

The DNS resolution step catches cases where a hostname like `internal.evil.com` resolves to `10.0.0.1`.

## Related RFCs

- **RFC 1918** — Address Allocation for Private Internets
- **RFC 6890** — Special-Purpose IP Address Registries
- **RFC 9728 §7.7** — Security considerations for metadata fetching (recommends SSRF defenses)

## See Also

- [PRD: Private issuer safety (SSRF guardrail)](PRD.md#private-issuer-safety-ssrf-guardrail)
- [Scan funnel documentation](funnel.md)
