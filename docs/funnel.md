# AuthProbe Funnel Overview

This document explains how AuthProbe stages its scan, what each step checks, and which RFCs inform the expectations.

## Scan Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AuthProbe Scan Funnel                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [1] Discovery ──► [2] MCP Init ──► [3] PRM ──► [4] Auth Server ──► [5] Token
│        │                │              │              │                │    │
│        ▼                ▼              ▼              ▼                ▼    │
│     401 + WWW-     initialize +    Fetch PRM     Fetch issuer      POST     │
│     Authenticate   tools/list      metadata      metadata         probe     │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Skip conditions:                                                           │
│    • Step 2 skipped if --mcp off                                            │
│    • Steps 3-5 skipped if no 401 (auth not required)                        │
│    • Steps 4-5 skipped if no authorization_servers found                    │
│    • Step 5 skipped if no token_endpoint found                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Call Trace

```
  ┌────────────┐                                     ┌────────────┐                     ┌────────────┐
  │ authprobe  │                                     │ MCP Server │                     │ Auth Server│
  └─────┬──────┘                                     └─────┬──────┘                     └─────┬──────┘
        │                                                  │                                  │
        │ ╔═══ Step 1: Discovery ══════════════════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  GET /mcp  Accept: text/event-stream             │                                  │
        ├─────────────────────────────────────────────────►│                                  │
        │                                                  │                                  │
        │  401  WWW-Authenticate: Bearer resource_metadata │                                  │
        │◄─────────────────────────────────────────────────┤                                  │
        │                                                  │                                  │
        │ ╔═══ Step 2: MCP Initialize ═════════════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  POST /mcp  {"method":"initialize",…}            │                                  │
        ├─────────────────────────────────────────────────►│                                  │
        │                                                  │                                  │
        │  200 OK {"result":{…}}                           │                                  │
        │◄─────────────────────────────────────────────────┤                                  │
        │                                                  │                                  │
        │  POST /mcp  {"method":"tools/list",…}            │                                  │
        ├─────────────────────────────────────────────────►│                                  │
        │                                                  │                                  │
        │  200 OK {"result":{"tools":[…]}}                 │                                  │
        │◄─────────────────────────────────────────────────┤                                  │
        │                                                  │                                  │
        │ ╔═══ Step 3: PRM Discovery ══════════════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  GET /.well-known/oauth-protected-resource       │                                  │
        ├─────────────────────────────────────────────────►│                                  │
        │                                                  │                                  │
        │  200 OK {"resource":"…","authorization_servers"} │                                  │
        │◄─────────────────────────────────────────────────┤                                  │
        │                                                  │                                  │
        │ ╔═══ Step 4: Auth Server Metadata ═══════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  GET /.well-known/oauth-authorization-server     │                                  │
        ├──────────────────────────────────────────────────┼─────────────────────────────────►│
        │                                                  │                                  │
        │  200 OK {"issuer":"…","token_endpoint":"…"}      │                                  │
        │◄─────────────────────────────────────────────────┼──────────────────────────────────┤
        │                                                  │                                  │
        │ ╔═══ Step 5: Token Readiness ════════════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  POST /token  grant_type=authorization_code      │                                  │
        ├──────────────────────────────────────────────────┼─────────────────────────────────►│
        │                                                  │                                  │
        │  400 Bad Request {"error":"invalid_grant"}       │                                  │
        │◄─────────────────────────────────────────────────┼──────────────────────────────────┤
        │                                                  │                                  │
        │ ╔═══ Step 6: DCR (Optional) ═════════════════════╪══════════════════════════════════╗
        │                                                  │                                  │
        │  POST /register {"redirect_uris":[…]}            │                                  │
        ├──────────────────────────────────────────────────┼─────────────────────────────────►│
        │                                                  │                                  │
        │  201 Created {"client_id":"…"}                   │                                  │
        │◄─────────────────────────────────────────────────┼──────────────────────────────────┤
        │                                                  │                                  │
        ▼                                                  ▼                                  ▼
```

## Scan Steps

| Step | Name                 | What is Scanned                                      | Expected Result                                                          | Relevant Specs                                                                                                              |
|------|----------------------|------------------------------------------------------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| 1    | Discovery            | Probe MCP endpoint for auth requirements             | `401 Unauthorized` + `WWW-Authenticate` header with `resource_metadata`  | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)                                                                   |
| 2    | MCP Initialize       | JSON-RPC `initialize` + `tools/list`                 | `200 OK` + valid JSON responses                                          | [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)                                                  |
| 3    | PRM Discovery        | Fetch Protected Resource Metadata (root/path-suffix) | `200 OK`, JSON with `resource` + `authorization_servers`                 | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728), [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986)        |
| 4    | Auth Server Metadata | Fetch `/.well-known/oauth-authorization-server`      | `200 OK`, JSON with `issuer`, `authorization_endpoint`, `token_endpoint` | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)        |
| 5    | Token Readiness      | POST invalid grant to token endpoint                 | JSON error response, not `200` with error payload                        | OAuth best practice                                                                                                         |
| 6    | DCR (Optional)       | POST dynamic client registration                     | `201 Created`, JSON with `client_id`                                     | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)                                                                   |

## Failure Codes by Step

### Step 1: Discovery

| Code                            | Expectation                                                | Spec                                                               |
|---------------------------------|------------------------------------------------------------|--------------------------------------------------------------------|
| `MCP_PROBE_TIMEOUT`             | Probe returns headers promptly                             | [MCP](https://modelcontextprotocol.io/specification/2025-11-25)    |
| `DISCOVERY_NO_WWW_AUTHENTICATE` | `401` includes `WWW-Authenticate` with `resource_metadata` | [RFC 9728 §5](https://datatracker.ietf.org/doc/html/rfc9728#section-5) |

### Step 2: MCP Initialize + Tools/List

| Code                               | Expectation                                | Spec                                                                  |
|------------------------------------|--------------------------------------------|-----------------------------------------------------------------------|
| `MCP_INITIALIZE_FAILED`            | `initialize` returns `200` with JSON       | [MCP](https://modelcontextprotocol.io/specification/2025-11-25)       |
| `MCP_TOOLS_LIST_FAILED`            | `tools/list` returns `200` with JSON       | [MCP](https://modelcontextprotocol.io/specification/2025-11-25)       |
| `MCP_JSONRPC_RESPONSE_INVALID`     | Response has valid JSON-RPC 2.0 structure  | [JSON-RPC 2.0](https://www.jsonrpc.org/specification)                 |
| `MCP_JSONRPC_RESPONSE_ID_MISMATCH` | Response ID matches request ID             | [JSON-RPC 2.0](https://www.jsonrpc.org/specification)                 |
| `MCP_PROTOCOL_VERSION_MISMATCH`    | Server returns compatible protocol version | [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) |

### Step 3: PRM Discovery

| Code                                | Expectation                                      | Spec                                                                       |
|-------------------------------------|--------------------------------------------------|----------------------------------------------------------------------------|
| `DISCOVERY_ROOT_WELLKNOWN_404`      | Root PRM reachable when path-suffix not required | [RFC 9728 §4](https://datatracker.ietf.org/doc/html/rfc9728#section-4)     |
| `PRM_HTTP_STATUS_NOT_200`           | PRM endpoint returns `200 OK`                    | [RFC 9728 §4](https://datatracker.ietf.org/doc/html/rfc9728#section-4)     |
| `PRM_CONTENT_TYPE_NOT_JSON`         | Response `Content-Type` is JSON                  | [RFC 9728 §4](https://datatracker.ietf.org/doc/html/rfc9728#section-4)     |
| `PRM_NOT_JSON_OBJECT`               | Response is a JSON object                        | [RFC 9728 §4](https://datatracker.ietf.org/doc/html/rfc9728#section-4)     |
| `PRM_RESOURCE_MISSING`              | PRM includes `resource` field                    | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3)     |
| `PRM_RESOURCE_MISMATCH`             | `resource` matches MCP endpoint                  | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3)     |
| `PRM_MISSING_AUTHORIZATION_SERVERS` | PRM includes `authorization_servers`             | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3)     |
| `PRM_BEARER_METHODS_INVALID`        | `bearer_methods_supported` values are valid      | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3)     |
| `PRM_WELLKNOWN_PATH_SUFFIX_MISSING` | Path-suffix PRM exists when resource has path    | [RFC 9728 §4.1](https://datatracker.ietf.org/doc/html/rfc9728#section-4.1) |
| `RFC3986_INVALID_URI`               | URLs parse as valid URIs                         | [RFC 3986 §3](https://datatracker.ietf.org/doc/html/rfc3986#section-3)     |
| `RFC3986_ABSOLUTE_HTTPS_REQUIRED`   | URLs are absolute HTTPS                          | [RFC 3986 §4.3](https://datatracker.ietf.org/doc/html/rfc3986#section-4.3) |
| `RESOURCE_FRAGMENT_FORBIDDEN`       | `resource` has no fragment                       | [RFC 8707 §2](https://datatracker.ietf.org/doc/html/rfc8707#section-2)     |

### Step 4: Auth Server Metadata

| Code                                         | Expectation                                        | Spec                                                                       |
|----------------------------------------------|----------------------------------------------------|----------------------------------------------------------------------------|
| `AUTH_SERVER_METADATA_UNREACHABLE`           | Metadata endpoint reachable                        | [RFC 8414 §3](https://datatracker.ietf.org/doc/html/rfc8414#section-3)     |
| `AUTH_SERVER_METADATA_INVALID`               | Metadata is `200` JSON with required fields        | [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2)     |
| `AUTH_SERVER_METADATA_CONTENT_TYPE_NOT_JSON` | Response is JSON                                   | [RFC 8414 §3](https://datatracker.ietf.org/doc/html/rfc8414#section-3)     |
| `AUTH_SERVER_ISSUER_MISMATCH`                | `issuer` equals discovery issuer                   | [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2)     |
| `AUTH_SERVER_ISSUER_QUERY_FRAGMENT`          | Issuer has no query/fragment                       | [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2)     |
| `AUTH_SERVER_ISSUER_PRIVATE_BLOCKED`         | Issuer not private (SSRF)                          | Local policy                                                               |
| `AUTH_SERVER_ENDPOINT_HOST_MISMATCH`         | Endpoints align with issuer host                   | [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2)     |
| `AUTH_SERVER_PKCE_S256_MISSING`              | `code_challenge_methods_supported` includes `S256` | [RFC 7636 §4.2](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2) |
| `AUTH_SERVER_PROTECTED_RESOURCES_MISMATCH`   | `protected_resources` includes resource            | [RFC 8707 §2](https://datatracker.ietf.org/doc/html/rfc8707#section-2)     |
| `JWKS_FETCH_ERROR`                           | `jwks_uri` reachable                               | [RFC 7517 §5](https://datatracker.ietf.org/doc/html/rfc7517#section-5)     |
| `JWKS_INVALID`                               | JWKS is valid JSON with `keys`                     | [RFC 7517 §5](https://datatracker.ietf.org/doc/html/rfc7517#section-5)     |

### Step 5: Token Readiness

| Code                               | Expectation                                        | Spec                |
|------------------------------------|----------------------------------------------------|---------------------|
| `TOKEN_RESPONSE_NOT_JSON_RISK`     | Token endpoint responds with JSON                  | OAuth best practice |
| `TOKEN_HTTP200_ERROR_PAYLOAD_RISK` | Token endpoint doesn't return `200` with `error`   | OAuth best practice |

### Step 6: DCR (Optional)

| Code                             | Expectation                                                      | Spec                                                                     |
|----------------------------------|------------------------------------------------------------------|--------------------------------------------------------------------------|
| `DCR_ENDPOINT_OPEN`              | Registration endpoint rejects unauthenticated requests           | [RFC 7591 §3](https://datatracker.ietf.org/doc/html/rfc7591#section-3)    |
| `DCR_HTTP_REDIRECT_ACCEPTED`     | Registration rejects non-HTTPS redirect URIs                     | [RFC 6749 §3.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.1) |
| `DCR_LOCALHOST_REDIRECT_ACCEPTED`| Registration validates localhost redirect URIs                   | OAuth best practice                                                      |
| `DCR_DANGEROUS_URI_ACCEPTED`     | Registration rejects dangerous URI schemes (e.g., `javascript:`)  | OAuth best practice                                                      |
| `DCR_EMPTY_REDIRECT_URIS_ACCEPTED` | Registration requires non-empty redirect URIs                 | [RFC 7591 §2](https://datatracker.ietf.org/doc/html/rfc7591#section-2)    |

### Redirect & SSRF Safety

| Code                        | Expectation                                  | Spec                                                                         |
|-----------------------------|----------------------------------------------|------------------------------------------------------------------------------|
| `METADATA_REDIRECT_BLOCKED` | Redirects are absolute HTTPS (strict mode)  | [RFC 9110 §15.4](https://datatracker.ietf.org/doc/html/rfc9110#section-15.4) |
| `METADATA_REDIRECT_LIMIT`   | Redirect chain within limit (5)             | [RFC 9110 §15.4](https://datatracker.ietf.org/doc/html/rfc9110#section-15.4) |
| `METADATA_SSRF_BLOCKED`     | Metadata hosts not private                  | Local policy                                                                 |

## Quick Reference

| Step                 | Skip Condition                   |
|----------------------|----------------------------------|
| 2 (MCP Initialize)   | MCP mode is `off`                |
| 3 (PRM Discovery)    | Auth not required (no 401)       |
| 4 (Auth Server)      | No authorization servers found   |
| 5 (Token Readiness)  | No token endpoints found         |
