# AuthProbe report

```
authprobe scan --md out.md https://compute.googleapis.com/mcp
```

Scanning: https://compute.googleapis.com/mcp

- Target: https://compute.googleapis.com/mcp
- MCP: best-effort
- RFC: best-effort
- Timestamp: 2026-01-31T21:30:59Z

## Funnel

- [1] MCP probe (401 + WWW-Authenticate): **PASS** (probe returned 405; continuing discovery)
- [2] MCP initialize + tools/list: **PASS** (initialize -> 200
notifications/initialized -> 202
tools/list -> 200 (tools: create_instance, delete_instance, start_instance, stop_instance, reset_instance, get_instance_basic_info, set_instance_machine_type, list_instance_attached_disks, list_instances, get_instance_group_manager_basic_info, list_instance_group_managers, list_managed_instances, list_instance_templates, get_instance_template_basic_info, get_instance_template_properties, get_disk_basic_info, get_disk_performance_config, list_disks, list_accelerator_types, list_machine_types, list_images, get_zone_operation, get_reservation_basic_info, get_reservation_details, list_reservations, list_commitments, get_commitment_basic_info, list_commitment_reservations, list_snapshots))
- [3] PRM fetch matrix: **PASS** (https://compute.googleapis.com/.well-known/oauth-protected-resource -> 404
https://compute.googleapis.com/.well-known/oauth-protected-resource/mcp -> 200)
- [4] Auth server metadata: **FAIL** (https://accounts.google.com/.well-known/oauth-authorization-server -> 200)
- [5] Token endpoint readiness (heuristics): **SKIP** (no token_endpoint in metadata)

## Primary finding

- Code: AUTH_SERVER_ISSUER_MISMATCH
- Severity: high
- Confidence: 1.00
- Evidence:
  - issuer mismatch: metadata issuer "https://accounts.google.com", expected "https://accounts.google.com/"
  - RFC 8414 requires the metadata issuer to exactly match the issuer used for discovery.

## All findings

- MCP_ORIGIN_NOT_VALIDATED (low, 1.00)
  - origin probe status 200
  - MCP servers should validate Origin to mitigate DNS rebinding and return 403 for invalid origins.
- MCP_PROTOCOL_VERSION_REJECTION_MISSING (medium, 1.00)
  - protocol version probe status 200
  - MCP servers that enforce MCP-Protocol-Version should respond with 400 for invalid values.
- AUTH_SERVER_ISSUER_MISMATCH (high, 1.00)
  - issuer mismatch: metadata issuer "https://accounts.google.com", expected "https://accounts.google.com/"
  - RFC 8414 requires the metadata issuer to exactly match the issuer used for discovery.
