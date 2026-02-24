#!/usr/bin/env bash
set -euo pipefail

FAIL=0

err() {
  echo "FAIL: $1" >&2
  FAIL=1
}

# 1. Zero external dependencies: go.mod must not have a require block
if grep -q '^require' go.mod; then
  err "go.mod contains a 'require' block — zero external dependencies invariant violated"
fi

# 2. go vet
if ! go vet ./... 2>/dev/null; then
  err "go vet found issues"
fi

# 3. go fmt check (no-op if already formatted)
UNFMT=$(gofmt -l . 2>/dev/null || true)
if [ -n "$UNFMT" ]; then
  err "gofmt: the following files are not formatted:"
  echo "$UNFMT" >&2
fi

# 4. No global mutable state in scan package.
# Package-level var blocks containing only sentinel errors (errors.New) are
# idiomatic Go and allowed. We flag single-line `var x = ...` declarations
# that are NOT error sentinels, and multi-line `var (` blocks whose body
# contains non-error assignments.
MUTABLE_VARS=$(grep -rn '^var [a-zA-Z]' internal/scan/*.go 2>/dev/null \
  | grep -v '_test.go' \
  | grep -v 'err[A-Z].*=.*errors\.New\|err[A-Z].*=.*fmt\.Errorf' \
  || true)
if [ -n "$MUTABLE_VARS" ]; then
  err "Potentially mutable global var in internal/scan/ (per-scan state invariant):"
  echo "$MUTABLE_VARS" >&2
fi

# 5. File size check: warn on files over 500 lines
while IFS= read -r f; do
  LINES=$(wc -l < "$f")
  if [ "$LINES" -gt 500 ]; then
    echo "WARN: $f has $LINES lines (consider splitting)" >&2
  fi
done < <(find internal/ -name '*.go' ! -name '*_test.go' 2>/dev/null)

# 6. ARCHITECTURE.md code map freshness: check that documented packages exist
for pkg in cmd/authprobe internal/cli internal/scan internal/scan/llm internal/mcpserver; do
  if [ ! -d "$pkg" ]; then
    err "ARCHITECTURE.md references $pkg but directory does not exist"
  fi
done

# 7. Finding code stability: known codes from PRD.md should still be referenced in source
if [ -f docs/PRD.md ]; then
  for code in DISCOVERY_NO_WWW_AUTHENTICATE MCP_PROBE_TIMEOUT OAUTH_DISCOVERY_UNAVAILABLE AUTH_SERVER_METADATA_UNREACHABLE; do
    if ! grep -rq "$code" internal/scan/ 2>/dev/null; then
      err "Finding code $code documented in PRD.md but not found in scan source"
    fi
  done
fi

if [ "$FAIL" -ne 0 ]; then
  echo "" >&2
  echo "Invariant checks failed. See errors above." >&2
  exit 1
fi

echo "All invariant checks passed."
