#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAPE_FILE="${ROOT_DIR}/scripts/demo.tape"
OUT_FILE="${ROOT_DIR}/docs/assets/demo.gif"

if ! command -v vhs >/dev/null 2>&1; then
  echo "error: vhs is required. Install from https://github.com/charmbracelet/vhs" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUT_FILE}")"

echo "Recording demo GIF to ${OUT_FILE}"
vhs "${TAPE_FILE}"
echo "Done."
