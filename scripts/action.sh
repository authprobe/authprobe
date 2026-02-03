#!/usr/bin/env bash
set -euo pipefail

command="${1:-}"
action_path="${GITHUB_ACTION_PATH:-$(pwd)}"
state_dir="${action_path}/.action-state"
mkdir -p "${state_dir}"
binary_path="${state_dir}/authprobe"

detect_os() {
  local uname_out
  uname_out="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "${uname_out}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    msys*|mingw*|cygwin*) echo "windows" ;;
    *) echo "linux" ;;
  esac
}

detect_arch() {
  local uname_out
  uname_out="$(uname -m)"
  case "${uname_out}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "amd64" ;;
  esac
}

download_binary() {
  local version os arch file url
  version="${INPUT_VERSION:-latest}"
  os="$(detect_os)"
  arch="$(detect_arch)"

  if [[ "${version}" == "latest" ]]; then
    if command -v jq >/dev/null 2>&1; then
      version="$(curl -sL "https://api.github.com/repos/authprobe/authprobe/releases/latest" | jq -r '.tag_name')"
    else
      version="$(curl -sL "https://api.github.com/repos/authprobe/authprobe/releases/latest" | python - <<'PY'
import json, sys
data = json.load(sys.stdin)
print(data.get("tag_name", ""))
PY
)"
    fi
  fi

  version="${version#v}"
  file="authprobe_${os}_${arch}"
  if [[ "${os}" == "windows" ]]; then
    file="${file}.exe"
  fi
  url="https://github.com/authprobe/authprobe/releases/download/v${version}/${file}"

  mkdir -p "${state_dir}"
  curl -sL "${url}" -o "${binary_path}"
  chmod +x "${binary_path}"
}

run_authprobe() {
  local cmd mcp_url args report_md report_json bundle
  cmd="${INPUT_COMMAND:-scan}"
  mcp_url="${INPUT_MCP_URL:-}"
  args="${INPUT_ARGS:-}"
  report_md="${INPUT_REPORT_MD:-}"
  report_json="${INPUT_REPORT_JSON:-}"
  bundle="${INPUT_BUNDLE:-}"

  if [[ ! -x "${binary_path}" ]]; then
    echo "authprobe binary not found. Run download step first." >&2
    exit 1
  fi

  declare -a run_args
  run_args=("${cmd}")
  if [[ "${cmd}" == "scan" ]]; then
    if [[ -z "${mcp_url}" ]]; then
      echo "mcp_url is required when command=scan." >&2
      exit 1
    fi
    run_args+=("${mcp_url}")
  fi
  if [[ -n "${report_md}" ]]; then
    run_args+=(--md "${report_md}")
  fi
  if [[ -n "${report_json}" ]]; then
    run_args+=(--json "${report_json}")
  fi
  if [[ -n "${bundle}" ]]; then
    run_args+=(--bundle "${bundle}")
  fi
  if [[ -n "${args}" ]]; then
    read -r -a extra_args <<< "${args}"
    run_args+=("${extra_args[@]}")
  fi

  "${binary_path}" "${run_args[@]}"
}

case "${command}" in
  download)
    download_binary
    ;;
  run)
    run_authprobe
    ;;
  *)
    echo "Usage: $0 {download|run}" >&2
    exit 1
    ;;
esac
