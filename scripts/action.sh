#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
action_path="${GITHUB_ACTION_PATH:-$(pwd)}"
state_root="${RUNNER_TEMP:-${action_path}}"
state_dir="${state_root}/authprobe-action/.action-state"
binary_name="authprobe"
binary_path="${state_dir}/${binary_name}"

log_err() {
  echo "[authprobe-action] ERROR: $*" >&2
}

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

resolve_latest_version() {
  local api_url
  local curl_args=()
  api_url="https://api.github.com/repos/authprobe/authprobe/releases/latest"

  curl_args=(
    -fSL
    --retry 3
    --retry-delay 1
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
  )


  local response
  if ! response="$(curl "${curl_args[@]}" "${api_url}")"; then
    log_err "Failed to resolve latest release tag (GitHub API). Pin inputs.version (e.g. v0.5.0)."
    return 1
  fi

  local tag_name=""
  if command -v jq >/dev/null 2>&1; then
    tag_name="$(printf '%s' "${response}" | jq -r '.tag_name // empty')"
  elif command -v python3 >/dev/null 2>&1; then
    tag_name="$(printf '%s' "${response}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name", ""))')"
  elif command -v python >/dev/null 2>&1; then
    tag_name="$(printf '%s' "${response}" | python -c 'import json,sys; print(json.load(sys.stdin).get("tag_name", ""))')"
  else
    log_err "Failed to resolve latest release tag: jq or python is required to parse GitHub API response. Pin inputs.version (e.g. v0.5.0)."
    return 1
  fi

  if [[ -z "${tag_name}" || "${tag_name}" == "null" ]]; then
    log_err "Failed to resolve latest release tag (GitHub API). Pin inputs.version (e.g. v0.5.0)."
    return 1
  fi

  printf '%s\n' "${tag_name#v}"
}

validate_binary_download() {
  local os="$1"

  if [[ ! -s "${binary_path}" ]]; then
    log_err "Downloaded binary is missing or empty at '${binary_path}'."
    return 1
  fi

  if [[ "${os}" != "windows" ]] && command -v file >/dev/null 2>&1; then
    local file_output
    file_output="$(file "${binary_path}" || true)"
    echo "[authprobe-action] Downloaded file type: ${file_output}"
    if [[ "${file_output}" == *"HTML"* || "${file_output}" == *"XML"* || "${file_output}" == *"text"* ]]; then
      log_err "Downloaded file does not look like a binary executable. URL may be invalid or returned an error page."
      return 1
    fi
  fi

  return 0
}

download_binary() {
  local version os arch file url
  version="${INPUT_VERSION:-latest}"
  os="$(detect_os)"
  arch="$(detect_arch)"

  if [[ "${os}" == "windows" ]]; then
    log_err "Windows runners are not supported by this composite action. Use ubuntu-latest or macos-latest."
    exit 1
  fi

  if [[ "${version}" == "latest" ]]; then
    version="$(resolve_latest_version)"
  fi

  version="${version#v}"
  file="authprobe_${os}_${arch}"
  if [[ "${os}" == "windows" ]]; then
    file="${file}.exe"
  fi
  url="https://github.com/authprobe/authprobe/releases/download/v${version}/${file}"

  mkdir -p "${state_dir}"

  if ! curl -fSL --retry 3 --retry-delay 1 "${url}" -o "${binary_path}"; then
    log_err "Failed to download AuthProbe binary from '${url}' (version='${version}', os='${os}', arch='${arch}')."
    return 1
  fi

  if ! validate_binary_download "${os}"; then
    log_err "Failed binary validation after download from '${url}'."
    return 1
  fi

  chmod +x "${binary_path}"
}

append_legacy_args() {
  local args_string="$1"
  local -n out_ref=$2

  if [[ -z "${args_string}" ]]; then
    return 0
  fi

  local parser_bin
  if command -v python3 >/dev/null 2>&1; then
    parser_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    parser_bin="python"
  else
    log_err "python or python3 is required to safely parse inputs.args."
    return 1
  fi

  local had_error=0
  while IFS= read -r -d '' arg_item; do
    out_ref+=("${arg_item}")
  done < <(ARG_STRING="${args_string}" "${parser_bin}" - <<'PY'
import os
import shlex
import sys

arg_string = os.environ.get("ARG_STRING", "")
try:
    parsed = shlex.split(arg_string)
except ValueError as exc:
    print(f"parse-error:{exc}", file=sys.stderr)
    sys.exit(1)

for arg in parsed:
    sys.stdout.write(arg)
    sys.stdout.write("\0")
PY
) || had_error=$?

  if [[ ${had_error} -ne 0 ]]; then
    log_err "Failed to parse inputs.args. Check for unmatched quotes."
    return 1
  fi
}

run_authprobe() {
  local cmd mcp_url args report_md report_json bundle
  cmd="${INPUT_COMMAND:-scan}"
  mcp_url="${INPUT_MCP_URL:-}"
  args="${INPUT_ARGS:-}"
  report_md="${INPUT_REPORT_MD:-}"
  report_json="${INPUT_REPORT_JSON:-}"
  bundle="${INPUT_BUNDLE:-}"

  if [[ "$(detect_os)" == "windows" ]]; then
    log_err "Windows runners are not supported by this composite action. Use ubuntu-latest or macos-latest."
    exit 1
  fi

  if [[ ! -x "${binary_path}" ]]; then
    log_err "AuthProbe binary not found at '${binary_path}'. Ensure the download step ran successfully."
    exit 1
  fi

  declare -a run_args
  run_args=("${cmd}")

  if [[ "${cmd}" == "scan" ]]; then
    if [[ -z "${mcp_url}" ]]; then
      log_err "inputs.mcp_url is required when inputs.command=scan."
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

  append_legacy_args "${args}" run_args

  "${binary_path}" "${run_args[@]}"
}

case "${command_name}" in
  download)
    download_binary
    ;;
  run)
    run_authprobe
    ;;
  *)
    log_err "Usage: $0 {download|run}"
    exit 1
    ;;
esac
