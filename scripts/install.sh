#!/usr/bin/env bash
set -euo pipefail

REPO="authprobe/authprobe"
INSTALL_DIR="${AUTHPROBE_INSTALL_DIR:-${HOME}/.local/bin}"
BINARY_NAME="authprobe"
TMP_DIR=""

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

log() {
  printf '[authprobe/install] %s\n' "$*"
}

warn() {
  printf '[authprobe/install] warning: %s\n' "$*" >&2
}

die() {
  printf '[authprobe/install] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_os() {
  local uname_out
  uname_out="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "${uname_out}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    *) die "unsupported operating system: ${uname_out} (expected linux or darwin)" ;;
  esac
}

detect_arch() {
  local uname_out
  uname_out="$(uname -m)"
  case "${uname_out}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) die "unsupported architecture: ${uname_out} (expected amd64 or arm64)" ;;
  esac
}

json_get() {
  local expr="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r "${expr}"
    return
  fi

  python3 -c "import json,sys; data=json.load(sys.stdin); print(${expr})"
}

fetch_release_json() {
  curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'User-Agent: authprobe-install-script' \
    "https://api.github.com/repos/${REPO}/releases/latest"
}

asset_name_matches_target() {
  local name="$1"
  local os="$2"
  local arch="$3"

  if [[ "${name}" == *"checksums"* || "${name}" == *"sha256"* || "${name}" == *"sbom"* || "${name}" == *.sig || "${name}" == *.pem || "${name}" == *.minisig ]]; then
    return 1
  fi

  [[ "${name}" == *"${os}"* && "${name}" == *"${arch}"* ]]
}

select_asset() {
  local release_json="$1"
  local os="$2"
  local arch="$3"

  local line name url
  while IFS=$'\t' read -r name url; do
    if asset_name_matches_target "${name}" "${os}" "${arch}"; then
      printf '%s\t%s\n' "${name}" "${url}"
      return 0
    fi
  done < <(printf '%s' "${release_json}" | if command -v jq >/dev/null 2>&1; then
    jq -r '.assets[] | [.name, .browser_download_url] | @tsv'
  else
    python3 - <<'PYJSON'
import json
import sys

data = json.load(sys.stdin)
for asset in data.get("assets", []):
    print(f"{asset.get('name', '')}	{asset.get('browser_download_url', '')}")
PYJSON
  fi)

  return 1
}

find_checksums_asset() {
  local release_json="$1"

  printf '%s' "${release_json}" | if command -v jq >/dev/null 2>&1; then
    jq -r '.assets[] | [.name, .browser_download_url] | @tsv' | awk -F'	' '
      BEGIN { IGNORECASE = 1 }
      $1 ~ /checksum|checksums|sha256/ { print; exit }
    '
  else
    python3 - <<'PYJSON'
import json
import re
import sys

data = json.load(sys.stdin)
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if re.search(r"checksum|checksums|sha256", name, re.I):
        print(f"{name}	{asset.get('browser_download_url', '')}")
        break
PYJSON
  fi
}


verify_checksum_if_available() {
  local binary_file="$1"
  local asset_name="$2"
  local release_json="$3"
  local checksum_entry checksum_name checksum_url

  checksum_entry="$(find_checksums_asset "${release_json}" || true)"
  if [[ -z "${checksum_entry}" ]]; then
    warn "no checksums asset found in latest release; skipping checksum verification"
    return 0
  fi

  checksum_name="${checksum_entry%%$'\t'*}"
  checksum_url="${checksum_entry#*$'\t'}"
  log "found checksums file: ${checksum_name}"

  local checksum_file
  checksum_file="${TMP_DIR}/${checksum_name}"
  curl -fsSL "${checksum_url}" -o "${checksum_file}"

  local expected
  expected="$(awk -v target="${asset_name}" '$0 ~ target { print $1; exit }' "${checksum_file}")"
  if [[ -z "${expected}" ]]; then
    warn "checksums file did not contain an entry for ${asset_name}; skipping verification"
    return 0
  fi

  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${binary_file}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${binary_file}" | awk '{print $1}')"
  else
    warn "no sha256 command available; skipping checksum verification"
    return 0
  fi

  if [[ "${expected}" != "${actual}" ]]; then
    die "checksum verification failed for ${asset_name}"
  fi

  log "checksum verification passed"
}

install_binary() {
  need_cmd curl
  need_cmd uname
  need_cmd mktemp
  need_cmd chmod
  need_cmd mkdir
  need_cmd awk
  need_cmd python3

  local os arch release_json tag_name asset_line asset_name asset_url downloaded
  os="$(detect_os)"
  arch="$(detect_arch)"
  log "detected target: ${os}/${arch}"

  release_json="$(fetch_release_json)"
  tag_name="$(printf '%s' "${release_json}" | if command -v jq >/dev/null 2>&1; then jq -r '.tag_name'; else python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))'; fi)"
  [[ -n "${tag_name}" && "${tag_name}" != "null" ]] || die "could not resolve latest release tag"
  log "latest release: ${tag_name}"

  if ! asset_line="$(select_asset "${release_json}" "${os}" "${arch}")"; then
    die "no downloadable asset found for ${os}/${arch} in ${tag_name}"
  fi

  asset_name="${asset_line%%$'\t'*}"
  asset_url="${asset_line#*$'\t'}"
  [[ -n "${asset_url}" ]] || die "selected asset did not include a download URL"
  log "selected asset: ${asset_name}"

  TMP_DIR="$(mktemp -d)"
  downloaded="${TMP_DIR}/${asset_name}"
  curl -fsSL "${asset_url}" -o "${downloaded}"

  verify_checksum_if_available "${downloaded}" "${asset_name}" "${release_json}"

  mkdir -p "${INSTALL_DIR}"
  install -m 0755 "${downloaded}" "${INSTALL_DIR}/${BINARY_NAME}"

  log "installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
  echo
  echo "Next steps:"
  echo "  1) Ensure ${INSTALL_DIR} is on your PATH"
  echo "     export PATH=\"${INSTALL_DIR}:\$PATH\""
  echo "  2) Verify installation"
  echo "     authprobe --version"
}

install_binary
