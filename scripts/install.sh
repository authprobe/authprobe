#!/usr/bin/env sh
set -eu

REPO="authprobe/authprobe"
INSTALL_DIR="${AUTHPROBE_INSTALL_DIR:-${HOME}/.local/bin}"
BINARY_NAME="authprobe"
TMP_DIR=""

cleanup() {
  if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT INT HUP TERM

log() {
  printf '[authprobe/install] %s\n' "$*" >&2
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
  uname_out="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "${uname_out}" in
    linux*) echo "linux" ;;
    darwin*) echo "darwin" ;;
    *) die "unsupported operating system: ${uname_out} (expected linux or darwin)" ;;
  esac
}

detect_arch() {
  uname_out="$(uname -m)"
  case "${uname_out}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) die "unsupported architecture: ${uname_out} (expected amd64 or arm64)" ;;
  esac
}

fetch_release_json() {
  curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'User-Agent: authprobe-install-script' \
    "https://api.github.com/repos/${REPO}/releases/latest"
}

asset_name_matches_target() {
  name="$1"
  os="$2"
  arch="$3"
  lname="$(printf '%s' "${name}" | tr '[:upper:]' '[:lower:]')"

  os_aliases="${os}"
  case "${os}" in
    darwin) os_aliases="${os_aliases} macos osx" ;;
  esac

  arch_aliases="${arch}"
  case "${arch}" in
    amd64) arch_aliases="${arch_aliases} x86_64 x64" ;;
    arm64) arch_aliases="${arch_aliases} aarch64" ;;
  esac

  case "${lname}" in
    *checksums*|*sha256*|*sbom*|*.sig|*.pem|*.minisig)
      return 1
      ;;
  esac

  for os_token in ${os_aliases}; do
    for arch_token in ${arch_aliases}; do
      case "${lname}" in
        *"${os_token}"*"${arch_token}"*|*"${arch_token}"*"${os_token}"*)
          return 0
          ;;
      esac
    done
  done

  return 1
}

list_assets() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '.assets[] | [.name, .browser_download_url] | @tsv'
  else
    python3 - <<'PYJSON'
import json
import sys

data = json.load(sys.stdin)
for asset in data.get("assets", []):
    print(f"{asset.get('name', '')}\t{asset.get('browser_download_url', '')}")
PYJSON
  fi
}

select_asset() {
  release_json="$1"
  os="$2"
  arch="$3"
  tab_char="$(printf '\t')"

  assets_tsv="${TMP_DIR}/assets.tsv"
  printf '%s' "${release_json}" | list_assets > "${assets_tsv}"

  while IFS="${tab_char}" read -r name url; do
    if asset_name_matches_target "${name}" "${os}" "${arch}"; then
      printf '%s\t%s\n' "${name}" "${url}"
      return 0
    fi
  done < "${assets_tsv}"

  return 1
}

find_checksums_asset() {
  release_json="$1"

  assets_tsv="${TMP_DIR}/assets.tsv"
  printf '%s' "${release_json}" | list_assets > "${assets_tsv}"

  awk -F '\t' '
    BEGIN { IGNORECASE = 1 }
    $1 ~ /checksum|checksums|sha256/ { print; exit }
  ' "${assets_tsv}"
}

verify_checksum_if_available() {
  binary_file="$1"
  asset_name="$2"
  release_json="$3"

  checksum_entry="$(find_checksums_asset "${release_json}" || true)"
  if [ -z "${checksum_entry}" ]; then
    warn "no checksums asset found in latest release; skipping checksum verification"
    return 0
  fi

  checksum_name="$(printf '%s' "${checksum_entry}" | awk -F '\t' '{print $1}')"
  checksum_url="$(printf '%s' "${checksum_entry}" | awk -F '\t' '{print $2}')"
  log "found checksums file: ${checksum_name}"

  checksum_file="${TMP_DIR}/${checksum_name}"
  curl -fsSL "${checksum_url}" -o "${checksum_file}"

  expected="$(awk -v target="${asset_name}" '$0 ~ target { print $1; exit }' "${checksum_file}")"
  if [ -z "${expected}" ]; then
    warn "checksums file did not contain an entry for ${asset_name}; skipping verification"
    return 0
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${binary_file}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${binary_file}" | awk '{print $1}')"
  else
    warn "no sha256 command available; skipping checksum verification"
    return 0
  fi

  if [ "${expected}" != "${actual}" ]; then
    die "checksum verification failed for ${asset_name}"
  fi

  log "checksum verification passed"
}

install_binary() {
  if [ ! -t 1 ]; then
    warn "stdout is redirected; run this script directly (do not pipe ./scripts/install.sh into sh)"
  fi

  need_cmd curl
  need_cmd uname
  need_cmd mktemp
  need_cmd chmod
  need_cmd mkdir
  need_cmd awk
  need_cmd python3
  need_cmd install

  os="$(detect_os)"
  arch="$(detect_arch)"
  log "detected target: ${os}/${arch}"

  TMP_DIR="$(mktemp -d)"

  release_json="$(fetch_release_json)"
  if command -v jq >/dev/null 2>&1; then
    tag_name="$(printf '%s' "${release_json}" | jq -r '.tag_name')"
  else
    tag_name="$(printf '%s' "${release_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))')"
  fi

  if [ -z "${tag_name}" ] || [ "${tag_name}" = "null" ]; then
    die "could not resolve latest release tag"
  fi
  log "latest release: ${tag_name}"

  if ! asset_line="$(select_asset "${release_json}" "${os}" "${arch}")"; then
    die "no downloadable asset found for ${os}/${arch} in ${tag_name}"
  fi

  asset_name="$(printf '%s' "${asset_line}" | awk -F '\t' '{print $1}')"
  asset_url="$(printf '%s' "${asset_line}" | awk -F '\t' '{print $2}')"
  [ -n "${asset_url}" ] || die "selected asset did not include a download URL"
  log "selected asset: ${asset_name}"

  downloaded="${TMP_DIR}/${asset_name}"
  curl -fsSL "${asset_url}" -o "${downloaded}"

  verify_checksum_if_available "${downloaded}" "${asset_name}" "${release_json}"

  mkdir -p "${INSTALL_DIR}"
  install -m 0755 "${downloaded}" "${INSTALL_DIR}/${BINARY_NAME}"

  log "installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
  cat >&2 <<EOF

Next steps:
  1) Ensure ${INSTALL_DIR} is on your PATH
     export PATH="${INSTALL_DIR}:\$PATH"
  2) Verify installation
     authprobe --version
EOF
}

install_binary
