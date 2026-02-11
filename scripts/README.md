# Scripts

## `install.sh`

One-command installer for end users:

```bash
curl -fsSL https://raw.githubusercontent.com/authprobe/authprobe/main/scripts/install.sh | sh
```

Behavior:
- Detects OS/arch (`linux|darwin` + `amd64|arm64`).
- Queries GitHub `releases/latest` and selects the first matching binary asset.
- Excludes non-binary assets (checksums, SBOM, signatures).
- Installs to `${AUTHPROBE_INSTALL_DIR:-$HOME/.local/bin}` without `sudo`.
- Verifies SHA256 when a checksums asset is present (best-effort with clear warnings).

## Demo recording pipeline

- `demo.tape` is a VHS script describing the terminal walkthrough.
- `record_demo.sh` runs VHS and writes `docs/assets/demo.gif`.

Usage:

```bash
scripts/record_demo.sh
```

## Maintainer compatibility notes

Release asset naming should continue to include both OS and arch in each binary filename (for example `authprobe_linux_amd64`) so `install.sh` can select the right file without brittle hardcoding.
