#!/usr/bin/env bash
# Install or upgrade Vaultify from GitHub Releases.
# Installs the binary as `vaultify` and ensures it is on your PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/securityjoes/vaultify/main/scripts/install.sh | bash
#   VAULTIFY_INSTALL_DIR=~/bin bash scripts/install.sh
set -euo pipefail

REPO="${VAULTIFY_REPO:-securityjoes/vaultify}"
INSTALL_DIR="${VAULTIFY_INSTALL_DIR:-${HOME}/.local/bin}"
PATH_MARKER="# vaultify PATH"

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$os" in
    darwin) os="darwin" ;;
    linux) os="linux" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac
  echo "${os}_${arch}"
}

fetch_latest_version() {
  local manifest url version api_url
  url="https://raw.githubusercontent.com/${REPO}/main/releases/latest.json"
  if manifest="$(curl -fsSL "$url" 2>/dev/null)"; then
    if command -v python3 >/dev/null 2>&1; then
      version="$(printf '%s' "$manifest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
    elif command -v jq >/dev/null 2>&1; then
      version="$(printf '%s' "$manifest" | jq -r '.version')"
    else
      version="$(printf '%s' "$manifest" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    fi
    if [[ -n "$version" ]]; then
      echo "$version"
      return 0
    fi
  fi
  api_url="https://api.github.com/repos/${REPO}/releases/latest"
  if command -v python3 >/dev/null 2>&1; then
    version="$(curl -fsSL "$api_url" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
  elif command -v jq >/dev/null 2>&1; then
    version="$(curl -fsSL "$api_url" | jq -r '.tag_name' | sed 's/^v//')"
  else
    echo "Could not resolve latest version from ${url} or ${api_url}" >&2
    exit 1
  fi
  if [[ -z "$version" ]]; then
    echo "Could not parse latest release for ${REPO}" >&2
    exit 1
  fi
  echo "$version"
}

path_has_install_dir() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) return 0 ;;
  esac
  return 1
}

append_path_to_file() {
  local file="$1"
  [[ -n "$file" ]] || return 0
  if [[ -f "$file" ]] && grep -Fq "$PATH_MARKER" "$file" 2>/dev/null; then
    return 0
  fi
  mkdir -p "$(dirname "$file")"
  {
    echo ""
    echo "$PATH_MARKER"
    echo "export PATH=\"${INSTALL_DIR}:\$PATH\""
  } >>"$file"
  echo "  updated ${file}"
}

ensure_path() {
  if path_has_install_dir; then
    echo "PATH already includes ${INSTALL_DIR}"
    return 0
  fi

  echo "Adding ${INSTALL_DIR} to your PATH..."
  local shell_name="${SHELL:-}"
  shell_name="${shell_name##*/}"

  case "$shell_name" in
    fish)
      local fish_dir="${HOME}/.config/fish/conf.d"
      mkdir -p "$fish_dir"
      local fish_file="${fish_dir}/vaultify.fish"
      if [[ ! -f "$fish_file" ]]; then
        {
          echo "# vaultify PATH"
          echo "fish_add_path -gm \"${INSTALL_DIR}\""
        } >"$fish_file"
        echo "  created ${fish_file}"
      fi
      ;;
    *)
      append_path_to_file "${HOME}/.zshrc"
      append_path_to_file "${HOME}/.bashrc"
      append_path_to_file "${HOME}/.profile"
      if [[ "$(uname -s)" == "Darwin" ]]; then
        append_path_to_file "${HOME}/.zprofile"
      fi
      ;;
  esac

  export PATH="${INSTALL_DIR}:${PATH}"
  echo ""
  echo "Open a new terminal (or run: source ~/.zshrc) then type: vaultify"
}

verify_command() {
  if command -v vaultify >/dev/null 2>&1; then
    echo ""
    echo "Ready: $(command -v vaultify)"
    vaultify -version 2>/dev/null || true
    return 0
  fi
  echo ""
  echo "Installed to ${INSTALL_DIR}/vaultify"
  echo "After opening a new terminal, run: vaultify"
  return 0
}

main() {
  local platform version asset tmp dest
  platform="$(detect_platform)"
  version="$(fetch_latest_version)"
  asset="vaultify_${version}_${platform}"
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT

  echo "Installing Vaultify v${version} for ${platform}..."
  curl -fsSL -o "$tmp" "https://github.com/${REPO}/releases/download/v${version}/${asset}"
  chmod +x "$tmp"

  mkdir -p "$INSTALL_DIR"
  dest="${INSTALL_DIR}/vaultify"
  mv -f "$tmp" "$dest"
  trap - EXIT

  echo "Installed ${dest}"
  ensure_path
  verify_command
}

main "$@"
