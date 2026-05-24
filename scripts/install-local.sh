#!/usr/bin/env bash
# Install the locally built dist/ binary as `vaultify` on PATH (no GitHub download).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="${VAULTIFY_INSTALL_DIR:-${HOME}/.local/bin}"
PATH_MARKER="# vaultify PATH"

platform="$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/arm64/arm64/')"
case "$platform" in
  darwin_arm64|darwin_amd64|linux_amd64|linux_arm64) ;;
  *) echo "Unsupported platform: $platform" >&2; exit 1 ;;
esac

version="$(grep 'BuildVersion' "$ROOT/internal/buildinfo/buildinfo.go" | sed -n 's/.*"\([^"]*\)".*/\1/p')"
src="$ROOT/dist/vaultify_${version}_${platform}"
if [[ ! -f "$src" ]]; then
  echo "Missing $src — build first:" >&2
  echo "  cd $ROOT && go build -o dist/vaultify_${version}_${platform} ./cmd/vaultify" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"

if [[ "$platform" == darwin_* ]]; then
  bash "$ROOT/scripts/build-macos-app.sh"
  APP_DEST="${HOME}/Applications/Vaultify.app"
  mkdir -p "${HOME}/Applications"
  rm -rf "$APP_DEST"
  cp -R "$ROOT/dist/Vaultify.app" "$APP_DEST"
  cat > "$INSTALL_DIR/vaultify" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
APP="${HOME}/Applications/Vaultify.app"
BIN="${APP}/Contents/MacOS/vaultify"
if [[ ! -x "$BIN" ]]; then
  echo "Vaultify.app not found at ${APP} — run: bash scripts/install-local.sh" >&2
  exit 1
fi
if [[ "${1:-}" == "-version" || "${1:-}" == "--version" ]]; then
  exec "$BIN" -version
fi
if [[ $# -gt 0 ]]; then
  open -a "$APP" --args "$@"
else
  open -a "$APP"
fi
WRAP
  chmod +x "$INSTALL_DIR/vaultify"
  echo "Installed macOS app to ${APP_DEST}"
else
  cp -f "$src" "$INSTALL_DIR/vaultify"
  chmod +x "$INSTALL_DIR/vaultify"
fi

append_path() {
  local file="$1"
  [[ -f "$file" ]] || touch "$file"
  grep -Fq "$PATH_MARKER" "$file" 2>/dev/null && return 0
  {
    echo ""
    echo "$PATH_MARKER"
    echo "export PATH=\"${INSTALL_DIR}:\$PATH\""
  } >>"$file"
}

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    append_path "${HOME}/.zshrc"
    append_path "${HOME}/.zprofile"
    append_path "${HOME}/.bashrc"
    echo "Added ${INSTALL_DIR} to shell profile(s). Run: source ~/.zshrc"
    ;;
esac

export PATH="${INSTALL_DIR}:${PATH}"
if [[ "$platform" == darwin_* ]]; then
  echo "Installed ${INSTALL_DIR}/vaultify ($("${HOME}/Applications/Vaultify.app/Contents/MacOS/vaultify" -version))"
else
  echo "Installed ${INSTALL_DIR}/vaultify ($("$INSTALL_DIR/vaultify" -version))"
fi
