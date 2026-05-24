#!/usr/bin/env bash
# Run Vaultify from source on macOS/Linux without a global Go install.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GOVER="${GOVER:-go1.26.3}"
GO_ROOT="${GO_ROOT:-$HOME/go-sdk}"
export PATH="$GO_ROOT/go/bin:$PATH"

if ! command -v go >/dev/null 2>&1; then
  echo "Installing Go $GOVER to $GO_ROOT ..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    arm64) GO_ARCH=arm64 ;;
    x86_64) GO_ARCH=amd64 ;;
    *) echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  TAR="${GOVER}.${OS}-${GO_ARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${TAR}" -o "/tmp/${TAR}"
  mkdir -p "$GO_ROOT"
  tar -C "$GO_ROOT" -xzf "/tmp/${TAR}"
fi

cd "$ROOT"
go mod tidy
exec go run ./cmd/vaultify "$@"
