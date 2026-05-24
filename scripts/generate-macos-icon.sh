#!/usr/bin/env bash
# Build a macOS .icns from a square PNG using sips + iconutil (Apple-native scaling).
set -euo pipefail

SRC="${1:-}"
OUT="${2:-}"
if [[ -z "$SRC" || -z "$OUT" ]]; then
  echo "usage: generate-macos-icon.sh <source.png> <output.icns>" >&2
  exit 2
fi
if [[ ! -f "$SRC" ]]; then
  echo "missing source: $SRC" >&2
  exit 1
fi
if ! command -v sips >/dev/null || ! command -v iconutil >/dev/null; then
  echo "sips and iconutil are required (macOS only)" >&2
  exit 1
fi

ICONSET="$(mktemp -d "${TMPDIR:-/tmp}/vaultify-icon.XXXXXX.iconset")"
cleanup() { rm -rf "$ICONSET"; }
trap cleanup EXIT

declare -a SIZES=(
  "16:icon_16x16.png"
  "32:icon_16x16@2x.png"
  "32:icon_32x32.png"
  "64:icon_32x32@2x.png"
  "128:icon_128x128.png"
  "256:icon_128x128@2x.png"
  "256:icon_256x256.png"
  "512:icon_256x256@2x.png"
  "512:icon_512x512.png"
  "1024:icon_512x512@2x.png"
)

for spec in "${SIZES[@]}"; do
  sz="${spec%%:*}"
  name="${spec#*:}"
  sips -z "$sz" "$sz" "$SRC" --out "$ICONSET/$name" >/dev/null
done

mkdir -p "$(dirname "$OUT")"
iconutil -c icns "$ICONSET" -o "$OUT"
echo "Generated $OUT from $SRC"
