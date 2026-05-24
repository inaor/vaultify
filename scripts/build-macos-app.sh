#!/usr/bin/env bash
# Build Vaultify.app for the current macOS architecture into dist/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(grep 'BuildVersion' "$ROOT/internal/buildinfo/buildinfo.go" | sed -n 's/.*"\([^"]*\)".*/\1/p')"
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/arm64/arm64/')"
BIN="$ROOT/dist/vaultify_${VERSION}_darwin_${ARCH}"
APPDIR="$ROOT/dist/Vaultify.app"
ICNS="$ROOT/dist/Vaultify.icns"

if [[ ! -f "$BIN" ]]; then
  echo "Missing $BIN — build first:" >&2
  echo "  go build -o $BIN ./cmd/vaultify" >&2
  exit 1
fi

LOGO_PNG="$ROOT/internal/web/assets/vaultify_logo.png"

if command -v iconutil >/dev/null && command -v sips >/dev/null; then
  bash "$ROOT/scripts/generate-macos-icon.sh" "$LOGO_PNG" "$ICNS"
else
  ( cd "$ROOT" && go run ./tools/icogen -format icns -in "$LOGO_PNG" -out "$ICNS" )
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/Contents/MacOS" "$APPDIR/Contents/Resources"
cp -f "$BIN" "$APPDIR/Contents/MacOS/vaultify"
chmod +x "$APPDIR/Contents/MacOS/vaultify"
cp -f "$ICNS" "$APPDIR/Contents/Resources/AppIcon.icns"
cat > "$APPDIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Vaultify</string>
  <key>CFBundleDisplayName</key><string>Vaultify</string>
  <key>CFBundleIdentifier</key><string>app.vaultify.cli</string>
  <key>CFBundleExecutable</key><string>vaultify</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>10.15</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APPDIR" >/dev/null 2>&1 || codesign --force --sign - "$APPDIR/Contents/MacOS/vaultify" >/dev/null 2>&1 || true
fi

echo "Built $APPDIR"
