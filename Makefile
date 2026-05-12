# Local release-style builds (CI uses .github/workflows/release.yml)
VERSION := 0.3.0
BINARY := vaultify
LDFLAGS := -ldflags "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=$(VERSION)"

LOGO_PNG := internal/web/assets/vaultify_logo.png
ICON_ICO := cmd/vaultify/vaultify.ico
ICON_SYSO := cmd/vaultify/rsrc_windows_amd64.syso
ICON_ICNS := dist/Vaultify.icns
LINUX_ICONS := dist/linux-icons

.PHONY: all clean clean-icon checksums dev icon icon-windows icon-macos icon-linux macos-app

# icon regenerates every per-platform icon artefact from the source
# logo PNG. Run after the logo changes; the Windows .syso is committed
# so casual contributors don't need rsrc installed.
icon: icon-windows icon-macos icon-linux

icon-windows: $(ICON_SYSO)
icon-macos:   $(ICON_ICNS)
icon-linux:   $(LINUX_ICONS)/vaultify.desktop

$(ICON_ICO): $(LOGO_PNG) tools/icogen/main.go
	go run ./tools/icogen -format ico -in $(LOGO_PNG) -out $(ICON_ICO)

$(ICON_SYSO): $(ICON_ICO)
	@command -v rsrc >/dev/null 2>&1 || { echo "rsrc not found; run: go install github.com/akavel/rsrc@latest"; exit 1; }
	rsrc -ico $(ICON_ICO) -arch amd64 -o $(ICON_SYSO)

$(ICON_ICNS): $(LOGO_PNG) tools/icogen/main.go
	mkdir -p dist
	go run ./tools/icogen -format icns -in $(LOGO_PNG) -out $(ICON_ICNS)

$(LINUX_ICONS)/vaultify.desktop: $(LOGO_PNG) tools/icogen/main.go
	mkdir -p $(LINUX_ICONS)
	go run ./tools/icogen -format png-set -in $(LOGO_PNG) -out $(LINUX_ICONS)

# macos-app wraps a darwin binary inside Vaultify.app/ with the icon
# and a minimal Info.plist. ARCH=amd64|arm64 selects the slice.
macos-app: ARCH ?= arm64
macos-app: $(ICON_ICNS)
	mkdir -p dist/Vaultify.app/Contents/MacOS dist/Vaultify.app/Contents/Resources
	GOOS=darwin GOARCH=$(ARCH) go build -trimpath $(LDFLAGS) -o dist/Vaultify.app/Contents/MacOS/vaultify ./cmd/vaultify
	cp $(ICON_ICNS) dist/Vaultify.app/Contents/Resources/AppIcon.icns
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	  '<plist version="1.0"><dict>' \
	  '  <key>CFBundleName</key><string>Vaultify</string>' \
	  '  <key>CFBundleDisplayName</key><string>Vaultify</string>' \
	  '  <key>CFBundleIdentifier</key><string>app.vaultify.cli</string>' \
	  '  <key>CFBundleExecutable</key><string>vaultify</string>' \
	  '  <key>CFBundleIconFile</key><string>AppIcon</string>' \
	  '  <key>CFBundlePackageType</key><string>APPL</string>' \
	  '  <key>CFBundleShortVersionString</key><string>$(VERSION)</string>' \
	  '  <key>CFBundleVersion</key><string>$(VERSION)</string>' \
	  '  <key>LSMinimumSystemVersion</key><string>10.15</string>' \
	  '  <key>NSHighResolutionCapable</key><true/>' \
	  '</dict></plist>' \
	  > dist/Vaultify.app/Contents/Info.plist
	@echo "wrote dist/Vaultify.app for darwin/$(ARCH)"

all: clean icon
	mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_windows_amd64.exe ./cmd/vaultify
	GOOS=darwin GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_darwin_amd64 ./cmd/vaultify
	GOOS=darwin GOARCH=arm64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_darwin_arm64 ./cmd/vaultify
	GOOS=linux GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_linux_amd64 ./cmd/vaultify
	GOOS=linux GOARCH=arm64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_linux_arm64 ./cmd/vaultify
	chmod +x dist/$(BINARY)_$(VERSION)_darwin_amd64 dist/$(BINARY)_$(VERSION)_darwin_arm64 dist/$(BINARY)_$(VERSION)_linux_amd64 dist/$(BINARY)_$(VERSION)_linux_arm64
	# Bundle the icon assets next to the binaries so a release archive
	# carries everything a user needs for shell-level branding.
	cp $(ICON_ICNS) dist/
	cp -R $(LINUX_ICONS) dist/
	$(MAKE) checksums

checksums:
	@cd dist && (command -v sha256sum >/dev/null 2>&1 && sha256sum vaultify_* > SHA256SUMS || shasum -a 256 vaultify_* > SHA256SUMS)
	@cat dist/SHA256SUMS

clean:
	rm -rf dist/

clean-icon:
	rm -f $(ICON_ICO) $(ICON_SYSO) $(ICON_ICNS)
	rm -rf $(LINUX_ICONS) dist/Vaultify.app

dev:
	go run ./cmd/vaultify
