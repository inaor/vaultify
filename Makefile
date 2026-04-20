# Local release-style builds (CI uses .github/workflows/release.yml)
VERSION := 0.1.7
BINARY := vaultify
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all clean checksums dev

all: clean
	mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_windows_amd64.exe ./cmd/vaultify
	GOOS=darwin GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_darwin_amd64 ./cmd/vaultify
	GOOS=darwin GOARCH=arm64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_darwin_arm64 ./cmd/vaultify
	GOOS=linux GOARCH=amd64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_linux_amd64 ./cmd/vaultify
	GOOS=linux GOARCH=arm64 go build -trimpath $(LDFLAGS) -o dist/$(BINARY)_$(VERSION)_linux_arm64 ./cmd/vaultify
	chmod +x dist/$(BINARY)_$(VERSION)_darwin_amd64 dist/$(BINARY)_$(VERSION)_darwin_arm64 dist/$(BINARY)_$(VERSION)_linux_amd64 dist/$(BINARY)_$(VERSION)_linux_arm64
	$(MAKE) checksums

checksums:
	@cd dist && (command -v sha256sum >/dev/null 2>&1 && sha256sum vaultify_* > SHA256SUMS || shasum -a 256 vaultify_* > SHA256SUMS)
	@cat dist/SHA256SUMS

clean:
	rm -rf dist/

dev:
	go run ./cmd/vaultify
