VERSION := 0.1.0
BINARY := vaultify
LDFLAGS := -ldflags "-s -w"

.PHONY: all build-windows build-mac-intel build-mac-arm build-linux clean

all: build-windows build-mac-intel build-mac-arm build-linux

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY).exe ./cmd/vaultify

build-mac-intel:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-mac-intel ./cmd/vaultify

build-mac-arm:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-mac-arm ./cmd/vaultify

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux ./cmd/vaultify

clean:
	rm -rf dist/

dev:
	go run ./cmd/vaultify
