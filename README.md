# Vaultify

**Find plaintext secrets. Move them to your vault. Clean your code.**

Vaultify scans your machine for leaked API keys, tokens, and credentials scattered across config files, `.env` files, IDE settings, and AI tool outputs. It helps you decide what to do with each one — vault it, remove it, or dismiss it — and then does it automatically.

## Quick Start

```bash
# Download the binary for your platform
# Windows: vaultify.exe
# macOS:   vaultify

# Run it — browser opens automatically
./vaultify
```

That's it. The dashboard opens in your browser. Click **Start Scan**, review findings, make decisions, apply.

## What It Does

1. **Scan** — walks your filesystem, matches 30+ regex patterns (AWS keys, GitHub PATs, Slack tokens, OpenAI keys, private key blocks, etc.)
2. **Review** — interactive table showing each unique secret, where it appears, and a redacted preview
3. **Decide** — for each secret: **Vault It** (move to 1Password/AWS/HashiCorp), **Remove From Code** (redact in place), or **Dismiss**
4. **Apply** — secrets are moved to your vault with `op://` references replacing the plaintext, or redacted with `REDACTED_BY_VAULTIFY`

## Supported Vaults

| Vault | Status | CLI |
|-------|--------|-----|
| 1Password | Production | `op` |
| AWS Secrets Manager | Experimental | `aws` |
| HashiCorp Vault | Experimental | `vault` |
| Doppler | Experimental | `doppler` |

## Build From Source

Requires Go 1.22+.

```bash
# Build for current platform
go build -o vaultify ./cmd/vaultify

# Cross-compile
make all  # builds for windows, mac (intel + arm), linux
```

## License

Proprietary. All rights reserved.
