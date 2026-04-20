# Vaultify

**Find plaintext secrets. Move them to your vault. Clean your code.**

Vaultify scans your machine for leaked API keys, tokens, and credentials scattered across config files, `.env` files, IDE settings, and AI tool outputs. It helps you decide what to do with each one — Vaultify it (store in your vault), remove it, or dismiss it — and then does it automatically.

**Source (private):** [github.com/inaor/vaultify_priv](https://github.com/inaor/vaultify_priv) — clone and set `origin` to that URL when you work from a machine that should sync with GitHub.

```bash
git remote add origin https://github.com/inaor/vaultify_priv.git
# or SSH: git@github.com:inaor/vaultify_priv.git
git push -u origin main
```

Pushing a version tag (e.g. `v0.1.7`) triggers the [Release workflow](.github/workflows/release.yml) on GitHub Actions for that repo.

## Quick Start

**Releases:** pre-built binaries (Windows, macOS Intel/ARM, Linux x86_64/ARM64), `SHA256SUMS`, and `LICENSE` are attached to each [GitHub Release](https://github.com/inaor/vaultify_priv/releases) (same private repo; only collaborators can fetch assets unless you later mirror builds elsewhere).

Pick the asset that matches your OS and architecture, e.g. `vaultify_0.1.7_linux_amd64`. Verify with `SHA256SUMS` (see the release notes).

```bash
# Example (Linux / macOS) — make executable if needed
chmod +x ./vaultify_0.1.7_linux_amd64
./vaultify_0.1.7_linux_amd64
```

On Windows, run the `.exe`; the dashboard opens at `http://localhost:9471` by default.

That's it. Click **Start Scan**, review findings, make decisions, apply.

## What It Does

1. **Scan** — walks your filesystem, matches 30+ regex patterns (AWS keys, GitHub PATs, Slack tokens, OpenAI keys, private key blocks, etc.)
2. **Review** — interactive table showing each unique secret, where it appears, and a redacted preview
3. **Decide** — for each secret: **Vaultify** (move to 1Password/AWS/HashiCorp), **Remove From Code** (redact in place), or **Dismiss**
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
# Current platform
go build -ldflags "-s -w -X main.version=0.1.7" -o vaultify ./cmd/vaultify

# Cross-compile all release targets into dist/ + SHA256SUMS (Unix shell + Make)
make all
```

## License

[MIT License](LICENSE)
