# Vaultify

**Find plaintext secrets. Move them to your vault. Clean your code.**

Vaultify scans your machine for leaked API keys, tokens, and credentials scattered across config files, `.env` files, IDE settings, and AI tool outputs. It helps you decide what to do with each one — Vaultify it (store in your vault), remove it, or dismiss it — and then does it automatically.

[Blazing Fast Scan for NHI](/docs/Screen Recording 2026-05-12 at 14.14.18)

**Source (private):** [github.com/inaor/vaultify_priv](https://github.com/inaor/vaultify_priv) — clone and set `origin` to that URL when you work from a machine that should sync with GitHub.

```bash
git remote add origin https://github.com/inaor/vaultify_priv.git
# or SSH: git@github.com:inaor/vaultify_priv.git
git push -u origin main
```

Pushing a version tag (e.g. `v0.3.0`) triggers the [Release workflow](.github/workflows/release.yml) on GitHub Actions for that repo.

## Quick Start

**Releases:** pre-built binaries (Windows, macOS Intel/ARM, Linux x86_64/ARM64), `SHA256SUMS`, and `LICENSE` are attached to each [GitHub Release](https://github.com/inaor/vaultify_priv/releases) (same private repo; only collaborators can fetch assets unless you later mirror builds elsewhere).

Pick the asset that matches your OS and architecture, e.g. `vaultify_0.3.0_linux_amd64`. Verify with `SHA256SUMS` (see the release notes).

```bash
# Example (Linux / macOS) — make executable if needed
chmod +x ./vaultify_0.3.0_linux_amd64
./vaultify_0.3.0_linux_amd64
```

On Windows, run the `.exe`; the dashboard opens at `http://localhost:9471` by default.

That's it. Click **Start Scan**, review findings, make decisions, apply.

### Native shell branding (icon parity)

Vaultify ships shell-level branding for every supported platform:

- **Windows** — the icon is **embedded inside `vaultify.exe`** (multi-resolution PE resource). Title bar, taskbar, Alt-Tab, Explorer thumbnails and the 1Password unlock prompt all show the Vaultify mark automatically. Nothing to install.
- **macOS** — download `vaultify_<ver>_darwin_<arch>.app.tar.gz` and extract; you get a `Vaultify.app` bundle with `AppIcon.icns` baked in. Drop it into `/Applications` (or anywhere) and Finder/Dock show the icon. The bare `vaultify_*_darwin_*` binary is also published if you prefer the CLI without the bundle. A standalone `Vaultify.icns` is in every release if you want to wrap your own bundle.
- **Linux** — download `vaultify_<ver>_linux-icons.tar.gz` and unpack into your icon and applications dirs:

    ```bash
    tar xzf vaultify_*_linux-icons.tar.gz
    cp -r linux-icons/16x16 linux-icons/22x22 linux-icons/24x24 \
          linux-icons/32x32 linux-icons/48x48 linux-icons/64x64 \
          linux-icons/128x128 linux-icons/256x256 linux-icons/512x512 \
          ~/.local/share/icons/hicolor/
    cp linux-icons/vaultify.desktop ~/.local/share/applications/
    gtk-update-icon-cache -f ~/.local/share/icons/hicolor 2>/dev/null || true
    ```

    GNOME / KDE / XFCE then show the Vaultify icon in launchers, Activities, and Alt-Tab.

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

## Pro licensing (JWT)

Contract for Pro activation tokens (issuer, claims, `kid` rotation, subscription vs perpetual): **[docs/licensing-jwt-v1.md](docs/licensing-jwt-v1.md)**.

## Build From Source

Requires Go 1.22+.

```bash
# Current platform
go build -ldflags "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=0.3.0" -o vaultify ./cmd/vaultify

# Pro build (unlimited scan): set BuildEdition=pro (optional: override MaxScanFilesStr=0 on free is redundant)
go build -ldflags "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=0.3.0 -X github.com/vaultify/vaultify/internal/buildinfo.BuildEdition=pro" -o vaultify ./cmd/vaultify

# Cross-compile all release targets into dist/ + SHA256SUMS
make all                            # Unix shell + Make
pwsh ./scripts/build-release.ps1    # Windows / PowerShell equivalent
```

## License

[MIT License](LICENSE)
