


<p align="center">
<img width="90" height="90" alt="vaultify_logo" src="https://github.com/user-attachments/assets/05e36d75-cdb6-46e4-a0ba-003d257a395a" /><img width="200" height="90" alt="vaultify_logo_long" src="https://github.com/user-attachments/assets/b258e763-ad8f-400a-bb0c-1dc6f2ccd9ba" />
</p>
<p align="center">
**Find plaintext secrets. Move them to your vault. Clean your code.**
</p>
Vaultify scans your machine for leaked API keys, tokens, and credentials scattered across config files, IDE settings, and AI tool outputs. It helps you decide what to do with each one — Vaultify it (store in your vault), remove it, or dismiss it — and then does it automatically.

<video src="https://github.com/user-attachments/assets/48795b05-b1b3-4d5b-9d5b-419086a73b69" width="848"
    height="477"
    controls
    playsinline></video>

## Quick Start

**Releases:** pre-built binaries (Windows, macOS Intel/ARM, Linux x86_64/ARM64), `SHA256SUMS`, and `LICENSE` are attached to each [GitHub Release](https://github.com/inaor/vaultify/releases). Pick the asset that matches your OS and architecture, e.g. `vaultify_0.3.0_linux_amd64`. Verify with `SHA256SUMS` (see the release notes).

```bash
# Example (Linux / macOS) — make executable if needed
chmod +x ./vaultify_0.3.0_linux_amd64
./vaultify_0.3.0_linux_amd64
```

On Windows, run the `.exe`; On MacOs unpack the `.app` and the dashboard will open at `http://localhost:9471` by default.

That's it. Click **Start Scan**, review findings, make decisions, apply.

<img width="848" height="824" alt="Untitled" src="https://github.com/user-attachments/assets/274e191c-af17-40e8-9fbf-9a228eccff5a" />

On your report you have a number of options - **Vaultify**, **Remove** or **Junk**.

## Quick Start

**Releases:** pre-built binaries (Windows, macOS Intel/ARM, Linux x86_64/ARM64), `SHA256SUMS`, and `LICENSE` are attached to each [GitHub Release](https://github.com/inaor/vaultify/releases). Pick the asset that matches your OS and architecture, e.g. `vaultify_0.3.0_linux_amd64`. Verify with `SHA256SUMS` (see the release notes).

```bash
# Example (Linux / macOS) — make executable if needed
chmod +x ./vaultify_0.3.0_linux_amd64
./vaultify_0.3.0_linux_amd64
```

On Windows, run the `.exe`; the dashboard opens at `http://localhost:9471` by default.

That's it. Click **Start Scan**, review findings, make decisions, apply.

<img width="848" height="824" alt="Untitled" src="https://github.com/user-attachments/assets/274e191c-af17-40e8-9fbf-9a228eccff5a" />

On your report you have a number of options - **Vaultify**, **Remove** or **Junk**.

## What It Does

1. **Scan** — walks your filesystem, matches 30+ regex patterns (AWS keys, GitHub PATs, Slack tokens, OpenAI keys, private key blocks, etc.)
2. **Review** — interactive table showing each unique secret, where it appears, and a redacted preview
3. **Decide** — for each secret: **Vaultify** (move to 1Password/AWS/HashiCorp), **Remove From Code** (redact in place), or **Dismiss**
4. **Apply** — secrets are moved to your vault with `op://` references replacing the plaintext, or redacted with `REDACTED_BY_VAULTIFY`

## Features

Using the Walkthrough you can find all the app features, including Vee, your Secret Agent, her FP Finder (requires AI model token), Generating reports, follow remediation, increase your secrets catalogue and more.

**Take into mind that the app is still in the making and might introduce bugs. Feel free to report them**

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
go build -ldflags "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=0.3.0" -o vaultify ./cmd/vaultify

# Cross-compile all release targets into dist/ + SHA256SUMS
make all                            # Unix shell + Make
pwsh ./scripts/build-release.ps1    # Windows / PowerShell equivalent
```

## License

[MIT License](LICENSE)

## Purpose

Vaultify was made by researchers, for researchers. 
For more about us, visit [JOES](https://www.securityjoes.com)
