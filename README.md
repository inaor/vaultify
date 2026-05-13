

<p align="center">
<img width="90" height="90" alt="vaultify_logo" src="https://github.com/user-attachments/assets/05e36d75-cdb6-46e4-a0ba-003d257a395a" /><br /><img width="200" height="90" alt="vaultify_logo_long" src="https://github.com/user-attachments/assets/b258e763-ad8f-400a-bb0c-1dc6f2ccd9ba" />
</p>

## Runs locally. Finds plaintext secrets. Move them to your vault in one click.

<p align="center">
  <a href="https://github.com/inaor/vaultify/releases/latest"><img src="https://img.shields.io/github/v/release/inaor/vaultify?sort=semver&logo=github&label=version" alt="Latest GitHub release" /></a>
  <a href="https://github.com/inaor/vaultify/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/inaor/vaultify?filename=go.mod&logo=go&label=Go" alt="Go version from go.mod" /></a>
  <a href="https://github.com/inaor/vaultify/blob/main/LICENSE"><img src="https://img.shields.io/github/license/inaor/vaultify?label=license" alt="License" /></a>
  <a href="https://github.com/inaor/vaultify/commits/main/"><img src="https://img.shields.io/github/last-commit/inaor/vaultify/main?label=last%20commit" alt="Last commit on main" /></a>
  <a href="https://pkg.go.dev/github.com/vaultify/vaultify"><img src="https://pkg.go.dev/badge/github.com/vaultify/vaultify.svg" alt="Go package documentation" /></a>
  <img src="https://img.shields.io/badge/NHI%E2%80%94relevant_secrets_%26_service_identity-6e40c9" alt="NHI-adjacent: exposed keys and service credentials" title="Surface API keys, tokens, and other material tied to non-human / machine identity in local code and config" />
</p>

Vaultify scans your machine for potential leaked non-human identities like API keys, tokens, and credentials scattered across config files, IDE settings, and AI tool outputs. It helps you decide what to do with each one — Vaultify it (store in your vault), remove it, or dismiss it — and then does it automatically.

*Vaultify can't understand Run-time. **Please be mindful with NHIs you vault**.*

https://github.com/user-attachments/assets/48795b05-b1b3-4d5b-9d5b-419086a73b69

<p align="center"><a href="https://github.com/user-attachments/assets/48795b05-b1b3-4d5b-9d5b-419086a73b69"><b>Open demo video</b></a> — the inline player scales with the clip’s resolution; export around <b>1280px</b> wide for a larger embed.</p>

## Quick Start

**Releases:** pre-built binaries (Windows, macOS Intel/ARM, Linux x86_64/ARM64), `SHA256SUMS`, and `LICENSE` are attached to each [GitHub Release](https://github.com/inaor/vaultify/releases). Pick the asset that matches your OS and architecture, e.g. `vaultify_0.3.0_linux_amd64`. Verify with `SHA256SUMS` (see the release notes).

```bash
# Example (Linux / macOS) — make executable if needed
chmod +x ./vaultify_0.3.0_linux_amd64
./vaultify_0.3.0_linux_amd64
```

- On Windows, run the `.exe`; 
- On MacOs unpack the `.app` 
- The dashboard should open at `http://localhost:9471` by default.

That's it. Click **Start Scan** or **Specific Folder**, then in the generated report choose how to secure your secrets - **Vaultify**, **Remove** or **Junk**.
review findings, make decisions, apply.

<img width="848" height="824" alt="Untitled" src="https://github.com/user-attachments/assets/274e191c-af17-40e8-9fbf-9a228eccff5a" />

## What It Does

1. **Scan** - walks your filesystem, matches 30+ regex patterns (AWS keys, GitHub PATs, Slack tokens, OpenAI keys, private key blocks, etc.)
2. **Review** - interactive table showing each unique secret, where it appears, and a redacted preview
3. **Decide** - for each secret: **Vaultify** (move to 1Password/AWS/HashiCorp), **Remove From Code** (redact in place), or **Dismiss**
4. **Apply Decisions** - secrets are moved to your vault with `op://` references replacing the plaintext, or redacted with `REDACTED_BY_VAULTIFY`
5. **Reports** - track your remediation process with the generated reports. with each secret handle, reports are updated
6. **Vee** - Vee is your Secret Agent. It's a BYOAI tuned to help you with the secrets management and provide you asisstance.

**Inspect other features and let us know how you liked them**

## Features

Using the Walkthrough you can find all the app features, including Vee, your Secret Agent, her FP Finder (requires AI model token), Generating reports, follow remediation, increase your secrets catalogue and more.

**Take into mind that the app is still in the making and might introduce bugs. Feel free to report them**

## Supported Vaults

| Vault | Status | CLI |
|-------|--------|-----|
| 1Password | Ready | `op` |
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
