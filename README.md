# Vaultify

**Find plaintext secrets → move them to your vault → clean your code.**

Local scanner + embedded dashboard. It walks your filesystem, flags API keys and tokens, and helps you **vault**, **redact**, or **dismiss** each finding—with optional **1Password** (`op`) integration for apply flows.

---

## Video examples

Add your recordings here (e.g. YouTube or Loom). Replace the placeholders when clips are ready.

| Clip | Link |
|------|------|
| **60-second overview** | *link TBD* |
| **First scan → Review → Apply** | *link TBD* |
| **1Password: Connect + Open Vault** | *link TBD* |
| **Posture & Activity (logs)** | *link TBD* |

---

## Quick start

**Binaries:** [Releases](https://github.com/inaor/vaultify/releases) — pick the asset for your OS/arch, verify with `SHA256SUMS` when published.

```bash
chmod +x ./vaultify_*_linux_amd64   # Linux / macOS if needed
./vaultify_*_linux_amd64
```

**macOS (first launch):** Downloaded releases are quarantined by Gatekeeper. If macOS reports the app as **“damaged”** or will not open it, strip quarantine on the `.app` bundle or bare binary (use your real path):

```bash
xattr -dr com.apple.quarantine /path/to/Vaultify-arm64.app
# or, for the standalone Mach-O binary:
xattr -dr com.apple.quarantine ~/Downloads/vaultify_*_darwin_arm64
```

Then open the app or run the binary again. For a frictionless first open without this step, the distributor would need **Developer ID signing + Apple notarization** (not included in OSS builds today).

Windows: run `vaultify.exe`. Browser opens **http://localhost:9471** → **Start Scan** → Review → Apply.

**From source** (Go 1.22+):

```bash
go build -ldflags "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=0.3.0" -o vaultify ./cmd/vaultify
```

Full cross-build (icons + `dist/`): `make all` or `pwsh ./scripts/build-release.ps1`.

---

## What you get

| | |
|--|--|
| **Scan** | Fast path-based walk + many secret patterns |
| **Review** | Table of unique hits, redacted previews, decisions |
| **Apply** | Vault references / redaction (1Password path today) |
| **Posture** | Rolling window of findings over time (SQLite) |

**Vaults today:** **1Password** (`op`) is the supported apply path; **AWS** stub exists; **HashiCorp Vault** / **Doppler** are reserved in the UI for later.

---

## GitHub release at the same version

The [release workflow](.github/workflows/release.yml) runs on `v*` tags and stamps `internal/buildinfo.BuildVersion` from the tag (for example `v0.3.0` → `0.3.0`). To ship **new binaries and assets** without changing that number:

1. On GitHub, remove the release tied to the tag if you want a clean release page (optional).
2. Delete the tag locally and on the remote, then recreate it on the commit you want published:

```bash
git tag -d v0.3.0
git push public :refs/tags/v0.3.0
git tag v0.3.0
git push public v0.3.0
```

3. After install, run a **new** build of `vaultify` / `Vaultify.app` and **hard refresh** the dashboard so embedded `dashboard.html` and `/assets/*` update.

---

## Docs

- **Release CI:** [.github/workflows/release.yml](.github/workflows/release.yml)

---

## License

[MIT](LICENSE)
