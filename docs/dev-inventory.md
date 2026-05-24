# Dev tooling inventory (v0.4.0)

Read-only **supply-chain context** collected after each secret scan.

## Scope

| Kind | Sources | Emits |
|------|---------|--------|
| **MCP servers** | Known MCP JSON configs under `$HOME` and scan roots | Server id, launcher command/package, remote endpoint host (sanitized) |
| **IDE plugins / editor extensions** | See table below | Plugin id, version, host IDE |

### IDE plugin sources (v0.4)

| Host | Config locations |
|------|------------------|
| **VS Code family** | `~/.vscode/extensions`, Cursor, Windsurf, VSCodium (+ remote/server trees) |
| **JetBrains** | `~/Library/Application Support/JetBrains/<Product>/plugins` (macOS), `%APPDATA%\JetBrains`, `~/.local/share/JetBrains`, `~/.config/JetBrains` |
| **Android Studio** | Same layout under `.../Google/AndroidStudio*` |
| **Visual Studio** | `%LOCALAPPDATA%\Microsoft\VisualStudio\*\Extensions\` (Windows; `extension.vsixmanifest`) |
| **Eclipse** | `~/.eclipse/org.eclipse.platform_*/plugins/*.jar`, `~/eclipse/plugins` |

Manifests read: `package.json` (VS Code), `META-INF/plugin.xml` (JetBrains), `extension.vsixmanifest` (Visual Studio), OSGi `MANIFEST.MF` inside bundle JARs (Eclipse).

This is **not** language/runtime inventory (Python packages, Maven deps, .NET NuGet, etc.) — that would be lockfile / dependency scanning (Bumblebee Tier-2).

## Explicit non-goals (this release)

- No lockfile / npm version inventory (Bumblebee-class)
- No exposure catalog matching
- No MCP `env` values or secret extraction
- No remediation actions on inventory rows
- No JetBrains plugin repos beyond on-disk installs

## Persistence

Session sidecar: `{sessionDir}/dev_inventory.json`

## API

- `GET /api/scan/state` → `dev_inventory`, `dev_inventory_count`
- `GET /api/sessions/{id}` → same fields when loading a saved session
