# Release notes

Each release ships human-readable notes in two formats:

| File | Used by |
|------|---------|
| `releases/notes/X.Y.Z.json` | In-app **Version** page (`GET /api/version/notes`) |
| `releases/notes/X.Y.Z.md` | GitHub Release body (prepended before download table) |

## Before tagging `vX.Y.Z`

1. Add `releases/notes/X.Y.Z.json` with `version`, `date`, optional `summary`, and `changes[]` (`type`: `new` \| `fix` \| `perf` \| `security`).
2. Add `releases/notes/X.Y.Z.md` with a short “What’s new” section for GitHub.
3. Prepend `X.Y.Z` to `releases/notes/index.json` → `"versions"` array.
4. Tag and push — CI publishes the release and bumps `releases/latest.json` (includes `notes_url`).

Change types in JSON map to colored chips in the app UI.
