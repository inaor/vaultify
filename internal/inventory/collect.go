package inventory

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Collect gathers MCP configs and IDE plugins (VS Code family, JetBrains,
// Visual Studio, Eclipse) under the user home and optional scan roots.
// Read-only; env values in MCP configs are ignored.
func Collect(ctx context.Context, scanRoots []string) ([]Item, error) {
	home, _ := os.UserHomeDir()
	seen := map[string]struct{}{}
	var out []Item

	add := func(it Item) {
		key := it.DedupeKey()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, it)
	}

	for _, root := range extensionRoots(home) {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		_ = collectExtensionRoot(ctx, root, add)
	}
	collectJetBrainsFromHome(ctx, home, add)
	collectVisualStudioFromHome(ctx, home, add)
	collectEclipseFromHome(ctx, home, add)

	mcpPaths := mcpConfigCandidates(home, scanRoots)
	for _, p := range mcpPaths {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		data, err := readBoundedMCP(p)
		if err != nil {
			continue
		}
		items, err := parseMCPConfig(p, data)
		if err != nil {
			continue
		}
		for _, it := range items {
			add(it)
		}
	}

	for _, root := range scanRoots {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			base := filepath.Base(path)
			switch {
			case base == "package.json":
				if _, ok := isExtensionPackageJSON(path); ok {
					data, err := readBoundedManifest(path)
					if err != nil {
						return nil
					}
					it, err := parseEditorExtension(path, data)
					if err == nil {
						add(it)
					}
				}
			case base == "plugin.xml" && isJetBrainsPluginXML(path):
				data, err := readBoundedFile(path, maxConfigBytes)
				if err != nil {
					return nil
				}
				it, err := parseJetBrainsPluginXML(path, data, jetbrainsHostFromPath(path))
				if err == nil {
					add(it)
				}
			case isVSIXManifest(path):
				data, err := readBoundedFile(path, maxConfigBytes)
				if err != nil {
					return nil
				}
				it, err := parseVSIXManifest(path, data)
				if err == nil {
					add(it)
				}
			case isEclipsePluginsJar(path):
				it, err := parseEclipseBundleJar(path, eclipseHostFromPath(path))
				if err == nil {
					add(it)
				}
			}
			if isKnownMCPConfig(path) {
				data, err := readBoundedMCP(path)
				if err != nil {
					return nil
				}
				items, err := parseMCPConfig(path, data)
				if err != nil {
					return nil
				}
				for _, it := range items {
					add(it)
				}
			}
			return nil
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func extensionRoots(home string) []string {
	if home == "" {
		return nil
	}
	suffixes := extensionRootSuffixes
	roots := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		roots = append(roots, filepath.Join(home, filepath.FromSlash(s)))
	}
	return roots
}

func collectExtensionRoot(ctx context.Context, root string, add func(Item)) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		manifest := filepath.Join(root, e.Name(), "package.json")
		data, err := readBoundedManifest(manifest)
		if err != nil {
			continue
		}
		it, err := parseEditorExtension(manifest, data)
		if err != nil {
			continue
		}
		add(it)
	}
	return nil
}

func mcpConfigCandidates(home string, scanRoots []string) []string {
	seen := map[string]struct{}{}
	var paths []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" || p == "." {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	if home != "" {
		for _, rel := range []string{
			".cursor/mcp.json",
			".codeium/windsurf/mcp_config.json",
			".claude/.mcp.json",
			".gemini/settings.json",
			"Library/Application Support/Claude/claude_desktop_config.json",
			".config/Claude/claude_desktop_config.json",
			".config/Claude Code/claude_desktop_config.json",
		} {
			add(filepath.Join(home, filepath.FromSlash(rel)))
		}
	}
	for _, root := range scanRoots {
		for _, name := range []string{"mcp.json", ".mcp.json"} {
			add(filepath.Join(root, name))
		}
	}
	sort.Strings(paths)
	return paths
}

// UnderRoot reports whether path is inside root (used in tests).
func UnderRoot(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(path, root+sep)
}
