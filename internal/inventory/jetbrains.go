package inventory

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// collectJetBrainsFromHome inventories IDE plugins under JetBrains and Android Studio config trees.
func collectJetBrainsFromHome(ctx context.Context, home string, add func(Item)) {
	if home == "" {
		return
	}
	for _, base := range jetbrainsConfigBases(home) {
		if ctx.Err() != nil {
			return
		}
		collectJetBrainsProductTree(ctx, base, add)
	}
	for _, base := range androidStudioConfigBases(home) {
		if ctx.Err() != nil {
			return
		}
		collectJetBrainsProductTree(ctx, base, add)
	}
}

func jetbrainsConfigBases(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "JetBrains")}
	case "windows":
		if app := os.Getenv("APPDATA"); app != "" {
			return []string{filepath.Join(app, "JetBrains")}
		}
	default:
		return []string{
			filepath.Join(home, ".local", "share", "JetBrains"),
			filepath.Join(home, ".config", "JetBrains"),
		}
	}
	return nil
}

func androidStudioConfigBases(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Google")}
	case "windows":
		if app := os.Getenv("APPDATA"); app != "" {
			return []string{filepath.Join(app, "Google")}
		}
	default:
		return []string{
			filepath.Join(home, ".config", "Google"),
			filepath.Join(home, ".local", "share", "Google"),
		}
	}
	return nil
}

func collectJetBrainsProductTree(ctx context.Context, base string, add func(Item)) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Android Studio product dirs live under Google/AndroidStudio*
		if strings.Contains(filepath.ToSlash(base), "/Google") && !strings.HasPrefix(name, "AndroidStudio") {
			continue
		}
		host := jetbrainsProductHost(name, strings.Contains(filepath.ToSlash(base), "/Google"))
		pluginsDir := filepath.Join(base, name, "plugins")
		collectJetBrainsPluginsDir(ctx, pluginsDir, host, add)
	}
}

func collectJetBrainsPluginsDir(ctx context.Context, pluginsDir, host string, add func(Item)) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if !e.IsDir() {
			continue
		}
		manifest := filepath.Join(pluginsDir, e.Name(), "META-INF", "plugin.xml")
		data, err := readBoundedFile(manifest, maxConfigBytes)
		if err != nil {
			continue
		}
		it, err := parseJetBrainsPluginXML(manifest, data, host)
		if err != nil {
			continue
		}
		add(it)
	}
}

func jetbrainsProductHost(productDir string, googleTree bool) string {
	if googleTree {
		return "android-studio"
	}
	lower := strings.ToLower(productDir)
	switch {
	case strings.Contains(lower, "intellij"):
		return "intellij"
	case strings.Contains(lower, "pycharm"):
		return "pycharm"
	case strings.Contains(lower, "webstorm"):
		return "webstorm"
	case strings.Contains(lower, "goland"):
		return "goland"
	case strings.Contains(lower, "rider"):
		return "rider"
	case strings.Contains(lower, "clion"):
		return "clion"
	case strings.Contains(lower, "phpstorm"):
		return "phpstorm"
	case strings.Contains(lower, "rubymine"):
		return "rubymine"
	case strings.Contains(lower, "datagrip"):
		return "datagrip"
	case strings.Contains(lower, "aqua"):
		return "jetbrains-aqua"
	default:
		return "jetbrains"
	}
}

type ideaPluginXML struct {
	XMLName xml.Name `xml:"idea-plugin"`
	ID      string   `xml:"id"`
	Name    string   `xml:"name"`
	Version string   `xml:"version"`
}

func parseJetBrainsPluginXML(path string, data []byte, host string) (Item, error) {
	var doc ideaPluginXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Item{}, err
	}
	id := strings.TrimSpace(doc.ID)
	name := strings.TrimSpace(doc.Name)
	version := strings.TrimSpace(doc.Version)
	if id == "" && name == "" {
		return Item{}, fmt.Errorf("jetbrains plugin missing id at %s", path)
	}
	if id == "" {
		id = name
	}
	if name == "" {
		name = id
	}
	if version == "" {
		pluginDir := filepath.Base(filepath.Dir(filepath.Dir(path)))
		if i := strings.LastIndexByte(pluginDir, '-'); i > 0 {
			version = pluginDir[i+1:]
		}
	}
	if version == "" {
		version = "unknown"
	}
	return Item{
		Kind:       KindEditorExtension,
		ID:         id,
		Name:       name,
		Version:    version,
		Host:       host,
		SourceFile: path,
		Confidence: "high",
	}, nil
}

func isJetBrainsPluginXML(path string) bool {
	if filepath.Base(path) != "plugin.xml" {
		return false
	}
	if filepath.Base(filepath.Dir(path)) != "META-INF" {
		return false
	}
	slash := filepath.ToSlash(path)
	return strings.Contains(slash, "/plugins/") ||
		strings.Contains(slash, "/JetBrains/") ||
		strings.Contains(slash, "/Google/AndroidStudio")
}

func jetbrainsHostFromPath(path string) string {
	slash := filepath.ToSlash(path)
	parts := strings.Split(slash, "/")
	for i, p := range parts {
		if p == "JetBrains" && i+1 < len(parts) {
			return jetbrainsProductHost(parts[i+1], false)
		}
		if p == "Google" && i+1 < len(parts) && strings.HasPrefix(parts[i+1], "AndroidStudio") {
			return "android-studio"
		}
	}
	return "jetbrains"
}
