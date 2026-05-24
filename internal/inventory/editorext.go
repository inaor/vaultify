package inventory

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

var extensionRootSuffixes = []string{
	".vscode/extensions",
	".vscode-server/extensions",
	".vscode-insiders/extensions",
	".cursor/extensions",
	".cursor-server/extensions",
	".windsurf/extensions",
	".windsurf-server/extensions",
	".vscodium/extensions",
}

func hostFromExtRoot(root string) string {
	slash := filepath.ToSlash(root)
	switch {
	case strings.Contains(slash, ".cursor"):
		return "cursor"
	case strings.Contains(slash, "windsurf"):
		return "windsurf"
	case strings.Contains(slash, "vscodium"):
		return "vscodium"
	case strings.Contains(slash, "insiders"):
		return "vscode-insiders"
	default:
		return "vscode"
	}
}

func isExtensionPackageJSON(path string) (extRoot string, ok bool) {
	if filepath.Base(path) != "package.json" {
		return "", false
	}
	dir := filepath.Dir(path)
	parent := filepath.ToSlash(filepath.Dir(dir))
	for _, seg := range extensionRootSuffixes {
		if strings.HasSuffix(parent, "/"+seg) || parent == seg {
			return filepath.Dir(dir), true
		}
	}
	return "", false
}

type extManifest struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
}

func parseEditorExtension(path string, data []byte) (Item, error) {
	var m extManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Item{}, fmt.Errorf("parse extension manifest: %w", err)
	}
	extDir := filepath.Dir(path)
	if m.Name == "" || m.Version == "" {
		bn := filepath.Base(extDir)
		if i := strings.LastIndexByte(bn, '-'); i > 0 {
			id, ver := bn[:i], bn[i+1:]
			if m.Version == "" {
				m.Version = ver
			}
			if m.Name == "" {
				if dot := strings.IndexByte(id, '.'); dot > 0 {
					m.Publisher = id[:dot]
					m.Name = id[dot+1:]
				} else {
					m.Name = id
				}
			}
		}
	}
	if m.Name == "" || m.Version == "" {
		return Item{}, fmt.Errorf("incomplete extension manifest at %s", path)
	}
	fullID := m.Name
	if m.Publisher != "" {
		fullID = m.Publisher + "." + m.Name
	}
	extRoot, _ := isExtensionPackageJSON(path)
	return Item{
		Kind:       KindEditorExtension,
		ID:         fullID,
		Name:       fullID,
		Version:    m.Version,
		Host:       hostFromExtRoot(extRoot),
		SourceFile: path,
		Confidence: "high",
	}, nil
}

func readBoundedManifest(path string) ([]byte, error) {
	return readBoundedFile(path, maxConfigBytes)
}
