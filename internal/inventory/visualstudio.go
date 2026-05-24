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

// collectVisualStudioFromHome inventories VSIX extensions for full Visual Studio (Windows).
func collectVisualStudioFromHome(ctx context.Context, home string, add func(Item)) {
	if runtime.GOOS != "windows" {
		return
	}
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return
	}
	vsRoot := filepath.Join(local, "Microsoft", "VisualStudio")
	entries, err := os.ReadDir(vsRoot)
	if err != nil {
		return
	}
	for _, inst := range entries {
		if ctx.Err() != nil {
			return
		}
		if !inst.IsDir() {
			continue
		}
		extRoot := filepath.Join(vsRoot, inst.Name(), "Extensions")
		_ = collectVisualStudioExtensionsTree(ctx, extRoot, add)
	}
}

func collectVisualStudioExtensionsTree(ctx context.Context, extRoot string, add func(Item)) error {
	publishers, err := os.ReadDir(extRoot)
	if err != nil {
		return err
	}
	for _, pub := range publishers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !pub.IsDir() {
			continue
		}
		pubDir := filepath.Join(extRoot, pub.Name())
		products, err := os.ReadDir(pubDir)
		if err != nil {
			continue
		}
		for _, prod := range products {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !prod.IsDir() {
				continue
			}
			verDir := filepath.Join(pubDir, prod.Name())
			versions, err := os.ReadDir(verDir)
			if err != nil {
				continue
			}
			for _, ver := range versions {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !ver.IsDir() {
					continue
				}
				manifest := filepath.Join(verDir, ver.Name(), "extension.vsixmanifest")
				data, err := readBoundedFile(manifest, maxConfigBytes)
				if err != nil {
					continue
				}
				it, err := parseVSIXManifest(manifest, data)
				if err != nil {
					continue
				}
				add(it)
			}
		}
	}
	return nil
}

type vsixManifest struct {
	XMLName  xml.Name `xml:"PackageManifest"`
	Metadata struct {
		Identity struct {
			ID        string `xml:"Id,attr"`
			Version   string `xml:"Version,attr"`
			Publisher string `xml:"Publisher,attr"`
		} `xml:"Identity"`
	} `xml:"Metadata"`
}

func parseVSIXManifest(path string, data []byte) (Item, error) {
	var doc vsixManifest
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Item{}, err
	}
	id := strings.TrimSpace(doc.Metadata.Identity.ID)
	pub := strings.TrimSpace(doc.Metadata.Identity.Publisher)
	ver := strings.TrimSpace(doc.Metadata.Identity.Version)
	if id == "" {
		return Item{}, fmt.Errorf("vsix manifest missing id at %s", path)
	}
	fullID := id
	if pub != "" {
		fullID = pub + "." + id
	}
	if ver == "" {
		ver = "unknown"
	}
	return Item{
		Kind:       KindEditorExtension,
		ID:         fullID,
		Name:       fullID,
		Version:    ver,
		Host:       "visual-studio",
		SourceFile: path,
		Confidence: "high",
	}, nil
}

func isVSIXManifest(path string) bool {
	return strings.EqualFold(filepath.Base(path), "extension.vsixmanifest") &&
		strings.Contains(filepath.ToSlash(path), "/Extensions/")
}
