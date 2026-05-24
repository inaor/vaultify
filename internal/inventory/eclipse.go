package inventory

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// collectEclipseFromHome inventories Eclipse/OSGi bundles under ~/.eclipse and common portable installs.
func collectEclipseFromHome(ctx context.Context, home string, add func(Item)) {
	if home == "" {
		return
	}
	eclipseHome := filepath.Join(home, ".eclipse")
	entries, err := os.ReadDir(eclipseHome)
	if err == nil {
		for _, e := range entries {
			if ctx.Err() != nil {
				return
			}
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "org.eclipse.platform") {
				continue
			}
			collectEclipsePluginsDir(ctx, filepath.Join(eclipseHome, e.Name(), "plugins"), "eclipse", add)
		}
	}
	for _, rel := range []string{"eclipse/plugins", "Eclipse/plugins"} {
		if ctx.Err() != nil {
			return
		}
		collectEclipsePluginsDir(ctx, filepath.Join(home, filepath.FromSlash(rel)), "eclipse-portable", add)
	}
}

func collectEclipsePluginsDir(ctx context.Context, pluginsDir, host string, add func(Item)) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		path := filepath.Join(pluginsDir, name)
		it, err := parseEclipseBundleJar(path, host)
		if err != nil {
			continue
		}
		add(it)
	}
}

func parseEclipseBundleJar(path, host string) (Item, error) {
	id, ver := eclipseIDVersionFromFilename(filepath.Base(path))
	if id == "" {
		return Item{}, fmt.Errorf("eclipse jar name not parseable: %s", path)
	}

	if manifestID, manifestVer, err := readEclipseManifestFromJar(path); err == nil {
		if manifestID != "" {
			id = manifestID
		}
		if manifestVer != "" {
			ver = manifestVer
		}
	}
	if ver == "" {
		ver = "unknown"
	}
	return Item{
		Kind:       KindEditorExtension,
		ID:         id,
		Name:       id,
		Version:    ver,
		Host:       host,
		SourceFile: path,
		Confidence: "high",
	}, nil
}

func eclipseIDVersionFromFilename(base string) (id, version string) {
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".jar"), ".JAR")
	underscore := strings.LastIndexByte(base, '_')
	if underscore <= 0 {
		return base, ""
	}
	return base[:underscore], base[underscore+1:]
}

func readEclipseManifestFromJar(jarPath string) (id, version string, err error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		return "", "", err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", "", err
		}
		id, version, err = parseOSGiManifest(rc)
		rc.Close()
		return id, version, err
	}
	return "", "", fmt.Errorf("no MANIFEST.MF in %s", jarPath)
}

func parseOSGiManifest(r io.Reader) (id, version string, err error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Bundle-SymbolicName:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Bundle-SymbolicName:"))
			if semi := strings.IndexByte(v, ';'); semi >= 0 {
				v = v[:semi]
			}
			id = strings.TrimSpace(v)
		}
		if strings.HasPrefix(line, "Bundle-Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Bundle-Version:"))
		}
	}
	if id == "" {
		return "", "", fmt.Errorf("manifest missing Bundle-SymbolicName")
	}
	return id, version, sc.Err()
}

func isEclipsePluginsJar(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".jar") {
		return false
	}
	slash := filepath.ToSlash(path)
	return strings.Contains(slash, "/plugins/") &&
		(strings.Contains(slash, "/.eclipse/") ||
			strings.Contains(slash, "/eclipse/plugins") ||
			strings.Contains(slash, "/Eclipse/plugins"))
}

func eclipseHostFromPath(path string) string {
	slash := filepath.ToSlash(path)
	if strings.Contains(slash, "/.eclipse/") {
		return "eclipse"
	}
	return "eclipse-portable"
}
