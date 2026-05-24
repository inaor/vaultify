package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseJetBrainsPluginXML(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<idea-plugin>
  <id>com.example.demo</id>
  <name>Demo Plugin</name>
  <version>2.1.0</version>
</idea-plugin>`)
	it, err := parseJetBrainsPluginXML("/tmp/plugins/demo/META-INF/plugin.xml", raw, "pycharm")
	if err != nil {
		t.Fatal(err)
	}
	if it.ID != "com.example.demo" || it.Version != "2.1.0" || it.Host != "pycharm" {
		t.Fatalf("unexpected item: %+v", it)
	}
}

func TestCollectJetBrainsPlugins(t *testing.T) {
	root := t.TempDir()
	product := filepath.Join(root, "Library", "Application Support", "JetBrains", "PyCharm2024.1", "plugins", "demo-plugin")
	if err := os.MkdirAll(filepath.Join(product, "META-INF"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(product, "META-INF", "plugin.xml")
	if err := os.WriteFile(manifest, []byte(`<idea-plugin><id>com.acme.tool</id><version>1.0.0</version></idea-plugin>`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Collect uses home; pass root as fake home with darwin layout only on darwin.
	// Use direct dir collection instead for portable test.
	var got []Item
	collectJetBrainsPluginsDir(context.Background(), filepath.Join(root, "Library", "Application Support", "JetBrains", "PyCharm2024.1", "plugins"), "pycharm", func(it Item) {
		got = append(got, it)
	})
	if len(got) != 1 || got[0].ID != "com.acme.tool" {
		t.Fatalf("want 1 jetbrains plugin, got %+v", got)
	}
}

func TestEclipseIDVersionFromFilename(t *testing.T) {
	id, ver := eclipseIDVersionFromFilename("org.eclipse.jdt.core_3.29.0.v20231201.jar")
	if id != "org.eclipse.jdt.core" || ver != "3.29.0.v20231201" {
		t.Fatalf("id=%q ver=%q", id, ver)
	}
}

func TestParseVSIXManifest(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Id="Contoso.Sample" Version="1.2.3" Publisher="Contoso" />
  </Metadata>
</PackageManifest>`)
	it, err := parseVSIXManifest(`C:\Users\x\AppData\Local\Microsoft\VisualStudio\17.0\Extensions\Contoso\Sample\1.0\extension.vsixmanifest`, raw)
	if err != nil {
		t.Fatal(err)
	}
	if it.ID != "Contoso.Contoso.Sample" {
		t.Fatalf("id=%q want Contoso.Contoso.Sample", it.ID)
	}
	if it.Version != "1.2.3" {
		t.Fatalf("version=%q", it.Version)
	}
	if it.Host != "visual-studio" {
		t.Fatalf("host=%q", it.Host)
	}
}
