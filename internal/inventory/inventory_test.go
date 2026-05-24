package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMCPConfig_stdio(t *testing.T) {
	raw := []byte(`{
	  "mcpServers": {
	    "github": {
	      "command": "npx",
	      "args": ["-y", "@modelcontextprotocol/server-github"]
	    }
	  }
	}`)
	items, err := parseMCPConfig("/Users/test/.cursor/mcp.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0].Kind != KindMCPServer || items[0].ID != "github" {
		t.Fatalf("unexpected item: %+v", items[0])
	}
	if items[0].Name != "@modelcontextprotocol/server-github" {
		t.Fatalf("name=%q", items[0].Name)
	}
	if items[0].Transport != "stdio" {
		t.Fatalf("transport=%q", items[0].Transport)
	}
}

func TestParseMCPConfig_remote(t *testing.T) {
	raw := []byte(`{
	  "mcpServers": {
	    "remote": {
	      "url": "https://user:pass@example.com/path?token=secret"
	    }
	  }
	}`)
	items, err := parseMCPConfig("/tmp/mcp.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1, got %d", len(items))
	}
	if items[0].RequestedSpec != "https://example.com" {
		t.Fatalf("sanitized url=%q", items[0].RequestedSpec)
	}
	if items[0].Transport != "remote" {
		t.Fatalf("transport=%q", items[0].Transport)
	}
}

func TestCollectExtensionsAndMCP(t *testing.T) {
	root := t.TempDir()
	extRoot := filepath.Join(root, ".cursor", "extensions", "acme.demo-1.2.3")
	if err := os.MkdirAll(extRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(extRoot, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"demo","publisher":"acme","version":"1.2.3"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mcpPath := filepath.Join(root, "mcp.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{"time":{"command":"uvx","args":["mcp-server-time"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	items, err := Collect(context.Background(), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) < 2 {
		t.Fatalf("want at least 2 items, got %d: %+v", len(items), items)
	}
	var ext, mcp bool
	for _, it := range items {
		if it.Kind == KindEditorExtension && it.ID == "acme.demo" {
			ext = true
		}
		if it.Kind == KindMCPServer && it.ID == "time" {
			mcp = true
		}
	}
	if !ext || !mcp {
		t.Fatalf("missing expected rows ext=%v mcp=%v all=%+v", ext, mcp, items)
	}
}
