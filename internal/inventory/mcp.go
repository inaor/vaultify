package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const maxConfigBytes = 512 * 1024

var knownMCPBasenames = map[string]bool{
	"mcp.json":                 true,
	".mcp.json":                true,
	"claude_desktop_config.json": true,
	"mcp_config.json":          true,
	"mcp_settings.json":        true,
	"cline_mcp_settings.json":  true,
}

func isKnownMCPConfig(path string) bool {
	base := filepath.Base(path)
	if knownMCPBasenames[base] {
		return true
	}
	return base == "settings.json" && filepath.Base(filepath.Dir(path)) == ".gemini"
}

func parseMCPConfig(path string, data []byte) ([]Item, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse mcp json: %w", err)
	}
	servers, envelope := extractMCPServers(root)
	if len(servers) == 0 {
		return nil, nil
	}
	out := make([]Item, 0, len(servers))
	for id, raw := range servers {
		it, ok := mcpServerItem(path, id, raw)
		if ok {
			out = append(out, it)
		}
	}
	_ = envelope
	return out, nil
}

func extractMCPServers(root map[string]json.RawMessage) (map[string]json.RawMessage, string) {
	for _, key := range []string{"mcpServers", "servers"} {
		if raw, ok := root[key]; ok {
			var m map[string]json.RawMessage
			if json.Unmarshal(raw, &m) == nil && len(m) > 0 {
				return m, key
			}
		}
	}
	// Flat envelope: top-level keys that look like server entries.
	flat := map[string]json.RawMessage{}
	for k, v := range root {
		if k == "schema_version" || k == "version" {
			continue
		}
		var probe map[string]any
		if json.Unmarshal(v, &probe) != nil {
			continue
		}
		if looksLikeMCPServerEntry(probe) {
			flat[k] = v
		}
	}
	return flat, "flat"
}

func looksLikeMCPServerEntry(m map[string]any) bool {
	if _, ok := m["command"]; ok {
		return true
	}
	if _, ok := m["url"]; ok {
		return true
	}
	if _, ok := m["serverUrl"]; ok {
		return true
	}
	if _, ok := m["httpUrl"]; ok {
		return true
	}
	if args, ok := m["args"].([]any); ok && len(args) > 0 {
		return true
	}
	if t, ok := m["type"].(string); ok && t != "" {
		return true
	}
	return false
}

type mcpServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	ServerURL string `json:"serverUrl"`
	HTTPURL   string `json:"httpUrl"`
	Type    string   `json:"type"`
}

func mcpServerItem(sourceFile, serverID string, raw json.RawMessage) (Item, bool) {
	var s mcpServer
	if err := json.Unmarshal(raw, &s); err != nil {
		return Item{}, false
	}
	it := Item{
		Kind:       KindMCPServer,
		ID:         serverID,
		Name:       serverID,
		SourceFile: sourceFile,
		Confidence: "low",
		Host:       "mcp",
	}
	remote := firstNonEmpty(s.URL, s.ServerURL, s.HTTPURL)
	if remote != "" && s.Command == "" {
		it.Transport = "remote"
		it.RequestedSpec = sanitizeRemoteURL(remote)
		it.Confidence = "medium"
		return it, true
	}
	if s.Command == "" && len(s.Args) == 0 {
		return Item{}, false
	}
	it.Transport = "stdio"
	it.Command = s.Command
	if pkg, spec := parseMCPPackage(s.Command, s.Args); pkg != "" {
		it.Name = pkg
		it.RequestedSpec = spec
		it.Confidence = "medium"
	}
	return it, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func sanitizeRemoteURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "remote"
	}
	if u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	if strings.HasPrefix(raw, "//") {
		if u.Host != "" {
			return "//" + u.Host
		}
	}
	return "remote"
}

func parseMCPPackage(command string, args []string) (name, spec string) {
	cmd := strings.ToLower(strings.TrimSpace(command))
	argv := append([]string{}, args...)
	switch {
	case cmd == "npx" || cmd == "bunx" || strings.HasSuffix(cmd, "/npx") || strings.HasSuffix(cmd, "/bunx"):
		return npmStyleSpec(argv)
	case cmd == "uvx" || cmd == "uv" || strings.HasSuffix(cmd, "/uvx") || strings.HasSuffix(cmd, "/uv"):
		return uvStyleSpec(command, argv)
	case cmd == "python" || cmd == "python3" || strings.HasSuffix(cmd, "/python") || strings.HasSuffix(cmd, "/python3"):
		return pythonModuleSpec(argv)
	case cmd == "docker" || strings.HasSuffix(cmd, "/docker"):
		return dockerImageSpec(argv)
	default:
		if len(argv) > 0 {
			return strings.TrimSpace(argv[0]), ""
		}
		return command, ""
	}
}

func npmStyleSpec(args []string) (string, string) {
	for i, a := range args {
		if a == "-y" || a == "--yes" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		pkg := strings.TrimSpace(a)
		if pkg == "" {
			continue
		}
		if strings.Contains(pkg, "@") && !strings.HasPrefix(pkg, "@") {
			parts := strings.SplitN(pkg, "@", 2)
			return parts[0], pkg
		}
		if strings.HasPrefix(pkg, "@") {
			// scoped package with optional @version
			if i+1 < len(args) && strings.HasPrefix(args[i+1], "@") {
				return pkg, pkg + args[i+1]
			}
		}
		return pkg, ""
	}
	return "", ""
}

func uvStyleSpec(command string, args []string) (string, string) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--from" && i+1 < len(args) {
			return strings.TrimSpace(args[i+1]), ""
		}
	}
	if strings.Contains(command, "uvx") || (len(args) > 0 && args[0] != "run") {
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			return strings.TrimSpace(args[0]), ""
		}
	}
	return "", ""
}

func pythonModuleSpec(args []string) (string, string) {
	for i, a := range args {
		if a == "-m" && i+1 < len(args) {
			return "python:" + strings.TrimSpace(args[i+1]), ""
		}
	}
	return "", ""
}

func dockerImageSpec(args []string) (string, string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == "run" {
			continue
		}
		ref := strings.TrimSpace(a)
		if ref == "" {
			continue
		}
		name, ver := ref, ""
		if idx := strings.LastIndex(ref, ":"); idx > strings.LastIndex(ref, "/") {
			name, ver = ref[:idx], ref[idx+1:]
		}
		return name, ver
	}
	return "", ""
}

func readBoundedMCP(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxConfigBytes))
}
