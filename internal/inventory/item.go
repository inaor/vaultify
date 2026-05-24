// Package inventory collects read-only dev-tooling context (MCP servers,
// IDE plugins / editor extensions) alongside secret scans. It never emits env secrets.
package inventory

import "crypto/sha256"

// Kind identifies an inventory row type.
type Kind string

const (
	KindMCPServer       Kind = "mcp_server"
	KindEditorExtension Kind = "editor_extension"
)

// Item is one installed or configured dev-tooling artifact on the host.
type Item struct {
	Kind          Kind   `json:"kind"`
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Version       string `json:"version,omitempty"`
	Host          string `json:"host,omitempty"`
	Command       string `json:"command,omitempty"`
	RequestedSpec string `json:"requested_spec,omitempty"`
	Transport     string `json:"transport,omitempty"`
	SourceFile    string `json:"source_file"`
	Confidence    string `json:"confidence"`
}

// DedupeKey returns a stable identity for merging duplicate discoveries.
func (it Item) DedupeKey() string {
	h := sha256.Sum256([]byte(string(it.Kind) + "\x00" + it.SourceFile + "\x00" + it.ID + "\x00" + it.Version))
	return "inv:" + string(h[:8])
}
