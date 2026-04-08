package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
)

// Session records metadata and findings for a single scan run.
type Session struct {
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	ScannedAt     string            `json:"scanned_at"`
	FindingsCount int               `json:"findings_count"`
	Findings      []scanner.Finding `json:"findings,omitempty"`
}

// SessionSummary is a lightweight version for listing.
type SessionSummary struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	ScannedAt     string `json:"scanned_at"`
	FindingsCount int    `json:"findings_count"`
	Remediated    int    `json:"remediated"`
	HasDecisions  bool   `json:"has_decisions"`
}

// Manager persists sessions to a base directory.
type Manager struct {
	baseDir string
}

// NewManager creates a Manager that stores sessions under baseDir.
func NewManager(baseDir string) *Manager {
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "vaultify-scans")
	}
	os.MkdirAll(baseDir, 0o755)
	return &Manager{baseDir: baseDir}
}

// NewID returns a random hex session identifier.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Dir returns the filesystem directory for a given session.
func (m *Manager) Dir(id string) string {
	return filepath.Join(m.baseDir, id)
}

// Save persists a session's findings to disk. Plaintext values are saved
// separately so the session JSON can be shared without exposing secrets.
func (m *Manager) Save(id string, findings []scanner.Finding, ts time.Time) error {
	dir := m.Dir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	// Save plaintext values separately
	type ptEntry struct {
		MatchSHA256 string `json:"match_sha256"`
		PatternID   string `json:"pattern_id"`
		Value       string `json:"value"`
	}
	var plaintext []ptEntry
	for _, f := range findings {
		if f.Value != "" {
			plaintext = append(plaintext, ptEntry{MatchSHA256: f.MatchSHA256, PatternID: f.PatternID, Value: f.Value})
		}
	}
	if len(plaintext) > 0 {
		ptData, _ := json.MarshalIndent(plaintext, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "plaintext.json"), ptData, 0o644)
	}

	// Strip values from session JSON
	clean := make([]scanner.Finding, len(findings))
	copy(clean, findings)
	for i := range clean {
		clean[i].Value = ""
	}

	s := Session{
		ID:            id,
		Status:        "complete",
		ScannedAt:     ts.UTC().Format(time.RFC3339),
		FindingsCount: len(findings),
		Findings:      clean,
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "session.json"), data, 0o644)
}

// LoadPlaintext reads the plaintext values for a session.
func (m *Manager) LoadPlaintext(id string) map[string]string {
	path := filepath.Join(m.Dir(id), "plaintext.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []struct {
		MatchSHA256 string `json:"match_sha256"`
		Value       string `json:"value"`
	}
	if json.Unmarshal(data, &entries) != nil {
		return nil
	}
	result := make(map[string]string, len(entries))
	for _, e := range entries {
		result[e.MatchSHA256] = e.Value
	}
	return result
}

// Get loads a session by ID.
func (m *Manager) Get(id string) (*Session, error) {
	path := filepath.Join(m.Dir(id), "session.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// List returns all sessions sorted newest-first (without findings data).
func (m *Manager) List() ([]SessionSummary, error) {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var sessions []SessionSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s, err := m.Get(e.Name())
		if err != nil {
			continue
		}
		decPath := filepath.Join(m.Dir(e.Name()), "decisions.json")
		hasDec := false
		remediated := 0
		if data, err := os.ReadFile(decPath); err == nil {
			hasDec = true
			var decs []struct{ Action string `json:"action"` }
			if json.Unmarshal(data, &decs) == nil {
				for _, d := range decs {
					if d.Action == "vault" || d.Action == "remove" { remediated++ }
				}
			}
		}
		sessions = append(sessions, SessionSummary{
			ID:            s.ID,
			Status:        s.Status,
			ScannedAt:     s.ScannedAt,
			FindingsCount: s.FindingsCount,
			Remediated:    remediated,
			HasDecisions:  hasDec,
		})
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].ScannedAt > sessions[j].ScannedAt
	})
	return sessions, nil
}
