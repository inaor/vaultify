package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
)

// Session records metadata and findings for a single scan run.
type Session struct {
	ID                    string            `json:"id"`
	Status                string            `json:"status"`
	ScannedAt             string            `json:"scanned_at"`
	FindingsCount         int               `json:"findings_count"`
	OriginalFindingsCount int               `json:"original_findings_count"`
	Findings              []scanner.Finding `json:"findings,omitempty"`
}

// SessionSummary is a lightweight version for listing.
type SessionSummary struct {
	ID                    string `json:"id"`
	Status                string `json:"status"`
	ScannedAt             string `json:"scanned_at"`
	FindingsCount         int    `json:"findings_count"`
	OriginalFindingsCount int    `json:"original_findings_count"`
	Remediated            int    `json:"remediated"`
	HasDecisions          bool   `json:"has_decisions"`
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
	os.MkdirAll(baseDir, 0o700)
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

// BaseDir returns the root directory where sessions and global files are stored.
func (m *Manager) BaseDir() string {
	return m.baseDir
}

// Save persists a session's findings to disk. No plaintext secret values
// are ever written — they are extracted live from source files at apply time.
func (m *Manager) Save(id string, findings []scanner.Finding, ts time.Time) error {
	if !IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}
	dir := m.Dir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	clean := make([]scanner.Finding, len(findings))
	copy(clean, findings)
	for i := range clean {
		if clean[i].LineSnippet != "" && clean[i].Value != "" {
			clean[i].LineSnippet = strings.Replace(clean[i].LineSnippet, clean[i].Value, "REDACTED_BY_VAULTIFY", 1)
		}
		clean[i].Value = ""
	}

	origCount := len(findings)
	if existing, err := m.Get(id); err == nil && existing.OriginalFindingsCount > 0 {
		origCount = existing.OriginalFindingsCount
	}

	s := Session{
		ID:                    id,
		Status:                "complete",
		ScannedAt:             ts.UTC().Format(time.RFC3339),
		FindingsCount:         len(findings),
		OriginalFindingsCount: origCount,
		Findings:              clean,
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "session.json"), data, 0o600)
}

// Get loads a session by ID.
func (m *Manager) Get(id string) (*Session, error) {
	if !IsValidID(id) {
		return nil, fmt.Errorf("read session: invalid session id")
	}
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

func (m *Manager) isArchived(id string) bool {
	_, err := os.Stat(filepath.Join(m.Dir(id), "archived.json"))
	return err == nil
}

// Archive marks a session as archived.
func (m *Manager) Archive(id string) error {
	if !IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}
	dir := m.Dir(id)
	return os.WriteFile(filepath.Join(dir, "archived.json"), []byte(`{"archived":true}`), 0o600)
}

// Unarchive removes the archived marker from a session.
func (m *Manager) Unarchive(id string) error {
	if !IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}
	return os.Remove(filepath.Join(m.Dir(id), "archived.json"))
}

func (m *Manager) listSessions(wantArchived bool) ([]SessionSummary, error) {
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
		archived := m.isArchived(e.Name())
		if archived != wantArchived {
			continue
		}
		s, err := m.Get(e.Name())
		if err != nil {
			continue
		}
		decPath := filepath.Join(m.Dir(e.Name()), "decisions.json")
		hasDec := false
		if _, err := os.ReadFile(decPath); err == nil {
			hasDec = true
		}
		// Remediation column reflects committed vault/remove only (see MergeRemediationApplied), not pending decisions.
		remediated := m.remediationAppliedCount(e.Name())
		origCount := s.OriginalFindingsCount
		if origCount == 0 {
			origCount = s.FindingsCount
		}
		sessions = append(sessions, SessionSummary{
			ID:                    s.ID,
			Status:                s.Status,
			ScannedAt:             s.ScannedAt,
			FindingsCount:         origCount,
			OriginalFindingsCount: origCount,
			Remediated:            remediated,
			HasDecisions:          hasDec,
		})
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].ScannedAt > sessions[j].ScannedAt
	})
	return sessions, nil
}

// List returns all active (non-archived) sessions sorted newest-first.
func (m *Manager) List() ([]SessionSummary, error) {
	return m.listSessions(false)
}

// ListArchived returns all archived sessions sorted newest-first.
func (m *Manager) ListArchived() ([]SessionSummary, error) {
	return m.listSessions(true)
}

const remediationAppliedFile = "remediation_applied.json"

// MergeRemediationApplied records match_sha256 values that successfully completed vault or remove during Apply.
func (m *Manager) MergeRemediationApplied(sessionID string, hashes []string) error {
	if sessionID == "" {
		return nil
	}
	if !IsValidID(sessionID) {
		return fmt.Errorf("invalid session id")
	}
	dir := m.Dir(sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, remediationAppliedFile)
	seen := make(map[string]struct{})
	if data, err := os.ReadFile(path); err == nil {
		var rf struct {
			Completed []string `json:"completed"`
		}
		if json.Unmarshal(data, &rf) == nil {
			for _, h := range rf.Completed {
				if h != "" {
					seen[h] = struct{}{}
				}
			}
		}
	}
	for _, h := range hashes {
		if h != "" {
			seen[h] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	data, err := json.MarshalIndent(struct {
		Completed []string `json:"completed"`
	}{Completed: out}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (m *Manager) remediationAppliedCount(sessionID string) int {
	if !IsValidID(sessionID) {
		return 0
	}
	path := filepath.Join(m.Dir(sessionID), remediationAppliedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var rf struct {
		Completed []string `json:"completed"`
	}
	if json.Unmarshal(data, &rf) != nil {
		return 0
	}
	return len(rf.Completed)
}
