package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
)

// SessionStore is the SQLite-backed implementation of session.Store.
//
// Per-session sidecar blobs (decisions.json, archived.json) are NOT
// migrated yet — handlers continue to write them under SessionsDir().
// Save() therefore lazily MkdirAll's the on-disk session directory so
// callers reaching for s.Dir(id) for those small files don't have to.
//
// Concurrency: SQLite is single-writer; the connection pool in Open()
// (max 4) keeps writes serial without any extra locking here.
type SessionStore struct {
	db          *sql.DB
	sessionsDir string // root for sidecar files; usually paths.SessionsDir()
}

// Compile-time assertion that *SessionStore satisfies session.Store.
var _ session.Store = (*SessionStore)(nil)

// NewSessionStore returns a store backed by an already-opened *sql.DB
// (use db.Open + db.Migrate first). sessionsDir is where sidecar files
// like decisions.json live; pass paths.SessionsDir() in production.
func NewSessionStore(d *sql.DB, sessionsDir string) *SessionStore {
	return &SessionStore{db: d, sessionsDir: sessionsDir}
}

// BaseDir returns the on-disk root used for non-session files (today
// just exclusions.json, which the server reads at NewServer time).
func (s *SessionStore) BaseDir() string { return s.sessionsDir }

// Dir returns the on-disk directory for sidecar files belonging to id.
// Pure getter — no I/O. Save() ensures the directory exists.
func (s *SessionStore) Dir(id string) string {
	return filepath.Join(s.sessionsDir, id)
}

// Save persists a scan's findings, redacting plaintext values just like
// the file-backed Manager does. INSERT OR REPLACE keeps the schema
// constraint clean while preserving original_findings_count across
// repeat saves (e.g. a post-Apply re-save with surviving findings).
func (s *SessionStore) Save(id string, findings []scanner.Finding, ts time.Time) error {
	if !session.IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}

	// Lazy on-disk dir for sidecar writes (decisions.json / archived.json).
	if err := os.MkdirAll(s.Dir(id), 0o700); err != nil {
		return fmt.Errorf("create session sidecar dir: %w", err)
	}

	clean := redactFindings(findings)
	payload, err := json.Marshal(clean)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	origCount := len(findings)
	row := s.db.QueryRowContext(ctx,
		`SELECT original_findings_count FROM sessions WHERE id = ?`, id)
	var existing int
	if err := row.Scan(&existing); err == nil && existing > 0 {
		origCount = existing
	} else if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read existing session: %w", err)
	}

	scannedAt := ts.UTC().Format(time.RFC3339)
	const stmt = `
		INSERT INTO sessions (id, status, scanned_at, findings_count, original_findings_count, archived, findings_json, updated_at)
		VALUES (?, 'complete', ?, ?, ?, COALESCE((SELECT archived FROM sessions WHERE id = ?), 0), ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(id) DO UPDATE SET
			status                  = excluded.status,
			scanned_at              = excluded.scanned_at,
			findings_count          = excluded.findings_count,
			original_findings_count = excluded.original_findings_count,
			findings_json           = excluded.findings_json,
			updated_at              = excluded.updated_at
	`
	if _, err := s.db.ExecContext(ctx, stmt,
		id, scannedAt, len(findings), origCount, id, payload,
	); err != nil {
		return fmt.Errorf("upsert session: %w", err)
	}
	return nil
}

// Get loads a session including its findings.
func (s *SessionStore) Get(id string) (*session.Session, error) {
	if !session.IsValidID(id) {
		return nil, fmt.Errorf("read session: invalid session id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, status, scanned_at, findings_count, original_findings_count, findings_json
		FROM sessions WHERE id = ?
	`, id)

	var (
		sess     session.Session
		payload  []byte
	)
	if err := row.Scan(
		&sess.ID, &sess.Status, &sess.ScannedAt,
		&sess.FindingsCount, &sess.OriginalFindingsCount, &payload,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("read session: not found")
		}
		return nil, fmt.Errorf("read session: %w", err)
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &sess.Findings); err != nil {
			return nil, fmt.Errorf("decode findings: %w", err)
		}
	}
	return &sess, nil
}

// List returns active (non-archived) sessions sorted newest-first.
func (s *SessionStore) List() ([]session.SessionSummary, error) {
	return s.listSessions(false)
}

// ListArchived returns archived sessions sorted newest-first.
func (s *SessionStore) ListArchived() ([]session.SessionSummary, error) {
	return s.listSessions(true)
}

func (s *SessionStore) listSessions(archived bool) ([]session.SessionSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	flag := 0
	if archived {
		flag = 1
	}
	const q = `
		SELECT
			s.id,
			s.status,
			s.scanned_at,
			s.findings_count,
			s.original_findings_count,
			COALESCE((SELECT COUNT(*) FROM remediation_applied r WHERE r.session_id = s.id), 0) AS remediated
		FROM sessions s
		WHERE s.archived = ?
		ORDER BY s.scanned_at DESC
	`
	rows, err := s.db.QueryContext(ctx, q, flag)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []session.SessionSummary
	for rows.Next() {
		var sm session.SessionSummary
		if err := rows.Scan(
			&sm.ID, &sm.Status, &sm.ScannedAt,
			&sm.FindingsCount, &sm.OriginalFindingsCount, &sm.Remediated,
		); err != nil {
			return nil, err
		}
		// Match Manager's contract: surface the original count in the
		// findings_count column when available — UI uses it as the
		// denominator for the remediation progress.
		if sm.OriginalFindingsCount > 0 {
			sm.FindingsCount = sm.OriginalFindingsCount
		} else {
			sm.OriginalFindingsCount = sm.FindingsCount
		}
		sm.HasDecisions = s.hasDecisions(sm.ID)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// hasDecisions checks the per-session sidecar for a saved decisions
// blob. Decisions remain on-disk in this slice; migrating that small
// JSON into SQLite is reserved for a later phase.
func (s *SessionStore) hasDecisions(id string) bool {
	if !session.IsValidID(id) {
		return false
	}
	_, err := os.Stat(filepath.Join(s.Dir(id), "decisions.json"))
	return err == nil
}

// Archive marks a session as archived. Idempotent on missing rows so
// callers don't have to special-case "already gone".
func (s *SessionStore) Archive(id string) error {
	if !session.IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET archived = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("archive session: %w", err)
	}
	return nil
}

// Unarchive flips a session back to the active list.
func (s *SessionStore) Unarchive(id string) error {
	if !session.IsValidID(id) {
		return fmt.Errorf("invalid session id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET archived = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("unarchive session: %w", err)
	}
	return nil
}

// MergeRemediationApplied records hashes that have been remediated.
// INSERT OR IGNORE makes the call naturally idempotent so the same
// hash being credited twice (e.g. from auto-credit + Apply) cannot
// double-count the Reports remediation column.
func (s *SessionStore) MergeRemediationApplied(sessionID string, hashes []string) error {
	if sessionID == "" {
		return nil
	}
	if !session.IsValidID(sessionID) {
		return fmt.Errorf("invalid session id")
	}
	if len(hashes) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("merge remediation begin: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO remediation_applied (session_id, match_sha256) VALUES (?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("merge remediation prepare: %w", err)
	}
	defer stmt.Close()

	for _, h := range hashes {
		if h == "" {
			continue
		}
		if _, err := stmt.ExecContext(ctx, sessionID, h); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("merge remediation exec: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("merge remediation commit: %w", err)
	}
	return nil
}

// redactFindings mirrors session.Manager.Save's hygiene: never persist
// the plaintext value, and replace any in-snippet occurrence with the
// REDACTED marker so a leaked DB still leaks no secrets.
func redactFindings(findings []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if out[i].LineSnippet != "" && out[i].Value != "" {
			out[i].LineSnippet = strings.Replace(out[i].LineSnippet, out[i].Value, "REDACTED_BY_VAULTIFY", 1)
		}
		out[i].Value = ""
	}
	return out
}
