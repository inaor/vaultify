package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
)

// PostureStore owns the rolling 30-day posture view: a stable
// fingerprint per (pattern, root, relative_path, value-hash) plus the
// timestamps and lifecycle (present / deleted) Vaultify needs to show
// drift over time.
//
// The store is intentionally separate from SessionStore: posture is a
// derived projection so reads can happen without coupling to session writes.
type PostureStore struct {
	db *sql.DB

	// Window is the rolling visibility horizon. Anything whose most
	// recent activity (last_seen or deleted_at) is older than now-Window
	// is pruned on every merge. 30 days is the product baseline; tests
	// override it.
	Window time.Duration
}

// PostureStatus enumerates the lifecycle states a fingerprint can be
// in. Stored as TEXT in SQLite so the DB stays self-describing.
type PostureStatus string

const (
	PostureStatusPresent PostureStatus = "present"
	PostureStatusDeleted PostureStatus = "deleted"
)

// PostureFinding is the wire/UI shape of a single posture row.
type PostureFinding struct {
	Fingerprint         string        `json:"fingerprint"`
	PatternID           string        `json:"pattern_id"`
	Severity            string        `json:"severity"`
	Description         string        `json:"description"`
	Root                string        `json:"root"`
	RelativePath        string        `json:"relative_path"`
	LineNumber          int           `json:"line_number"`
	MatchSHA256         string        `json:"match_sha256"`
	RedactedPreview     string        `json:"redacted_preview"`
	Status              PostureStatus `json:"status"`
	FirstSeen           string        `json:"first_seen"`
	LastSeen            string        `json:"last_seen"`
	LastSessionID       string        `json:"last_session_id"`
	DeletedAt           string        `json:"deleted_at,omitempty"`
	ValidationStatus    string        `json:"validation_status,omitempty"`
	ValidationCheckedAt string        `json:"validation_checked_at,omitempty"`
}

// PostureSummary is the top-of-page header on the Posture UI.
type PostureSummary struct {
	WindowDays int `json:"window_days"`
	Total      int `json:"total"`
	Present    int `json:"present"`
	Deleted    int `json:"deleted"`

	// Severity histograms restricted to status=present so the UI
	// shows current-risk numbers, not historical noise.
	HighPresent   int `json:"high_present"`
	MediumPresent int `json:"medium_present"`
	LowPresent    int `json:"low_present"`

	// Distinct sessions inside the rolling window, useful for showing
	// "based on 3 scans in the last 30 days".
	ScansInWindow int `json:"scans_in_window"`

	// Validation rollups inside the window. ActivePresent is the
	// headline number Vaultify exists for: secrets that were last
	// confirmed live by the provider AND are still on disk.
	ActivePresent  int `json:"active_present"`
	InvalidPresent int `json:"invalid_present"`
}

// NewPostureStore returns a store backed by an already-migrated DB.
// Pass time.Hour*24*30 for production; tests pass shorter windows.
func NewPostureStore(d *sql.DB, window time.Duration) *PostureStore {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	return &PostureStore{db: d, Window: window}
}

// Fingerprint computes the stable identity for a finding inside the
// posture table. Exposed so tests and callers can pre-compute it
// without round-tripping through MergeScan.
func Fingerprint(patternID, root, relativePath, matchSHA256 string) string {
	h := sha256.New()
	h.Write([]byte(patternID))
	h.Write([]byte("|"))
	h.Write([]byte(root))
	h.Write([]byte("|"))
	h.Write([]byte(relativePath))
	h.Write([]byte("|"))
	h.Write([]byte(matchSHA256))
	return hex.EncodeToString(h.Sum(nil))
}

// MergeScan integrates one scan's findings into the posture table.
// The merge is bounded to scanRoots: fingerprints under any other
// root are left alone, so a partial scan never wrongly marks an
// untouched directory as "deleted".
//
// Steps inside one transaction:
//  1. UPSERT every supplied finding -> status=present, refresh last_seen.
//  2. For every fingerprint already on disk under the supplied roots
//     that did NOT show up this scan and is currently `present`, flip
//     to `deleted` with deleted_at = scannedAt.
//  3. Prune rows whose most recent activity is older than the rolling
//     window so the table doesn't grow unbounded.
func (p *PostureStore) MergeScan(
	ctx context.Context,
	sessionID string,
	scannedAt time.Time,
	scanRoots []string,
	findings []scanner.Finding,
) (PostureMergeReport, error) {
	rep := PostureMergeReport{}
	if p == nil || p.db == nil {
		return rep, fmt.Errorf("posture: nil store")
	}

	// Normalise the roots once. Empty or duplicate roots would skew
	// the "absent this scan" detection.
	roots := normaliseRoots(scanRoots)
	if len(roots) == 0 {
		// No scope means we can't reason about deletions safely;
		// upsert what we got and skip the deletion sweep.
		roots = nil
	}
	scannedAtStr := scannedAt.UTC().Format(time.RFC3339)

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("posture merge begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// --- 1. UPSERT findings ---
	seen := make(map[string]struct{}, len(findings))
	upsert, err := tx.PrepareContext(ctx, `
		INSERT INTO posture_findings (
			fingerprint, pattern_id, severity, description,
			root, relative_path, line_number, match_sha256, redacted_preview,
			status, first_seen, last_seen, last_session_id, deleted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'present', ?, ?, ?, NULL)
		ON CONFLICT(fingerprint) DO UPDATE SET
			pattern_id       = excluded.pattern_id,
			severity         = excluded.severity,
			description      = excluded.description,
			line_number      = excluded.line_number,
			redacted_preview = excluded.redacted_preview,
			status           = 'present',
			last_seen        = excluded.last_seen,
			last_session_id  = excluded.last_session_id,
			deleted_at       = NULL
	`)
	if err != nil {
		return rep, fmt.Errorf("posture merge prepare upsert: %w", err)
	}
	defer upsert.Close()

	for _, f := range findings {
		if f.Root == "" || f.RelativePath == "" || f.MatchSHA256 == "" {
			// Skip malformed findings rather than corrupt the index.
			continue
		}
		fp := Fingerprint(f.PatternID, f.Root, f.RelativePath, f.MatchSHA256)
		seen[fp] = struct{}{}

		res, err := upsert.ExecContext(ctx,
			fp, f.PatternID, f.Severity, f.Description,
			f.Root, f.RelativePath, f.LineNumber, f.MatchSHA256, f.RedactedPreview,
			scannedAtStr, scannedAtStr, sessionID,
		)
		if err != nil {
			return rep, fmt.Errorf("posture upsert %s: %w", fp, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			// SQLite reports the same RowsAffected for INSERT and
			// UPDATE on UPSERT; we'll separate new vs revived later.
			rep.Upserted++
		}
	}

	// --- 2. Mark absent-from-this-scan fingerprints as deleted ---
	if len(roots) > 0 && len(seen) > 0 {
		n, err := markAbsentDeleted(ctx, tx, roots, seen, scannedAtStr)
		if err != nil {
			return rep, err
		}
		rep.MarkedDeleted = n
	} else if len(roots) > 0 && len(seen) == 0 {
		// Empty scan over a real scope: every present row in those
		// roots is by definition deleted.
		n, err := markAbsentDeleted(ctx, tx, roots, nil, scannedAtStr)
		if err != nil {
			return rep, err
		}
		rep.MarkedDeleted = n
	}

	// --- 3. Refresh validation_status from the cache table so the
	//        Posture page can headline "active right now" without an
	//        extra join at read time. Only touches rows we just
	//        upserted; sweep-deleted rows keep whatever validation
	//        status they had at the time of removal.
	if _, err := tx.ExecContext(ctx, `
		UPDATE posture_findings
		SET validation_status = COALESCE((SELECT status FROM validations v WHERE v.match_sha256 = posture_findings.match_sha256), validation_status, ''),
		    validation_checked_at = COALESCE((SELECT checked_at FROM validations v WHERE v.match_sha256 = posture_findings.match_sha256), validation_checked_at, '')
		WHERE last_session_id = ?
	`, sessionID); err != nil {
		return rep, fmt.Errorf("posture validation refresh: %w", err)
	}

	// --- 4. Prune rows past the rolling window ---
	cutoff := scannedAt.Add(-p.Window).UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `
		DELETE FROM posture_findings
		WHERE COALESCE(deleted_at, last_seen) < ?
	`, cutoff)
	if err != nil {
		return rep, fmt.Errorf("posture prune: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		rep.Pruned = int(n)
	}

	if err = tx.Commit(); err != nil {
		return rep, fmt.Errorf("posture merge commit: %w", err)
	}
	return rep, nil
}

// PostureMergeReport summarises what one MergeScan call did. Used by
// callers (handlers / startup banner / Logs tab) for observability.
type PostureMergeReport struct {
	Upserted      int `json:"upserted"`
	MarkedDeleted int `json:"marked_deleted"`
	Pruned        int `json:"pruned"`
}

// markAbsentDeleted flips every `present` row under the given roots
// whose fingerprint is NOT in `seen` to status='deleted'. seen may be
// nil for the empty-scan case (mark all rows under those roots).
func markAbsentDeleted(ctx context.Context, tx *sql.Tx, roots []string, seen map[string]struct{}, scannedAtStr string) (int, error) {
	rootsSQL, rootArgs := inClause(roots)
	q := `
		SELECT fingerprint
		FROM posture_findings
		WHERE status = 'present' AND root IN (` + rootsSQL + `)
	`
	rows, err := tx.QueryContext(ctx, q, rootArgs...)
	if err != nil {
		return 0, fmt.Errorf("posture sweep query: %w", err)
	}
	var toDelete []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return 0, err
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		toDelete = append(toDelete, fp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(toDelete) == 0 {
		return 0, nil
	}

	stmt, err := tx.PrepareContext(ctx, `
		UPDATE posture_findings
		SET status = 'deleted', deleted_at = ?
		WHERE fingerprint = ? AND status = 'present'
	`)
	if err != nil {
		return 0, fmt.Errorf("posture sweep prepare: %w", err)
	}
	defer stmt.Close()
	count := 0
	for _, fp := range toDelete {
		res, err := stmt.ExecContext(ctx, scannedAtStr, fp)
		if err != nil {
			return count, fmt.Errorf("posture sweep update: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			count++
		}
	}
	return count, nil
}

// Recent returns every posture row currently inside the rolling
// window, newest activity first. The caller is expected to enforce
// HTTP auth / session scoping — the store does not gate.
func (p *PostureStore) Recent(ctx context.Context, now time.Time) ([]PostureFinding, error) {
	cutoff := now.Add(-p.Window).UTC().Format(time.RFC3339)
	rows, err := p.db.QueryContext(ctx, `
		SELECT fingerprint, pattern_id, severity, description,
			root, relative_path, line_number, match_sha256, redacted_preview,
			status, first_seen, last_seen, last_session_id, COALESCE(deleted_at, ''),
			COALESCE(validation_status, ''), COALESCE(validation_checked_at, '')
		FROM posture_findings
		WHERE COALESCE(deleted_at, last_seen) >= ?
		ORDER BY
			CASE status WHEN 'present' THEN 0 ELSE 1 END,
			CASE validation_status WHEN 'active' THEN 0 ELSE 1 END,
			CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
			last_seen DESC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("posture recent: %w", err)
	}
	defer rows.Close()

	var out []PostureFinding
	for rows.Next() {
		var f PostureFinding
		var status string
		if err := rows.Scan(
			&f.Fingerprint, &f.PatternID, &f.Severity, &f.Description,
			&f.Root, &f.RelativePath, &f.LineNumber, &f.MatchSHA256, &f.RedactedPreview,
			&status, &f.FirstSeen, &f.LastSeen, &f.LastSessionID, &f.DeletedAt,
			&f.ValidationStatus, &f.ValidationCheckedAt,
		); err != nil {
			return nil, err
		}
		f.Status = PostureStatus(status)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Summary returns aggregate counts inside the rolling window. The
// scans_in_window count is taken from the sessions table.
func (p *PostureStore) Summary(ctx context.Context, now time.Time) (PostureSummary, error) {
	sum := PostureSummary{WindowDays: int(p.Window / (24 * time.Hour))}
	cutoff := now.Add(-p.Window).UTC().Format(time.RFC3339)

	row := p.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			SUM(CASE WHEN status='present' THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='deleted' THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='present' AND severity='high'   THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='present' AND severity='medium' THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='present' AND severity='low'    THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='present' AND validation_status='active'  THEN 1 ELSE 0 END),
			SUM(CASE WHEN status='present' AND validation_status='invalid' THEN 1 ELSE 0 END)
		FROM posture_findings
		WHERE COALESCE(deleted_at, last_seen) >= ?
	`, cutoff)

	// SUM() returns NULL on empty tables; nullable wrappers.
	var total, present, deleted, high, med, low, active, invalid sql.NullInt64
	if err := row.Scan(&total, &present, &deleted, &high, &med, &low, &active, &invalid); err != nil {
		return sum, fmt.Errorf("posture summary: %w", err)
	}
	sum.Total = int(total.Int64)
	sum.Present = int(present.Int64)
	sum.Deleted = int(deleted.Int64)
	sum.HighPresent = int(high.Int64)
	sum.MediumPresent = int(med.Int64)
	sum.LowPresent = int(low.Int64)
	sum.ActivePresent = int(active.Int64)
	sum.InvalidPresent = int(invalid.Int64)

	// Best-effort: count distinct sessions in the window. Failing
	// the lookup shouldn't break the summary endpoint.
	var scans sql.NullInt64
	_ = p.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sessions WHERE scanned_at >= ?
	`, cutoff).Scan(&scans)
	sum.ScansInWindow = int(scans.Int64)
	return sum, nil
}

// normaliseRoots trims, dedupes, and sorts the input so the SQL IN
// clause has a stable shape across calls (helpful for tests).
func normaliseRoots(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// inClause builds a "?, ?, ?" placeholder string and matching args
// slice for SQL IN clauses. Caller must guarantee non-empty input.
func inClause(items []string) (string, []any) {
	placeholders := make([]string, len(items))
	args := make([]any, len(items))
	for i, v := range items {
		placeholders[i] = "?"
		args[i] = v
	}
	return strings.Join(placeholders, ","), args
}
