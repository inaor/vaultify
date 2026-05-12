package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
)

// AppStateKeyPostureBackfilled is the app_state row that records when
// the one-shot posture backfill ran. Once set, BackfillPostureFromSessions
// short-circuits — re-running it would either be a no-op (rows already
// merged) or wrongly resurrect rows the user has since pruned/deleted.
const AppStateKeyPostureBackfilled = "posture.backfilled_at"

// PostureBackfillReport summarises what BackfillPostureFromSessions did
// so the startup banner / Logs tab can show concrete numbers.
type PostureBackfillReport struct {
	AlreadyDone      bool   `json:"already_done"`
	SessionsScanned  int    `json:"sessions_scanned"`
	SessionsReplayed int    `json:"sessions_replayed"`
	Upserts          int    `json:"upserts"`
	Deletions        int    `json:"deletions"`
	Pruned           int    `json:"pruned"`
	OldestScannedAt  string `json:"oldest_scanned_at,omitempty"`
	NewestScannedAt  string `json:"newest_scanned_at,omitempty"`
}

// BackfillPostureFromSessions replays every session row through the
// posture store in chronological order so a Pro user sees a populated
// Posture page on first visit, instead of having to wait for fresh
// scans. Idempotent via the AppStateKeyPostureBackfilled flag — a
// second call is a no-op.
//
// Why chronological order matters: the posture lifecycle (present →
// deleted → resurrected) is sensitive to the order MergeScan sees
// fingerprints. Replaying out of order would produce nonsense status
// values for things that were repeatedly deleted/added across scans.
//
// Each session's `scanRoots` is derived from the unique Root values
// of its findings. A session whose findings are empty (or whose roots
// can't be determined) skips the deletion sweep — same behaviour as
// MergeScan when called with an empty roots slice.
func BackfillPostureFromSessions(ctx context.Context, d *sql.DB, p *PostureStore) (PostureBackfillReport, error) {
	rep := PostureBackfillReport{}
	if d == nil || p == nil {
		return rep, nil
	}

	// Idempotency probe.
	if v, err := getAppState(ctx, d, AppStateKeyPostureBackfilled); err != nil {
		return rep, fmt.Errorf("posture backfill probe: %w", err)
	} else if v != "" {
		rep.AlreadyDone = true
		return rep, nil
	}

	rows, err := d.QueryContext(ctx, `
		SELECT id, scanned_at, findings_json
		FROM sessions
		WHERE archived = 0
		ORDER BY scanned_at ASC
	`)
	if err != nil {
		return rep, fmt.Errorf("posture backfill list: %w", err)
	}
	defer rows.Close()

	type sessRow struct {
		id        string
		scannedAt time.Time
		payload   []byte
	}
	var work []sessRow
	for rows.Next() {
		var (
			id, scannedAtStr string
			payload          []byte
		)
		if err := rows.Scan(&id, &scannedAtStr, &payload); err != nil {
			return rep, fmt.Errorf("posture backfill scan: %w", err)
		}
		t, err := time.Parse(time.RFC3339, scannedAtStr)
		if err != nil {
			// A malformed scanned_at should not abort the whole
			// backfill — skip the row, keep going.
			continue
		}
		work = append(work, sessRow{id: id, scannedAt: t, payload: payload})
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}

	// QueryContext returns ASC by scanned_at, but defensive sort in
	// case identical timestamps came back in unstable order.
	sort.SliceStable(work, func(i, j int) bool {
		if work[i].scannedAt.Equal(work[j].scannedAt) {
			return work[i].id < work[j].id
		}
		return work[i].scannedAt.Before(work[j].scannedAt)
	})

	rep.SessionsScanned = len(work)
	if len(work) > 0 {
		rep.OldestScannedAt = work[0].scannedAt.UTC().Format(time.RFC3339)
		rep.NewestScannedAt = work[len(work)-1].scannedAt.UTC().Format(time.RFC3339)
	}

	for _, s := range work {
		var findings []scanner.Finding
		if len(s.payload) > 0 {
			if err := json.Unmarshal(s.payload, &findings); err != nil {
				continue // skip corrupt session
			}
		}
		roots := uniqueRootsFromFindings(findings)
		mr, err := p.MergeScan(ctx, s.id, s.scannedAt, roots, findings)
		if err != nil {
			return rep, fmt.Errorf("posture backfill replay %s: %w", s.id, err)
		}
		rep.SessionsReplayed++
		rep.Upserts += mr.Upserted
		rep.Deletions += mr.MarkedDeleted
		rep.Pruned += mr.Pruned
	}

	if err := setAppState(ctx, d, AppStateKeyPostureBackfilled, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return rep, fmt.Errorf("posture backfill mark done: %w", err)
	}
	return rep, nil
}

// uniqueRootsFromFindings collects the distinct Root paths present in
// a session's findings. Posture's deletion sweep only fires for these
// roots, so a session whose findings are empty silently skips the
// sweep — matching MergeScan's "no scope, only upsert" semantics.
func uniqueRootsFromFindings(findings []scanner.Finding) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, f := range findings {
		if f.Root == "" {
			continue
		}
		if _, ok := seen[f.Root]; ok {
			continue
		}
		seen[f.Root] = struct{}{}
		out = append(out, f.Root)
	}
	sort.Strings(out)
	return out
}

func getAppState(ctx context.Context, d *sql.DB, key string) (string, error) {
	row := d.QueryRowContext(ctx, `SELECT value FROM app_state WHERE key = ?`, key)
	var v string
	switch err := row.Scan(&v); err {
	case nil:
		return v, nil
	case sql.ErrNoRows:
		return "", nil
	default:
		return "", err
	}
}

func setAppState(ctx context.Context, d *sql.DB, key, value string) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO app_state (key, value, set_at)
		VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(key) DO UPDATE SET
			value  = excluded.value,
			set_at = excluded.set_at
	`, key, value)
	return err
}
