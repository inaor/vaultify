package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vaultify/vaultify/internal/session"
)

// ImportReport summarises a one-shot import from the legacy JSON
// session manager. Counts are cumulative across active and archived.
type ImportReport struct {
	SessionsScanned    int
	SessionsImported   int
	SessionsAlready    int
	RemediationHashes  int
	DecisionFilesSeen  int
}

// ImportFromStore copies every session known to src into the SQLite
// database d. Sessions already present in d are left alone, so this
// is safe to call on every startup. The legacy JSON files are NOT
// deleted — Phase 6b is a non-destructive cutover so a downgrade can
// fall back to the JSON manager unchanged.
//
// Decision blobs and archived markers stay on disk; only the canonical
// session row + remediation_applied hashes get pulled into SQLite.
//
// Performance: the importer walks the JSON store's directory directly
// to enumerate session IDs (a cheap dir read) and only loads the full
// session.json via src.Get for IDs that aren't already in SQLite. On a
// machine where every session has already been imported, this turns
// what used to be a multi-second / multi-MB JSON parse storm — driven
// by src.List loading each session.json end-to-end just to build a
// summary — into a few file-stat calls. That mattered: large scans can
// produce session.json files in the tens of MB.
func ImportFromStore(ctx context.Context, d *sql.DB, src session.Store) (ImportReport, error) {
	rep := ImportReport{}
	if d == nil || src == nil {
		return rep, nil
	}

	refs, err := collectSessionRefs(src)
	if err != nil {
		return rep, fmt.Errorf("import enumerate: %w", err)
	}

	for _, ref := range refs {
		rep.SessionsScanned++

		already, err := sessionExists(ctx, d, ref.id)
		if err != nil {
			return rep, err
		}
		if already {
			rep.SessionsAlready++
			// Even when the session row is present, retry merging
			// the on-disk remediation hashes — earlier importer
			// runs may have skipped them during a partial failure.
			n, err := importRemediation(ctx, d, src, ref.id)
			if err != nil {
				return rep, err
			}
			rep.RemediationHashes += n
			if hasDecisionsOnDisk(src, ref.id) {
				rep.DecisionFilesSeen++
			}
			continue
		}

		full, err := src.Get(ref.id)
		if err != nil {
			// Skip a corrupt JSON session rather than abort the
			// whole import — the user can still operate.
			continue
		}
		if err := insertImportedSession(ctx, d, full, ref.archived); err != nil {
			return rep, err
		}
		rep.SessionsImported++

		n, err := importRemediation(ctx, d, src, ref.id)
		if err != nil {
			return rep, err
		}
		rep.RemediationHashes += n
		if hasDecisionsOnDisk(src, ref.id) {
			rep.DecisionFilesSeen++
		}
	}
	return rep, nil
}

// sessionRef is a (id, archived) pair gathered straight from disk so
// the importer can decide what to load without paying for a full
// session.json parse per dir.
type sessionRef struct {
	id       string
	archived bool
}

// collectSessionRefs lists session ID directories under src.BaseDir()
// and tags each one as archived based on the cheap presence of an
// archived.json marker. It deliberately avoids src.List / src.Get so
// that startup stays fast on machines with many sessions or very
// large session.json blobs (a large scan can produce 20+ MB JSON).
func collectSessionRefs(src session.Store) ([]sessionRef, error) {
	base := src.BaseDir()
	if base == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]sessionRef, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !session.IsValidID(id) {
			continue
		}
		ref := sessionRef{id: id}
		if _, err := os.Stat(filepath.Join(src.Dir(id), "archived.json")); err == nil {
			ref.archived = true
		}
		out = append(out, ref)
	}
	return out, nil
}

func sessionExists(ctx context.Context, d *sql.DB, id string) (bool, error) {
	row := d.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE id = ?`, id)
	var n int
	err := row.Scan(&n)
	switch err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, fmt.Errorf("import probe %s: %w", id, err)
	}
}

func insertImportedSession(ctx context.Context, d *sql.DB, sess *session.Session, archived bool) error {
	clean := redactFindings(sess.Findings)
	payload, err := json.Marshal(clean)
	if err != nil {
		return fmt.Errorf("import marshal %s: %w", sess.ID, err)
	}

	scannedAt := sess.ScannedAt
	if scannedAt == "" {
		scannedAt = time.Now().UTC().Format(time.RFC3339)
	}
	originalCount := sess.OriginalFindingsCount
	if originalCount == 0 {
		originalCount = sess.FindingsCount
	}
	status := sess.Status
	if status == "" {
		status = "complete"
	}
	flag := 0
	if archived {
		flag = 1
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO sessions (id, status, scanned_at, findings_count, original_findings_count, archived, findings_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`,
		sess.ID, status, scannedAt, sess.FindingsCount, originalCount, flag, payload,
	)
	if err != nil {
		return fmt.Errorf("import insert %s: %w", sess.ID, err)
	}
	return nil
}

// importRemediation reads the legacy remediation_applied.json file (if
// any) and merges its hashes into SQLite. INSERT OR IGNORE means a
// partial previous import does not double-count.
func importRemediation(ctx context.Context, d *sql.DB, src session.Store, id string) (int, error) {
	path := filepath.Join(src.Dir(id), "remediation_applied.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, nil // unreadable JSON shouldn't break the boot
	}
	var rf struct {
		Completed []string `json:"completed"`
	}
	if err := json.Unmarshal(data, &rf); err != nil {
		return 0, nil
	}
	if len(rf.Completed) == 0 {
		return 0, nil
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("import remediation begin %s: %w", id, err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO remediation_applied (session_id, match_sha256) VALUES (?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return 0, fmt.Errorf("import remediation prepare %s: %w", id, err)
	}
	defer stmt.Close()

	added := 0
	for _, h := range rf.Completed {
		if h == "" {
			continue
		}
		res, err := stmt.ExecContext(ctx, id, h)
		if err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("import remediation exec %s: %w", id, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("import remediation commit %s: %w", id, err)
	}
	return added, nil
}

func hasDecisionsOnDisk(src session.Store, id string) bool {
	_, err := os.Stat(filepath.Join(src.Dir(id), "decisions.json"))
	return err == nil
}
