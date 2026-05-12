package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// migration is a single forward-only schema step. ID must be a
// monotonically increasing positive integer and is used as the primary
// key in schema_migrations. Down migrations are intentionally absent —
// rolling back a Vaultify schema in production isn't a supported flow.
type migration struct {
	ID   int
	Name string
	SQL  string
}

// migrations is the canonical list, applied in ID order. ALWAYS append;
// never edit a shipped entry — that would corrupt installed databases
// because the schema_migrations table records "already applied".
//
// Style:
//   - One logical change per migration.
//   - Use IF NOT EXISTS for tables/indexes; safe re-application matters
//     when an older binary half-migrated and crashed.
//   - Keep statements ASCII so it round-trips through Go string literals.
var migrations = []migration{
	{
		ID:   1,
		Name: "sessions_and_remediation",
		SQL: `
			CREATE TABLE IF NOT EXISTS sessions (
				id                       TEXT PRIMARY KEY,
				status                   TEXT NOT NULL,
				scanned_at               TEXT NOT NULL,
				findings_count           INTEGER NOT NULL,
				original_findings_count  INTEGER NOT NULL,
				archived                 INTEGER NOT NULL DEFAULT 0,
				findings_json            BLOB NOT NULL,
				created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
				updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
			);

			CREATE INDEX IF NOT EXISTS idx_sessions_archived_scanned
				ON sessions(archived, scanned_at DESC);

			CREATE TABLE IF NOT EXISTS remediation_applied (
				session_id   TEXT NOT NULL,
				match_sha256 TEXT NOT NULL,
				applied_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
				PRIMARY KEY (session_id, match_sha256),
				FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
			);

			CREATE INDEX IF NOT EXISTS idx_remediation_applied_session
				ON remediation_applied(session_id);
		`,
	},
	{
		ID:   2,
		Name: "posture_findings",
		// Rolling 30-day fingerprint of every distinct finding ever
		// observed across scans. fingerprint is a stable hash of
		// pattern_id|root|relative_path|match_sha256 so re-scanning the
		// same source produces the same row, while moving or rotating
		// the secret produces a new fingerprint (and the old one
		// transitions to `deleted` on the next scan of its root).
		SQL: `
			CREATE TABLE IF NOT EXISTS posture_findings (
				fingerprint      TEXT PRIMARY KEY,
				pattern_id       TEXT NOT NULL,
				severity         TEXT NOT NULL,
				description      TEXT NOT NULL,
				root             TEXT NOT NULL,
				relative_path    TEXT NOT NULL,
				line_number      INTEGER NOT NULL DEFAULT 0,
				match_sha256     TEXT NOT NULL,
				redacted_preview TEXT NOT NULL DEFAULT '',
				status           TEXT NOT NULL,                 -- present | deleted
				first_seen       TEXT NOT NULL,
				last_seen        TEXT NOT NULL,
				last_session_id  TEXT NOT NULL,
				deleted_at       TEXT
			);

			CREATE INDEX IF NOT EXISTS idx_posture_root_status
				ON posture_findings(root, status);
			CREATE INDEX IF NOT EXISTS idx_posture_status_last
				ON posture_findings(status, last_seen DESC);
			CREATE INDEX IF NOT EXISTS idx_posture_severity_status
				ON posture_findings(severity, status);
		`,
	},
	{
		ID:   3,
		Name: "app_state",
		// Generic key/value table for one-shot flags (e.g. "posture
		// backfill already ran") and small singletons that don't
		// deserve their own schema. Versioned alongside the rest so a
		// later boot can rely on its presence without defensive
		// CREATE-IF-NOT-EXISTS scattered through callers.
		SQL: `
			CREATE TABLE IF NOT EXISTS app_state (
				key    TEXT PRIMARY KEY,
				value  TEXT NOT NULL,
				set_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
			);
		`,
	},
	{
		ID:   4,
		Name: "validations",
		// Active-validation cache. PRIMARY KEY is match_sha256 so the
		// table can NEVER store the plaintext value, only its hash.
		// validator_id matches internal/validation.Validator.ID().
		// status is the same enum the API returns to the UI.
		SQL: `
			CREATE TABLE IF NOT EXISTS validations (
				match_sha256   TEXT PRIMARY KEY,
				validator_id   TEXT NOT NULL,
				status         TEXT NOT NULL,
				reason         TEXT NOT NULL,
				http_status    INTEGER NOT NULL DEFAULT 0,
				checked_at     TEXT NOT NULL,
				expires_at     TEXT,
				source         TEXT NOT NULL DEFAULT 'user'
			);
			CREATE INDEX IF NOT EXISTS idx_validations_status_checked
				ON validations(status, checked_at DESC);
			CREATE INDEX IF NOT EXISTS idx_validations_validator
				ON validations(validator_id, status);
		`,
	},
	{
		ID:   5,
		Name: "posture_validation",
		// Slice D extension: store the latest validation outcome on
		// each posture row so the Posture page can headline "X active
		// secrets right now" without joining at read time.
		SQL: `
			ALTER TABLE posture_findings ADD COLUMN validation_status TEXT NOT NULL DEFAULT '';
			ALTER TABLE posture_findings ADD COLUMN validation_checked_at TEXT NOT NULL DEFAULT '';
			CREATE INDEX IF NOT EXISTS idx_posture_validation
				ON posture_findings(validation_status, last_seen DESC);
		`,
	},
}

// Migrate brings db up to the latest schema version. It is safe to
// call on every startup and on a fresh database. Returns the number
// of migrations that were freshly applied this call (0 when up-to-date).
func Migrate(ctx context.Context, d *sql.DB) (applied int, err error) {
	if d == nil {
		return 0, fmt.Errorf("db.Migrate: nil db")
	}

	// schema_migrations is itself unversioned: created on demand so the
	// runner has somewhere to write progress.
	if _, err := d.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id          INTEGER PRIMARY KEY,
			name        TEXT NOT NULL,
			applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		);
	`); err != nil {
		return 0, fmt.Errorf("db.Migrate bootstrap: %w", err)
	}

	have, err := loadAppliedIDs(ctx, d)
	if err != nil {
		return 0, err
	}

	pending := make([]migration, 0, len(migrations))
	for _, m := range migrations {
		if _, ok := have[m.ID]; ok {
			continue
		}
		pending = append(pending, m)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].ID < pending[j].ID })

	for _, m := range pending {
		if err := runOne(ctx, d, m); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}

func loadAppliedIDs(ctx context.Context, d *sql.DB) (map[int]struct{}, error) {
	rows, err := d.QueryContext(ctx, `SELECT id FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("db.Migrate read applied: %w", err)
	}
	defer rows.Close()

	out := make(map[int]struct{})
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

func runOne(ctx context.Context, d *sql.DB, m migration) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db.Migrate %d %s begin: %w", m.ID, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("db.Migrate %d %s exec: %w", m.ID, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(id, name) VALUES(?, ?)`,
		m.ID, m.Name,
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("db.Migrate %d %s record: %w", m.ID, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db.Migrate %d %s commit: %w", m.ID, m.Name, err)
	}
	return nil
}

// LatestVersion returns the highest migration ID known to this binary.
// Useful for the startup banner and diagnostics.
func LatestVersion() int {
	highest := 0
	for _, m := range migrations {
		if m.ID > highest {
			highest = m.ID
		}
	}
	return highest
}

// CurrentVersion returns the highest migration ID actually recorded in
// db. Returns 0 when no migrations have run.
func CurrentVersion(ctx context.Context, d *sql.DB) (int, error) {
	row := d.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(id), 0) FROM schema_migrations
	`)
	var v int
	if err := row.Scan(&v); err != nil {
		// schema_migrations may not exist yet on a brand-new DB before
		// Migrate runs. Treat that as version 0.
		return 0, nil
	}
	return v, nil
}
