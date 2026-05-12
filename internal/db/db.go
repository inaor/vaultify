// Package db is the embedded-SQLite foundation for Vaultify.
//
// It owns the single application database (vaultify.db) plus a small
// versioned-migration runner. No business logic lives here — concrete
// stores (sessions, posture, etc.) layer on top in their own files.
//
// Driver choice: modernc.org/sqlite is pure Go, so Vaultify keeps
// shipping a single static binary on Windows/macOS/Linux without cgo.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vaultify/vaultify/internal/paths"
)

// FileName is the SQLite database file under paths.Root().
const FileName = "vaultify.db"

// DefaultPath returns the absolute path Vaultify uses by default.
func DefaultPath() string { return filepath.Join(paths.Root(), FileName) }

// Open opens (and creates if missing) the SQLite database at path with
// the production-friendly defaults Vaultify expects: WAL journal,
// foreign keys on, busy_timeout to soak short lock waits, and a small
// connection pool (SQLite is a single-writer engine, so contention
// matters more than parallelism).
//
// Caller owns the returned *sql.DB and is responsible for Close.
func Open(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("db.Open: empty path")
	}
	if err := ensureDir(path); err != nil {
		return nil, err
	}

	dsn := buildDSN(path)
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: %w", err)
	}

	// SQLite is single-writer; one open conn keeps writes serial and
	// avoids "database is locked" surprises. Reads still get a small
	// pool via WAL.
	d.SetMaxOpenConns(4)
	d.SetMaxIdleConns(2)
	d.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("db.Open ping: %w", err)
	}

	if err := applyPragmas(ctx, d); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// buildDSN composes a modernc.org/sqlite DSN with the safety pragmas
// that should be set before the first query.
func buildDSN(path string) string {
	q := url.Values{}
	q.Set("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "busy_timeout(5000)")
	return "file:" + path + "?" + q.Encode()
}

// applyPragmas re-asserts pragmas after Open in case the DSN parser
// silently dropped one. Any failure is fatal — running without WAL or
// FKs would surprise callers.
func applyPragmas(ctx context.Context, d *sql.DB) error {
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	} {
		if _, err := d.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("db.applyPragmas %q: %w", stmt, err)
		}
	}
	return nil
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return paths.Ensure() // best-effort; root may already exist
}
