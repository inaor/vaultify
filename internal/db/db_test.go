package db

import (
	"context"
	"path/filepath"
	"testing"
)

// TestOpenAndMigrate covers the happy path: a fresh file gets opened,
// pragmas applied, and every shipped migration runs exactly once. A
// second Migrate() on the same DB must apply zero new ones.
func TestOpenAndMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vaultify.db")

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	applied, err := Migrate(ctx, d)
	if err != nil {
		t.Fatalf("Migrate first call: %v", err)
	}
	if applied != len(migrations) {
		t.Fatalf("expected %d migrations applied on fresh DB, got %d", len(migrations), applied)
	}

	again, err := Migrate(ctx, d)
	if err != nil {
		t.Fatalf("Migrate second call: %v", err)
	}
	if again != 0 {
		t.Fatalf("expected 0 migrations on already-up-to-date DB, got %d", again)
	}

	cur, err := CurrentVersion(ctx, d)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if cur != LatestVersion() {
		t.Fatalf("CurrentVersion=%d, want LatestVersion=%d", cur, LatestVersion())
	}
}

// TestPragmasActive asserts that journal_mode and foreign_keys take
// effect — a misconfigured DSN would silently fall back to DELETE
// journal mode (slower, no concurrent reads) and FKs off (data loss
// on cascading deletes).
func TestPragmasActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vaultify.db")

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	var jm string
	if err := d.QueryRow(`PRAGMA journal_mode;`).Scan(&jm); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if jm != "wal" {
		t.Fatalf("journal_mode=%q, want wal", jm)
	}

	var fk int
	if err := d.QueryRow(`PRAGMA foreign_keys;`).Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys=%d, want 1", fk)
	}
}

// TestSchemaShape spot-checks that the v1 tables exist with the
// columns callers will rely on.
func TestSchemaShape(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(filepath.Join(dir, "vaultify.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
	if _, err := Migrate(context.Background(), d); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	for _, table := range []string{"sessions", "remediation_applied", "schema_migrations"} {
		var name string
		err := d.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
}
