package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
)

// freshDBPair returns an open DB plus a SessionStore + PostureStore
// sharing the same handle, all migrated to the latest schema. Used by
// backfill tests that need to seed sessions then replay them.
func freshDBPair(t *testing.T, window time.Duration) (*SessionStore, *PostureStore) {
	t.Helper()
	root := t.TempDir()
	d, err := Open(filepath.Join(root, "vaultify.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := Migrate(context.Background(), d); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	sidecar := filepath.Join(root, "sessions")
	return NewSessionStore(d, sidecar), NewPostureStore(d, window)
}

// TestBackfillReplaysChronologically asserts that a backfill over two
// sessions where the second one *removed* one finding produces the
// expected (present, deleted) state — exactly as if Posture had been
// running live.
func TestBackfillReplaysChronologically(t *testing.T) {
	sStore, pStore := freshDBPair(t, 30*24*time.Hour)
	ctx := context.Background()

	t1 := time.Now().Add(-48 * time.Hour).UTC()
	t2 := time.Now().Add(-24 * time.Hour).UTC()

	id1 := session.NewID()
	if err := sStore.Save(id1, []scanner.Finding{
		{PatternID: "openai", Severity: "high", Root: "/repo", RelativePath: "a.go", MatchSHA256: "h1"},
		{PatternID: "anthropic", Severity: "medium", Root: "/repo", RelativePath: "b.go", MatchSHA256: "h2"},
	}, t1); err != nil {
		t.Fatalf("seed1: %v", err)
	}
	id2 := session.NewID()
	if err := sStore.Save(id2, []scanner.Finding{
		{PatternID: "openai", Severity: "high", Root: "/repo", RelativePath: "a.go", MatchSHA256: "h1"},
	}, t2); err != nil {
		t.Fatalf("seed2: %v", err)
	}

	rep, err := BackfillPostureFromSessions(ctx, sStore.db, pStore)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if rep.AlreadyDone {
		t.Fatalf("first backfill should not be already-done")
	}
	if rep.SessionsReplayed != 2 || rep.Upserts == 0 || rep.Deletions != 1 {
		t.Fatalf("backfill report wrong: %+v", rep)
	}

	rows, err := pStore.Recent(ctx, time.Now())
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 posture rows, got %d", len(rows))
	}
	statusByPath := map[string]PostureStatus{}
	for _, f := range rows {
		statusByPath[f.RelativePath] = f.Status
	}
	if statusByPath["a.go"] != PostureStatusPresent {
		t.Fatalf("a.go should be present, got %v", statusByPath["a.go"])
	}
	if statusByPath["b.go"] != PostureStatusDeleted {
		t.Fatalf("b.go should be deleted, got %v", statusByPath["b.go"])
	}
}

// TestBackfillIdempotent confirms the AppStateKeyPostureBackfilled
// flag short-circuits repeat invocations.
func TestBackfillIdempotent(t *testing.T) {
	sStore, pStore := freshDBPair(t, 30*24*time.Hour)
	ctx := context.Background()
	id := session.NewID()
	if err := sStore.Save(id, []scanner.Finding{
		{PatternID: "openai", Severity: "high", Root: "/r", RelativePath: "x.go", MatchSHA256: "h1"},
	}, time.Now().Add(-time.Hour).UTC()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := BackfillPostureFromSessions(ctx, sStore.db, pStore); err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	rep2, err := BackfillPostureFromSessions(ctx, sStore.db, pStore)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if !rep2.AlreadyDone {
		t.Fatalf("second backfill should report already_done, got %+v", rep2)
	}
	if rep2.SessionsReplayed != 0 {
		t.Fatalf("second backfill should not replay anything, got %d", rep2.SessionsReplayed)
	}
}

// TestBackfillEmptyDB safely no-ops when there are no sessions yet.
func TestBackfillEmptyDB(t *testing.T) {
	sStore, pStore := freshDBPair(t, 30*24*time.Hour)
	rep, err := BackfillPostureFromSessions(context.Background(), sStore.db, pStore)
	if err != nil {
		t.Fatalf("backfill empty: %v", err)
	}
	if rep.AlreadyDone || rep.SessionsScanned != 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

// TestBackfillSkipsArchived asserts archived sessions don't pollute
// the posture view — they're historical noise the user has already
// hidden.
func TestBackfillSkipsArchived(t *testing.T) {
	sStore, pStore := freshDBPair(t, 30*24*time.Hour)
	ctx := context.Background()

	live := session.NewID()
	if err := sStore.Save(live, []scanner.Finding{
		{PatternID: "openai", Severity: "high", Root: "/r", RelativePath: "a.go", MatchSHA256: "h1"},
	}, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("seed live: %v", err)
	}

	dead := session.NewID()
	if err := sStore.Save(dead, []scanner.Finding{
		{PatternID: "anthropic", Severity: "high", Root: "/r", RelativePath: "z.go", MatchSHA256: "h2"},
	}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("seed dead: %v", err)
	}
	if err := sStore.Archive(dead); err != nil {
		t.Fatalf("archive: %v", err)
	}

	if _, err := BackfillPostureFromSessions(ctx, sStore.db, pStore); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	rows, _ := pStore.Recent(ctx, time.Now())
	if len(rows) != 1 || rows[0].MatchSHA256 != "h1" {
		t.Fatalf("expected only the live session's finding, got %+v", rows)
	}
}
