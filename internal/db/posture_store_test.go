package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
)

func freshPosture(t *testing.T, window time.Duration) *PostureStore {
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
	return NewPostureStore(d, window)
}

func mkF(pattern, root, rel, hash, sev string, line int) scanner.Finding {
	return scanner.Finding{
		PatternID:       pattern,
		Severity:        sev,
		Description:     pattern + " key",
		Root:            root,
		RelativePath:    rel,
		MatchSHA256:     hash,
		LineNumber:      line,
		RedactedPreview: "sk-...xxxx",
	}
}

// TestPostureMergeUpsertsAndDeletes covers the core lifecycle: new
// fingerprints become `present`; the next scan over the same root
// without one of them flips that one to `deleted`; a third scan that
// re-includes it revives it back to `present` and clears deleted_at.
func TestPostureMergeUpsertsAndDeletes(t *testing.T) {
	p := freshPosture(t, 30*24*time.Hour)
	ctx := context.Background()
	root := "C:/repo"

	t1 := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	rep, err := p.MergeScan(ctx, "sess1", t1, []string{root}, []scanner.Finding{
		mkF("openai", root, "a.go", "h1", "high", 10),
		mkF("anthropic", root, "b.go", "h2", "medium", 20),
	})
	if err != nil {
		t.Fatalf("merge1: %v", err)
	}
	if rep.Upserted != 2 || rep.MarkedDeleted != 0 {
		t.Fatalf("merge1 report = %+v, want Upserted=2 MarkedDeleted=0", rep)
	}

	t2 := t1.Add(time.Hour)
	rep, err = p.MergeScan(ctx, "sess2", t2, []string{root}, []scanner.Finding{
		mkF("openai", root, "a.go", "h1", "high", 10),
		// b.go missing -> should be marked deleted
	})
	if err != nil {
		t.Fatalf("merge2: %v", err)
	}
	if rep.MarkedDeleted != 1 {
		t.Fatalf("merge2 marked=%d, want 1", rep.MarkedDeleted)
	}
	all, _ := p.Recent(ctx, t2)
	if len(all) != 2 {
		t.Fatalf("expected 2 rows still in window, got %d", len(all))
	}
	statusByPath := map[string]PostureStatus{}
	for _, f := range all {
		statusByPath[f.RelativePath] = f.Status
	}
	if statusByPath["a.go"] != PostureStatusPresent || statusByPath["b.go"] != PostureStatusDeleted {
		t.Fatalf("unexpected statuses: %+v", statusByPath)
	}

	// Bring b.go back; it should resurrect.
	t3 := t2.Add(time.Hour)
	if _, err := p.MergeScan(ctx, "sess3", t3, []string{root}, []scanner.Finding{
		mkF("openai", root, "a.go", "h1", "high", 10),
		mkF("anthropic", root, "b.go", "h2", "medium", 20),
	}); err != nil {
		t.Fatalf("merge3: %v", err)
	}
	all, _ = p.Recent(ctx, t3)
	for _, f := range all {
		if f.RelativePath == "b.go" {
			if f.Status != PostureStatusPresent {
				t.Fatalf("b.go did not resurrect: %+v", f)
			}
			if f.DeletedAt != "" {
				t.Fatalf("b.go deleted_at not cleared: %q", f.DeletedAt)
			}
		}
	}
}

// TestPostureMergeRespectsScopeBoundaries asserts that a scan with
// scanRoots=[/a] never marks fingerprints under /b as deleted.
func TestPostureMergeRespectsScopeBoundaries(t *testing.T) {
	p := freshPosture(t, 30*24*time.Hour)
	ctx := context.Background()
	t1 := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	if _, err := p.MergeScan(ctx, "sA", t1, []string{"/a", "/b"}, []scanner.Finding{
		mkF("openai", "/a", "x.go", "h1", "high", 1),
		mkF("openai", "/b", "y.go", "h2", "high", 1),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t2 := t1.Add(time.Hour)
	rep, err := p.MergeScan(ctx, "sB", t2, []string{"/a"}, nil)
	if err != nil {
		t.Fatalf("scan-only-/a: %v", err)
	}
	if rep.MarkedDeleted != 1 {
		t.Fatalf("expected only /a row deleted, got MarkedDeleted=%d", rep.MarkedDeleted)
	}
	rows, _ := p.Recent(ctx, t2)
	for _, f := range rows {
		switch f.Root {
		case "/a":
			if f.Status != PostureStatusDeleted {
				t.Fatalf("/a row not deleted: %+v", f)
			}
		case "/b":
			if f.Status != PostureStatusPresent {
				t.Fatalf("/b row should remain present: %+v", f)
			}
		}
	}
}

// TestPostureWindowPrunes asserts that rows whose last activity
// (last_seen for present rows, deleted_at for deleted ones) drops
// outside the rolling window are physically removed on the next
// merge. The test scans a *different* root on the second pass so
// the seeded /r fingerprint is neither refreshed nor flipped to
// deleted — it simply ages out as the wall clock advances.
func TestPostureWindowPrunes(t *testing.T) {
	p := freshPosture(t, 24*time.Hour) // 1-day window for the test
	ctx := context.Background()
	t1 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if _, err := p.MergeScan(ctx, "old", t1, []string{"/r"}, []scanner.Finding{
		mkF("openai", "/r", "old.go", "ho", "high", 1),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Scan a different root 72h later; the /r fingerprint is out of
	// scope so it is neither resurrected nor marked deleted, and its
	// last_seen stays at t1 — which is now beyond the 1-day window.
	t2 := t1.Add(72 * time.Hour)
	rep, err := p.MergeScan(ctx, "new", t2, []string{"/q"}, []scanner.Finding{
		mkF("openai", "/q", "new.go", "hn", "high", 1),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if rep.Pruned != 1 {
		t.Fatalf("expected exactly 1 pruned row, got %+v", rep)
	}
	rows, _ := p.Recent(ctx, t2)
	for _, f := range rows {
		if f.RelativePath == "old.go" {
			t.Fatalf("old fingerprint not pruned: %+v", f)
		}
	}
}

// TestPostureRetainsRecentDeletions documents the inverse: a
// deletion detected this scan must remain visible for the full
// rolling window so the UI can highlight it as "Deleted N days ago".
func TestPostureRetainsRecentDeletions(t *testing.T) {
	p := freshPosture(t, 24*time.Hour)
	ctx := context.Background()
	t1 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if _, err := p.MergeScan(ctx, "s1", t1, []string{"/r"}, []scanner.Finding{
		mkF("openai", "/r", "x.go", "h1", "high", 1),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Same root, x.go gone -> mark deleted at t2. t2 is far past t1
	// but the prune cutoff is t2-24h, so deleted_at=t2 stays inside
	// the window and the row must NOT be pruned.
	t2 := t1.Add(72 * time.Hour)
	rep, err := p.MergeScan(ctx, "s2", t2, []string{"/r"}, nil)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if rep.MarkedDeleted != 1 {
		t.Fatalf("expected 1 marked deleted, got %+v", rep)
	}
	rows, _ := p.Recent(ctx, t2)
	if len(rows) != 1 || rows[0].Status != PostureStatusDeleted {
		t.Fatalf("recent deletion not visible: %+v", rows)
	}
}

// TestPostureSummaryShapes covers severity-by-status counts.
func TestPostureSummaryShapes(t *testing.T) {
	p := freshPosture(t, 30*24*time.Hour)
	ctx := context.Background()
	now := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	if _, err := p.MergeScan(ctx, "s1", now, []string{"/r"}, []scanner.Finding{
		mkF("openai", "/r", "a.go", "h1", "high", 1),
		mkF("openai", "/r", "b.go", "h2", "high", 1),
		mkF("anthropic", "/r", "c.go", "h3", "medium", 1),
		mkF("aws", "/r", "d.go", "h4", "low", 1),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Drop b.go on the next scan to create one deletion.
	if _, err := p.MergeScan(ctx, "s2", now.Add(time.Minute), []string{"/r"}, []scanner.Finding{
		mkF("openai", "/r", "a.go", "h1", "high", 1),
		mkF("anthropic", "/r", "c.go", "h3", "medium", 1),
		mkF("aws", "/r", "d.go", "h4", "low", 1),
	}); err != nil {
		t.Fatalf("merge: %v", err)
	}

	sum, err := p.Summary(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Total != 4 || sum.Present != 3 || sum.Deleted != 1 {
		t.Fatalf("totals wrong: %+v", sum)
	}
	if sum.HighPresent != 1 || sum.MediumPresent != 1 || sum.LowPresent != 1 {
		t.Fatalf("severity histogram wrong: %+v", sum)
	}
	if sum.WindowDays != 30 {
		t.Fatalf("window_days=%d, want 30", sum.WindowDays)
	}
}

// TestFingerprintStable asserts the hash function is deterministic
// and order-sensitive across the four input components.
func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("openai", "/r", "a.go", "h1")
	b := Fingerprint("openai", "/r", "a.go", "h1")
	if a != b {
		t.Fatalf("non-deterministic fingerprint: %s vs %s", a, b)
	}
	if a == Fingerprint("openai", "/r", "a.go", "h2") {
		t.Fatalf("hash collides on different match_sha256")
	}
	if a == Fingerprint("anthropic", "/r", "a.go", "h1") {
		t.Fatalf("hash collides on different pattern")
	}
}
