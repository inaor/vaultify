package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
)

// freshStore returns a SessionStore backed by a freshly-migrated
// SQLite file plus the on-disk sidecar root.
func freshStore(t *testing.T) (*SessionStore, string) {
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
	if err := os.MkdirAll(sidecar, 0o700); err != nil {
		t.Fatalf("mkdir sidecar: %v", err)
	}
	return NewSessionStore(d, sidecar), sidecar
}

// TestSaveAndGet covers the round-trip and confirms plaintext values
// never reach the DB.
func TestSaveAndGet(t *testing.T) {
	store, _ := freshStore(t)
	id := session.NewID()

	findings := []scanner.Finding{
		{
			PatternID:    "openai_key",
			Severity:     "high",
			Description:  "OpenAI key",
			RelativePath: "main.go",
			LineNumber:   12,
			MatchSHA256:  "abc123",
			Value:        "sk-secret",
			LineSnippet:  "key := \"sk-secret\"",
		},
	}
	if err := store.Save(id, findings, time.Now()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != id || got.FindingsCount != 1 || got.OriginalFindingsCount != 1 {
		t.Fatalf("unexpected session: %+v", got)
	}
	if got.Findings[0].Value != "" {
		t.Fatalf("plaintext value persisted: %q", got.Findings[0].Value)
	}
	if !strings.Contains(got.Findings[0].LineSnippet, "REDACTED_BY_VAULTIFY") {
		t.Fatalf("snippet not redacted: %q", got.Findings[0].LineSnippet)
	}
}

// TestSavePreservesOriginalCount mirrors the Manager contract: a
// re-save with fewer findings (post-Apply) keeps the historical
// original_findings_count.
func TestSavePreservesOriginalCount(t *testing.T) {
	store, _ := freshStore(t)
	id := session.NewID()

	first := []scanner.Finding{
		{PatternID: "a", MatchSHA256: "h1"},
		{PatternID: "b", MatchSHA256: "h2"},
		{PatternID: "c", MatchSHA256: "h3"},
	}
	if err := store.Save(id, first, time.Now()); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	second := []scanner.Finding{{PatternID: "a", MatchSHA256: "h1"}}
	if err := store.Save(id, second, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Save second: %v", err)
	}
	got, _ := store.Get(id)
	if got.FindingsCount != 1 {
		t.Fatalf("findings_count=%d, want 1", got.FindingsCount)
	}
	if got.OriginalFindingsCount != 3 {
		t.Fatalf("original_findings_count=%d, want 3", got.OriginalFindingsCount)
	}
}

// TestArchiveAndList ensures the archived flag flips between the two
// list methods correctly.
func TestArchiveAndList(t *testing.T) {
	store, _ := freshStore(t)
	id := session.NewID()
	if err := store.Save(id, []scanner.Finding{{MatchSHA256: "x"}}, time.Now()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if got, _ := store.List(); len(got) != 1 {
		t.Fatalf("active list len=%d, want 1", len(got))
	}
	if got, _ := store.ListArchived(); len(got) != 0 {
		t.Fatalf("archived list len=%d, want 0", len(got))
	}

	if err := store.Archive(id); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if got, _ := store.List(); len(got) != 0 {
		t.Fatalf("active list after archive len=%d, want 0", len(got))
	}
	if got, _ := store.ListArchived(); len(got) != 1 {
		t.Fatalf("archived list len=%d, want 1", len(got))
	}

	if err := store.Unarchive(id); err != nil {
		t.Fatalf("Unarchive: %v", err)
	}
	if got, _ := store.List(); len(got) != 1 {
		t.Fatalf("active list after unarchive len=%d, want 1", len(got))
	}
}

// TestMergeRemediationAppliedDedupes asserts the remediation column
// counts each hash once even when MergeRemediationApplied is called
// twice.
func TestMergeRemediationAppliedDedupes(t *testing.T) {
	store, _ := freshStore(t)
	id := session.NewID()
	if err := store.Save(id, []scanner.Finding{{MatchSHA256: "x"}, {MatchSHA256: "y"}}, time.Now()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := store.MergeRemediationApplied(id, []string{"h1", "h2", "h3", ""}); err != nil {
			t.Fatalf("merge %d: %v", i, err)
		}
	}
	summaries, _ := store.List()
	if len(summaries) != 1 || summaries[0].Remediated != 3 {
		t.Fatalf("expected 1 session with Remediated=3, got %+v", summaries)
	}
}

// TestHasDecisionsViaSidecar verifies the on-disk decisions.json
// detection still works through the SessionStore.
func TestHasDecisionsViaSidecar(t *testing.T) {
	store, sidecar := freshStore(t)
	id := session.NewID()
	if err := store.Save(id, nil, time.Now()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, _ := store.List()
	if len(got) != 1 || got[0].HasDecisions {
		t.Fatalf("expected HasDecisions=false, got %+v", got)
	}

	dir := filepath.Join(sidecar, id)
	if err := os.WriteFile(filepath.Join(dir, "decisions.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write decisions sidecar: %v", err)
	}
	got, _ = store.List()
	if !got[0].HasDecisions {
		t.Fatalf("expected HasDecisions=true after sidecar write")
	}
}

// TestImportFromStore exercises the one-shot importer end-to-end:
// active + archived sessions, remediation hashes, and idempotency on
// a second pass.
func TestImportFromStore(t *testing.T) {
	src := session.NewManager(t.TempDir())

	activeID := session.NewID()
	archivedID := session.NewID()

	if err := src.Save(activeID, []scanner.Finding{{MatchSHA256: "a1"}, {MatchSHA256: "a2"}}, time.Now()); err != nil {
		t.Fatalf("src.Save active: %v", err)
	}
	if err := src.Save(archivedID, []scanner.Finding{{MatchSHA256: "z1"}}, time.Now()); err != nil {
		t.Fatalf("src.Save archived: %v", err)
	}
	if err := src.Archive(archivedID); err != nil {
		t.Fatalf("src.Archive: %v", err)
	}
	if err := src.MergeRemediationApplied(activeID, []string{"a1"}); err != nil {
		t.Fatalf("src.Merge: %v", err)
	}

	dst, _ := freshStore(t)
	rep, err := ImportFromStore(context.Background(), dst.db, src)
	if err != nil {
		t.Fatalf("ImportFromStore: %v", err)
	}
	if rep.SessionsScanned != 2 || rep.SessionsImported != 2 || rep.SessionsAlready != 0 {
		t.Fatalf("first import counts wrong: %+v", rep)
	}
	if rep.RemediationHashes != 1 {
		t.Fatalf("first import remediation count=%d, want 1", rep.RemediationHashes)
	}

	active, _ := dst.List()
	archived, _ := dst.ListArchived()
	if len(active) != 1 || active[0].ID != activeID || active[0].Remediated != 1 {
		t.Fatalf("active after import: %+v", active)
	}
	if len(archived) != 1 || archived[0].ID != archivedID {
		t.Fatalf("archived after import: %+v", archived)
	}

	rep2, err := ImportFromStore(context.Background(), dst.db, src)
	if err != nil {
		t.Fatalf("ImportFromStore second pass: %v", err)
	}
	if rep2.SessionsImported != 0 || rep2.SessionsAlready != 2 {
		t.Fatalf("second import not idempotent: %+v", rep2)
	}
}
