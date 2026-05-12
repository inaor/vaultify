package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func freshValidationDB(t *testing.T) (*ValidationTestStore, func()) {
	t.Helper()
	root := t.TempDir()
	d, err := Open(filepath.Join(root, "vaultify.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := Migrate(context.Background(), d); err != nil {
		d.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return &ValidationTestStore{DB: d}, func() { d.Close() }
}

// ValidationTestStore is a tiny adapter so the test reads naturally
// (`store.DB` rather than passing the raw handle around).
type ValidationTestStore struct {
	DB interface {
		// satisfied by *sql.DB; kept abstract for the test
	}
}

// TestSaveAndGetValidation covers the upsert + freshness contract.
func TestSaveAndGetValidation(t *testing.T) {
	root := t.TempDir()
	d, err := Open(filepath.Join(root, "vaultify.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
	if _, err := Migrate(context.Background(), d); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	rec := ValidationRecord{
		MatchSHA256: "h1",
		ValidatorID: "openai",
		Status:      "active",
		Reason:      "openai.200_ok",
		HTTPStatus:  200,
		CheckedAt:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		Source:      "user",
	}
	if err := SaveValidation(ctx, d, rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, ok, err := GetValidation(ctx, d, "h1")
	if err != nil || !ok {
		t.Fatalf("get failed ok=%v err=%v", ok, err)
	}
	if got.Status != "active" || got.HTTPStatus != 200 {
		t.Fatalf("round-trip wrong: %+v", got)
	}
	if !got.IsFresh(now.Add(time.Hour)) {
		t.Fatalf("expected fresh within ttl")
	}
	if got.IsFresh(now.Add(48 * time.Hour)) {
		t.Fatalf("expected stale beyond ttl")
	}

	// Upsert: re-validate with new status, hash unchanged.
	rec.Status = "invalid"
	rec.Reason = "openai.401_invalid_api_key"
	rec.HTTPStatus = 401
	if err := SaveValidation(ctx, d, rec); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	got2, _, _ := GetValidation(ctx, d, "h1")
	if got2.Status != "invalid" || got2.HTTPStatus != 401 {
		t.Fatalf("upsert did not overwrite: %+v", got2)
	}
}

func TestGetValidationsForHashes(t *testing.T) {
	root := t.TempDir()
	d, err := Open(filepath.Join(root, "vaultify.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
	if _, err := Migrate(context.Background(), d); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()
	for i, st := range []string{"active", "invalid", "error"} {
		_ = SaveValidation(ctx, d, ValidationRecord{
			MatchSHA256: string(rune('a' + i)),
			ValidatorID: "openai",
			Status:      st,
			Reason:      "test",
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		})
	}
	got, err := GetValidationsForHashes(ctx, d, []string{"a", "b", "z"})
	if err != nil {
		t.Fatalf("bulk get: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 hits (a,b), got %d", len(got))
	}
	if got["a"].Status != "active" || got["b"].Status != "invalid" {
		t.Fatalf("wrong rows: %+v", got)
	}
	if _, ok := got["z"]; ok {
		t.Fatalf("z should not be present")
	}
}
