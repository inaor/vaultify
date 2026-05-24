package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOpPathFromEnv(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "op")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OP_CLI", fake)
	ResetOpPathCache()

	got, err := ResolveOpPath()
	if err != nil {
		t.Fatalf("ResolveOpPath: %v", err)
	}
	want, _ := filepath.EvalSymlinks(fake)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != want && got != fake {
		t.Fatalf("got %q want %q", got, fake)
	}
}

func TestResolveOpPathHomebrewCandidate(t *testing.T) {
	if _, err := os.Stat("/opt/homebrew/bin/op"); err != nil {
		t.Skip("no homebrew op on this machine")
	}
	t.Setenv("OP_CLI", "")
	ResetOpPathCache()
	t.Setenv("PATH", "/usr/bin:/bin")

	got, err := ResolveOpPath()
	if err != nil {
		t.Fatalf("ResolveOpPath: %v", err)
	}
	if got == "" {
		t.Fatal("expected path")
	}
}
