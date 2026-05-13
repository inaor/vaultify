package server

import (
	"os"
	"path/filepath"
	"testing"
)

// isSubpath guards browse API against directory escape attempts.

func TestIsSubpath(t *testing.T) {
	tmp := t.TempDir()
	inside := filepath.Join(tmp, "a", "b")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if !isSubpath(tmp, inside) {
		t.Fatalf("expected %q under %q", inside, tmp)
	}
	outside, err := os.MkdirTemp("", "vaultify-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	if isSubpath(tmp, outside) {
		t.Fatalf("did not expect %q under %q", outside, tmp)
	}
}
