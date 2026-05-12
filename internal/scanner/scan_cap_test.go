package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestScanRespectsFileCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "f"+strconv.Itoa(i)+".env")
		if err := os.WriteFile(p, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := NewScanner()
	const cap = 3
	var scanned int
	_, capped, err := s.Scan(context.Background(), []string{dir}, cap, func(progress, total int, _ string) {
		scanned = progress
		if cap > 0 && total != cap {
			t.Errorf("expected progress total %d, got %d", cap, total)
		}
	}, func(Finding) {})
	if err != nil {
		t.Fatal(err)
	}
	if !capped {
		t.Fatal("expected capped true when more eligible files exist than cap")
	}
	if scanned != cap {
		t.Fatalf("expected files scanned == cap (%d), got %d", cap, scanned)
	}
}

func TestScanUncapped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "only.env")
	if err := os.WriteFile(p, []byte("FOO=barsecretvaluehere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewScanner()
	n, capped, err := s.Scan(context.Background(), []string{dir}, 0, func(_, _ int, _ string) {}, func(Finding) {})
	if err != nil {
		t.Fatal(err)
	}
	if capped {
		t.Fatal("did not expect capped")
	}
	if n != 1 {
		t.Fatalf("expected 1 file scanned, got %d", n)
	}
}
