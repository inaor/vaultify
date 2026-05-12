package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// buildCorpus creates N files in a fresh temp dir. Every 10th file
// embeds a real-looking AWS key, so the scanner produces ~N/10 findings.
// This is enough of a mixed workload to catch regressions in the hot
// path without pulling in a giant fixture.
func buildCorpus(tb testing.TB, n int) string {
	tb.Helper()
	dir := tb.TempDir()
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	boring := []byte("function handler() { return true; }\n// no secrets here\n")
	withKey := []byte("AWS_ACCESS_KEY_ID=" + awsKey + "\nFOO=bar\n")
	for i := 0; i < n; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i/100))
		_ = os.MkdirAll(sub, 0o700)
		name := fmt.Sprintf("file_%06d", i)
		var p string
		var data []byte
		if i%10 == 0 {
			p = filepath.Join(sub, name+".env")
			data = withKey
		} else {
			p = filepath.Join(sub, name+".js")
			data = boring
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	return dir
}

// BenchmarkScanner_EmbeddedCorpus measures the throughput of a single
// Scan over a 2000-file synthetic tree. Each iteration rebuilds the
// corpus in a temp dir so the benchmark is hermetic.
func BenchmarkScanner_EmbeddedCorpus(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := buildCorpus(b, 2000)
		s := NewScanner()
		var findings atomic.Int64
		b.StartTimer()
		filesScanned, _, err := s.Scan(context.Background(), []string{dir}, 0, func(_, _ int, _ string) {}, func(Finding) {
			findings.Add(1)
		})
		if err != nil {
			b.Fatal(err)
		}
		if filesScanned < 1800 { // allow for tiny race window; walk should see everything
			b.Fatalf("expected ~2000 files scanned, got %d", filesScanned)
		}
	}
}

// TestScan_CapExact asserts the free-tier cap fires on exactly N files
// even when many more eligible files exist in the tree. This guards the
// capDone/enqueued invariant during future hot-path refactors.
func TestScan_CapExact(t *testing.T) {
	dir := buildCorpus(t, 300)
	s := NewScanner()
	const cap = 50
	var findingCount atomic.Int64
	n, capped, err := s.Scan(context.Background(), []string{dir}, cap, func(_, _ int, _ string) {}, func(Finding) {
		findingCount.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !capped {
		t.Fatal("expected capped=true with 300 eligible files and cap=50")
	}
	if n != cap {
		t.Fatalf("expected exactly %d files scanned, got %d", cap, n)
	}
}
