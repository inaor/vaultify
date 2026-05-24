package archive

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractZip(t *testing.T) {
	zipPath := writeTestZip(t, map[string]string{
		"project/.env": "AWS_KEY=AKIA123",
		"project/src/main.go": "package main",
	})

	dest := filepath.Join(t.TempDir(), "out")
	m, err := ExtractZip(zipPath, dest, Limits{MaxFiles: 100, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if m.FilesExtracted != 2 {
		t.Fatalf("files=%d want 2", m.FilesExtracted)
	}
	if _, err := os.Stat(filepath.Join(dest, "project", ".env")); err != nil {
		t.Fatalf("missing .env: %v", err)
	}
}

func TestExtractZipSlipBlocked(t *testing.T) {
	zipPath := writeTestZip(t, map[string]string{
		"../escape.txt": "nope",
		"ok.txt":        "yes",
	})

	dest := filepath.Join(t.TempDir(), "out")
	m, err := ExtractZip(zipPath, dest, Limits{MaxFiles: 100, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if m.SkippedEntries != 1 {
		t.Fatalf("skipped=%d want 1", m.SkippedEntries)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("zip slip escaped extract root")
	}
}

func TestIsSupported(t *testing.T) {
	if !IsSupported("/tmp/leak.ZIP") {
		t.Fatal("expected .zip support")
	}
	if IsSupported("/tmp/leak.rar") {
		t.Fatal("rar should not be supported yet")
	}
}

func TestExtractZipEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "empty.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ExtractZip(path, filepath.Join(t.TempDir(), "out"), DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "no extractable") {
		t.Fatalf("expected empty archive error, got %v", err)
	}
}
