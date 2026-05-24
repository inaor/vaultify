// Package archive unpacks leak bundles for local inspection scans.
package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxFilesDefault = 5000
	MaxBytesDefault = 500 * 1024 * 1024 // 500 MiB uncompressed
)

// Limits caps archive extraction for operator-machine stability.
type Limits struct {
	MaxFiles int
	MaxBytes int64
}

// DefaultLimits returns sensible caps for IR bundle inspection.
func DefaultLimits() Limits {
	return Limits{MaxFiles: MaxFilesDefault, MaxBytes: MaxBytesDefault}
}

// Manifest describes what was extracted from an archive.
type Manifest struct {
	ArchivePath    string `json:"archive_path"`
	ExtractRoot    string `json:"extract_root"`
	FilesExtracted int    `json:"files_extracted"`
	BytesExtracted int64  `json:"bytes_extracted"`
	SkippedEntries int    `json:"skipped_entries"`
}

// IsSupported reports whether Vaultify can unpack the path (ZIP only for now).
func IsSupported(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".zip")
}

// ExtractZip unpacks a ZIP into destRoot with zip-slip protection and size caps.
func ExtractZip(archivePath, destRoot string, lim Limits) (*Manifest, error) {
	if lim.MaxFiles <= 0 {
		lim.MaxFiles = MaxFilesDefault
	}
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = MaxBytesDefault
	}

	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	destRoot = filepath.Clean(destRoot)
	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create extract dir: %w", err)
	}

	m := &Manifest{ArchivePath: archivePath, ExtractRoot: destRoot}

	for _, f := range r.File {
		if m.FilesExtracted >= lim.MaxFiles {
			return m, fmt.Errorf("archive exceeds file limit (%d)", lim.MaxFiles)
		}

		target, err := safeJoin(destRoot, f.Name)
		if err != nil {
			m.SkippedEntries++
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return nil, fmt.Errorf("mkdir %q: %w", f.Name, err)
			}
			continue
		}

		size := int64(f.UncompressedSize64)
		if size <= 0 {
			size = int64(f.UncompressedSize)
		}
		if m.BytesExtracted+size > lim.MaxBytes {
			return m, fmt.Errorf("archive exceeds size limit (%d bytes)", lim.MaxBytes)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, fmt.Errorf("mkdir parent for %q: %w", f.Name, err)
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open entry %q: %w", f.Name, err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("create %q: %w", f.Name, err)
		}
		n, err := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return nil, fmt.Errorf("extract %q: %w", f.Name, err)
		}

		m.FilesExtracted++
		m.BytesExtracted += n
	}

	if m.FilesExtracted == 0 && m.SkippedEntries == 0 {
		return m, fmt.Errorf("archive contains no extractable files")
	}

	return m, nil
}

func safeJoin(root, name string) (string, error) {
	name = filepath.Clean(name)
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		return "", fmt.Errorf("invalid archive path %q", name)
	}
	target := filepath.Join(root, name)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("zip slip blocked: %q", name)
	}
	return target, nil
}
