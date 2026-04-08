package redactor

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const redactionMarker = "REDACTED_BY_VAULTIFY"

// RedactResult captures the outcome of a single file-redaction attempt.
type RedactResult struct {
	FilePath    string
	Redacted    bool
	AlreadyDone bool
	Error       string
}

// Redactor performs SHA256-verified secret redaction in source files.
type Redactor struct{}

// RedactFile replaces the first regex match whose SHA256 equals wantSHA256
// with the REDACTED_BY_VAULTIFY marker. A .bak backup is created before writing.
//
// lineNumber is 1-based.
func (r *Redactor) RedactFile(filePath string, lineNumber int, patternRegex *regexp.Regexp, wantSHA256 string) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", filePath, err)
	}

	lines, err := splitLines(data)
	if err != nil {
		return false, err
	}

	if lineNumber < 1 || lineNumber > len(lines) {
		return false, fmt.Errorf("line %d out of range (file has %d lines)", lineNumber, len(lines))
	}

	idx := lineNumber - 1
	line := lines[idx]

	if strings.Contains(line, redactionMarker) {
		return false, nil // already redacted
	}

	matches := patternRegex.FindAllString(line, -1)
	if len(matches) == 0 {
		return false, fmt.Errorf("pattern did not match on line %d", lineNumber)
	}

	replaced := false
	for _, m := range matches {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(m)))
		if hash == wantSHA256 {
			lines[idx] = strings.Replace(line, m, redactionMarker, 1)
			replaced = true
			break
		}
	}

	if !replaced {
		return false, fmt.Errorf("no match on line %d has SHA256 %s", lineNumber, wantSHA256)
	}

	if err := createBackup(filePath); err != nil {
		return false, err
	}

	if err := writeLines(filePath, lines); err != nil {
		return false, err
	}

	return true, nil
}

func splitLines(data []byte) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning lines: %w", err)
	}
	return lines, nil
}

func createBackup(filePath string) error {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading for backup: %w", err)
	}
	bakPath := filePath + ".bak"
	if err := os.WriteFile(bakPath, src, 0o644); err != nil {
		return fmt.Errorf("writing backup %s: %w", bakPath, err)
	}
	return nil
}

func writeLines(filePath string, lines []string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filePath, err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filePath, []byte(content), info.Mode()); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}
	return nil
}
