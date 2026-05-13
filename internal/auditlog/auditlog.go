// Package auditlog implements a simple append-only JSON audit trail for the local agent.
package auditlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelDebug Level = "debug"
	LevelAudit Level = "audit"
)

type Entry struct {
	Timestamp string `json:"timestamp"`
	Level     Level  `json:"level"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	SessionID string `json:"session_id,omitempty"`
}

type Logger struct {
	mu      sync.Mutex
	entries []Entry
	dir     string
}

func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	l := &Logger{dir: dir}
	l.load()
	return l, nil
}

func (l *Logger) Dir() string { return l.dir }

func (l *Logger) Add(level Level, action, detail string, sessionID string) {
	e := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Action:    action,
		Detail:    detail,
		SessionID: sessionID,
	}
	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
	l.appendToFile(e)
}

func (l *Logger) Audit(action, detail string, sessionID string) {
	l.Add(LevelAudit, action, detail, sessionID)
}

func (l *Logger) Info(action, detail string) {
	l.Add(LevelInfo, action, detail, "")
}

func (l *Logger) Warn(action, detail string) {
	l.Add(LevelWarn, action, detail, "")
}

func (l *Logger) Error(action, detail string) {
	l.Add(LevelError, action, detail, "")
}

func (l *Logger) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *Logger) logFilePath() string {
	return filepath.Join(l.dir, "vaultify.log")
}

func (l *Logger) appendToFile(e Entry) {
	f, err := os.OpenFile(l.logFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(e)
	f.Write(data)
	f.WriteString("\n")
}

func (l *Logger) load() {
	data, err := os.ReadFile(l.logFilePath())
	if err != nil {
		return
	}

	var entries []Entry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) == nil && e.Timestamp != "" {
			entries = append(entries, e)
		}
	}
	l.mu.Lock()
	l.entries = entries
	l.mu.Unlock()
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
