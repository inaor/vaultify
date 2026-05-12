// Package logging provides a central slog-based logger for Vaultify.
// Records are emitted to a rotating JSON file, stderr in text form, and
// a live in-memory ring buffer that HTTP clients can subscribe to for
// the Logs tab.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Record is the wire shape streamed to WS clients and returned from
// /api/logs/tail. Attrs flattens every slog.Attr onto a single map;
// grouped attrs collapse into their group name.
type Record struct {
	Time  string         `json:"time"`
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Options configures the logging core.
type Options struct {
	LogFilePath  string
	MaxFileBytes int64
	MaxBackups   int
	StderrLevel  slog.Level
	FileLevel    slog.Level
	RingCapacity int
}

// Defaults returns sensible defaults; callers override specific fields.
func Defaults(logFile string) Options {
	return Options{
		LogFilePath:  logFile,
		MaxFileBytes: 2 * 1024 * 1024,
		MaxBackups:   5,
		StderrLevel:  slog.LevelInfo,
		FileLevel:    slog.LevelDebug,
		RingCapacity: 500,
	}
}

// Core ties the logger, rotating file, and live subscribers together.
type Core struct {
	logger *slog.Logger
	file   *rotatingFile
	ring   *ringBuffer

	subsMu sync.Mutex
	subs   map[int]chan Record
	nextID int
}

// New creates a Core ready to emit records.
func New(opts Options) (*Core, error) {
	if opts.RingCapacity <= 0 {
		opts.RingCapacity = 500
	}
	rf := &rotatingFile{
		path:       opts.LogFilePath,
		maxBytes:   opts.MaxFileBytes,
		maxBackups: opts.MaxBackups,
	}
	if err := rf.openLocked(); err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	core := &Core{
		file: rf,
		ring: newRingBuffer(opts.RingCapacity),
		subs: make(map[int]chan Record),
	}
	fileHandler := slog.NewJSONHandler(rf, &slog.HandlerOptions{Level: opts.FileLevel})
	stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.StderrLevel})
	tee := &teeHandler{handlers: []slog.Handler{fileHandler, stderrHandler}, core: core}
	core.logger = slog.New(tee)
	return core, nil
}

// Logger returns the slog logger.
func (c *Core) Logger() *slog.Logger { return c.logger }

// Close closes the rotating file.
func (c *Core) Close() error {
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}

// Recent returns up to n most recent records (0 means all available).
func (c *Core) Recent(n int) []Record { return c.ring.snapshot(n) }

// Subscribe returns a channel that will receive future records and a
// cancel function that unsubscribes and closes the channel. Slow
// consumers miss messages rather than blocking the log path.
func (c *Core) Subscribe() (<-chan Record, func()) {
	ch := make(chan Record, 64)
	c.subsMu.Lock()
	id := c.nextID
	c.nextID++
	c.subs[id] = ch
	c.subsMu.Unlock()
	return ch, func() {
		c.subsMu.Lock()
		if existing, ok := c.subs[id]; ok {
			delete(c.subs, id)
			close(existing)
		}
		c.subsMu.Unlock()
	}
}

func (c *Core) publish(r Record) {
	c.ring.push(r)
	c.subsMu.Lock()
	for _, ch := range c.subs {
		select {
		case ch <- r:
		default:
		}
	}
	c.subsMu.Unlock()
}

// StdlogAdapter returns an io.Writer that forwards stdlib log.Printf
// output into slog as info-level records with source=stdlog so existing
// log.Printf call sites appear in the Logs tab without needing migration.
func (c *Core) StdlogAdapter() io.Writer { return &stdlogWriter{logger: c.logger} }

type stdlogWriter struct{ logger *slog.Logger }

func (s *stdlogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg == "" {
		return len(p), nil
	}
	s.logger.Info(msg, slog.String("source", "stdlog"))
	return len(p), nil
}

// ---------------- tee handler ----------------

type teeHandler struct {
	handlers []slog.Handler
	core     *Core
}

func (t *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return true
}

func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range t.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	if t.core != nil {
		t.core.publish(makeRecord(r))
	}
	return nil
}

func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &teeHandler{handlers: out, core: t.core}
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithGroup(name)
	}
	return &teeHandler{handlers: out, core: t.core}
}

func makeRecord(r slog.Record) Record {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	return Record{
		Time:  r.Time.UTC().Format(time.RFC3339Nano),
		Level: r.Level.String(),
		Msg:   r.Message,
		Attrs: attrs,
	}
}

// ---------------- rotating file ----------------

type rotatingFile struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		if err := r.openLocked(); err != nil {
			return 0, err
		}
	}
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}
	return nil
}

func (r *rotatingFile) openLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, _ := f.Stat()
	var sz int64
	if fi != nil {
		sz = fi.Size()
	}
	r.file = f
	r.size = sz
	return nil
}

func (r *rotatingFile) rotateLocked() error {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	if r.maxBackups <= 0 {
		return r.openLocked()
	}
	oldest := fmt.Sprintf("%s.%d", r.path, r.maxBackups)
	_ = os.Remove(oldest)
	for i := r.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", r.path, i)
		dst := fmt.Sprintf("%s.%d", r.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	if _, err := os.Stat(r.path); err == nil {
		_ = os.Rename(r.path, r.path+".1")
	}
	return r.openLocked()
}

// ---------------- ring buffer ----------------

type ringBuffer struct {
	mu   sync.Mutex
	buf  []Record
	head int
	size int
	cap  int
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{buf: make([]Record, capacity), cap: capacity}
}

func (r *ringBuffer) push(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := (r.head + r.size) % r.cap
	r.buf[idx] = rec
	if r.size < r.cap {
		r.size++
	} else {
		r.head = (r.head + 1) % r.cap
	}
}

func (r *ringBuffer) snapshot(limit int) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.size
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Record, n)
	start := r.head + (r.size - n)
	for i := 0; i < n; i++ {
		out[i] = r.buf[(start+i)%r.cap]
	}
	return out
}
