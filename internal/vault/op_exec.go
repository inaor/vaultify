package vault

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OpError captures details of a failed `op` invocation. Handlers and
// callers can inspect this to surface structured errors to the UI, and
// slog records emitted by RunOp already include the same fields.
type OpError struct {
	Op       string        // short label, e.g. "vault list"
	ExitCode int           // 0 when the process did not exit cleanly
	Timeout  bool          // true when the context deadline fired
	Duration time.Duration // wall-clock time spent in the subprocess
	Stderr   string        // truncated stderr text
	Err      error         // underlying error from exec.Cmd
}

func (e *OpError) Error() string {
	if e == nil {
		return "op error"
	}
	if e.Timeout {
		return "op " + e.Op + ": timeout after " + e.Duration.Round(time.Millisecond).String()
	}
	if e.Err != nil {
		return "op " + e.Op + ": " + e.Err.Error()
	}
	return "op " + e.Op + ": error"
}

func (e *OpError) Unwrap() error { return e.Err }

// opLogger is the slog logger used for op subprocess traces. Set via
// SetLogger during server startup; defaults to slog.Default.
var opLogger *slog.Logger

// SetLogger wires a logger for op subprocess tracing. Safe to call once
// at startup from cmd/vaultify/main.go.
func SetLogger(l *slog.Logger) { opLogger = l }

func getLogger() *slog.Logger {
	if opLogger != nil {
		return opLogger
	}
	return slog.Default()
}

// RunOp executes the 1Password CLI with the given args under the
// provided context, emitting op.start / op.finish / op.error slog
// records that describe what the subprocess did and how long it took.
//
// opName is a short label for the log record ("vault list", "item
// create"). The caller is responsible for holding any mutex required
// by the calling code path.
func RunOp(ctx context.Context, opPath, opName string, args []string) ([]byte, *OpError) {
	logger := getLogger().With(
		slog.String("op", opName),
		slog.Int("argc", len(args)),
	)
	logger.Debug("op.start")
	start := time.Now()

	cmd := exec.CommandContext(ctx, opPath, args...)
	cmd.Env = append(os.Environ(), "OP_BIOMETRIC_UNLOCK_ENABLED=true")
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	out, err := cmd.Output()
	duration := time.Since(start)

	if err != nil {
		opErr := &OpError{
			Op:       opName,
			Duration: duration,
			Stderr:   truncate(strings.TrimSpace(stderrBuf.String()), 400),
			Err:      err,
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			opErr.ExitCode = exitErr.ExitCode()
		}
		if ctx.Err() == context.DeadlineExceeded {
			opErr.Timeout = true
		}
		logger.Warn("op.error",
			slog.String("duration", duration.Round(time.Millisecond).String()),
			slog.Int("exit_code", opErr.ExitCode),
			slog.Bool("timeout", opErr.Timeout),
			slog.String("stderr", opErr.Stderr),
			slog.String("err", err.Error()),
		)
		return nil, opErr
	}

	logger.Debug("op.finish",
		slog.String("duration", duration.Round(time.Millisecond).String()),
		slog.Int("bytes", len(out)),
	)
	return out, nil
}

// runOpWithTimeout is a convenience wrapper that allocates a context
// with the given timeout, calls RunOp, and cancels the context.
func runOpWithTimeout(opPath, opName string, args []string, timeout time.Duration) ([]byte, *OpError) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunOp(ctx, opPath, opName, args)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
