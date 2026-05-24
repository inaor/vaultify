package vault

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	opPathOnce sync.Once
	opPath     string
	opPathErr  error
)

// ResolveOpPath returns the absolute path to the 1Password CLI binary.
// It checks OP_CLI, PATH (via LookPath), then common install locations.
func ResolveOpPath() (string, error) {
	opPathOnce.Do(func() {
		opPath, opPathErr = resolveOpPathOnce()
	})
	return opPath, opPathErr
}

// OpInstalled reports whether the 1Password CLI is available on this machine.
func OpInstalled() bool {
	_, err := ResolveOpPath()
	return err == nil
}

// ResetOpPathCache clears the cached op path (for tests).
func ResetOpPathCache() {
	opPathOnce = sync.Once{}
	opPath = ""
	opPathErr = nil
}

func resolveOpPathOnce() (string, error) {
	if p := os.Getenv("OP_CLI"); p != "" {
		if abs, err := validateOpExecutable(p); err == nil {
			return abs, nil
		}
	}
	if p, err := exec.LookPath("op"); err == nil {
		if abs, err := validateOpExecutable(p); err == nil {
			return abs, nil
		}
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		"/opt/homebrew/bin/op",
		"/usr/local/bin/op",
		filepath.Join(home, ".local", "bin", "op"),
	}
	for _, c := range candidates {
		if abs, err := validateOpExecutable(c); err == nil {
			return abs, nil
		}
	}
	if runtime.GOOS == "darwin" {
		if p := opPathFromLoginShell(); p != "" {
			if abs, err := validateOpExecutable(p); err == nil {
				return abs, nil
			}
		}
	}
	return "", errors.New("op CLI not found")
}

func validateOpExecutable(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		return "", errors.New("not found")
	}
	// Symlinks (Homebrew cask) are fine; the target must exist.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if st2, err := os.Stat(abs); err != nil || st2.IsDir() {
		return "", errors.New("not executable")
	}
	return abs, nil
}

func opPathFromLoginShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	out, err := exec.Command(shell, "-l", "-c", "command -v op").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
