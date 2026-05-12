// Package paths returns OS-specific directories Vaultify uses for
// config, state (sessions), and logs. It also migrates legacy %TEMP%
// data into the new locations on first run.
package paths

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const appDirName = "Vaultify"

// Root returns the base application directory. Subdirectories for
// config, sessions, and logs live under here.
func Root() string {
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, appDirName)
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "AppData", "Local", appDirName)
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", appDirName)
	default:
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			return filepath.Join(v, "vaultify")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".local", "share", "vaultify")
	}
}

// ConfigDir returns the directory where app-settings.json lives.
func ConfigDir() string { return filepath.Join(Root(), "config") }

// SessionsDir returns the directory where per-scan session folders live.
func SessionsDir() string { return filepath.Join(Root(), "sessions") }

// LogDir returns the directory where vaultify.log and audit.log live.
func LogDir() string { return filepath.Join(Root(), "logs") }

// ConfigFile joins a filename into ConfigDir.
func ConfigFile(name string) string { return filepath.Join(ConfigDir(), name) }

// LogFile joins a filename into LogDir.
func LogFile(name string) string { return filepath.Join(LogDir(), name) }

// LegacyTempRoot returns the deprecated %TEMP%/vaultify-scans path.
func LegacyTempRoot() string { return filepath.Join(os.TempDir(), "vaultify-scans") }

// Ensure creates every Vaultify directory with restrictive permissions.
// Returns the first error encountered; callers should log but not fatal.
func Ensure() error {
	for _, d := range []string{Root(), ConfigDir(), SessionsDir(), LogDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// MigrationReport describes what (if anything) Migrate moved.
type MigrationReport struct {
	MovedSessions    int
	MovedLogFiles    int
	MovedAppSettings bool
	LegacyRoot       string
}

// Migrate copies session directories, logs, and app-settings.json from
// the legacy %TEMP% location into the new directories. It never
// overwrites an existing destination; the legacy file is left alone
// in that case. Safe to call on every startup — no-op when there is
// nothing left to migrate.
func Migrate() (MigrationReport, error) {
	rep := MigrationReport{LegacyRoot: LegacyTempRoot()}
	info, err := os.Stat(rep.LegacyRoot)
	if err != nil || !info.IsDir() {
		return rep, nil
	}
	if err := Ensure(); err != nil {
		return rep, err
	}

	entries, err := os.ReadDir(rep.LegacyRoot)
	if err != nil {
		return rep, err
	}
	for _, e := range entries {
		name := e.Name()
		src := filepath.Join(rep.LegacyRoot, name)
		switch {
		case e.IsDir() && name == ".logs":
			moved, _ := copyFilesNonDestructive(src, LogDir())
			rep.MovedLogFiles += moved
		case e.IsDir() && isSessionIDName(name):
			dst := filepath.Join(SessionsDir(), name)
			if _, err := os.Stat(dst); err == nil {
				continue
			}
			if err := os.Rename(src, dst); err == nil {
				rep.MovedSessions++
			}
		case !e.IsDir() && name == "app-settings.json":
			dst := ConfigFile("app-settings.json")
			if _, err := os.Stat(dst); err == nil {
				continue
			}
			if err := copyFile(src, dst); err == nil {
				rep.MovedAppSettings = true
			}
		}
	}
	return rep, nil
}

func isSessionIDName(name string) bool {
	if len(name) != 16 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func copyFilesNonDestructive(srcDir, dstDir string) (int, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(srcDir, e.Name())
		dst := filepath.Join(dstDir, e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := copyFile(src, dst); err == nil {
			moved++
		}
	}
	return moved, nil
}
