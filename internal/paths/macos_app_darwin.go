//go:build darwin

package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// RunningFromMacOSAppBundle reports whether this process was started from
// Vaultify.app/Contents/MacOS (required for 1Password to show Vaultify in CLI auth prompts).
func RunningFromMacOSAppBundle() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return strings.Contains(filepath.Clean(exe), ".app/Contents/MacOS/")
}

// MacOSAppBinary returns the Vaultify.app executable if installed locally.
func MacOSAppBinary() string {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "Applications", "Vaultify.app", "Contents", "MacOS", "vaultify"),
		"/Applications/Vaultify.app/Contents/MacOS/vaultify",
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
