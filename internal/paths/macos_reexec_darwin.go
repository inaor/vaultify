//go:build darwin

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const macOSReexecEnv = "VAULTIFY_IN_APP"

// MaybeReexecFromMacOSAppBundle launches Vaultify.app via Launch Services when this
// process was started from Terminal. That detaches from the terminal session so
// 1Password CLI authorization shows Vaultify (with its icon), not Terminal.
// Returns true when the caller should exit immediately.
func MaybeReexecFromMacOSAppBundle(argv []string) bool {
	if os.Getenv(macOSReexecEnv) == "1" || RunningFromMacOSAppBundle() {
		return false
	}
	appBundle := MacOSAppBundlePath()
	if appBundle == "" {
		return false
	}
	args := []string{"-a", appBundle}
	if len(argv) > 1 {
		args = append(args, "--args")
		args = append(args, argv[1:]...)
	}
	cmd := exec.Command("open", args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// MacOSAppBundlePath returns .../Vaultify.app when installed locally.
func MacOSAppBundlePath() string {
	bin := MacOSAppBinary()
	if bin == "" {
		return ""
	}
	// .../Vaultify.app/Contents/MacOS/vaultify -> .../Vaultify.app
	p := filepath.Clean(bin)
	if !strings.HasSuffix(p, filepath.Join("Contents", "MacOS", "vaultify")) {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(p)))
}
