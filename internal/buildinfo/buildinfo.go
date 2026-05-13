// Package buildinfo holds link-time version and scan limits for Vaultify binaries.
package buildinfo

import (
	"strconv"
)

// Link-time overrides (defaults suit the open-source build).
var (
	BuildVersion    = "0.3.0"
	MaxScanFilesStr = "0" // "0" = unlimited
)

// Edition returns a stable label for /api/version and the UI.
func Edition() string {
	return "open"
}

// MaxScanFiles returns the inclusive file scan cap: 0 means unlimited.
func MaxScanFiles() int {
	n, err := strconv.Atoi(MaxScanFilesStr)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// FileCapForAPI returns the cap for JSON: 0 means unlimited.
func FileCapForAPI() int {
	return MaxScanFiles()
}

// Version returns the embedded release version.
func Version() string {
	if BuildVersion == "" {
		return "0.0.0"
	}
	return BuildVersion
}
