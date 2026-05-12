// Package buildinfo holds link-time version and scan limits for Vaultify binaries.
package buildinfo

import (
	"strconv"
)

// Link-time overrides (defaults suit the open-source build).
var (
	BuildVersion    = "0.3.0"
	BuildEdition    = "open" // retained for ldflags; Edition() always reports open source
	MaxScanFilesStr = "0"    // "0" = unlimited (default for OSS)
)

// Edition returns a stable edition label for /api/version and the UI.
// Open-source builds do not use tiered licensing.
func Edition() string {
	return "open"
}

// IsPro is retained so existing feature gates compile; the OSS tree
// always behaves as fully unlocked.
func IsPro() bool {
	return true
}

// SetRuntimePro is a no-op kept for API compatibility with older call sites.
func SetRuntimePro(_ bool) {}

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
