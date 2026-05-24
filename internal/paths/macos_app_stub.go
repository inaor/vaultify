//go:build !darwin

package paths

// RunningFromMacOSAppBundle is always true off macOS (no app-bundle UX).
func RunningFromMacOSAppBundle() bool { return true }

// MacOSAppBundlePath returns empty on non-macOS platforms.
func MacOSAppBundlePath() string { return "" }
