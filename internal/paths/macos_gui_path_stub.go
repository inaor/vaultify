//go:build !darwin

package paths

// EnsureMacOSGUIPath is a no-op on non-macOS platforms.
func EnsureMacOSGUIPath() {}
