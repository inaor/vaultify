//go:build !darwin

package paths

// MaybeReexecFromMacOSAppBundle is a no-op off macOS.
func MaybeReexecFromMacOSAppBundle(_ []string) bool { return false }
