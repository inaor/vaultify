package session

import "regexp"

// NewID returns 8 random bytes as 16 lowercase hex characters.
var validSessionID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// IsValidID reports whether id matches the format produced by NewID (16 hex chars).
func IsValidID(id string) bool {
	return validSessionID.MatchString(id)
}
