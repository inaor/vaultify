// Package session defines filesystem-backed scan sessions and stable identifiers.
package session

import "regexp"

// validSessionID matches ids produced by NewID (16 lowercase hex characters).
var validSessionID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// IsValidID reports whether id matches the format produced by NewID (16 hex chars).
func IsValidID(id string) bool {
	return validSessionID.MatchString(id)
}
