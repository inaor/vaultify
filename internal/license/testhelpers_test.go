package license

import (
	"encoding/base64"
	"encoding/json"
)

// jsonEncodeRawURL is a test-only helper to base64url-no-padding-encode
// a JSON-marshalled value, so tests can hand-craft JWT segments.
func jsonEncodeRawURL(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
