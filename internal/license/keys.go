package license

import (
	"crypto/ed25519"
	"encoding/base64"
)

// DefaultIssuer + DefaultAudience are the values production tokens
// must carry. Centralised here (rather than scattered through call
// sites) so swapping environments — e.g. running staging against a
// different issuer for QA — is a single-source change.
const (
	DefaultIssuer   = "https://vaultify.live"
	DefaultAudience = "vaultify-pro"
)

// DefaultKeys returns the embedded Ed25519 public-key registry.
// Each environment file (keys_dev.go, keys_prod.go, future
// keys_staging.go) adds its own kid -> public-key entries via its
// own add*Keys helper. Multiple environments coexist intentionally:
// a single binary can verify dev tokens (for QA) and prod tokens
// (for customers) without recompilation.
//
// Adding a new key = drop a keys_<env>.go file with constants + an
// add helper, then call it here. Never edit a shipped file in place.
func DefaultKeys() KeyRegistry {
	reg := KeyRegistry{}
	addDevKeys(reg)
	addProdKeys(reg)
	return reg
}

// decodeB64Pub parses a base64-no-padding ed25519 public-key string
// from the embedded constants. Returns (nil, false) on malformed
// values rather than panicking — a typo in a key file should fail
// at boot with a clear "license: empty key registry" instead of
// crashing the agent.
func decodeB64Pub(s string) (ed25519.PublicKey, bool) {
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
