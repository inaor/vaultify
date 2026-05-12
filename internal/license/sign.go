package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Sign produces a compact-serialised JWT (`header.payload.signature`)
// for the supplied claims. Used by the dev licensetool CLI and by
// tests; production signing happens in the Cloudflare Worker.
//
// kid identifies which key in the registry the verifier should use.
// priv MUST be a 64-byte Ed25519 private key (ed25519.PrivateKey).
func Sign(claims Claims, kid string, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("license.Sign: private key wrong size (%d, want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if kid == "" {
		return "", fmt.Errorf("license.Sign: kid required")
	}
	hdr := Header{Alg: "EdDSA", Typ: "JWT", Kid: kid}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(hb) + "." + enc(pb)
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + enc(sig), nil
}
