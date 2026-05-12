// licensetool signs Vaultify Pro JWTs for development and end-to-end
// testing. Production tokens are signed by the Cloudflare Worker on
// license.vaultify.live; this CLI exists so you can demo the
// Activate Pro flow without the Worker yet existing.
//
// Usage:
//
//	go run ./tools/licensetool sign \
//	    -priv-file .dev-keys/vf-pro-dev-2026-04.priv \
//	    -kid       vf-pro-dev-2026-04 \
//	    -sub       ord_DEMO_001 \
//	    -tid       pro \
//	    -days      30
//
// The token prints to stdout. Paste it into the Vaultify dashboard's
// Settings -> Activate Pro page; the Vaultify agent verifies offline
// against the embedded public key and flips Pro on.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vaultify/vaultify/internal/license"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "sign" {
		fmt.Fprintln(os.Stderr, "usage: licensetool sign [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privFile := fs.String("priv-file", ".dev-keys/vf-pro-dev-2026-04.priv", "path to base64 (RawStd) Ed25519 private key")
	kid := fs.String("kid", "vf-pro-dev-2026-04", "key id; must match an entry in the embedded registry")
	iss := fs.String("iss", license.DefaultIssuer, "iss claim")
	aud := fs.String("aud", license.DefaultAudience, "aud claim")
	sub := fs.String("sub", "ord_DEMO_001", "sub claim — your billing system's stable id")
	tid := fs.String("tid", "pro", "tid claim — pro | pro-perpetual")
	jti := fs.String("jti", "", "jti claim (optional); empty = omit")
	days := fs.Int("days", 30, "exp = now + days (use 36500 for ~100 years on perpetual licenses)")
	_ = fs.Parse(os.Args[2:])

	priv, err := loadPriv(*privFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load priv: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UTC()
	c := license.Claims{
		Iss: *iss, Aud: *aud, Sub: *sub, Tid: *tid, Ver: license.SchemaVersion,
		Iat: now.Unix(),
		Exp: now.Add(time.Duration(*days) * 24 * time.Hour).Unix(),
		Jti: *jti,
	}
	tok, err := license.Sign(c, *kid, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(tok)
}

// loadPriv reads the base64-no-padding (RawStd) Ed25519 private key
// produced by `tools/keygen`. Trims trailing whitespace so manual
// edits / Windows line endings don't trip the decoder.
func loadPriv(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	dec, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("priv key wrong size: %d (want %d)", len(dec), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}
