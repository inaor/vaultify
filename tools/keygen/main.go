// keygen produces a fresh Ed25519 keypair for signing Vaultify Pro
// licenses. Output format is two base64-no-padding lines so the values
// drop straight into Go source / Cloudflare Worker secrets / 1Password
// without further escaping.
//
// Usage:
//
//	go run ./tools/keygen                 # prints to stdout, copy/paste
//	go run ./tools/keygen -kid vf-pro-prod-2026-04
//
// Production keypairs MUST be generated on a clean machine you control.
// The private half is the Vaultify Pro trust root: do not paste it
// into shared chats, paste-bins, or any SaaS dashboard. Store it in
// 1Password / a hardware key / your own secret manager and load it
// into the Cloudflare Worker via `wrangler secret put`.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	kid := flag.String("kid", "vf-pro-dev", "key id (matches the JWT header `kid`)")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}

	enc := base64.RawStdEncoding.EncodeToString
	fmt.Printf("# Vaultify Pro Ed25519 keypair (kid=%s)\n", *kid)
	fmt.Println("# Public key  -> safe to ship in vaultify.exe")
	fmt.Println("# Private key -> CF Worker secret only / 1Password / your KMS")
	fmt.Printf("kid:        %s\n", *kid)
	fmt.Printf("public:     %s\n", enc(pub))
	fmt.Printf("private:    %s\n", enc(priv))
	fmt.Println()
	fmt.Println("# Quick paste targets:")
	fmt.Println("# - internal/license/keys_dev.go: replace devPublicKeyB64 with the `public` value above")
	fmt.Println("# - .dev-keys/<kid>.priv (gitignored): write the `private` value")
	fmt.Println("# - Cloudflare Worker:   wrangler secret put ED25519_PRIVATE_KEY")
}
