package license

// Production signing keypair. The 32-byte seed for this public key
// lives ONLY in two places:
//
//   1. The user-controlled 1Password vault entry titled
//      "Vaultify Pro signing key — vf-pro-prod-2026-04"
//   2. The Cloudflare Workers Secret Store on license.vaultify.live
//      (set via `wrangler secret put ED25519_PRIVATE_KEY_B64`)
//
// The private key never enters source control, build pipelines, or
// any developer machine outside the one that generated it.
//
// Rotation contract (per docs/licensing-jwt-v1.md §6):
//   - Generate a new keypair with `tools/keygen -kid vf-pro-prod-YYYY-MM`
//   - Add a new constant pair below; do NOT edit the existing entry
//   - Ship a Vaultify release that knows both keys
//   - Roll the Cloudflare Worker secret to the new private key
//   - Wait for outstanding tokens under the old kid to expire
//   - Drop the old constants in a later release
const (
	prodPublicKeyB64_2026_04 = "87QLzwMk8ouXCFhUg633URBVBmR/lGvLQN2T5VMxKSI"
	prodKID_2026_04          = "vf-pro-prod-2026-04"
)

func addProdKeys(reg KeyRegistry) {
	if pub, ok := decodeB64Pub(prodPublicKeyB64_2026_04); ok {
		reg[prodKID_2026_04] = pub
	}
}
