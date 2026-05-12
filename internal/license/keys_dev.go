package license

// Development signing keypair. The corresponding 32-byte seed lives
// in .dev-keys/vf-pro-dev-2026-04.priv (gitignored) and is loaded
// only by tools/licensetool when minting test tokens. Production
// never references this key.
//
// Keep the dev key embedded alongside prod so engineers can mint
// tokens locally for QA without touching the prod private key. A
// dev-issued token will fail to validate in the wild only because
// no real Vaultify customer has a token signed under this kid.
const (
	devPublicKeyB64 = "521/Q997j+QYNLoP14D8tDjzWr2ulXfsHWOM4OLXUME"
	devKID          = "vf-pro-dev-2026-04"
)

func addDevKeys(reg KeyRegistry) {
	if pub, ok := decodeB64Pub(devPublicKeyB64); ok {
		reg[devKID] = pub
	}
}
