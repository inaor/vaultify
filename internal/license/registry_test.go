package license

import "testing"

// TestDefaultKeysContainsBothEnvironments guards against a silent
// drop of an environment key — decodeB64Pub returns (nil,false) on
// malformed values rather than panicking, so a typo in a kid file
// would otherwise just leave the registry short by one entry without
// the build catching it. This test fails loudly the moment that
// happens.
func TestDefaultKeysContainsBothEnvironments(t *testing.T) {
	reg := DefaultKeys()

	if _, ok := reg[devKID]; !ok {
		t.Errorf("dev kid %q missing from DefaultKeys() — keys_dev.go probably has a malformed public key", devKID)
	}
	if _, ok := reg[prodKID_2026_04]; !ok {
		t.Errorf("prod kid %q missing from DefaultKeys() — keys_prod.go probably has a malformed public key", prodKID_2026_04)
	}
	if len(reg) < 2 {
		t.Fatalf("DefaultKeys() should contain at least 2 entries (dev + prod), got %d", len(reg))
	}
}
