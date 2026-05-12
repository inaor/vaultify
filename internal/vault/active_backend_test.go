package vault

import (
	"testing"
)

func TestValidVaultCLI(t *testing.T) {
	for _, cli := range []string{"op", "aws", "vault", "doppler"} {
		if !ValidVaultCLI(cli) {
			t.Fatalf("expected valid: %q", cli)
		}
	}
	for _, cli := range []string{"", "gcp", "OP", "1password"} {
		if ValidVaultCLI(cli) {
			t.Fatalf("expected invalid: %q", cli)
		}
	}
}

func TestBackendFor(t *testing.T) {
	if b := BackendFor("op"); b.CLIName() != "op" || !b.SupportsSecretApply() {
		t.Fatalf("op backend: %#v", b)
	}
	for _, cli := range []string{"aws", "vault", "doppler"} {
		b := BackendFor(cli)
		if b.CLIName() != cli {
			t.Fatalf("cli want %q got %q", cli, b.CLIName())
		}
		if b.SupportsSecretApply() || b.SupportsVeeCredentialStore() {
			t.Fatalf("%q should not support apply/vee yet", cli)
		}
		if b.AuthSignedIn(true) || b.AuthSignedIn(false) {
			t.Fatalf("%q AuthSignedIn should be false without integration", cli)
		}
	}
	if b := BackendFor("unknown"); b.CLIName() != "op" {
		t.Fatalf("unknown should default to op, got %q", b.CLIName())
	}
}

func TestAppSettingsRoundTrip(t *testing.T) {
	data, err := MarshalSelected("doppler")
	if err != nil {
		t.Fatal(err)
	}
	if got := ParseSelectedCLI(data); got != "doppler" {
		t.Fatalf("ParseSelectedCLI: want doppler got %q", got)
	}
	if got := ParseSelectedCLI([]byte(`{"selected_vault_cli":"nope"}`)); got != "" {
		t.Fatalf("invalid cli should return empty, got %q", got)
	}
}

func TestStubCreateAndSignIn(t *testing.T) {
	b := BackendFor("aws").(stubBackend)
	if _, err := b.CreateCredentialItem("v", "t", "secret", ""); err == nil {
		t.Fatal("expected error")
	}
	ok, hint := b.OpenSignInAndWait()
	if ok || hint == "" {
		t.Fatalf("OpenSignInAndWait: ok=%v hint=%q", ok, hint)
	}
}
