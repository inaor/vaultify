package vault

import (
	"fmt"
	"os/exec"
)

type stubBackend struct {
	cli  string
	name string
	bin  string
}

func (s stubBackend) CLIName() string { return s.cli }

func (s stubBackend) Name() string { return s.name }

func (s stubBackend) Installed() bool {
	_, err := exec.LookPath(s.bin)
	return err == nil
}

func (s stubBackend) SupportsSecretApply() bool { return false }

func (s stubBackend) SupportsVeeCredentialStore() bool { return false }

func (s stubBackend) InvalidateAuthCache() {}

func (s stubBackend) AuthSignedIn(force bool) bool { return false }

func (s stubBackend) ListVaults() ([]ListEntry, error) { return nil, nil }

func (s stubBackend) EnsureVaultExists(name string) {}

func (s stubBackend) CreateCredentialItem(vaultName, title, secret, apiURL string) (string, error) {
	return "", fmt.Errorf("%s integration is not available yet — select 1Password as the active vault for Apply and Vee", s.name)
}

func (s stubBackend) CredentialReference(vaultName, itemID string) string { return "" }

func (s stubBackend) ReadSecret(ref string) (string, error) { return "", nil }

func (s stubBackend) OpenSignInAndWait() (bool, string) {
	return false, "This vault provider is selected for future use. Choose 1Password to sign in with the CLI and use Apply or Vee vault features today."
}

func (s stubBackend) CreateEmptyVault(name string) error {
	return fmt.Errorf("%s does not support creating vaults from Vaultify yet", s.name)
}

func (s stubBackend) StoreVeeProviderKey(vaultName, provider, key, model string) (stored, changed bool, err error) {
	return false, false, fmt.Errorf("%s does not store Vee keys yet — select 1Password as the active vault", s.name)
}
