package vault

import (
	"fmt"
	"os/exec"
	"strings"
)

// HashiCorpVaultProvider is a stub provider for HashiCorp Vault.
type HashiCorpVaultProvider struct{}

func (h *HashiCorpVaultProvider) Name() string    { return "HashiCorp Vault" }
func (h *HashiCorpVaultProvider) CLIName() string { return "vault" }

func (h *HashiCorpVaultProvider) Detect() (bool, string) {
	path, err := exec.LookPath("vault")
	if err != nil || path == "" {
		return false, ""
	}
	out, err := exec.Command("vault", "version").Output()
	if err != nil {
		return true, "unknown"
	}
	return true, strings.TrimSpace(string(out))
}

func (h *HashiCorpVaultProvider) CreateItem(vault, title string, fields map[string]string) (string, error) {
	return "", fmt.Errorf("HashiCorp Vault: CreateItem not yet implemented")
}

func (h *HashiCorpVaultProvider) GetReference(vaultName, itemID, field string) string {
	return fmt.Sprintf("vault:secret/data/%s/%s#%s", vaultName, itemID, field)
}

func (h *HashiCorpVaultProvider) ReadSecret(reference string) (string, error) {
	return "", fmt.Errorf("HashiCorp Vault: ReadSecret not yet implemented")
}

func (h *HashiCorpVaultProvider) InstallCommand() string {
	return "winget install -e --id Hashicorp.Vault"
}
