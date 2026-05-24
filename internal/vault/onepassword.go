package vault

import (
	"fmt"
	"os/exec"
	"strings"
)

// OnePasswordProvider integrates with the 1Password CLI (op).
type OnePasswordProvider struct{}

func (o *OnePasswordProvider) Name() string    { return "1Password" }
func (o *OnePasswordProvider) CLIName() string { return "op" }

func (o *OnePasswordProvider) Detect() (bool, string) {
	path, err := ResolveOpPath()
	if err != nil || path == "" {
		return false, ""
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return true, "unknown"
	}
	return true, strings.TrimSpace(string(out))
}

func (o *OnePasswordProvider) CreateItem(vault, title string, fields map[string]string) (string, error) {
	cred := fields["credential"]
	if cred == "" {
		return "", fmt.Errorf("credential field required")
	}
	apiURL := fields["url"]
	return onePasswordBackend{}.CreateCredentialItem(vault, title, cred, apiURL)
}

func (o *OnePasswordProvider) GetReference(vault, itemID, field string) string {
	return fmt.Sprintf("op://%s/%s/%s", vault, itemID, field)
}

func (o *OnePasswordProvider) ReadSecret(reference string) (string, error) {
	return onePasswordBackend{}.ReadSecret(reference)
}

func (o *OnePasswordProvider) InstallCommand() string {
	return "winget install -e --id AgileBits.1Password.CLI"
}

// Patterns returns the secret-pattern IDs that 1Password handles (everything except AWS-specific keys).
func (o *OnePasswordProvider) Patterns() []string {
	return []string{
		"generic_api_key",
		"generic_secret",
		"private_key",
		"connection_string",
		"password_in_url",
		"bearer_token",
		"basic_auth",
		"jwt_token",
	}
}
