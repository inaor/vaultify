package vault

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// OnePasswordProvider integrates with the 1Password CLI (op).
type OnePasswordProvider struct{}

func (o *OnePasswordProvider) Name() string    { return "1Password" }
func (o *OnePasswordProvider) CLIName() string { return "op" }

func (o *OnePasswordProvider) Detect() (bool, string) {
	path, err := exec.LookPath("op")
	if err != nil || path == "" {
		return false, ""
	}
	out, err := exec.Command("op", "--version").Output()
	if err != nil {
		return true, "unknown"
	}
	return true, strings.TrimSpace(string(out))
}

func (o *OnePasswordProvider) CreateItem(vault, title string, fields map[string]string) (string, error) {
	args := []string{
		"item", "create",
		"--vault", vault,
		"--category", "API Credential",
		"--title", title,
		"--format", "json",
	}
	for k, v := range fields {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}

	out, err := exec.Command("op", args...).Output()
	if err != nil {
		return "", fmt.Errorf("op item create: %w", err)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return "", fmt.Errorf("parsing op output: %w", err)
	}
	return result.ID, nil
}

func (o *OnePasswordProvider) GetReference(vault, itemID, field string) string {
	return fmt.Sprintf("op://%s/%s/%s", vault, itemID, field)
}

func (o *OnePasswordProvider) ReadSecret(reference string) (string, error) {
	out, err := exec.Command("op", "read", reference).Output()
	if err != nil {
		return "", fmt.Errorf("op read: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
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
