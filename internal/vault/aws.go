package vault

import (
	"fmt"
	"os/exec"
	"strings"
)

// AwsSecretsManagerProvider is a stub provider for AWS Secrets Manager.
type AwsSecretsManagerProvider struct{}

func (a *AwsSecretsManagerProvider) Name() string    { return "AWS Secrets Manager" }
func (a *AwsSecretsManagerProvider) CLIName() string { return "aws" }

func (a *AwsSecretsManagerProvider) Detect() (bool, string) {
	path, err := exec.LookPath("aws")
	if err != nil || path == "" {
		return false, ""
	}
	out, err := exec.Command("aws", "--version").Output()
	if err != nil {
		return true, "unknown"
	}
	return true, strings.TrimSpace(string(out))
}

func (a *AwsSecretsManagerProvider) CreateItem(vault, title string, fields map[string]string) (string, error) {
	return "", fmt.Errorf("AWS Secrets Manager: CreateItem not yet implemented")
}

func (a *AwsSecretsManagerProvider) GetReference(vault, itemID, field string) string {
	return fmt.Sprintf("arn:aws:secretsmanager:::secret:%s/%s#%s", vault, itemID, field)
}

func (a *AwsSecretsManagerProvider) ReadSecret(reference string) (string, error) {
	return "", fmt.Errorf("AWS Secrets Manager: ReadSecret not yet implemented")
}

func (a *AwsSecretsManagerProvider) InstallCommand() string {
	return "winget install -e --id Amazon.AWSCLI"
}

// Patterns returns the secret-pattern IDs that AWS Secrets Manager handles.
func (a *AwsSecretsManagerProvider) Patterns() []string {
	return []string{
		"aws_access_key_id",
		"aws_temp_access_key_id",
	}
}
