package vault

import "fmt"

// VaultProvider abstracts secret-vault CLI interactions.
type VaultProvider interface {
	Name() string
	CLIName() string
	Detect() (installed bool, version string)
	CreateItem(vault, title string, fields map[string]string) (itemID string, err error)
	GetReference(vault, itemID, field string) string
	ReadSecret(reference string) (string, error)
	InstallCommand() string
}

// ProviderStatus captures the detection result for a single vault provider.
type ProviderStatus struct {
	Name       string
	CLIName    string
	Installed  bool
	Version    string
	InstallCmd string
	Patterns   []string
}

// AllProviders returns every known VaultProvider in priority order.
func AllProviders() []VaultProvider {
	return []VaultProvider{
		&OnePasswordProvider{},
		&AwsSecretsManagerProvider{},
		&HashiCorpVaultProvider{},
		&DopplerProvider{},
	}
}

// DetectAllProviders probes every known provider and returns their status.
func DetectAllProviders() []ProviderStatus {
	type patterned interface {
		Patterns() []string
	}

	var results []ProviderStatus
	for _, p := range AllProviders() {
		installed, version := p.Detect()
		ps := ProviderStatus{
			Name:       p.Name(),
			CLIName:    p.CLIName(),
			Installed:  installed,
			Version:    version,
			InstallCmd: p.InstallCommand(),
		}
		if pp, ok := p.(patterned); ok {
			ps.Patterns = pp.Patterns()
		}
		results = append(results, ps)
	}
	return results
}

// ProviderSummary returns a human-readable status line for a provider.
func ProviderSummary(ps ProviderStatus) string {
	if ps.Installed {
		return fmt.Sprintf("[installed] %s (%s v%s)", ps.Name, ps.CLIName, ps.Version)
	}
	return fmt.Sprintf("[missing]   %s — install with: %s", ps.Name, ps.InstallCmd)
}
