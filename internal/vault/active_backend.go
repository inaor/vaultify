package vault

import "encoding/json"

// ListEntry is one row for the Apply modal vault picker (1Password vault list shape).
type ListEntry struct {
	Name  string `json:"name"`
	Items int    `json:"items"`
}

// ActiveBackend is the vault product wired from the user's sidebar selection.
// Only the selected backend should perform auth, listing, or secret writes.
type ActiveBackend interface {
	CLIName() string
	Name() string
	Installed() bool
	// SupportsSecretApply is true when Apply can move findings into this vault (1Password today).
	SupportsSecretApply() bool
	// SupportsVeeCredentialStore is true when Vee can store/read API keys via this backend.
	SupportsVeeCredentialStore() bool
	InvalidateAuthCache()
	AuthSignedIn(force bool) bool
	ListVaults() ([]ListEntry, error)
	EnsureVaultExists(name string)
	CreateCredentialItem(vaultName, title, secret, apiURL string) (itemID string, err error)
	CredentialReference(vaultName, itemID string) string
	ReadSecret(ref string) (string, error)
	// OpenSignInAndWait opens the vendor app (1Password) and polls until AuthSignedIn or timeout.
	OpenSignInAndWait() (ok bool, hint string)
	// CreateEmptyVault creates a new logical vault/bucket (1Password vault).
	CreateEmptyVault(name string) error
	// StoreVeeProviderKey persists an LLM API key for Vee into the
	// given vault. Returns changed=true when the stored credential or
	// model was actually written; changed=false when the vault already
	// held an identical entry (diff-aware store).
	StoreVeeProviderKey(vaultName, provider, key, model string) (stored, changed bool, err error)
}

// BackendFor returns the implementation for a sidebar CLI id (op, aws, vault, doppler).
func BackendFor(cli string) ActiveBackend {
	switch cli {
	case "op":
		return onePasswordBackend{}
	case "aws":
		return stubBackend{cli: "aws", name: "AWS Secrets Manager", bin: "aws"}
	case "vault":
		return stubBackend{cli: "vault", name: "HashiCorp Vault", bin: "vault"}
	case "doppler":
		return stubBackend{cli: "doppler", name: "Doppler", bin: "doppler"}
	default:
		return onePasswordBackend{}
	}
}

// ValidVaultCLI reports whether cli is a known vault sidebar id.
func ValidVaultCLI(cli string) bool {
	switch cli {
	case "op", "aws", "vault", "doppler":
		return true
	default:
		return false
	}
}

// DefaultVeeVaultName is the 1Password vault used for Vee provider
// API keys when the user has not configured anything else.
const DefaultVeeVaultName = "Vaultify"

// AppSettings is persisted in ConfigDir()/app-settings.json.
type AppSettings struct {
	SelectedVaultCLI string `json:"selected_vault_cli"`
	VeeVaultName     string `json:"vee_vault_name,omitempty"`
}

// MarshalAppSettings serialises the full settings object.
func MarshalAppSettings(s AppSettings) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ParseAppSettings tolerantly reads settings JSON, returning a zero
// value when the file is missing or malformed.
func ParseAppSettings(data []byte) AppSettings {
	var s AppSettings
	_ = json.Unmarshal(data, &s)
	return s
}

// MarshalSelected writes settings JSON for the selected CLI only.
// Retained as a convenience so older call sites keep compiling.
func MarshalSelected(cli string) ([]byte, error) {
	return MarshalAppSettings(AppSettings{SelectedVaultCLI: cli})
}

// ParseSelectedCLI extracts selected_vault_cli from settings JSON;
// returns "" if missing or invalid.
func ParseSelectedCLI(data []byte) string {
	s := ParseAppSettings(data)
	if !ValidVaultCLI(s.SelectedVaultCLI) {
		return ""
	}
	return s.SelectedVaultCLI
}
