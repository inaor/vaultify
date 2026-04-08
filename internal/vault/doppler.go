package vault

import (
	"fmt"
	"os/exec"
	"strings"
)

// DopplerProvider is a stub provider for the Doppler CLI.
type DopplerProvider struct{}

func (d *DopplerProvider) Name() string    { return "Doppler" }
func (d *DopplerProvider) CLIName() string { return "doppler" }

func (d *DopplerProvider) Detect() (bool, string) {
	path, err := exec.LookPath("doppler")
	if err != nil || path == "" {
		return false, ""
	}
	out, err := exec.Command("doppler", "--version").Output()
	if err != nil {
		return true, "unknown"
	}
	return true, strings.TrimSpace(string(out))
}

func (d *DopplerProvider) CreateItem(vault, title string, fields map[string]string) (string, error) {
	return "", fmt.Errorf("Doppler: CreateItem not yet implemented")
}

func (d *DopplerProvider) GetReference(vault, itemID, field string) string {
	return fmt.Sprintf("doppler://%s/%s/%s", vault, itemID, field)
}

func (d *DopplerProvider) ReadSecret(reference string) (string, error) {
	return "", fmt.Errorf("Doppler: ReadSecret not yet implemented")
}

func (d *DopplerProvider) InstallCommand() string {
	return "winget install -e --id Doppler.CLI"
}
