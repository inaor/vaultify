package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/vaultify/vaultify/internal/paths"
	"github.com/vaultify/vaultify/internal/vault"
)

func (srv *Server) settingsPath() string {
	return paths.ConfigFile("app-settings.json")
}

func (srv *Server) loadAppSettings() vault.AppSettings {
	data, err := os.ReadFile(srv.settingsPath())
	if err != nil {
		return vault.AppSettings{}
	}
	return vault.ParseAppSettings(data)
}

func (srv *Server) saveAppSettings(s vault.AppSettings) error {
	data, err := vault.MarshalAppSettings(s)
	if err != nil {
		return err
	}
	return os.WriteFile(srv.settingsPath(), data, 0o600)
}

func (srv *Server) loadVaultSelection() {
	settings := srv.loadAppSettings()
	cli := settings.SelectedVaultCLI
	if !vault.ValidVaultCLI(cli) {
		cli = "op"
	}
	veeName := settings.VeeVaultName
	if veeName == "" {
		veeName = vault.DefaultVeeVaultName
	}
	srv.vaultSelectMu.Lock()
	srv.vaultSelectCLI = cli
	srv.veeVaultName = veeName
	srv.vaultSelectMu.Unlock()
}

// currentSettingsLocked returns a snapshot of everything we persist.
// Caller must hold vaultSelectMu for reading.
func (srv *Server) currentSettingsLocked() vault.AppSettings {
	cli := srv.vaultSelectCLI
	if !vault.ValidVaultCLI(cli) {
		cli = "op"
	}
	return vault.AppSettings{
		SelectedVaultCLI: cli,
		VeeVaultName:     srv.veeVaultName,
	}
}

func (srv *Server) saveVaultSelection() error {
	srv.vaultSelectMu.RLock()
	settings := srv.currentSettingsLocked()
	srv.vaultSelectMu.RUnlock()
	return srv.saveAppSettings(settings)
}

// getVeeVaultName returns the 1Password vault Vee reads LLM keys from.
// Defaults to DefaultVeeVaultName when the user has not configured one.
func (srv *Server) getVeeVaultName() string {
	srv.vaultSelectMu.RLock()
	defer srv.vaultSelectMu.RUnlock()
	if srv.veeVaultName == "" {
		return vault.DefaultVeeVaultName
	}
	return srv.veeVaultName
}

// setVeeVaultName updates the configured vault and persists settings.
func (srv *Server) setVeeVaultName(name string) error {
	if name == "" {
		name = vault.DefaultVeeVaultName
	}
	srv.vaultSelectMu.Lock()
	srv.veeVaultName = name
	settings := srv.currentSettingsLocked()
	srv.vaultSelectMu.Unlock()
	return srv.saveAppSettings(settings)
}

func (srv *Server) getSelectedVaultCLI() string {
	srv.vaultSelectMu.RLock()
	defer srv.vaultSelectMu.RUnlock()
	if srv.vaultSelectCLI == "" {
		return "op"
	}
	return srv.vaultSelectCLI
}

func (srv *Server) setSelectedVaultCLI(cli string) error {
	if !vault.ValidVaultCLI(cli) {
		return fmt.Errorf("invalid vault cli")
	}
	srv.vaultSelectMu.Lock()
	old := srv.vaultSelectCLI
	if old == "" {
		old = "op"
	}
	srv.vaultSelectCLI = cli
	srv.vaultSelectMu.Unlock()
	// Only invalidate the op auth cache when the selection transition
	// actually involves op. Switching between stub providers (aws ↔
	// doppler) left the op cache intact before, then a subsequent
	// dashboard navigation fired a spontaneous probe — that's one of
	// the causes of unsolicited 1Password prompts.
	if old == "op" && cli != "op" || cli == "op" && old != "op" {
		vault.BackendFor("op").InvalidateAuthCache()
	}
	return srv.saveVaultSelection()
}

func (srv *Server) activeBackend() vault.ActiveBackend {
	return vault.BackendFor(srv.getSelectedVaultCLI())
}

type vaultSelectedRequest struct {
	CLI string `json:"cli"`
}

func (srv *Server) handleVaultSelectedGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"cli": srv.getSelectedVaultCLI()})
}

func (srv *Server) handleVaultSelectedPost(w http.ResponseWriter, r *http.Request) {
	var req vaultSelectedRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if !vault.ValidVaultCLI(req.CLI) {
		httpError(w, http.StatusBadRequest, "invalid cli")
		return
	}
	if err := srv.setSelectedVaultCLI(req.CLI); err != nil {
		httpError(w, http.StatusInternalServerError, "save selection: %v", err)
		return
	}
	srv.addAuditEntry("vault_selection", req.CLI)
	writeJSON(w, http.StatusOK, map[string]string{"cli": srv.getSelectedVaultCLI()})
}
