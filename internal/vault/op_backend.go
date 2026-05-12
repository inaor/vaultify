package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	opVaultListTimeout = 15 * time.Second
	// opSignInProbeTimeout is the per-probe ceiling used inside the
	// BeginSignIn loop only. The 15 s cap is fine for steady-state
	// probes (desktop unlocked → answer is immediate), but on the
	// first unlock the user is interactively driving Windows Hello /
	// the WAM modal: Authorize → password / biometric → desktop wakes
	// → CLI integration responds. Real-world flows routinely take
	// 20–35 s, so the 15 s probe was killing op.exe mid-flow and
	// declaring the desktop unresponsive before the user had even
	// finished typing their password. 45 s gives the human leg of the
	// unlock enough headroom; signinTotalBudget plus the consecutive-
	// timeout bail-out still keep the loop bounded.
	opSignInProbeTimeout = 45 * time.Second
	// Item create/edit can involve 1Password round-trips; allow extra headroom.
	opItemWriteTimeout = 20 * time.Second
	// Item read is fast when the desktop app is unlocked; short ceiling limits hangs.
	opItemReadTimeout = 10 * time.Second
)

type onePasswordBackend struct{}

func (onePasswordBackend) CLIName() string { return "op" }
func (onePasswordBackend) Name() string    { return "1Password" }

func (onePasswordBackend) Installed() bool {
	_, err := exec.LookPath("op")
	return err == nil
}

func (onePasswordBackend) SupportsSecretApply() bool        { return true }
func (onePasswordBackend) SupportsVeeCredentialStore() bool { return true }

func (onePasswordBackend) InvalidateAuthCache() {
	OpController().InvalidateAuthCache()
}

// OpAuthSignedIn remains for backward compatibility with legacy call
// sites. It now routes through the controller so there is a single
// source of auth truth. Force=true triggers a probe; force=false
// returns the cached state.
func OpAuthSignedIn(force bool) bool {
	if !force {
		return OpController().SignedIn()
	}
	ctx, cancel := context.WithTimeout(context.Background(), opVaultListTimeout+2*time.Second)
	defer cancel()
	return OpController().Probe(ctx, true) == OpStateSignedIn
}

func (onePasswordBackend) AuthSignedIn(force bool) bool { return OpAuthSignedIn(force) }

func parseListEntries(raw []byte) ([]ListEntry, error) {
	var vaults []ListEntry
	if err := json.Unmarshal(raw, &vaults); err != nil {
		return nil, err
	}
	return vaults, nil
}

func (onePasswordBackend) ListVaults() ([]ListEntry, error) {
	c := OpController()
	if cached := c.CachedVaultListJSON(); len(cached) > 0 {
		if entries, err := parseListEntries(cached); err == nil {
			return entries, nil
		}
	}
	out, opErr := c.RunRead(context.Background(), "vault list", []string{"vault", "list", "--format=json"}, opVaultListTimeout)
	if opErr != nil {
		return nil, nil
	}
	c.setVaultListCache(out)
	return parseListEntries(out)
}

func (onePasswordBackend) EnsureVaultExists(name string) {
	c := OpController()
	if out, opErr := c.RunRead(context.Background(), "vault get", []string{"vault", "get", name, "--format=json"}, opVaultListTimeout); opErr == nil && len(out) > 2 {
		return
	}
	if _, createErr := c.RunWrite(context.Background(), "vault create", []string{"vault", "create", name}, opVaultListTimeout); createErr != nil {
		log.Printf("vault create %q: %s", name, createErr.Error())
		return
	}
	log.Printf("vault %q created", name)
	c.setVaultListCache(nil)
}

func (onePasswordBackend) CreateCredentialItem(vaultName, title, secret, apiURL string) (string, error) {
	args := []string{"item", "create",
		"--vault", vaultName,
		"--category", "API Credential",
		"--title", title,
		"--format", "json",
		"credential=" + secret,
	}
	if apiURL != "" {
		args = append(args, "--url", apiURL)
	}
	c := OpController()
	out, opErr := c.RunWrite(context.Background(), "item create", args, opItemWriteTimeout)
	if opErr != nil {
		return "", fmt.Errorf("failed to create 1Password item")
	}
	var item struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(out, &item) != nil {
		return "", fmt.Errorf("could not parse item ID from op output")
	}
	c.setVaultListCache(nil)
	return item.ID, nil
}

func (onePasswordBackend) CredentialReference(vaultName, itemID string) string {
	return fmt.Sprintf("op://%s/%s/credential", vaultName, itemID)
}

func (onePasswordBackend) ReadSecret(ref string) (string, error) {
	c := OpController()
	out, opErr := c.RunRead(context.Background(), "read", []string{"read", ref}, opItemReadTimeout)
	if opErr != nil {
		return "", opErr
	}
	return strings.TrimSpace(string(out)), nil
}

// OpenSignInAndWait is a legacy synchronous path kept for callers that
// have not yet migrated to BeginSignIn + WS notifications. It blocks
// until the controller flips to signed_in or the loop times out.
func (onePasswordBackend) OpenSignInAndWait() (bool, string) {
	c := OpController()
	c.BeginSignIn()
	deadline := time.Now().Add(55 * time.Second)
	for time.Now().Before(deadline) {
		if c.SignedIn() {
			return true, ""
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false, "Unlock 1Password (password or Touch ID), keep \u201cIntegrate with 1Password CLI\u201d on in Settings \u203a Developer, then click Retry. The first connection can take a full minute."
}

func (onePasswordBackend) CreateEmptyVault(name string) error {
	c := OpController()
	if _, opErr := c.RunWrite(context.Background(), "vault create", []string{"vault", "create", name}, opVaultListTimeout); opErr != nil {
		log.Printf("op vault create %q: %s", name, opErr.Error())
		return fmt.Errorf("vault creation failed")
	}
	c.setVaultListCache(nil)
	return nil
}

func (onePasswordBackend) StoreVeeProviderKey(vaultName, provider, key, model string) (stored, changed bool, err error) {
	if vaultName == "" {
		vaultName = DefaultVeeVaultName
	}
	onePasswordBackend{}.EnsureVaultExists(vaultName)
	title := fmt.Sprintf("vee-%s-key", provider)
	m := model
	if m == "" {
		m = "default"
	}
	c := OpController()

	// Diff-aware: if an item with the same credential AND same username
	// already exists, skip the write and report changed=false. Writes
	// through op still cost a subprocess each, so saving the no-op is
	// worth a cheap read first.
	credRef := fmt.Sprintf("op://%s/%s/credential", vaultName, title)
	userRef := fmt.Sprintf("op://%s/%s/username", vaultName, title)
	existingCred, readErr := onePasswordBackend{}.ReadSecret(credRef)
	if readErr == nil && existingCred == key {
		existingModel, _ := onePasswordBackend{}.ReadSecret(userRef)
		if existingModel == m {
			return true, false, nil
		}
	}

	createArgs := []string{"item", "create", "--vault", vaultName, "--category", "API Credential", "--title", title, "credential=" + key, "username=" + m}
	if _, createErr := c.RunWrite(context.Background(), "item create (vee)", createArgs, opItemWriteTimeout); createErr != nil {
		editArgs := []string{"item", "edit", title, "--vault", vaultName, "credential=" + key, "username=" + m}
		if _, editErr := c.RunWrite(context.Background(), "item edit (vee)", editArgs, opItemWriteTimeout); editErr != nil {
			log.Printf("vee store key: create=%s edit=%s", createErr.Error(), editErr.Error())
			return false, false, fmt.Errorf("failed to store key in vault")
		}
	}
	c.setVaultListCache(nil)
	return true, true, nil
}

func tryOpenOnePasswordDesktop() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", "onepassword://")
		if err := cmd.Start(); err != nil {
			log.Printf("open 1Password (windows): %v", err)
		}
	case "darwin":
		if err := exec.Command("open", "-a", "1Password").Start(); err != nil {
			_ = exec.Command("open", "onepassword://").Start()
		}
	default:
		_ = exec.Command("xdg-open", "onepassword://").Start()
	}
}
