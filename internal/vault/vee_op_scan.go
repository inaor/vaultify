package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
)

const opItemGetTimeout = 12 * time.Second

// VeeKeySlot is the vault-backed Vee credential row for one LLM provider.
type VeeKeySlot struct {
	HasKey bool
	Model  string
}

// VeeProviderKeyScan loads Vee API key presence and stored model names
// using at most one `op item list` on the target vault plus one
// `op item get` per provider item found. Each subprocess call runs
// through the OpSessionController so it respects the per-op RWMutex
// and subscriber-aware logging.
//
// vaultName is the 1Password vault to search; pass DefaultVeeVaultName
// when the user has not configured one.
//
// Caller must only invoke when 1Password is the active backend and
// `op` is on PATH.
func VeeProviderKeyScan(opPath, vaultName string) map[string]VeeKeySlot {
	out := map[string]VeeKeySlot{
		"openai":    {},
		"anthropic": {},
		"gemini":    {},
	}
	_ = opPath // retained for API compatibility; controller resolves opPath itself
	if vaultName == "" {
		vaultName = DefaultVeeVaultName
	}

	c := OpController()

	listCtx, cancelList := context.WithTimeout(context.Background(), opVaultListTimeout)
	defer cancelList()
	listOut, listErr := c.RunRead(listCtx, "item list (vee)", []string{"item", "list", "--vault", vaultName, "--format=json"}, opVaultListTimeout)
	if listErr != nil || len(bytes.TrimSpace(listOut)) == 0 {
		return out
	}
	items := parseOpItemListJSON(listOut)
	if len(items) == 0 {
		return out
	}
	titleToID := make(map[string]string, len(items))
	for _, it := range items {
		if it.ID != "" && it.Title != "" {
			titleToID[it.Title] = it.ID
		}
	}
	for prov, title := range map[string]string{
		"openai":    "vee-openai-key",
		"anthropic": "vee-anthropic-key",
		"gemini":    "vee-gemini-key",
	} {
		id := titleToID[title]
		if id == "" {
			continue
		}
		getCtx, cancelGet := context.WithTimeout(context.Background(), opItemGetTimeout)
		detail, getErr := c.RunRead(getCtx, "item get (vee)", []string{"item", "get", id, "--vault", vaultName, "--format=json"}, opItemGetTimeout)
		cancelGet()
		if getErr != nil || len(detail) == 0 {
			continue
		}
		hasKey, model := parseVeeItemCredentialAndUsername(detail)
		s := out[prov]
		s.HasKey = hasKey
		s.Model = model
		out[prov] = s
	}
	return out
}

type opItemListRow struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// parseOpItemListJSON accepts a top-level JSON array or common wrapper
// shapes from `op item list --format=json`.
func parseOpItemListJSON(raw []byte) []opItemListRow {
	var items []opItemListRow
	if json.Unmarshal(raw, &items) == nil && len(items) > 0 {
		return items
	}
	var wrapped struct {
		Items []opItemListRow `json:"items"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && len(wrapped.Items) > 0 {
		return wrapped.Items
	}
	return nil
}

// parseVeeItemCredentialAndUsername reads 1Password item JSON for API
// Credential fields.
func parseVeeItemCredentialAndUsername(itemJSON []byte) (hasKey bool, model string) {
	var root struct {
		Fields []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if json.Unmarshal(itemJSON, &root) != nil {
		return false, ""
	}
	for _, f := range root.Fields {
		switch f.ID {
		case "credential":
			if strings.TrimSpace(f.Value) != "" {
				hasKey = true
			}
		case "username":
			model = strings.TrimSpace(f.Value)
		}
	}
	return hasKey, model
}
