package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vaultify/vaultify/internal/inventory"
)

const devInventoryFile = "dev_inventory.json"

// SaveDevInventory writes inventory rows for a session (sidecar file).
func SaveDevInventory(sessionDir string, items []inventory.Item) error {
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	payload, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionDir, devInventoryFile), payload, 0o600)
}

// LoadDevInventory reads inventory rows for a session. Missing file → nil slice.
func LoadDevInventory(sessionDir string) ([]inventory.Item, error) {
	path := filepath.Join(sessionDir, devInventoryFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var items []inventory.Item
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	return items, nil
}
