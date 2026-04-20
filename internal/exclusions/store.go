package exclusions

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry records one excluded finding (match fingerprint) for future scan suppression.
type Entry struct {
	MatchSHA256 string `json:"match_sha256"`
	PatternID   string `json:"pattern_id,omitempty"`
	AddedAt     string `json:"added_at"`
	Source      string `json:"source,omitempty"`
}

// Store persists excluded match SHA256 hashes to disk (global, not per-session).
type Store struct {
	path    string
	mu      sync.RWMutex
	entries []Entry
	index   map[string]struct{}
}

// New creates a store writing to path (typically .../vaultify-scans/exclusions.json).
func New(path string) *Store {
	return &Store{path: path, index: make(map[string]struct{})}
}

// Load reads the exclusions file. Safe to call repeatedly.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.entries = nil
			s.index = make(map[string]struct{})
			return nil
		}
		return err
	}
	var wrapper struct {
		Version int     `json:"version"`
		Entries []Entry `json:"entries"`
	}
	if json.Unmarshal(data, &wrapper) == nil && len(wrapper.Entries) > 0 {
		s.entries = wrapper.Entries
	} else {
		s.entries = nil
		var legacy []string
		if json.Unmarshal(data, &legacy) == nil {
			for _, h := range legacy {
				if h == "" {
					continue
				}
				s.entries = append(s.entries, Entry{MatchSHA256: h, AddedAt: time.Now().UTC().Format(time.RFC3339)})
			}
		}
	}
	s.rebuildIndexLocked()
	return nil
}

func (s *Store) rebuildIndexLocked() {
	s.index = make(map[string]struct{})
	for _, e := range s.entries {
		if e.MatchSHA256 != "" {
			s.index[e.MatchSHA256] = struct{}{}
		}
	}
}

// Contains reports whether this match hash is excluded.
func (s *Store) Contains(hash string) bool {
	if hash == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.index[hash]
	return ok
}

// Add merges entries (skips duplicates).
func (s *Store) Add(entries ...Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, e := range entries {
		if e.MatchSHA256 == "" {
			continue
		}
		if _, exists := s.index[e.MatchSHA256]; exists {
			continue
		}
		if e.AddedAt == "" {
			e.AddedAt = time.Now().UTC().Format(time.RFC3339)
		}
		s.entries = append(s.entries, e)
		s.index[e.MatchSHA256] = struct{}{}
		changed = true
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// Remove deletes one hash from the exclusion list.
func (s *Store) Remove(hash string) error {
	if hash == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.index[hash]; !ok {
		return nil
	}
	var out []Entry
	for _, e := range s.entries {
		if e.MatchSHA256 != hash {
			out = append(out, e)
		}
	}
	s.entries = out
	s.rebuildIndexLocked()
	return s.saveLocked()
}

// List returns a copy of all entries.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *Store) saveLocked() error {
	wrapper := struct {
		Version int     `json:"version"`
		Entries []Entry `json:"entries"`
	}{Version: 1, Entries: s.entries}
	data, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
