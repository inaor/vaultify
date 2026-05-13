package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
)

//go:embed patterns.json
var patternsJSON []byte

type Pattern struct {
	ID          string  `json:"id"`
	Prefix      string  `json:"prefix,omitempty"`
	Regex       string  `json:"regex"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	IgnoreCase  bool    `json:"ignore_case"`
	MinEntropy  float64 `json:"min_entropy,omitempty"`
	AddedIn     string  `json:"added_in,omitempty"`
}

type CompiledPattern struct {
	Pattern
	Regex *regexp.Regexp
}

type patternsFile struct {
	SchemaVersion string    `json:"schema_version,omitempty"`
	Patterns      []Pattern `json:"patterns"`
}

// Pattern registry: parse patterns.json and compile every regex exactly
// once per process. Before this, LoadPatterns() was called from every
// NewScanner, every RecoverPlaintext call, and every handleApply — each
// one re-parsed the embedded JSON and recompiled ~30 regexes, which
// showed up as avoidable allocations during bulk Apply.
var (
	patternsOnce     sync.Once
	cachedRaw        []Pattern
	cachedCompiled   []CompiledPattern
	cachedPatternIDs map[string]int // pattern_id -> index in cachedCompiled
)

func loadPatternsLocked() {
	var raw patternsFile
	if err := json.Unmarshal(patternsJSON, &raw); err != nil {
		fmt.Printf("warning: parsing patterns.json: %v\n", err)
		return
	}
	cachedRaw = raw.Patterns

	compiled := make([]CompiledPattern, 0, len(raw.Patterns))
	ids := make(map[string]int, len(raw.Patterns))
	for _, p := range raw.Patterns {
		expr := p.Regex
		if p.IgnoreCase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			fmt.Printf("warning: compiling pattern %q: %v\n", p.ID, err)
			continue
		}
		ids[p.ID] = len(compiled)
		compiled = append(compiled, CompiledPattern{Pattern: p, Regex: re})
	}
	cachedCompiled = compiled
	cachedPatternIDs = ids
}

// RawPatterns returns the raw (uncompiled) pattern rows. The slice is
// cached; callers must not mutate it.
func RawPatterns() []Pattern {
	patternsOnce.Do(loadPatternsLocked)
	return cachedRaw
}

// LoadPatterns returns the compiled patterns. Kept as a function name
// for backward compatibility with older call sites; cheap after the
// first invocation.
func LoadPatterns() []CompiledPattern {
	patternsOnce.Do(loadPatternsLocked)
	return cachedCompiled
}

// PatternByID returns the compiled pattern for the given id, or nil if
// unknown. Lookup is O(1) via the registry map.
func PatternByID(id string) *CompiledPattern {
	patternsOnce.Do(loadPatternsLocked)
	idx, ok := cachedPatternIDs[id]
	if !ok {
		return nil
	}
	return &cachedCompiled[idx]
}
