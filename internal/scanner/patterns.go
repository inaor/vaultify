package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
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
	Patterns []Pattern `json:"patterns"`
}

func RawPatterns() []Pattern {
	var raw patternsFile
	if err := json.Unmarshal(patternsJSON, &raw); err != nil {
		return nil
	}
	return raw.Patterns
}

func LoadPatterns() []CompiledPattern {
	var raw patternsFile
	if err := json.Unmarshal(patternsJSON, &raw); err != nil {
		fmt.Printf("warning: parsing patterns.json: %v\n", err)
		return nil
	}

	compiled := make([]CompiledPattern, 0, len(raw.Patterns))
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
		compiled = append(compiled, CompiledPattern{Pattern: p, Regex: re})
	}
	return compiled
}
