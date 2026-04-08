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
	ID          string `json:"id"`
	Regex       string `json:"regex"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	IgnoreCase  bool   `json:"ignore_case"`
}

type CompiledPattern struct {
	Pattern
	Regex *regexp.Regexp
}

type patternsFile struct {
	Patterns []Pattern `json:"patterns"`
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
