package validation

import (
	"fmt"
	"strings"

	"github.com/vaultify/vaultify/internal/scanner"
)

// VeeRecommendation is the Vee-engine output per finding. One primary
// action + an optional alternate keep the UI from drowning in floats.
// Reason is templated text the row tooltip + audit log surface verbatim.
type VeeRecommendation struct {
	Recommended string  `json:"recommended"`           // vault | remove | graveyard | rotate | keep
	Alt         string  `json:"alt,omitempty"`
	Confidence  float64 `json:"confidence"`            // 0..1
	Reason      string  `json:"reason"`
}

// Recommend runs the deterministic rule engine. Inputs are everything
// the agent already knows about a finding (heuristic + active
// validation + scanner severity + path), so this is a pure function
// safe to invoke per-row at session-detail time without an LLM call.
//
// Rule priority is fixed and matches the design doc:
//  1. op:// reference        -> keep                 (good practice)
//  2. validation == invalid  -> remove               (key already revoked)
//  3. validation == active   -> vault + rotate alt   (live key in plaintext)
//  4. heuristic == fake      -> graveyard            (placeholder/demo)
//  5. unsupported + heuristic_valid + high           -> vault
//  6. default                -> vault                (safer choice)
func Recommend(f scanner.Finding, vstatus Status) VeeRecommendation {
	provider := strings.TrimSpace(f.PatternID)
	pathHint := f.RelativePath
	if pathHint == "" {
		pathHint = "this file"
	}

	switch f.PatternID {
	case "op_secret_ref", "vault_ref":
		return VeeRecommendation{
			Recommended: "keep",
			Confidence:  1.00,
			Reason:      "Good practice: this is an op:// reference, the secret is already in the vault.",
		}
	}

	switch vstatus {
	case StatusInvalid:
		return VeeRecommendation{
			Recommended: "remove",
			Alt:         "graveyard",
			Confidence:  0.95,
			Reason:      fmt.Sprintf("This %s key is already revoked. Safe to remove from %s for hygiene.", provider, pathHint),
		}
	case StatusActive:
		return VeeRecommendation{
			Recommended: "vault",
			Alt:         "rotate",
			Confidence:  0.92,
			Reason:      fmt.Sprintf("ACTIVE %s key in plaintext at %s. Vault it now, then rotate at the provider.", provider, pathHint),
		}
	}

	if f.HeuristicStatus == StatusFake {
		return VeeRecommendation{
			Recommended: "graveyard",
			Alt:         "remove",
			Confidence:  0.85,
			Reason:      "Looks like a placeholder / demo value. Move to Junkyard so it never re-appears.",
		}
	}

	if vstatus == StatusUnsupported && f.HeuristicStatus == StatusValid && severityRank(f.Severity) <= 1 {
		return VeeRecommendation{
			Recommended: "vault",
			Alt:         "remove",
			Confidence:  0.70,
			Reason:      fmt.Sprintf("No live check available for %s, but heuristics + severity say treat as real. Vault to be safe.", provider),
		}
	}

	return VeeRecommendation{
		Recommended: "vault",
		Confidence:  0.50,
		Reason:      "Default safer choice. Vault unless you know it's a placeholder.",
	}
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
