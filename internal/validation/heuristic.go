// Package validation classifies findings without ever calling a third
// party. Slice A of the Secret Validation system: pure-local signals
// (regex shape, entropy, file context, recency) plus a curated
// fake/placeholder detector. Active validators land in a sibling file
// in Slice B.
//
// Scope rule: this package consumes scanner.Finding (one-way dep) and
// is the single source of truth for the HeuristicStatus values written
// into Finding by the server. Nothing else may set those fields.
package validation

import (
	"path/filepath"
	"strings"

	"github.com/vaultify/vaultify/internal/scanner"
)

// HeuristicStatus values. Mirrored to the wire in scanner.Finding.HeuristicStatus.
const (
	StatusEmpty          = ""                  // not yet classified (legacy/placeholder)
	StatusFake           = "heuristic_fake"    // obvious placeholder / demo / repeated chars
	StatusValid          = "heuristic_valid"   // looks like a real key by shape + entropy + context
	StatusNotValidatable = "not_validatable"   // op:// ref, JWT shape, AWS temp creds, or no validator covers this pattern
)

// Classify turns a single Finding into (heuristic_status, validator_id).
// Pure function: no I/O, safe to call from any goroutine.
//
// The Value is required for the fake-pattern check; on a Finding whose
// Value has already been redacted (post-storage), Classify falls back
// to shape signals only and may report StatusValid where it would have
// reported StatusFake on the live value. That's an acceptable degradation
// because heuristics are recomputed on every fresh scan.
func Classify(f scanner.Finding) (status string, validatorID string) {
	validatorID = ValidatorIDForPattern(f.PatternID)

	// 1. Always-good-practice patterns short-circuit. The op:// reference
	//    is already in the vault by definition; flagging it as anything
	//    other than NotValidatable would muddle the Reports remediation
	//    column the user already worked hard to get right.
	switch f.PatternID {
	case "op_secret_ref", "vault_ref":
		return StatusNotValidatable, ""
	case "jwt", "aws_temp_access_key_id":
		// These have local-only signals (exp claim, expiry token); we
		// treat them as not-validatable in Slice A and revisit with a
		// proper local validator in Slice B.
		return StatusNotValidatable, validatorID
	}

	// 2. Fake / placeholder detection wins over everything else.
	if isFakePlaceholder(f.Value) {
		return StatusFake, validatorID
	}

	// 3. No active validator wired up for this pattern? Mark not_validatable
	//    so the UI can grey the [Check] button. We still let the heuristic
	//    score below run for telemetry, but the visible status reflects
	//    user intent: there's nothing they can do live.
	if validatorID == "" {
		return StatusNotValidatable, ""
	}

	// 4. Score-based decision for everything else. Threshold tuned to
	//    err on the side of "show as valid, let the user check" for
	//    patterns that have a validator.
	if HeuristicScore(f) >= 0.55 {
		return StatusValid, validatorID
	}
	return StatusNotValidatable, validatorID
}

// HeuristicScore implements the weighted-signal model from the design.
// Exported so tests and the future audit layer can show the breakdown.
//
//	score = 0.35 * pattern_confidence
//	      + 0.25 * normalize(entropy, 3.0, 5.0)
//	      + 0.20 * length_score(pattern_id, len(value))
//	      + 0.10 * context_weight(file_path, line_snippet)
//	      + 0.10 * recency_weight (caller passes via Finding metadata; 0.6 default)
//
// Recency is approximated from the file mtime if a future Finding ever
// carries it; today scanner.Finding has no mtime so we use a neutral 0.6
// constant — predictable and overridable later without a schema break.
func HeuristicScore(f scanner.Finding) float64 {
	conf := clamp(f.Confidence, 0, 1)
	ent := normalize(f.Entropy, 3.0, 5.0)
	lenScore := lengthScore(f.PatternID, len(f.Value))
	ctxScore := contextWeight(f.RelativePath, f.LineSnippet)
	recency := 0.6 // neutral; caller can override via a future field

	return 0.35*conf + 0.25*ent + 0.20*lenScore + 0.10*ctxScore + 0.10*recency
}

// ----- fake / placeholder detection ---------------------------------

var (
	// Common placeholder substrings that real keys never contain.
	// Lower-cased substring match.
	placeholderTokens = []string{
		"example", "your_api", "your-api", "yourkey", "your_key",
		"your-key", "your_token", "your-token", "placeholder",
		"changeme", "change_me", "change-me", "fake", "demo", "dummy",
		"sample", "todo", "fixme", "test_test", "test-test",
		"replaceme", "replace_me", "replace-me", "<your", "...",
		"vaultify_demo",
	}

	// Canonical SDK / docs fixtures. These ARE valid-shape keys but the
	// vendor explicitly publishes them as test placeholders.
	knownTestFixtures = map[string]struct{}{
		"sk-test_4eC39HqLyjWDarjtT1zdp7dc":            {}, // Stripe public docs
		"sk_test_4eC39HqLyjWDarjtT1zdp7dc":            {}, // Stripe alt
		"AKIAIOSFODNN7EXAMPLE":                        {}, // AWS docs
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY":    {}, // AWS docs
		"GOCSPX-EXAMPLE_DEMO_VALUE":                   {}, // Google
	}
)

// isFakePlaceholder reports whether the value is obviously a docs
// placeholder, a demo fixture, or filler text. Never auto-deletes
// anything on its own — only hints the UI.
func isFakePlaceholder(v string) bool {
	if v == "" {
		return false // Value already redacted, can't tell — defer to score.
	}
	if _, ok := knownTestFixtures[v]; ok {
		return true
	}
	if isAllSameChar(v, 7) {
		// Whole-string repeated character (>=7 chars). Catches the
		// `xxxxxxxxx` / `aaaaaa` test stand-ins. RE2 has no
		// backreferences so this is implemented as a byte scan.
		return true
	}
	lc := strings.ToLower(v)
	for _, tok := range placeholderTokens {
		if strings.Contains(lc, tok) {
			return true
		}
	}
	// Long stretch of identical chars anywhere in the string (>=8 in a row).
	if hasLongRun(v, 8) {
		return true
	}
	return false
}

// isAllSameChar reports whether s consists entirely of the same byte
// repeated at least minLen times.
func isAllSameChar(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	c := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != c {
			return false
		}
	}
	return true
}

func hasLongRun(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			run++
			if run >= minRun {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// ----- score components ---------------------------------------------

// lengthScore returns 1.0 when the value falls inside the canonical
// length window for the pattern, dropping toward 0 as it deviates.
// Patterns we don't know stay neutral (0.5).
//
// Windows are intentionally generous; provider key formats evolve.
func lengthScore(patternID string, n int) float64 {
	low, high, ok := canonicalLength(patternID)
	if !ok {
		return 0.5
	}
	if n >= low && n <= high {
		return 1.0
	}
	// Linear falloff outside the window, capped at 0.
	if n < low {
		gap := low - n
		return clamp(1.0-float64(gap)/float64(low), 0, 1)
	}
	gap := n - high
	return clamp(1.0-float64(gap)/float64(high), 0, 1)
}

func canonicalLength(patternID string) (low, high int, ok bool) {
	switch patternID {
	case "openai_api_key", "OPENAI_API_KEY", "openai_project", "openai_legacy":
		return 40, 200, true
	case "anthropic_api_key", "ANTHROPIC_API_KEY", "anthropic_api":
		return 60, 120, true
	case "slack_bot_token", "slack_user_token", "slack_bot", "slack_user", "slack_app":
		return 50, 100, true
	case "github_pat", "github_oauth", "gh_pat_classic", "gh_pat_fine", "github_app":
		return 36, 120, true
	case "stripe_secret_key", "stripe_secret":
		return 30, 120, true
	case "aws_access_key_id", "AWS_ACCESS_KEY_ID":
		return 16, 24, true
	case "gemini_api_key", "google_api_key", "GOOGLE_API_KEY":
		return 30, 60, true
	case "sendgrid_api_key", "sendgrid", "SENDGRID_API_KEY":
		return 60, 80, true
	}
	return 0, 0, false
}

// contextWeight up-weights findings in classic secret-bearing files
// and down-weights findings in documentation, comments, or tests.
func contextWeight(relPath, snippet string) float64 {
	base := 0.5
	rel := strings.ToLower(relPath)
	name := strings.ToLower(filepath.Base(rel))
	ext := strings.ToLower(filepath.Ext(rel))

	switch {
	case strings.HasPrefix(name, ".env"), name == "credentials", name == "secrets":
		base = 1.0
	case ext == ".env" || ext == ".pem" || ext == ".key" || ext == ".p12":
		base = 1.0
	case ext == ".yml" || ext == ".yaml" || ext == ".toml" ||
		ext == ".json" || ext == ".tfvars" || ext == ".properties":
		base = 0.85
	case ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".mjs" ||
		ext == ".py" || ext == ".rb" || ext == ".go" || ext == ".java":
		base = 0.75
	case ext == ".md" || ext == ".rst" || ext == ".txt":
		base = 0.30
	}

	// Test directories drag confidence down: real prod keys live elsewhere.
	if strings.Contains(rel, "/test/") || strings.Contains(rel, "\\test\\") ||
		strings.Contains(rel, "/tests/") || strings.Contains(rel, "\\tests\\") ||
		strings.Contains(rel, "fixtures") || strings.Contains(rel, "__mocks__") ||
		strings.Contains(rel, "examples") {
		base *= 0.5
	}

	// Comment lines are usually intentional placeholders.
	trim := strings.TrimSpace(snippet)
	if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "/*") {
		base *= 0.4
	}
	return clamp(base, 0, 1)
}

// ----- math helpers -------------------------------------------------

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// normalize maps v in [lo, hi] linearly into [0, 1]. v < lo -> 0, v > hi -> 1.
func normalize(v, lo, hi float64) float64 {
	if hi <= lo {
		return 0
	}
	t := (v - lo) / (hi - lo)
	return clamp(t, 0, 1)
}
