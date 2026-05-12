package validation

import (
	"testing"

	"github.com/vaultify/vaultify/internal/scanner"
)

// helper: build a Finding with the minimum fields Classify reads.
func mkFinding(pattern, value, relPath, snippet string, entropy, conf float64) scanner.Finding {
	return scanner.Finding{
		PatternID:    pattern,
		Value:        value,
		RelativePath: relPath,
		LineSnippet:  snippet,
		Entropy:      entropy,
		Confidence:   conf,
	}
}

// TestVaultRefAlwaysNotValidatable proves the good-practice short-circuit:
// op:// references must never end up labelled "fake" or "valid", so the
// Reports remediation column the user already trusts stays consistent.
func TestVaultRefAlwaysNotValidatable(t *testing.T) {
	f := mkFinding("op_secret_ref", "op://Personal/OpenAI/credential", ".env", "key=op://...", 4.5, 0.9)
	status, vid := Classify(f)
	if status != StatusNotValidatable {
		t.Fatalf("op_secret_ref: status=%q, want %q", status, StatusNotValidatable)
	}
	if vid != "" {
		t.Fatalf("op_secret_ref should have no validator, got %q", vid)
	}
}

// TestPlaceholderTextIsFake covers the cheapest, highest-leverage win
// for the user: marking docs / examples / placeholders so they never
// burn a Pro quota on validation.
func TestPlaceholderTextIsFake(t *testing.T) {
	cases := []struct {
		name, value string
	}{
		{"your_api_here", "sk-your_api_here_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{"placeholder", "sk-placeholder_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{"all-x", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{"long run", "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"AWS docs fixture", "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mkFinding("openai_api_key", tc.value, "src/index.ts", "", 4.5, 0.9)
			if status, _ := Classify(f); status != StatusFake {
				t.Fatalf("expected fake, got %q (value=%q)", status, tc.value)
			}
		})
	}
}

// TestRealLookingKeyIsValid exercises the score-based path: a high-
// entropy, well-shaped, .env-located OpenAI key should land on
// heuristic_valid with the correct validator id.
func TestRealLookingKeyIsValid(t *testing.T) {
	value := "sk-proj-" + repeatN("aZ7Q9", 12) // 68 chars, no obvious patterns
	f := mkFinding("openai_api_key", value, ".env.production", "OPENAI_API_KEY="+value, 4.6, 0.92)
	status, vid := Classify(f)
	if status != StatusValid {
		t.Fatalf("status=%q, want %q (score=%.3f)", status, StatusValid, HeuristicScore(f))
	}
	if vid != "openai" {
		t.Fatalf("validator_id=%q, want openai", vid)
	}
}

// TestUnsupportedPatternHasNoValidator asserts the registry honestly
// reports "no live endpoint" for patterns we don't have a validator
// for yet — the UI uses this to grey out [Check]. Uses a realistic-
// looking PKCS#1 header WITHOUT the literal "..." ellipsis (which is
// a real placeholder token elsewhere) so we exercise the
// "no validator -> not_validatable" branch, not the fake detector.
func TestUnsupportedPatternHasNoValidator(t *testing.T) {
	val := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxYz" + repeatN("aZ7Q9w", 60) + "\n-----END RSA PRIVATE KEY-----"
	f := mkFinding("rsa_private_key", val, "id_rsa", "", 5.5, 0.95)
	status, vid := Classify(f)
	if status != StatusNotValidatable {
		t.Fatalf("status=%q, want %q", status, StatusNotValidatable)
	}
	if vid != "" {
		t.Fatalf("validator_id=%q, want empty", vid)
	}
}

// TestCommentLineDownweighted exercises the contextWeight path: the
// same value in a comment should score lower than in a .env file.
func TestCommentLineDownweighted(t *testing.T) {
	value := "sk-" + repeatN("aZ7Q9", 12)
	bare := mkFinding("openai_api_key", value, ".env", "OPENAI_API_KEY="+value, 4.5, 0.9)
	commented := mkFinding("openai_api_key", value, "src/foo.ts", "// example: "+value, 4.5, 0.9)
	if HeuristicScore(bare) <= HeuristicScore(commented) {
		t.Fatalf("expected bare(.env) score > commented(src), got %.3f vs %.3f",
			HeuristicScore(bare), HeuristicScore(commented))
	}
}

// TestRedactedValueDefersToScore documents the post-storage degradation:
// once Finding.Value has been redacted, fake detection can't fire, but
// Classify must still return *something* sensible based on shape.
func TestRedactedValueDefersToScore(t *testing.T) {
	// Empty value with a known validator pattern -> falls through to
	// score path; with neutral defaults it lands not_validatable
	// (length_score is low because n=0).
	f := mkFinding("openai_api_key", "", ".env", "", 4.5, 0.9)
	status, _ := Classify(f)
	if status == StatusFake {
		t.Fatalf("redacted Finding misclassified as fake")
	}
}

func repeatN(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
