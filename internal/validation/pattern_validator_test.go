package validation

import (
	"testing"

	"github.com/vaultify/vaultify/internal/scanner"
)

// Catalog patterns that must resolve to a live validator registry key.
var catalogWithValidator = map[string]string{
	"openai_project":    "openai",
	"openai_legacy":     "openai",
	"anthropic_api":     "anthropic",
	"google_api_key":    "gemini",
	"slack_bot":         "slack",
	"slack_user":        "slack",
	"slack_app":         "slack",
	"gh_pat_classic":    "github",
	"gh_pat_fine":       "github",
	"github_oauth":      "github",
	"github_app":        "github",
	"stripe_secret":     "stripe",
	"sendgrid":          "sendgrid",
	"aws_access_key_id": "aws",
}

func TestValidatorIDForPattern_catalog(t *testing.T) {
	for patternID, want := range catalogWithValidator {
		if got := ValidatorIDForPattern(patternID); got != want {
			t.Errorf("ValidatorIDForPattern(%q) = %q, want %q", patternID, got, want)
		}
	}
}

func TestValidatorIDForPattern_contextAliases(t *testing.T) {
	cases := map[string]string{
		"OPENAI_API_KEY":    "openai",
		"ANTHROPIC_API_KEY": "anthropic",
		"GITHUB_TOKEN":      "github",
		"SENDGRID_API_KEY":  "sendgrid",
	}
	for patternID, want := range cases {
		if got := ValidatorIDForPattern(patternID); got != want {
			t.Errorf("alias %q = %q, want %q", patternID, got, want)
		}
	}
}

func TestValidatorIDForPattern_noValidator(t *testing.T) {
	for _, id := range []string{"jwt", "op_secret_ref", "private_key_block", "slack_webhook", "gitlab_pat"} {
		if got := ValidatorIDForPattern(id); got != "" {
			t.Errorf("pattern %q should have no validator, got %q", id, got)
		}
	}
}

func TestClassify_catalogOpenAIProject(t *testing.T) {
	value := "sk-proj-" + repeatN("aZ7Q9", 12)
	f := scanner.Finding{
		PatternID:    "openai_project",
		Value:        value,
		RelativePath: ".env",
		LineSnippet:  "OPENAI_API_KEY=" + value,
		Entropy:      4.6,
		Confidence:   0.92,
	}
	status, vid := Classify(f)
	if status != StatusValid {
		t.Fatalf("status=%q want %q score=%.3f", status, StatusValid, HeuristicScore(f))
	}
	if vid != "openai" {
		t.Fatalf("validator_id=%q want openai", vid)
	}
}

func TestClassify_catalogGitHubClassic(t *testing.T) {
	value := "ghp_" + repeatN("aZ7Q9wXcD2", 4)
	f := scanner.Finding{
		PatternID:    "gh_pat_classic",
		Value:        value,
		RelativePath: ".env",
		Entropy:      4.5,
		Confidence:   0.9,
	}
	_, vid := Classify(f)
	if vid != "github" {
		t.Fatalf("validator_id=%q want github", vid)
	}
}

// Ensure every Patterns() entry round-trips through ValidatorIDForPattern.
func TestValidatorRegistryPatternsAligned(t *testing.T) {
	for _, vid := range RegisteredIDs() {
		v, ok := ValidatorByID(vid)
		if !ok {
			t.Fatalf("missing validator %q", vid)
		}
		for _, pid := range v.Patterns() {
			got := ValidatorIDForPattern(pid)
			if got != vid {
				t.Errorf("pattern %q registered under %q but ValidatorIDForPattern => %q", pid, vid, got)
			}
		}
	}
}
