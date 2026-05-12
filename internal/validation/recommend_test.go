package validation

import (
	"testing"

	"github.com/vaultify/vaultify/internal/scanner"
)

func TestRecommendOpRefIsKeep(t *testing.T) {
	r := Recommend(scanner.Finding{PatternID: "op_secret_ref"}, StatusUnknown)
	if r.Recommended != "keep" {
		t.Fatalf("op_secret_ref -> %q, want keep", r.Recommended)
	}
}

func TestRecommendInvalidIsRemove(t *testing.T) {
	r := Recommend(scanner.Finding{PatternID: "openai_api_key", RelativePath: "src/x.ts"}, StatusInvalid)
	if r.Recommended != "remove" || r.Alt != "graveyard" {
		t.Fatalf("invalid -> %+v", r)
	}
	if r.Confidence < 0.9 {
		t.Fatalf("invalid confidence too low: %.2f", r.Confidence)
	}
}

func TestRecommendActiveIsVaultRotate(t *testing.T) {
	r := Recommend(scanner.Finding{PatternID: "openai_api_key", RelativePath: "src/x.ts"}, StatusActive)
	if r.Recommended != "vault" || r.Alt != "rotate" {
		t.Fatalf("active -> %+v", r)
	}
}

func TestRecommendFakeIsGraveyard(t *testing.T) {
	r := Recommend(scanner.Finding{PatternID: "openai_api_key", HeuristicStatus: StatusFake}, StatusUnknown)
	if r.Recommended != "graveyard" {
		t.Fatalf("fake -> %q, want graveyard", r.Recommended)
	}
}

func TestRecommendUnsupportedHighGoesToVault(t *testing.T) {
	r := Recommend(scanner.Finding{
		PatternID:       "rsa_private_key",
		HeuristicStatus: StatusValid,
		Severity:        "high",
	}, StatusUnsupported)
	if r.Recommended != "vault" {
		t.Fatalf("unsupported+high -> %q, want vault", r.Recommended)
	}
}

func TestRecommendDefaultIsVault(t *testing.T) {
	r := Recommend(scanner.Finding{PatternID: "generic_secret", Severity: "low"}, StatusUnknown)
	if r.Recommended != "vault" {
		t.Fatalf("default -> %q, want vault", r.Recommended)
	}
	if r.Confidence > 0.6 {
		t.Fatalf("default confidence should be modest, got %.2f", r.Confidence)
	}
}
