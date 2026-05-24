package validation

// patternValidatorAliases maps context-layer env var names and legacy
// pattern_ids to validator registry keys. Catalog rows in patterns.json
// are resolved via each validator's Patterns() list at Register() time.
var patternValidatorAliases = map[string]string{
	// OpenAI
	"openai_api_key": "openai",
	"OPENAI_API_KEY": "openai",
	// Anthropic
	"anthropic_api_key": "anthropic",
	"ANTHROPIC_API_KEY": "anthropic",
	// Google / Gemini (catalog id is google_api_key)
	"gemini_api_key": "gemini",
	"GOOGLE_API_KEY": "gemini",
	// Slack
	"slack_bot_token": "slack",
	"slack_user_token": "slack",
	"SLACK_BOT_TOKEN":  "slack",
	"SLACK_TOKEN":      "slack",
	// GitHub
	"github_pat":   "github",
	"GITHUB_TOKEN": "github",
	"GH_TOKEN":     "github",
	// Stripe
	"stripe_secret_key": "stripe",
	"STRIPE_SECRET_KEY": "stripe",
	"STRIPE_API_KEY":    "stripe",
	// SendGrid
	"sendgrid_api_key": "sendgrid",
	"SENDGRID_API_KEY": "sendgrid",
	// AWS (live check still unsupported; id enables consistent labeling)
	"AWS_ACCESS_KEY_ID": "aws",
}

// ValidatorIDForPattern returns the validator registry key for a
// pattern_id, or "" when no live checker is registered.
func ValidatorIDForPattern(patternID string) string {
	if id, ok := patternValidatorAliases[patternID]; ok {
		return id
	}
	if v, ok := ValidatorForPattern(patternID); ok {
		return v.ID()
	}
	return ""
}

// PatternHasValidator reports whether pattern_id can be passed to
// ValidatorByID after Classify (includes aws, which is registered but
// may return StatusUnsupported at call time).
func PatternHasValidator(patternID string) bool {
	return ValidatorIDForPattern(patternID) != ""
}
