package validation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// init wires every shipped validator into the global registry. New
// providers add a struct + Validate impl in this file (or a
// dedicated file in the same package) and append themselves here.
func init() {
	Register(&openaiValidator{})
	Register(&anthropicValidator{})
	Register(&geminiValidator{})
	Register(&slackValidator{})
	Register(&githubValidator{})
	Register(&stripeValidator{})
	Register(&sendgridValidator{})
	Register(&awsValidator{})
}

// ----- OpenAI -------------------------------------------------------

type openaiValidator struct{}

func (openaiValidator) ID() string         { return "openai" }
func (openaiValidator) Patterns() []string { return []string{"openai_api_key", "OPENAI_API_KEY"} }
func (openaiValidator) TTL() time.Duration { return 24 * time.Hour }

func (v openaiValidator) Validate(ctx context.Context, value string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openaiBaseURL()+"/v1/models", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- Anthropic ----------------------------------------------------

type anthropicValidator struct{}

func (anthropicValidator) ID() string         { return "anthropic" }
func (anthropicValidator) Patterns() []string { return []string{"anthropic_api_key"} }
func (anthropicValidator) TTL() time.Duration { return 24 * time.Hour }

func (v anthropicValidator) Validate(ctx context.Context, value string) (Result, error) {
	// Anthropic returns 401 on bad key for any /v1/* with x-api-key.
	// /v1/models is cheap and listed in their docs as auth-only.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, anthropicBaseURL()+"/v1/models", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	req.Header.Set("x-api-key", value)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- Gemini -------------------------------------------------------

type geminiValidator struct{}

func (geminiValidator) ID() string         { return "gemini" }
func (geminiValidator) Patterns() []string { return []string{"gemini_api_key"} }
func (geminiValidator) TTL() time.Duration { return 24 * time.Hour }

func (v geminiValidator) Validate(ctx context.Context, value string) (Result, error) {
	// Google's Gemini API takes ?key=<value> on /v1beta/models. 200 on valid,
	// 400/403 on invalid (the API returns 400 for bad keys, frustratingly).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geminiBaseURL()+"/v1beta/models?key="+value, nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusBadRequest {
		// Google encodes "invalid api key" as 400. Treat as Invalid.
		return Result{Status: StatusInvalid, Reason: "gemini.400_invalid_api_key", HTTPStatus: 400}, nil
	}
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- Slack --------------------------------------------------------

type slackValidator struct{}

func (slackValidator) ID() string         { return "slack" }
func (slackValidator) Patterns() []string { return []string{"slack_bot_token", "slack_user_token", "slack_app", "slack_bot", "slack_user"} }
func (slackValidator) TTL() time.Duration { return 24 * time.Hour }

func (v slackValidator) Validate(ctx context.Context, value string) (Result, error) {
	// Slack's auth.test always 200s; the body's `ok` field tells us
	// whether the token is good. invalid_auth / token_revoked map to
	// Invalid; everything else (account_inactive, missing_scope, etc.)
	// still proves the token is recognised, so it's Active.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackBaseURL()+"/api/auth.test", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return classifyHTTP(v.ID(), resp.StatusCode), nil
	}
	var slackResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &slackResp); err != nil {
		return Result{Status: StatusError, Reason: "slack.malformed_response", HTTPStatus: resp.StatusCode}, nil
	}
	if slackResp.OK {
		return Result{Status: StatusActive, Reason: "slack.auth_test_ok", HTTPStatus: 200}, nil
	}
	switch slackResp.Error {
	case "invalid_auth", "token_revoked", "token_expired", "not_authed", "account_inactive":
		return Result{Status: StatusInvalid, Reason: "slack." + slackResp.Error, HTTPStatus: 200}, nil
	default:
		return Result{Status: StatusError, Reason: "slack." + slackResp.Error, HTTPStatus: 200}, nil
	}
}

// ----- GitHub -------------------------------------------------------

type githubValidator struct{}

func (githubValidator) ID() string         { return "github" }
func (githubValidator) Patterns() []string { return []string{"github_pat", "github_oauth", "gh_pat_fine", "gh_pat_classic", "github_app"} }
func (githubValidator) TTL() time.Duration { return 24 * time.Hour }

func (v githubValidator) Validate(ctx context.Context, value string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubBaseURL()+"/user", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	// Fine-grained PATs (`github_pat_*`) and OAuth use Bearer; classic
	// PATs use `token <value>`. Both shapes work with `token` for
	// classic AND fine-grained per current docs, so we use `token` and
	// fall back to `Bearer` if 401 — but only if the token shape
	// suggests a fine-grained PAT (starts with github_pat_). Keep the
	// extra round-trip out of the hot path.
	req.Header.Set("Authorization", "token "+value)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusUnauthorized && strings.HasPrefix(value, "github_pat_") {
		// Retry with Bearer for fine-grained.
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubBaseURL()+"/user", nil)
		req2.Header.Set("Authorization", "Bearer "+value)
		req2.Header.Set("Accept", "application/vnd.github+json")
		resp2, err := HTTPClient().Do(req2)
		if err == nil {
			defer resp2.Body.Close()
			_, _ = io.Copy(io.Discard, resp2.Body)
			return classifyHTTP(v.ID(), resp2.StatusCode), nil
		}
	}
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- Stripe -------------------------------------------------------

type stripeValidator struct{}

func (stripeValidator) ID() string         { return "stripe" }
func (stripeValidator) Patterns() []string { return []string{"stripe_secret_key", "stripe_secret"} }
func (stripeValidator) TTL() time.Duration { return 24 * time.Hour }

func (v stripeValidator) Validate(ctx context.Context, value string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeBaseURL()+"/v1/balance", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- SendGrid -----------------------------------------------------

type sendgridValidator struct{}

func (sendgridValidator) ID() string         { return "sendgrid" }
func (sendgridValidator) Patterns() []string { return []string{"sendgrid_api_key", "SENDGRID_API_KEY"} }
func (sendgridValidator) TTL() time.Duration { return 24 * time.Hour }

func (v sendgridValidator) Validate(ctx context.Context, value string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sendgridBaseURL()+"/v3/scopes", nil)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	req.Header.Set("Authorization", "Bearer "+value)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return classifyNetworkErr(v.ID(), err), nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return classifyHTTP(v.ID(), resp.StatusCode), nil
}

// ----- AWS (STS GetCallerIdentity) ---------------------------------

type awsValidator struct{}

func (awsValidator) ID() string         { return "aws" }
func (awsValidator) Patterns() []string { return []string{"aws_access_key_id"} }
func (awsValidator) TTL() time.Duration { return 24 * time.Hour }

// Validate for AWS is special: the access key alone is not enough,
// we'd need the matching secret access key plus optional session
// token. Vaultify's scanner doesn't pair them yet, so this validator
// reports `unsupported` rather than ever issuing an API call. The
// registry still names it so the UI shows a consistent "AWS" label.
func (v awsValidator) Validate(ctx context.Context, value string) (Result, error) {
	return Result{
		Status: StatusUnsupported,
		Reason: "aws.requires_paired_secret",
	}, nil
}

// ----- base URL hooks (overridable in tests) -----------------------

var (
	openaiBaseURLOverride    string
	anthropicBaseURLOverride string
	geminiBaseURLOverride    string
	slackBaseURLOverride     string
	githubBaseURLOverride    string
	stripeBaseURLOverride    string
	sendgridBaseURLOverride  string
)

func openaiBaseURL() string {
	if openaiBaseURLOverride != "" {
		return openaiBaseURLOverride
	}
	return "https://api.openai.com"
}
func anthropicBaseURL() string {
	if anthropicBaseURLOverride != "" {
		return anthropicBaseURLOverride
	}
	return "https://api.anthropic.com"
}
func geminiBaseURL() string {
	if geminiBaseURLOverride != "" {
		return geminiBaseURLOverride
	}
	return "https://generativelanguage.googleapis.com"
}
func slackBaseURL() string {
	if slackBaseURLOverride != "" {
		return slackBaseURLOverride
	}
	return "https://slack.com"
}
func githubBaseURL() string {
	if githubBaseURLOverride != "" {
		return githubBaseURLOverride
	}
	return "https://api.github.com"
}
func stripeBaseURL() string {
	if stripeBaseURLOverride != "" {
		return stripeBaseURLOverride
	}
	return "https://api.stripe.com"
}
func sendgridBaseURL() string {
	if sendgridBaseURLOverride != "" {
		return sendgridBaseURLOverride
	}
	return "https://api.sendgrid.com"
}

// SetProviderBaseURL is the test-only hook for redirecting a provider
// to an httptest server. Empty value resets to default.
func SetProviderBaseURL(id, url string) {
	switch id {
	case "openai":
		openaiBaseURLOverride = url
	case "anthropic":
		anthropicBaseURLOverride = url
	case "gemini":
		geminiBaseURLOverride = url
	case "slack":
		slackBaseURLOverride = url
	case "github":
		githubBaseURLOverride = url
	case "stripe":
		stripeBaseURLOverride = url
	case "sendgrid":
		sendgridBaseURLOverride = url
	}
}
