package validation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// runProviderTest spins up an httptest server with the supplied
// handler, points the provider at it, validates a token, and runs the
// supplied assertions on the result. The Authorization (or x-api-key)
// header on the request is forwarded back via headerMatch so the test
// can confirm the validator built the request correctly.
func runProviderTest(t *testing.T, id string, handler http.HandlerFunc, value string) Result {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	SetProviderBaseURL(id, srv.URL)
	t.Cleanup(func() { SetProviderBaseURL(id, "") })

	v, ok := ValidatorByID(id)
	if !ok {
		t.Fatalf("validator %s not registered", id)
	}
	res, err := v.Validate(context.Background(), value)
	if err != nil {
		t.Fatalf("validator returned err: %v", err)
	}
	return res
}

func TestOpenAIValidator(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantStatus Status
	}{
		{"active 200", 200, StatusActive},
		{"invalid 401", 401, StatusInvalid},
		{"forbidden 403", 403, StatusInvalid},
		{"rate limited 429", 429, StatusRateLimited},
		{"server error 500", 500, StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runProviderTest(t, "openai", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/models" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
					t.Errorf("missing Bearer auth, got %q", got)
				}
				w.WriteHeader(tc.status)
			}, "sk-test-1234")
			if res.Status != tc.wantStatus {
				t.Fatalf("status=%q want %q (reason=%s)", res.Status, tc.wantStatus, res.Reason)
			}
		})
	}
}

func TestAnthropicValidatorHeaders(t *testing.T) {
	res := runProviderTest(t, "anthropic", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			t.Errorf("missing x-api-key header")
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing anthropic-version header")
		}
		w.WriteHeader(200)
	}, "sk-ant-test")
	if res.Status != StatusActive {
		t.Fatalf("status=%q want active", res.Status)
	}
}

func TestGeminiInvalidAs400(t *testing.T) {
	res := runProviderTest(t, "gemini", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			t.Errorf("missing ?key= query")
		}
		w.WriteHeader(http.StatusBadRequest)
	}, "AIza-fake")
	if res.Status != StatusInvalid {
		t.Fatalf("gemini 400 should map to invalid, got %q", res.Status)
	}
	if res.Reason != "gemini.400_invalid_api_key" {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestSlackOKBodyVariants(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus Status
		wantReason string
	}{
		{"active", `{"ok":true,"user":"u"}`, StatusActive, "slack.auth_test_ok"},
		{"invalid auth", `{"ok":false,"error":"invalid_auth"}`, StatusInvalid, "slack.invalid_auth"},
		{"token revoked", `{"ok":false,"error":"token_revoked"}`, StatusInvalid, "slack.token_revoked"},
		{"unknown error", `{"ok":false,"error":"missing_scope"}`, StatusError, "slack.missing_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runProviderTest(t, "slack", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/auth.test" {
					t.Errorf("path=%s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("method=%s want POST", r.Method)
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(tc.body))
			}, "xoxb-test")
			if res.Status != tc.wantStatus {
				t.Fatalf("status=%q want %q", res.Status, tc.wantStatus)
			}
			if res.Reason != tc.wantReason {
				t.Fatalf("reason=%q want %q", res.Reason, tc.wantReason)
			}
		})
	}
}

func TestGitHubFineGrainedFallback(t *testing.T) {
	calls := 0
	res := runProviderTest(t, "github", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/user" {
			t.Errorf("path=%s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		// First call uses `token <v>`, second uses `Bearer <v>`.
		if calls == 1 && !strings.HasPrefix(auth, "token ") {
			t.Errorf("first call should use 'token ' auth, got %q", auth)
		}
		if calls == 1 {
			w.WriteHeader(401) // trigger the fine-grained fallback
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("second call should use Bearer, got %q", auth)
		}
		w.WriteHeader(200)
	}, "github_pat_11AAAA_xyz")
	if calls != 2 {
		t.Fatalf("expected 2 attempts (classic then bearer fallback), got %d", calls)
	}
	if res.Status != StatusActive {
		t.Fatalf("status=%q want active", res.Status)
	}
}

func TestStripeAndSendGrid(t *testing.T) {
	for _, p := range []string{"stripe", "sendgrid"} {
		t.Run(p, func(t *testing.T) {
			res := runProviderTest(t, p, func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
					t.Errorf("[%s] missing Bearer, got %q", p, got)
				}
				w.WriteHeader(401)
			}, "sk_test_zzz")
			if res.Status != StatusInvalid {
				t.Fatalf("[%s] expected invalid on 401, got %q", p, res.Status)
			}
		})
	}
}

func TestAWSAlwaysUnsupported(t *testing.T) {
	v, _ := ValidatorByID("aws")
	res, _ := v.Validate(context.Background(), "AKIAIOSFODNN7EXAMPLE")
	if res.Status != StatusUnsupported {
		t.Fatalf("AWS should be unsupported until we pair the secret, got %q", res.Status)
	}
}

func TestRegistryHasAllProviders(t *testing.T) {
	want := []string{"anthropic", "aws", "gemini", "github", "openai", "sendgrid", "slack", "stripe"}
	got := RegisteredIDs()
	if len(got) != len(want) {
		t.Fatalf("got %d validators, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("registered[%d]=%s, want %s", i, got[i], w)
		}
	}
}

// TestNetworkErrorClassified covers the path where the provider URL
// is unreachable: the validator must return Error rather than panic.
func TestNetworkErrorClassified(t *testing.T) {
	SetProviderBaseURL("openai", "http://127.0.0.1:1") // refused
	t.Cleanup(func() { SetProviderBaseURL("openai", "") })
	v, _ := ValidatorByID("openai")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	res, _ := v.Validate(ctx, "sk-x")
	if res.Status != StatusError {
		t.Fatalf("status=%q want error", res.Status)
	}
}
