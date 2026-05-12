package validation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Status enumerates the wire/cache states an active validation can
// land in. Mirrored to JSON unchanged.
type Status string

const (
	StatusUnknown      Status = ""              // never checked
	StatusActive       Status = "active"        // provider authenticated successfully
	StatusInvalid      Status = "invalid"       // provider rejected (401/403/404)
	StatusRateLimited  Status = "rate_limited"  // 429
	StatusError        Status = "error"         // network / unknown / timeout
	StatusUnsupported  Status = "unsupported"   // no validator covers this pattern
)

// Result is what every Validator returns. Reason is a stable token
// like "openai.401_invalid_api_key" so the UI / Vee rules can switch
// on it without parsing free-form text.
type Result struct {
	Status     Status
	Reason     string
	HTTPStatus int
}

// Validator is the contract every per-provider live checker
// implements. Validate must NEVER persist or log the value parameter
// and MUST return within its own internal timeout (do not rely on the
// caller's context for safety).
type Validator interface {
	ID() string                                                       // "openai"
	Patterns() []string                                               // pattern_ids it covers
	Validate(ctx context.Context, value string) (Result, error)
	TTL() time.Duration                                               // freshness window for caching
}

// ----- registry -----------------------------------------------------

var (
	regMu       sync.RWMutex
	regByID     = map[string]Validator{}
	regByPat    = map[string][]Validator{}
)

// Register adds a validator to the global registry. Designed to be
// called from per-validator init() functions; safe but expected to
// run during package initialisation only.
func Register(v Validator) {
	if v == nil || v.ID() == "" {
		panic("validation.Register: nil or unnamed validator")
	}
	regMu.Lock()
	defer regMu.Unlock()
	regByID[v.ID()] = v
	for _, p := range v.Patterns() {
		regByPat[p] = append(regByPat[p], v)
	}
}

// ValidatorByID looks up a validator by its registry id.
func ValidatorByID(id string) (Validator, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	v, ok := regByID[id]
	return v, ok
}

// ValidatorForPattern returns the first validator that covers
// pattern_id. Multiple validators per pattern is uncommon but allowed
// (deterministic order: insertion order).
func ValidatorForPattern(patternID string) (Validator, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	vs := regByPat[patternID]
	if len(vs) == 0 {
		return nil, false
	}
	return vs[0], true
}

// RegisteredIDs returns all known validator ids, sorted. Useful for
// /api/version diagnostics and tests.
func RegisteredIDs() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(regByID))
	for id := range regByID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ----- shared HTTP client ------------------------------------------

// httpClient is the single net/http.Client every provider validator
// uses. Strict timeouts and explicit redirect policy keep providers
// from getting clever with our connections.
//
// httpClientOverride lets tests substitute httptest servers via the
// transport layer without each validator having to thread a client
// through.
var (
	httpClient         = newDefaultHTTPClient()
	httpClientOverride *http.Client
	httpMu             sync.RWMutex
)

func newDefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// SetHTTPClient overrides the shared client used by every validator.
// Tests call this with an httptest.Server-backed client; production
// never calls it.
func SetHTTPClient(c *http.Client) {
	httpMu.Lock()
	httpClientOverride = c
	httpMu.Unlock()
}

// HTTPClient returns the active client (override if set, default otherwise).
func HTTPClient() *http.Client {
	httpMu.RLock()
	defer httpMu.RUnlock()
	if httpClientOverride != nil {
		return httpClientOverride
	}
	return httpClient
}

// ----- request helpers ---------------------------------------------

// classifyHTTP turns a vendor HTTP status into a generic Result. Each
// validator wraps this for provider-specific niceties (e.g. parsing a
// JSON `error` field). Reason is `<id>.<status>` for default classes.
func classifyHTTP(id string, status int) Result {
	switch {
	case status >= 200 && status < 300:
		return Result{Status: StatusActive, Reason: fmt.Sprintf("%s.%d_ok", id, status), HTTPStatus: status}
	case status == 401 || status == 403:
		return Result{Status: StatusInvalid, Reason: fmt.Sprintf("%s.%d_unauthorized", id, status), HTTPStatus: status}
	case status == 404:
		return Result{Status: StatusInvalid, Reason: fmt.Sprintf("%s.%d_not_found", id, status), HTTPStatus: status}
	case status == 429:
		return Result{Status: StatusRateLimited, Reason: fmt.Sprintf("%s.429_rate_limited", id), HTTPStatus: status}
	case status >= 500:
		return Result{Status: StatusError, Reason: fmt.Sprintf("%s.%d_server_error", id, status), HTTPStatus: status}
	default:
		return Result{Status: StatusError, Reason: fmt.Sprintf("%s.%d_unexpected", id, status), HTTPStatus: status}
	}
}

// classifyNetworkErr converts low-level net errors into a generic
// "error" outcome so the UI can surface a graceful "could not reach
// provider" rather than 500-ing.
func classifyNetworkErr(id string, err error) Result {
	if errors.Is(err, context.DeadlineExceeded) {
		return Result{Status: StatusError, Reason: id + ".timeout"}
	}
	return Result{Status: StatusError, Reason: id + ".network"}
}
