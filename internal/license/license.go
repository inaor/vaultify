// Package license implements offline JWT verification of Vaultify Pro
// licenses, per the v1 contract in docs/licensing-jwt-v1.md.
//
// Trust model
//
//   - Tokens are signed by a Vaultify-controlled Cloudflare Worker on
//     license.vaultify.live with an Ed25519 private key. The Worker is
//     the sole signer; billing platforms (Base44, LemonSqueezy, Stripe)
//     never hold signing material — they only fire webhooks at the
//     Worker.
//   - The corresponding public key(s) are baked into vaultify.exe via
//     keys_*.go. Multiple keys are supported via the JWT `kid` header so
//     a key rotation does not strand existing tokens.
//   - Verification is fully offline: no network call, no telemetry, no
//     vendor dependency at runtime. This is the property docs/§1
//     ("Offline verification") demands.
//
// Algorithm: Ed25519 (`alg: EdDSA`) only for v1. RS256/HS256 are
// explicitly rejected — symmetric / SaaS-held key models invite the
// failure modes the v1 contract was written to avoid.
package license

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Header is the subset of the JOSE header we look at.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims is the v1 payload contract from docs/licensing-jwt-v1.md §3.
// Only the fields Vaultify uses at runtime; unknown claims are ignored.
type Claims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Tid string `json:"tid"`
	Ver int    `json:"ver"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp,omitempty"`
	Nbf int64  `json:"nbf,omitempty"`
	Jti string `json:"jti,omitempty"`
}

// Typed errors. Callers (HTTP layer, Activate-Pro UI, audit log) switch
// on these so the user sees actionable text instead of "invalid token".
var (
	ErrMalformed      = errors.New("license: malformed JWT")
	ErrUnsupportedAlg = errors.New("license: unsupported alg (only EdDSA accepted)")
	ErrUnsupportedTyp = errors.New("license: unsupported typ (only JWT accepted)")
	ErrUnknownKid     = errors.New("license: unknown kid")
	ErrBadSignature   = errors.New("license: signature did not verify")
	ErrAudience       = errors.New("license: wrong audience (aud)")
	ErrIssuer         = errors.New("license: wrong issuer (iss)")
	ErrVersion        = errors.New("license: unsupported ver")
	ErrTier           = errors.New("license: unrecognised tid")
	ErrExpired        = errors.New("license: expired")
	ErrNotYetValid    = errors.New("license: not yet valid (nbf)")
	ErrMissingClaim   = errors.New("license: required claim missing")
)

// SchemaVersion is the only `ver` value v1 binaries accept. The doc
// requires this to be incremented on any breaking change.
const SchemaVersion = 1

// Tiers Vaultify recognises. Anything else lands ErrTier.
var validTiers = map[string]struct{}{
	"pro":           {},
	"pro-perpetual": {},
}

// Options drives Verify. ExpectedIssuer + ExpectedAudience are required
// (Verify will refuse empty values rather than silently accept any
// token). Now lets tests inject a clock; production should leave it nil.
type Options struct {
	Keys             KeyRegistry
	ExpectedIssuer   string
	ExpectedAudience string
	Now              func() time.Time
	ClockSkew        time.Duration
}

// KeyRegistry maps a JWT `kid` to its Ed25519 public key. The runtime
// registry is built from keys_dev.go + keys_prod.go in init() and made
// available via DefaultKeys.
type KeyRegistry map[string]ed25519.PublicKey

// Verify parses, signature-checks, and claim-checks a JWT. Caller
// receives the parsed Claims on success or a typed error on failure.
// Passes ErrBadSignature, never a base-error from crypto, so the UI
// can show a stable reason without leaking internal details.
//
// Per doc §5 the order matters:
//  1. Parse + header sanity (alg, typ, kid known)
//  2. Verify signature with the resolved public key
//  3. Required-claims presence
//  4. Audience / issuer / version / tier
//  5. Time bounds (exp, nbf) with optional skew
func Verify(token string, opts Options) (Claims, error) {
	if opts.Keys == nil || len(opts.Keys) == 0 {
		return Claims{}, fmt.Errorf("%w: empty key registry", ErrUnknownKid)
	}
	if opts.ExpectedIssuer == "" || opts.ExpectedAudience == "" {
		return Claims{}, fmt.Errorf("%w: ExpectedIssuer/Audience required", ErrMissingClaim)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ClockSkew < 0 {
		opts.ClockSkew = 0
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	headerB, payloadB, sigB := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header b64: %v", ErrMalformed, err)
	}
	var hdr Header
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return Claims{}, fmt.Errorf("%w: header json: %v", ErrMalformed, err)
	}
	if hdr.Alg != "EdDSA" {
		return Claims{}, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlg, hdr.Alg)
	}
	if hdr.Typ != "" && hdr.Typ != "JWT" {
		return Claims{}, fmt.Errorf("%w: typ=%q", ErrUnsupportedTyp, hdr.Typ)
	}
	if hdr.Kid == "" {
		return Claims{}, fmt.Errorf("%w: kid is required", ErrMalformed)
	}
	pub, ok := opts.Keys[hdr.Kid]
	if !ok {
		return Claims{}, fmt.Errorf("%w: kid=%q", ErrUnknownKid, hdr.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: sig b64: %v", ErrMalformed, err)
	}
	signed := []byte(headerB + "." + payloadB)
	if ok := ed25519.Verify(pub, signed, sig); !ok {
		// constant-time false return path — ed25519.Verify is already
		// CT, but we double up for clarity.
		_ = subtle.ConstantTimeCompare([]byte{0}, []byte{1})
		return Claims{}, ErrBadSignature
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload b64: %v", ErrMalformed, err)
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	dec.DisallowUnknownFields() // strict: catches typos / future fields v1 doesn't know
	// DisallowUnknownFields would force every signer to mirror our
	// schema exactly — too strict for forward-compat. Drop the
	// strict mode; we still validate the fields we care about.
	dec = json.NewDecoder(strings.NewReader(string(payloadJSON)))
	if err := dec.Decode(&c); err != nil {
		return Claims{}, fmt.Errorf("%w: payload json: %v", ErrMalformed, err)
	}

	// Required claims (doc §3).
	if c.Iss == "" || c.Aud == "" || c.Sub == "" || c.Tid == "" || c.Ver == 0 || c.Iat == 0 {
		return Claims{}, fmt.Errorf("%w: iss/aud/sub/tid/ver/iat required", ErrMissingClaim)
	}
	if c.Iss != opts.ExpectedIssuer {
		return Claims{}, fmt.Errorf("%w: iss=%q", ErrIssuer, c.Iss)
	}
	if c.Aud != opts.ExpectedAudience {
		return Claims{}, fmt.Errorf("%w: aud=%q", ErrAudience, c.Aud)
	}
	if c.Ver != SchemaVersion {
		return Claims{}, fmt.Errorf("%w: ver=%d", ErrVersion, c.Ver)
	}
	if _, ok := validTiers[c.Tid]; !ok {
		return Claims{}, fmt.Errorf("%w: tid=%q", ErrTier, c.Tid)
	}

	// Time bounds (doc §5.6).
	now := opts.Now().UTC()
	if c.Exp != 0 {
		expT := time.Unix(c.Exp, 0).UTC()
		if !now.Before(expT.Add(opts.ClockSkew)) {
			return Claims{}, fmt.Errorf("%w: exp=%s", ErrExpired, expT.Format(time.RFC3339))
		}
	}
	if c.Nbf != 0 {
		nbfT := time.Unix(c.Nbf, 0).UTC()
		if now.Before(nbfT.Add(-opts.ClockSkew)) {
			return Claims{}, fmt.Errorf("%w: nbf=%s", ErrNotYetValid, nbfT.Format(time.RFC3339))
		}
	}
	return c, nil
}

// IsActive returns true when the claims are non-zero — convenience for
// callers that load a persisted token and want a single-line check.
// "Currently active" is enforced by Verify's exp/nbf logic; once Verify
// returned the claims, they're known good as of that instant.
func (c Claims) IsActive() bool { return c.Sub != "" && c.Tid != "" }

// IsPerpetual reports whether the token is a one-time-purchase license.
// Useful for UI ("Pro \u2014 Lifetime" vs "Pro until ...").
func (c Claims) IsPerpetual() bool { return c.Tid == "pro-perpetual" }

// ExpAt returns the JWT exp time as a time.Time (zero when missing).
func (c Claims) ExpAt() time.Time {
	if c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0).UTC()
}
