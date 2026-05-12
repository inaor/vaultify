package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// freshKeypair generates a per-test Ed25519 keypair so tests never
// depend on the committed dev keypair (and so a prod-only build of
// the package keeps these tests passing).
func freshKeypair(t *testing.T, kid string) (KeyRegistry, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return KeyRegistry{kid: pub}, priv
}

// baseClaims returns a claim set valid against the matching opts.
func baseClaims(now time.Time) Claims {
	return Claims{
		Iss: "https://vaultify.live",
		Aud: "vaultify-pro",
		Sub: "ord_TEST_001",
		Tid: "pro",
		Ver: 1,
		Iat: now.Unix(),
		Exp: now.Add(30 * 24 * time.Hour).Unix(),
		Jti: "lic_TEST_001",
	}
}

func baseOpts(keys KeyRegistry, now time.Time) Options {
	return Options{
		Keys:             keys,
		ExpectedIssuer:   "https://vaultify.live",
		ExpectedAudience: "vaultify-pro",
		Now:              func() time.Time { return now },
		ClockSkew:        2 * time.Minute,
	}
}

func TestVerifyHappyPath(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	tok, err := Sign(c, "kid-1", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(tok, baseOpts(keys, now))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Sub != c.Sub || got.Tid != c.Tid || got.Ver != c.Ver {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if !got.IsActive() {
		t.Fatalf("expected IsActive true")
	}
	if got.IsPerpetual() {
		t.Fatalf("pro should not be perpetual")
	}
}

func TestVerifyExpired(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Exp = now.Add(-time.Hour).Unix() // expired an hour ago
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Nbf = now.Add(time.Hour).Unix() // valid in an hour
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("got %v, want ErrNotYetValid", err)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Aud = "vaultify-enterprise" // wrong audience
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrAudience) {
		t.Fatalf("got %v, want ErrAudience", err)
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Iss = "https://impostor.example"
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrIssuer) {
		t.Fatalf("got %v, want ErrIssuer", err)
	}
}

func TestVerifyWrongVersion(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Ver = 2 // future schema not understood by this binary
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v, want ErrVersion", err)
	}
}

func TestVerifyUnknownKid(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	tok, _ := Sign(c, "different-kid", priv) // signed with priv but header advertises a kid the registry doesn't know
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("got %v, want ErrUnknownKid", err)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	now := time.Now()
	keys, _ := freshKeypair(t, "kid-1")          // registry trusts kid-1
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader) // sign with a DIFFERENT key
	c := baseClaims(now)
	tok, _ := Sign(c, "kid-1", otherPriv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerifyMissingClaim(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Sub = "" // required by doc §3
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("got %v, want ErrMissingClaim", err)
	}
}

func TestVerifyUnsupportedAlg(t *testing.T) {
	// Hand-craft a header advertising HS256 (the v1 contract refuses
	// symmetric algs outright, even before the signature is checked).
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	tok, _ := Sign(c, "kid-1", priv)
	// Replace the EdDSA header with HS256 by hand.
	parts := splitJWT(tok)
	parts[0] = base64URLEncodeJSON(t, map[string]string{"alg": "HS256", "typ": "JWT", "kid": "kid-1"})
	bad := parts[0] + "." + parts[1] + "." + parts[2]
	_, err := Verify(bad, baseOpts(keys, now))
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("got %v, want ErrUnsupportedAlg", err)
	}
}

func TestVerifyClockSkewGrace(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Exp = now.Add(-30 * time.Second).Unix() // 30s past, but inside 2m skew
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if err != nil {
		t.Fatalf("expired-but-inside-skew should pass, got %v", err)
	}
}

// PerpetualLicense uses tid=pro-perpetual + a far-future exp per doc §4.2.
func TestVerifyPerpetualTier(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Tid = "pro-perpetual"
	c.Exp = now.Add(100 * 365 * 24 * time.Hour).Unix()
	tok, _ := Sign(c, "kid-1", priv)
	got, err := Verify(tok, baseOpts(keys, now))
	if err != nil {
		t.Fatalf("Verify perpetual: %v", err)
	}
	if !got.IsPerpetual() {
		t.Fatalf("expected IsPerpetual true")
	}
}

func TestVerifyUnknownTier(t *testing.T) {
	now := time.Now()
	keys, priv := freshKeypair(t, "kid-1")
	c := baseClaims(now)
	c.Tid = "enterprise" // not a Pro tid
	tok, _ := Sign(c, "kid-1", priv)
	_, err := Verify(tok, baseOpts(keys, now))
	if !errors.Is(err, ErrTier) {
		t.Fatalf("got %v, want ErrTier", err)
	}
}

// ----- helpers -----

func splitJWT(tok string) [3]string {
	var parts [3]string
	i := 0
	cur := 0
	for j := 0; j < len(tok) && i < 3; j++ {
		if tok[j] == '.' {
			parts[i] = tok[cur:j]
			i++
			cur = j + 1
		}
	}
	parts[i] = tok[cur:]
	return parts
}

func base64URLEncodeJSON(t *testing.T, v any) string {
	t.Helper()
	tok, err := jsonEncodeRawURL(v)
	if err != nil {
		t.Fatalf("encodeJSON: %v", err)
	}
	return tok
}
