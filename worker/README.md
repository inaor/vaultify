# Vaultify License Signer (Cloudflare Worker)

Signs Vaultify Pro license JWTs (Ed25519, `licensing-jwt-v1.md`) on billing webhooks. The Worker is the licensing trust root: every customer's `vaultify.exe` verifies offline against the Ed25519 public key embedded at build time, so this Worker never sees a customer's scan data and the customer's machine never phones home for verification.

```
                    Base44 / Stripe / LemonSqueezy
                              │ POST webhook (HMAC-signed)
                              ▼
                    license.vaultify.live  (this Worker)
                              │ Ed25519 signs JWT (private key in CF Workers Secret Store)
                              ▼
                    customer email (Resend)  ──▶  pasted into Vaultify
                                                      │
                                                      ▼
                                              vaultify.exe verifies offline
                                              with embedded public key
```

---

## What the Worker does

| Route | Method | Purpose |
|---|---|---|
| `/healthz` | `GET` | uptime probe; returns the active `kid` + `audience` |
| `/webhook/base44` | `POST` | called by Base44 on subscription events; HMAC-verified, mints + emails a JWT |
| `/admin/issue` | `POST` | bearer-token-gated manual issuance for support / refunds / re-sends |

What it explicitly **doesn't** do:

- No customer DB / KV writes — fully stateless in v1.
- No verification proxying — the Worker only **issues** tokens; verification happens entirely in `vaultify.exe`.
- No ingress from anything other than Cloudflare (the route is owned by your CF zone).

---

## Deploy in 5 minutes

Prerequisites you do **once**:

1. `vaultify.live` zone in your Cloudflare account (free plan is fine).
2. Workers enabled (free tier covers ~100K requests/day).
3. `npm i -g wrangler` then `wrangler login` (opens browser, click Allow).

```sh
cd worker
npm install                       # pulls @noble/ed25519 + dev deps
npm run typecheck                 # confirms TS compiles
npm test                          # runs vitest (jwt, webhook, claims, cross-stack)
```

### Generate the production keypair (once, on a clean machine)

```sh
# From the repo root, NOT inside worker/:
go run ./tools/keygen -kid vf-pro-prod-2026-04
```

Output looks like:

```
kid:        vf-pro-prod-2026-04
public:     UnEYrR…                   <-- commit to internal/license/keys_prod.go
private:    sPFhk…                    <-- WARNING: never commit this
```

What to do with each half:

| Half | Where it goes |
|---|---|
| **Public**  | Add to `internal/license/keys_prod.go` (a new file alongside `keys_dev.go`); ship in the next Vaultify release |
| **Private** | Stays only on the machine that generated it + Cloudflare Workers Secret Store. Back it up to your 1Password / hardware key. |

### Set the Worker secrets

Three required secrets, one optional:

```sh
wrangler secret put ED25519_PRIVATE_KEY_B64
# Paste the `private:` value from keygen. CF stores it encrypted at
# rest; you cannot read it back from the dashboard.

wrangler secret put BASE44_WEBHOOK_SECRET
# The HMAC secret Base44 will sign webhook bodies with. Generate with
# any password manager (32+ random bytes) and paste the same value
# into Base44's webhook configuration.

wrangler secret put ADMIN_TOKEN
# Bearer token for /admin/issue. Treat as an emergency support knob.

# Optional - omit to skip email; the Worker returns the token in the
# response body instead and Base44 (or you) deliver it.
wrangler secret put RESEND_API_KEY
```

### Deploy

```sh
wrangler deploy
# wrangler prints something like:
# https://vaultify-license.<account>.workers.dev
# Add the route mapping in wrangler.toml [[routes]] (already pinned
# to license.vaultify.live) so customers hit the friendly hostname.
```

Verify:

```sh
curl https://license.vaultify.live/healthz
# {"ok":true,"kid":"vf-pro-prod-2026-04","audience":"vaultify-pro"}
```

### Configure the Base44 webhook

In Base44's webhook settings, point subscription events at:

```
URL:     https://license.vaultify.live/webhook/base44
Method:  POST
Header:  X-Base44-Signature: hex(HMAC-SHA256(body, BASE44_WEBHOOK_SECRET))
Events:  subscription.created, subscription.renewed, order.paid, order.completed
```

Base44 sends JSON; the Worker reads the following fields defensively:

| JSON field | Used as | Notes |
|---|---|---|
| `event_type` (or `type`) | route gate | only the four listed events mint tokens |
| `data.subscription_id` (or `data.order_id`, `data.id`) | `sub` claim | required |
| `data.customer_email` (or `data.email`) | email recipient | optional |
| `data.tier` (or `data.tid`) | tier | defaults to `pro`; `pro-perpetual` honoured |
| `data.expires_at` (or `data.current_period_end`) | `exp` claim | defaults to `now + LICENSE_DAYS_DEFAULT` (365 d) |

If Base44's actual payload differs, edit `readIssuanceFromBase44` in `src/index.ts` — that's the only place the Worker touches their schema.

### Test it end-to-end

Sign a token via the admin endpoint (no Base44 involvement):

```sh
curl -X POST https://license.vaultify.live/admin/issue \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"sub":"ord_TEST_001","tid":"pro","email":"you@example.com"}'
```

Paste the `token` from the response into Vaultify (Settings → License → Activate Pro). The dashboard's brand pill should flip to `Pro`.

---

## Local development (no Cloudflare account required)

```sh
cd worker
npm install
npm run dev          # wrangler dev --local; serves on http://localhost:8787

# In another shell, simulate a webhook against your local Worker:
SECRET="dev-only-secret"
BODY='{"event_type":"subscription.created","data":{"id":"ord_LOCAL","customer_email":"a@b.c","tier":"pro"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
curl -X POST http://localhost:8787/webhook/base44 \
     -H "X-Base44-Signature: $SIG" \
     -d "$BODY"
```

Local `wrangler dev` reads secrets from `.dev.vars` (gitignored). Sample:

```ini
ED25519_PRIVATE_KEY_B64=sPFhkJglo4aL50qfQowyo/8a9I9uIIslvqsnXxOVpSjnbX9D33uP5Bg0ug/XgPy0OPNava6Vd+wdY4zg4tdQwQ
BASE44_WEBHOOK_SECRET=dev-only-secret
ADMIN_TOKEN=dev-admin-token
# RESEND_API_KEY left blank in dev; the Worker will return the token in the response.
```

The dev keypair above matches the one shipped in `internal/license/keys_dev.go`, so a token signed by `wrangler dev` is accepted by a stock `vaultify.exe` running on the same machine.

---

## Key rotation

Append-only `kid` model. When you want to retire `vf-pro-prod-2026-04`:

1. Generate a new keypair: `go run ./tools/keygen -kid vf-pro-prod-2027-04`.
2. Add the new public key to `internal/license/keys_prod.go` **alongside** the old one. Ship a Vaultify release that knows both.
3. Once enough customers have updated, change `KID` in `wrangler.toml` and `wrangler secret put ED25519_PRIVATE_KEY_B64` with the new private key. Deploy.
4. New tokens are signed with the new key and accepted by every Vaultify version that ever shipped knowing it. Old tokens keep working until their `exp` because the old public key is still in the binary.
5. After the grace window, drop the old public key from `keys_prod.go` and ship.

This is the rotation flow `licensing-jwt-v1.md` §6 prescribes.

---

## Files

| File | Purpose |
|---|---|
| `wrangler.toml` | Worker config + route mapping |
| `package.json` | TS deps (`@noble/ed25519`, vitest, wrangler) |
| `tsconfig.json` | strict TS, ES2022 target |
| `src/index.ts` | Router + Base44 / admin handlers |
| `src/jwt.ts` | Ed25519 JWT signing |
| `src/webhook.ts` | HMAC-SHA256 webhook verification |
| `src/claims.ts` | Maps issuance input → JWT Claims (v1 contract) |
| `src/email.ts` | Resend transactional email (optional) |
| `src/types.ts` | `Env` + `Claims` + `IssuanceInput` |
| `test/jwt.test.ts` | round-trip + key format + b64url |
| `test/webhook.test.ts` | valid / tampered / wrong-length / non-hex |
| `test/claims.test.ts` | shape + idempotent jti |
| `test/cross-stack.test.ts` | Worker-signed JWT verifies against committed dev public key (same one Go's verifier uses) |
