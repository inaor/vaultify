# Vaultify Pro — License JWT contract (v1)

This document is the **single source of truth** for Pro activation tokens.  
Payment providers (Wix, Base44, etc.), signing services, and the Vaultify Pro binary must implement **only** what is specified here. Breaking changes require a new **`ver`** (and usually a new **`kid`**).

---

## 1. Goals

- **Offline verification:** The Vaultify Pro app must validate a licence **without** sending scan paths, findings, or file contents to any server.
- **Minimal PII:** The JWT must not contain passwords, card data, third-party API keys, or filesystem paths.
- **Rotation:** Signing keys can be rotated using **`kid`** without breaking older Pro builds until you sunset old keys.

---

## 2. Token format

- **Type:** JSON Web Token (JWT), compact serialization: `header.payload.signature` (Base64URL segments).
- **Recommended algorithm:** **`EdDSA`** with **Ed25519** (`alg: EdDSA` in JOSE).  
  - **Rationale:** Short public keys, fast verification, no RSA padding foot-guns.  
  - **Allowed alternative:** **`RS256`** if your stack only supports RSA—document the `kid` and public key PEM explicitly in the release notes for that build.
- **Header (required keys):**

| Key | Value |
|-----|--------|
| `alg` | `EdDSA` (preferred) or `RS256` (alternative) |
| `typ` | `JWT` |
| `kid` | Opaque key id, e.g. `vf-pro-2026-04` — maps to **one** embedded public key in the app |

---

## 3. Payload claims (v1)

All times are **Unix seconds** (numeric).

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | Issuer URI, e.g. `https://vaultify.live` |
| `aud` | Yes | Audience; must be exactly `vaultify-pro` |
| `sub` | Yes | Opaque subject id: **customer id**, **order id**, or stable id from your billing system (no email unless you accept GDPR/support trade-offs) |
| `tid` | Yes | **Tier / SKU**, e.g. `pro` — used for feature gating |
| `ver` | Yes | **Schema version**; must be integer **1** for this document |
| `iat` | Yes | Issued-at |
| `exp` | **Conditional** | See §4 (subscription vs perpetual) |

**Optional (reserved for v1, may be ignored by app until used):**

| Claim | Description |
|-------|-------------|
| `jti` | Unique token id — enables one-time activation or revocation lists later |
| `nbf` | Not-before (Unix); if present, app must reject verification before `nbf` |

**Forbidden in payload:** free-text addresses of scanned repos, workspace roots, secret values, payment instrument identifiers beyond opaque `sub`.

---

## 4. Pro SKU semantics (A3) — subscription vs perpetual

Choose **one** model per issued token; the app uses **`exp`** as follows.

### 4.1 Subscription (recurring billing)

- **`tid`:** `pro` (or `pro-annual` if you split SKUs later—document each `tid` in release notes).
- **`exp`:** **Required.** Instant when access ends if not renewed (build in a small grace window in the **signer**, e.g. `exp = paid_through + 48h`, if you want to avoid clock-skew support pain).
- **Renewal:** New JWT issued on each successful renewal (same `sub`, new `iat`/`exp`, new `jti` if used).

### 4.2 Perpetual (one-time purchase)

- **`tid`:** `pro-perpetual` (recommended distinct value so analytics and support stay clear).
- **`exp`:** **Far-future** (e.g. 100 years) **or** omit `exp` only if the **app explicitly treats missing `exp` as perpetual** for `tid === pro-perpetual`**—pick one rule globally and test it.**

**Recommendation:** Always include **`exp`** even for perpetual (far-future) so all code paths stay uniform.

---

## 5. Verification rules (Vaultify Pro app)

1. Parse JWT; require header `kid` present and known (embedded allow-list).
2. Verify signature with the public key for that `kid`.
3. Require `iss`, `aud`, `sub`, `tid`, `ver`, `iat` present and types correct.
4. Require `aud === "vaultify-pro"` and `ver === 1` (integer or JSON number that equals 1).
5. Require `iss` to match configured allow-list (e.g. exactly `https://vaultify.live` for production builds).
6. Time checks:
   - Reject if `exp` present and `now >= exp` (use small clock skew tolerance, e.g. ±120s, if implemented).
   - If `nbf` present, reject if `now < nbf`.
7. Map **`tid`** to entitlements (e.g. `pro` / `pro-perpetual` → unlimited scan cap when Phase B/C is implemented).

---

## 6. Key rotation (A2)

1. Generate a new Ed25519 keypair in your secure environment (HSM or locked CI).
2. Assign a new **`kid`** (never reuse).
3. Ship a new Pro binary that embeds **both** old and new public keys until you announce sunset for the old `kid`.
4. New licences use the new `kid`; old licences keep working until old key is removed from the binary.

**Do not** reuse `kid` for a different key material.

---

## 7. Signing responsibility

- **Preferred:** A Vaultify-controlled **signer** (HTTPS) invoked only from your billing webhooks (Wix, etc.). The **private** key never lives in payment SaaS dashboards.
- **Development:** Use a separate **`kid`** (e.g. `vf-pro-dev`) and a dev keypair; **never** ship dev private keys in production binaries.

---

## 8. Example (illustrative only — do not use in production)

**Header (decoded JSON):**

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "vf-pro-dev"
}
```

**Payload (decoded JSON):**

```json
{
  "iss": "https://vaultify.live",
  "aud": "vaultify-pro",
  "sub": "ord_01HZEXAMPLE",
  "tid": "pro",
  "ver": 1,
  "iat": 1710000000,
  "exp": 1712592000,
  "jti": "lic_01HZEXAMPLE"
}
```

**Compact JWT:** `[header].[payload].[signature]` — generate with your signer or test tooling; commit **only** invalid/signature-wrong examples to the repo if needed for unit tests, not valid production secrets.

---

## 9. Test vectors (for CI — future)

When `internal/license` (or similar) exists:

- Add **golden tests**: wrong signature, wrong `aud`, expired `exp`, wrong `ver`, unknown `kid`, valid dev token.
- Store **public** dev key in repo; keep **private** dev key in CI secrets or local `.env` excluded from git.

---

## 10. Changelog

| Date | Change |
|------|--------|
| 2026-04-23 | Initial v1 contract (Phases A1–A3) |

---

## 11. Related work (not in this doc)

- **Phase B:** Free scan file cap enforced in Go (`internal/scanner`, default **10,000** eligible files), `/api/version` exposes `edition` + `file_cap` (0 = unlimited for Pro builds), WebSocket `scan_complete` includes `scan_capped`.
- **Phase C:** Settings UI “Activate Pro” + persistence.
- **Phase E:** Wix / Base44 webhooks → signer → customer receives JWT.

When any of the above changes validation or claims, update **`ver`**, this document, and the changelog table.
