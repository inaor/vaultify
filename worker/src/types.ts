/**
 * Env binds the Worker runtime configuration. Public values come from
 * wrangler.toml [vars]; secrets are set with `wrangler secret put`.
 */
export interface Env {
  // Public (wrangler.toml [vars])
  ISSUER: string;
  AUDIENCE: string;
  KID: string;
  SCHEMA_VERSION: string;
  LICENSE_DAYS_DEFAULT: string;
  SUPPORT_EMAIL: string;
  EMAIL_FROM: string;

  // Required secrets
  ED25519_PRIVATE_KEY_B64: string;   // 64-byte Go ed25519 private, base64-no-padding
  BASE44_WEBHOOK_SECRET: string;     // HMAC-SHA256 secret
  ADMIN_TOKEN: string;               // bearer token for /admin/issue

  // Optional secrets
  RESEND_API_KEY?: string;
}

/**
 * Claims is the v1 contract from docs/licensing-jwt-v1.md §3.
 * Mirrored exactly by internal/license.Claims on the Go verifier side.
 */
export interface Claims {
  iss: string;
  aud: string;
  sub: string;
  tid: 'pro' | 'pro-perpetual';
  ver: 1;
  iat: number;
  exp: number;
  jti?: string;
  nbf?: number;
}

/**
 * IssuanceInput captures everything the Worker needs to mint one
 * license, regardless of source (Base44 webhook, admin endpoint, etc.).
 * Source-specific code (webhook.ts) reduces its own payload to this.
 */
export interface IssuanceInput {
  sub: string;             // stable id from billing system (order id, sub id)
  email?: string;          // delivery target; optional
  tid: 'pro' | 'pro-perpetual';
  expiresAt?: Date;        // explicit billed-through; absent = use default
  source: 'base44' | 'admin';
}
