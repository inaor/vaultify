/**
 * Build a v1 license JWT Claims object from a normalised IssuanceInput.
 * This is the only place that knows the v1 contract details — webhook
 * handlers and the admin endpoint both flow through here so the
 * issuance shape is identical regardless of source.
 */
import type { Claims, Env, IssuanceInput } from './types.ts';

export function buildClaims(env: Env, input: IssuanceInput, now: Date = new Date()): Claims {
  if (!input.sub) throw new Error('claims: sub required');
  const days = Number(env.LICENSE_DAYS_DEFAULT) || 365;
  const exp = input.expiresAt ?? new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
  return {
    iss: env.ISSUER,
    aud: env.AUDIENCE,
    sub: input.sub,
    tid: input.tid,
    ver: 1,
    iat: Math.floor(now.getTime() / 1000),
    exp: Math.floor(exp.getTime() / 1000),
    jti: makeJti(input.sub, input.source, now),
  };
}

/**
 * makeJti is deterministic for the same (sub, source, second-bucket).
 * That gives us natural idempotency: if Base44 retries the webhook
 * within the same second, the resulting JWT is byte-identical, so
 * customers don't see a "your license changed" surprise on retries.
 */
function makeJti(sub: string, source: string, now: Date): string {
  const minute = Math.floor(now.getTime() / 60000); // 1-minute bucket
  return `lic_${source}_${sub}_${minute}`;
}
