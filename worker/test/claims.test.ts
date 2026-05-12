import { describe, expect, it } from 'vitest';
import { buildClaims } from '../src/claims.ts';
import type { Env, IssuanceInput } from '../src/types.ts';

const baseEnv: Env = {
  ISSUER: 'https://vaultify.live',
  AUDIENCE: 'vaultify-pro',
  KID: 'vf-pro-prod-2026-04',
  SCHEMA_VERSION: '1',
  LICENSE_DAYS_DEFAULT: '365',
  SUPPORT_EMAIL: 'support@vaultify.live',
  EMAIL_FROM: 'Vaultify <licenses@vaultify.live>',
  ED25519_PRIVATE_KEY_B64: '',  // unused in this test
  BASE44_WEBHOOK_SECRET: '',
  ADMIN_TOKEN: '',
};

describe('buildClaims', () => {
  it('fills the v1 contract from a base44 issuance', () => {
    const now = new Date('2026-05-01T00:00:00Z');
    const input: IssuanceInput = { sub: 'ord_42', tid: 'pro', source: 'base44' };
    const c = buildClaims(baseEnv, input, now);
    expect(c).toMatchObject({
      iss: 'https://vaultify.live',
      aud: 'vaultify-pro',
      sub: 'ord_42',
      tid: 'pro',
      ver: 1,
    });
    expect(c.iat).toBe(Math.floor(now.getTime() / 1000));
    expect(c.exp).toBe(Math.floor(now.getTime() / 1000) + 365 * 86400);
    expect(c.jti).toContain('lic_base44_ord_42_');
  });

  it('honours an explicit expiresAt', () => {
    const now = new Date('2026-05-01T00:00:00Z');
    const exp = new Date('2027-05-01T00:00:00Z');
    const c = buildClaims(baseEnv, { sub: 'x', tid: 'pro', expiresAt: exp, source: 'admin' }, now);
    expect(c.exp).toBe(Math.floor(exp.getTime() / 1000));
  });

  it('rejects empty sub', () => {
    expect(() =>
      buildClaims(baseEnv, { sub: '', tid: 'pro', source: 'admin' })
    ).toThrow(/sub required/);
  });

  it('jti is identical for two issuances inside the same minute (idempotency on Base44 retry)', () => {
    const now = new Date('2026-05-01T00:00:30Z');
    const a = buildClaims(baseEnv, { sub: 'x', tid: 'pro', source: 'base44' }, now);
    const b = buildClaims(baseEnv, { sub: 'x', tid: 'pro', source: 'base44' }, new Date(now.getTime() + 5_000));
    expect(a.jti).toBe(b.jti);
  });
});
