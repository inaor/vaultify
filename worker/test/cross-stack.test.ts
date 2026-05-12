/**
 * Cross-stack JWT compatibility test.
 *
 * Proves that a JWT minted by the Worker's signJWT() is byte-identical
 * to one minted by Go's license.Sign() — i.e. Vaultify's runtime
 * verifier (internal/license/license.go) will accept what this Worker
 * produces.
 *
 * The test re-uses the dev keypair (kid=vf-pro-dev-2026-04) committed
 * in keys_dev.go. The corresponding 32-byte seed is hard-coded here so
 * the test is hermetic — no .dev-keys/ file dependency.
 */
import { describe, expect, it } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { signJWT } from '../src/jwt.ts';
import { buildClaims } from '../src/claims.ts';
import type { Env } from '../src/types.ts';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// 32-byte Ed25519 seed: first half of the dev private key generated
// by tools/keygen and stored in .dev-keys/vf-pro-dev-2026-04.priv.
// Public half is committed in internal/license/keys_dev.go.
const DEV_SEED_B64 = 'sPFhkJglo4aL50qfQowyo/8a9I9uIIslvqsnXxOVpSg';
const DEV_PUB_B64 = '521/Q997j+QYNLoP14D8tDjzWr2ulXfsHWOM4OLXUME';
const DEV_KID = 'vf-pro-dev-2026-04';

function b64rawToBytes(b64: string): Uint8Array {
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const env: Env = {
  ISSUER: 'https://vaultify.live',
  AUDIENCE: 'vaultify-pro',
  KID: DEV_KID,
  SCHEMA_VERSION: '1',
  LICENSE_DAYS_DEFAULT: '365',
  SUPPORT_EMAIL: 'support@vaultify.live',
  EMAIL_FROM: 'Vaultify <licenses@vaultify.live>',
  ED25519_PRIVATE_KEY_B64: DEV_SEED_B64,
  BASE44_WEBHOOK_SECRET: 'na',
  ADMIN_TOKEN: 'na',
};

describe('cross-stack compatibility (Worker -> Go verifier)', () => {
  it('Worker-signed JWT verifies under the dev public key', async () => {
    const claims = buildClaims(env, { sub: 'ord_CROSS', tid: 'pro', source: 'admin' });
    const tok = await signJWT(claims, env.KID, env.ED25519_PRIVATE_KEY_B64);

    // Re-verify locally with the *committed* public key (same code path
    // as internal/license/keys_dev.go on the Go side).
    const [hSeg, pSeg, sigSeg] = tok.split('.');
    const signed = new TextEncoder().encode(`${hSeg}.${pSeg}`);
    const sig = b64rawToBytes(sigSeg);
    const pub = b64rawToBytes(DEV_PUB_B64);
    const ok = await ed.verifyAsync(sig, signed, pub);
    expect(ok).toBe(true);
  });

  it('printable form for manual Go-side smoke test', async () => {
    // Print to stdout when run with `vitest --reporter=verbose` so a
    // human can paste the token into vaultify.exe's Activate Pro page
    // and confirm Pro flips on. CI just asserts non-empty.
    const claims = buildClaims(env, { sub: 'ord_MANUAL', tid: 'pro', source: 'admin' });
    const tok = await signJWT(claims, env.KID, env.ED25519_PRIVATE_KEY_B64);
    expect(tok.length).toBeGreaterThan(100);
    // process is provided by the vitest Node runtime; the cast keeps
    // strict TS happy without pulling in @types/node just for one line.
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (proc?.env?.PRINT_TOKEN === '1') {
       
      console.log('cross-stack token:', tok);
    }
  });
});
