import { describe, expect, it } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { signJWT, b64url, decodePrivateKeyB64 } from '../src/jwt.ts';
import type { Claims } from '../src/types.ts';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function freshKeypair(): Promise<{ privB64: string; pub: Uint8Array }> {
  const seed = ed.utils.randomPrivateKey(); // 32 bytes
  const pub = await ed.getPublicKeyAsync(seed);
  // Mimic the Go format the secret store will hold: 64 bytes (seed||pub)
  const expanded = new Uint8Array(64);
  expanded.set(seed, 0);
  expanded.set(pub, 32);
  return { privB64: btoa(String.fromCharCode(...expanded)).replace(/=+$/, ''), pub };
}

const baseClaims = (): Claims => ({
  iss: 'https://vaultify.live',
  aud: 'vaultify-pro',
  sub: 'ord_TEST',
  tid: 'pro',
  ver: 1,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 86400,
});

describe('signJWT', () => {
  it('produces a 3-segment compact JWT that round-trips through ed25519', async () => {
    const { privB64, pub } = await freshKeypair();
    const c = baseClaims();
    const tok = await signJWT(c, 'kid-1', privB64);

    const parts = tok.split('.');
    expect(parts).toHaveLength(3);

    // Header check.
    const hdr = JSON.parse(dec.decode(b64urlDecode(parts[0])));
    expect(hdr).toMatchObject({ alg: 'EdDSA', typ: 'JWT', kid: 'kid-1' });

    // Payload claim round-trip.
    const got = JSON.parse(dec.decode(b64urlDecode(parts[1]))) as Claims;
    expect(got.iss).toBe(c.iss);
    expect(got.aud).toBe(c.aud);
    expect(got.sub).toBe(c.sub);
    expect(got.tid).toBe(c.tid);
    expect(got.ver).toBe(1);

    // Signature must verify against the public half — this is the
    // exact check the Go verifier will run on Vaultify's side.
    const sig = b64urlDecode(parts[2]);
    const signed = enc.encode(`${parts[0]}.${parts[1]}`);
    const ok = await ed.verifyAsync(sig, signed, pub);
    expect(ok).toBe(true);
  });

  it('rejects an empty kid', async () => {
    const { privB64 } = await freshKeypair();
    await expect(signJWT(baseClaims(), '', privB64)).rejects.toThrow(/kid required/);
  });
});

describe('decodePrivateKeyB64', () => {
  it('accepts the 64-byte Go-style concatenation', async () => {
    const seed = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(seed);
    const expanded = new Uint8Array(64);
    expanded.set(seed, 0); expanded.set(pub, 32);
    const b64 = btoa(String.fromCharCode(...expanded)).replace(/=+$/, '');
    expect(decodePrivateKeyB64(b64)).toEqual(seed);
  });

  it('accepts a bare 32-byte seed', async () => {
    const seed = ed.utils.randomPrivateKey();
    const b64 = btoa(String.fromCharCode(...seed)).replace(/=+$/, '');
    expect(decodePrivateKeyB64(b64)).toEqual(seed);
  });

  it('rejects wrong sizes', () => {
    const bad = btoa('hello').replace(/=+$/, '');
    expect(() => decodePrivateKeyB64(bad)).toThrow(/wrong size/);
  });
});

describe('b64url', () => {
  it('strips padding and uses URL-safe alphabet', () => {
    expect(b64url('foo')).toBe('Zm9v');
    expect(b64url('?>>>>')).not.toContain('+');
    expect(b64url('?>>>>')).not.toContain('/');
    expect(b64url('any')).not.toContain('=');
  });
});
