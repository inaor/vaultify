/**
 * Ed25519 JWT signing for Vaultify Pro licenses.
 *
 * Implementation note on the keypair format
 * -----------------------------------------
 * Go's crypto/ed25519 (and our tools/keygen) emits a 64-byte private
 * key that is concatenation of the 32-byte seed and the 32-byte public
 * key. Most modern Ed25519 libraries (including @noble/ed25519) work
 * with the 32-byte seed directly. We slice transparently so the
 * Worker can ingest whatever the user pasted into `wrangler secret`
 * without first reformatting it.
 *
 * We use @noble/ed25519 instead of WebCrypto's native Ed25519 to
 * avoid the compatibility-flag dance — Cloudflare's native support
 * exists but its availability has shifted across compat-date windows.
 * @noble/ed25519 is audited, ~4 KB minified, and pure-JS.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import type { Claims } from './types.ts';

// @noble/ed25519 v2 needs the SHA-512 implementation injected once.
// This is safe to call repeatedly; it's a no-op after the first call.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const enc = new TextEncoder();

/**
 * b64url base64url-encodes (no padding) a Uint8Array or UTF-8 string.
 * The JWT spec forbids padding in segments, so we strip `=` explicitly.
 */
export function b64url(bytes: Uint8Array | string): string {
  const data = typeof bytes === 'string' ? enc.encode(bytes) : bytes;
  let bin = '';
  for (let i = 0; i < data.length; i++) bin += String.fromCharCode(data[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * decodePrivateKeyB64 accepts a base64-no-padding string from
 * `wrangler secret put` and returns the 32-byte Ed25519 seed.
 *
 * Both the 32-byte seed and the 64-byte Go-style concatenation are
 * accepted. Any other length is rejected up-front so a typo'd secret
 * surfaces as a clear startup error instead of a cryptic verify
 * failure on the Vaultify side.
 */
export function decodePrivateKeyB64(b64: string): Uint8Array {
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (out.length === 32) return out;
  if (out.length === 64) return out.slice(0, 32);
  throw new Error(`ed25519 private key wrong size: ${out.length} (want 32 or 64)`);
}

/**
 * signJWT serialises and signs a JWT in compact form. Header is fixed
 * to {alg:EdDSA, typ:JWT, kid}. Claims pass through to the payload
 * unchanged — caller is responsible for filling them per the v1
 * contract before this is invoked.
 */
export async function signJWT(claims: Claims, kid: string, privKeyB64: string): Promise<string> {
  if (!kid) throw new Error('signJWT: kid required');
  const seed = decodePrivateKeyB64(privKeyB64);
  const header = { alg: 'EdDSA', typ: 'JWT', kid };
  const headerSeg = b64url(JSON.stringify(header));
  const payloadSeg = b64url(JSON.stringify(claims));
  const signing = `${headerSeg}.${payloadSeg}`;
  const sig = await ed.signAsync(enc.encode(signing), seed);
  return `${signing}.${b64url(sig)}`;
}
