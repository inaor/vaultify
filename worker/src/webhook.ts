/**
 * Base44 webhook signature verification.
 *
 * Base44's webhook authentication uses HMAC-SHA256 over the raw
 * request body, with the digest expressed as a hex string in a
 * dedicated header. Since the exact header name varies by platform
 * (Stripe uses `Stripe-Signature`, GitHub uses `X-Hub-Signature-256`,
 * Base44 uses something similar), the header name is configurable.
 *
 * Constant-time comparison is mandatory: a non-CT compare leaks the
 * shared secret over time via response-timing oracles when an
 * attacker probes us with crafted bodies + random signatures.
 */
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

const enc = new TextEncoder();

/**
 * verifyBase44Webhook returns true iff the supplied signature is a
 * valid HMAC-SHA256 of body using secret. Accepts hex (any case).
 *
 * Caller is responsible for reading the request body once and feeding
 * the same bytes here.
 */
export function verifyBase44Webhook(body: string, signatureHex: string, secret: string): boolean {
  if (!body || !signatureHex || !secret) return false;
  const want = hmac(sha256, enc.encode(secret), enc.encode(body));
  let got: Uint8Array;
  try {
    got = hexToBytes(signatureHex);
  } catch {
    return false;
  }
  return constantTimeEqual(want, got);
}

function hexToBytes(s: string): Uint8Array {
  const clean = s.startsWith('sha256=') ? s.slice(7) : s;
  if (clean.length === 0 || clean.length % 2 !== 0) {
    throw new Error('webhook: signature not valid hex');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error('webhook: signature not valid hex');
    out[i] = byte;
  }
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
