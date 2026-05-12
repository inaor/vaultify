import { describe, expect, it } from 'vitest';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { verifyBase44Webhook } from '../src/webhook.ts';

const enc = new TextEncoder();

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const SECRET = 'this-is-a-shared-base44-webhook-secret';
const BODY = JSON.stringify({ event_type: 'subscription.created', sub_id: 'ord_1' });
const VALID_SIG = hex(hmac(sha256, enc.encode(SECRET), enc.encode(BODY)));

describe('verifyBase44Webhook', () => {
  it('accepts a correctly-signed body', () => {
    expect(verifyBase44Webhook(BODY, VALID_SIG, SECRET)).toBe(true);
  });

  it('accepts the sha256= prefixed shape some platforms emit', () => {
    expect(verifyBase44Webhook(BODY, `sha256=${VALID_SIG}`, SECRET)).toBe(true);
  });

  it('rejects a tampered body', () => {
    expect(verifyBase44Webhook(BODY + 'x', VALID_SIG, SECRET)).toBe(false);
  });

  it('rejects a wrong-length signature without throwing', () => {
    expect(verifyBase44Webhook(BODY, '0123', SECRET)).toBe(false);
  });

  it('rejects non-hex signatures', () => {
    expect(verifyBase44Webhook(BODY, 'not-hex-but-correct-length-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-x', SECRET)).toBe(false);
  });

  it('returns false on empty inputs without exposing the secret', () => {
    expect(verifyBase44Webhook('', VALID_SIG, SECRET)).toBe(false);
    expect(verifyBase44Webhook(BODY, '', SECRET)).toBe(false);
    expect(verifyBase44Webhook(BODY, VALID_SIG, '')).toBe(false);
  });
});
