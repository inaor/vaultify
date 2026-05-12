/**
 * Vaultify Pro license signer (Cloudflare Worker).
 *
 * Routes
 *   GET  /healthz                            - uptime probe
 *   POST /webhook/base44                     - Base44 fires this on subscription events
 *   POST /admin/issue                        - manual issuance (support / refunds)
 *
 * Trust boundary
 *   The Ed25519 private key lives ONLY in CF Workers' secret store.
 *   Vaultify binaries embed only the corresponding public key; they
 *   verify offline. Even if this Worker is compromised, the worst
 *   outcome is forged tokens for the duration of the breach plus the
 *   time it takes you to rotate `kid` in keys_prod.go and ship a new
 *   binary. Old tokens stay accepted until their `exp` because v1
 *   verifiers explicitly trust whatever `kid` is embedded.
 */
import { signJWT } from './jwt.ts';
import { verifyBase44Webhook } from './webhook.ts';
import { buildClaims } from './claims.ts';
import { sendLicenseEmail } from './email.ts';
import type { Env, IssuanceInput } from './types.ts';

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === 'GET' && url.pathname === '/healthz') {
      return json(200, { ok: true, kid: env.KID, audience: env.AUDIENCE });
    }
    if (req.method === 'POST' && url.pathname === '/webhook/base44') {
      return handleBase44Webhook(req, env);
    }
    if (req.method === 'POST' && url.pathname === '/admin/issue') {
      return handleAdminIssue(req, env);
    }
    return json(404, { error: 'not_found', path: url.pathname });
  },
};

// --- Base44 webhook handler ----------------------------------------

async function handleBase44Webhook(req: Request, env: Env): Promise<Response> {
  // Read body once: HMAC verification + JSON parse both consume it.
  const body = await req.text();
  // Header name is defensive: Base44 hasn't pinned a spec; if they
  // ever rename it we adjust here, not in three places.
  const sig = req.headers.get('X-Base44-Signature')
            ?? req.headers.get('X-Webhook-Signature')
            ?? '';
  if (!verifyBase44Webhook(body, sig, env.BASE44_WEBHOOK_SECRET)) {
    return json(401, { error: 'invalid_signature' });
  }
  let evt: Record<string, unknown>;
  try {
    evt = JSON.parse(body);
  } catch {
    return json(400, { error: 'malformed_json' });
  }

  const eventType = String(evt.event_type ?? evt.type ?? '');
  // Only mint licenses for events that represent paid access starting
  // or renewing. Cancellations / refunds are handled by NOT issuing
  // a renewal: existing tokens age out via `exp`. Real revocation
  // (jti deny-list) is reserved for v2.
  const issuesLicense = ['subscription.created', 'subscription.renewed', 'order.paid', 'order.completed']
      .includes(eventType);
  if (!issuesLicense) {
    return json(202, { ok: true, ignored: true, reason: `event_type=${eventType}` });
  }

  const input: IssuanceInput | { error: string } = readIssuanceFromBase44(evt);
  if ('error' in input) {
    return json(400, input);
  }
  return mintAndDeliver(env, input);
}

// --- Admin handler --------------------------------------------------

async function handleAdminIssue(req: Request, env: Env): Promise<Response> {
  const auth = req.headers.get('Authorization') ?? '';
  const want = `Bearer ${env.ADMIN_TOKEN}`;
  if (!env.ADMIN_TOKEN || !ctEqualString(auth, want)) {
    return json(401, { error: 'unauthorized' });
  }
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json(400, { error: 'malformed_json' });
  }
  const sub = String(body.sub ?? '');
  if (!sub) return json(400, { error: 'sub_required' });
  const tid = (body.tid === 'pro-perpetual' ? 'pro-perpetual' : 'pro') as IssuanceInput['tid'];
  const email = body.email ? String(body.email) : undefined;
  const expiresAt = body.expires_at ? new Date(String(body.expires_at)) : undefined;
  return mintAndDeliver(env, { sub, tid, email, expiresAt, source: 'admin' });
}

// --- Common issuance pipeline --------------------------------------

async function mintAndDeliver(env: Env, input: IssuanceInput): Promise<Response> {
  const claims = buildClaims(env, input);
  const token = await signJWT(claims, env.KID, env.ED25519_PRIVATE_KEY_B64);

  // Email when configured; otherwise return the token in the response
  // so the caller (Base44 / admin) can deliver it however they prefer.
  let emailed = false;
  if (input.email) {
    try {
      emailed = await sendLicenseEmail(env, {
        to: input.email,
        token,
        tier: claims.tid,
        expiresAt: input.tid === 'pro-perpetual' ? null : new Date(claims.exp * 1000).toISOString().slice(0, 10),
      });
    } catch (e) {
      // 5xx so Base44 retries; the deterministic jti keeps idempotency
      // intact across retries.
      return json(502, { error: 'email_failed', detail: String((e as Error).message ?? e) });
    }
  }

  return json(200, {
    ok: true,
    issued_for: input.sub,
    tid: claims.tid,
    exp: claims.exp,
    jti: claims.jti,
    emailed,
    // Token is included only when email didn't go out (or wasn't
    // configured). Caller decides what to do with it.
    token: emailed ? undefined : token,
  });
}

// --- Base44 payload reducer ----------------------------------------
// Base44's webhook shape isn't stable across configurations, so we
// pull a small set of fields defensively. Document this contract in
// the Worker README + Base44 webhook config.

function readIssuanceFromBase44(evt: Record<string, unknown>): IssuanceInput | { error: string } {
  const data = (evt.data ?? evt) as Record<string, unknown>;
  const sub = String(
    data.subscription_id ?? data.order_id ?? data.id ?? '',
  );
  if (!sub) return { error: 'missing_sub' };
  const email = data.customer_email ? String(data.customer_email)
              : data.email ? String(data.email)
              : undefined;
  const tier = String(data.tier ?? data.tid ?? 'pro');
  const tid = tier === 'pro-perpetual' ? 'pro-perpetual' : 'pro';
  const expiresAt = data.expires_at ? new Date(String(data.expires_at))
                  : data.current_period_end ? new Date(String(data.current_period_end))
                  : undefined;
  return { sub, email, tid, expiresAt, source: 'base44' };
}

// --- helpers --------------------------------------------------------

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function ctEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
