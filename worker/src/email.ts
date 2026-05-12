/**
 * Email delivery via Resend.
 *
 * Why Resend
 * ----------
 * Resend's HTTPS API is a single endpoint, no SDK needed, and it
 * works inside a Worker without any Node-compat shims. A swap to
 * Postmark / SendGrid is a 30-line edit confined to this file.
 *
 * Optional behaviour
 * ------------------
 * If RESEND_API_KEY isn't set we skip email and let the caller
 * decide what to do with the token (e.g. include it in the webhook
 * response so Base44 can show it on the receipt page). This makes
 * v1 deploy possible before the email vendor is in place.
 */
import type { Env } from './types.ts';

export interface SendLicenseArgs {
  to: string;
  token: string;
  expiresAt: string | null;     // ISO date string; null for perpetual
  tier: 'pro' | 'pro-perpetual';
}

/**
 * Returns true on success, false when no API key is configured (the
 * caller falls back to returning the token in the response). Throws
 * on actual delivery errors so the Worker returns 5xx and Base44
 * retries the webhook.
 */
export async function sendLicenseEmail(env: Env, args: SendLicenseArgs): Promise<boolean> {
  if (!env.RESEND_API_KEY) return false;

  const expiryLine = args.expiresAt
    ? `Your license is valid until <strong>${args.expiresAt}</strong>.`
    : `Your license is <strong>perpetual</strong> — no expiry.`;

  const html = `
    <p>Welcome to Vaultify Pro.</p>
    <p>Paste this token into Vaultify (Settings &rarr; License &rarr; Activate Pro):</p>
    <pre style="white-space:pre-wrap;word-break:break-all;background:#f4f4f5;padding:14px;border-radius:8px;font-family:ui-monospace,SF Mono,Consolas,monospace;font-size:13px">${args.token}</pre>
    <p>${expiryLine}</p>
    <p style="color:#52525b;font-size:13px">Tier: <code>${args.tier}</code><br>
    Need help? Reply to this email or write <a href="mailto:${env.SUPPORT_EMAIL}">${env.SUPPORT_EMAIL}</a>.</p>
  `;
  const text = [
    'Welcome to Vaultify Pro.',
    '',
    'Paste this token into Vaultify (Settings -> License -> Activate Pro):',
    '',
    args.token,
    '',
    args.expiresAt ? `Valid until ${args.expiresAt}.` : 'Perpetual license — no expiry.',
    '',
    `Tier: ${args.tier}`,
    `Help: ${env.SUPPORT_EMAIL}`,
  ].join('\n');

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: [args.to],
      subject: 'Your Vaultify Pro license',
      html,
      text,
    }),
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`resend ${resp.status}: ${body.slice(0, 300)}`);
  }
  return true;
}
