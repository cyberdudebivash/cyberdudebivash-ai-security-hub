// =============================================================================
// CYBERDUDEBIVASH AI Security Hub | handlers/partnerAuth.js
//
// Real MSSP partner self-serve authentication — passwordless magic-link login.
// mssp_partners has no password column (schema_master.sql, by design); this is
// the standard, secure passwordless pattern for a B2B partner portal: a
// short-lived, single-use link is emailed to the partner's on-file
// contact_email, then exchanged client-side for a longer-lived session token.
// Emails go out for real via sendEmail() (Resend primary, MailChannels
// fallback) — the same transport already used for purchase confirmations and
// the drip-sequence engine, not a stub.
//
// Routes:
//   POST /api/partners/login   → request a login link (generic response, no
//                                 account enumeration)
//   POST /api/partners/verify  → exchange the one-time token for a session
//   POST /api/partners/logout  → invalidate the current session
//   GET  /api/partners/me      → the logged-in partner's own profile
//
// resolvePartnerSession() is also imported by auth/middleware.js and wired
// into resolveAuthV5() as a first-class auth path, alongside JWT and API key.
// =============================================================================

import { sendEmail } from '../services/emailEngine.js';
import { generateAccessToken } from '../lib/razorpay.js';

const PORTAL_BASE_URL = 'https://cyberdudebivash.in';
const LOGIN_TOKEN_TTL = 900;         // 15 minutes, single-use
const SESSION_TTL     = 86400 * 30;  // 30 days — matches the mssp:token convention in msspOnboardingHandler.js
const MAX_LOGIN_REQUESTS_PER_HOUR = 5;

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// ── POST /api/partners/login ──────────────────────────────────────────────
// Body: { email }. Always returns the same generic 200 whether or not the
// email matches a real partner — prevents using this endpoint to enumerate
// which companies are (or aren't) MSSP partners.
export async function handlePartnerLoginRequest(request, env) {
  try {
    const body  = await request.json().catch(() => ({}));
    const email = String(body.email || '').toLowerCase().trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: 'Valid email required' }, 400);
    }
    if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

    const GENERIC_OK = {
      success: true,
      message: 'If that email belongs to a registered MSSP partner account, a login link has been sent.',
    };

    // Rate limit per email, independent of whether the account exists, so
    // this endpoint can't be used to enumerate accounts via timing either.
    const rlKey = `partner:login:ratelimit:${email}`;
    const count = parseInt((await env.KV.get(rlKey)) || '0', 10);
    if (count >= MAX_LOGIN_REQUESTS_PER_HOUR) return jsonResponse(GENERIC_OK);
    await env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

    const partner = await env.DB.prepare(
      `SELECT id, company, contact_email, status FROM mssp_partners WHERE contact_email=?`
    ).bind(email).first().catch(() => null);

    // status='pending' = an admin created the row but the partner never
    // activated via checkout/trial (see msspOps.js handleAddMsspPartner) —
    // there's no active identity to log into yet either way.
    if (!partner || partner.status === 'pending') return jsonResponse(GENERIC_OK);

    const token = generateAccessToken();
    await env.KV.put(
      `partner:login_token:${token}`,
      JSON.stringify({ partnerId: partner.id, email: partner.contact_email }),
      { expirationTtl: LOGIN_TOKEN_TTL }
    );

    const loginUrl = `${PORTAL_BASE_URL}/partner-portal.html?token=${token}`;
    sendEmail(env, {
      to: partner.contact_email,
      subject: 'Your CYBERDUDEBIVASH Partner Portal login link',
      html: `<p>Hi ${partner.company || 'there'},</p><p>Click below to log in to your MSSP Partner Portal. This link expires in 15 minutes and can only be used once.</p><p><a href="${loginUrl}">${loginUrl}</a></p><p>If you didn't request this, you can safely ignore this email.</p>`,
      text: `Log in to your MSSP Partner Portal: ${loginUrl}\n\nThis link expires in 15 minutes and can only be used once. If you didn't request this, ignore this email.`,
    }).catch(e => console.error('[Partner Auth] login email send failed:', e.message));

    return jsonResponse(GENERIC_OK);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/partners/verify ─────────────────────────────────────────────
// Body: { token } — the one-time token from the emailed link.
export async function handlePartnerLoginVerify(request, env) {
  try {
    const body  = await request.json().catch(() => ({}));
    const token = String(body.token || '').trim();
    if (!token) return jsonResponse({ error: 'token required' }, 400);
    if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

    const raw = await env.KV.get(`partner:login_token:${token}`);
    if (!raw) return jsonResponse({ error: 'This login link is invalid or has expired. Request a new one.' }, 401);
    await env.KV.delete(`partner:login_token:${token}`); // single-use, consumed regardless of outcome below

    const { partnerId } = JSON.parse(raw);
    const partner = await env.DB.prepare(
      `SELECT id, company, contact_email, tier, plan, status, brand_name, custom_domain, primary_color, client_count, max_clients, margin_pct FROM mssp_partners WHERE id=?`
    ).bind(partnerId).first().catch(() => null);
    if (!partner) return jsonResponse({ error: 'Partner account no longer exists' }, 404);

    const sessionToken = generateAccessToken();
    await env.KV.put(
      `partner:session:${sessionToken}`,
      JSON.stringify({ partnerId: partner.id, email: partner.contact_email, company: partner.company, tier: partner.tier }),
      { expirationTtl: SESSION_TTL }
    );

    return jsonResponse({
      success:       true,
      session_token: sessionToken,
      expires_in:    SESSION_TTL,
      partner: {
        id: partner.id, company: partner.company, email: partner.contact_email,
        tier: partner.tier, plan: partner.plan, status: partner.status,
        brand_name: partner.brand_name, custom_domain: partner.custom_domain,
        primary_color: partner.primary_color, client_count: partner.client_count,
        max_clients: partner.max_clients, margin_pct: partner.margin_pct,
      },
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/partners/logout ─────────────────────────────────────────────
export async function handlePartnerLogout(request, env) {
  const token = request.headers.get('x-partner-token') ||
                request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || '';
  if (token) await env.KV.delete(`partner:session:${token}`).catch(() => {});
  return jsonResponse({ success: true });
}

// ── GET /api/partners/me ──────────────────────────────────────────────────
// Requires a resolved partner session — authCtx.partnerId, set by
// resolvePartnerSession() below via resolveAuthV5().
export async function handlePartnerMe(request, env, authCtx = {}) {
  if (!authCtx.partnerId) {
    return jsonResponse({ error: 'Not logged in as a partner. Use POST /api/partners/login.' }, 401);
  }
  if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);
  const partner = await env.DB.prepare(
    `SELECT id, company, contact_email, tier, plan, status, brand_name, custom_domain, primary_color, client_count, max_clients, margin_pct, onboarded_at FROM mssp_partners WHERE id=?`
  ).bind(authCtx.partnerId).first().catch(() => null);
  if (!partner) return jsonResponse({ error: 'Partner account not found' }, 404);
  return jsonResponse({ success: true, partner });
}

// ── Auth-layer resolver ────────────────────────────────────────────────────
// Reads a partner session token (Authorization: Bearer <token> or
// x-partner-token) and returns an authCtx-shaped object, or null if there's
// no valid session. Called from resolveAuthV5() (auth/middleware.js) between
// the JWT and API-key checks. Partner session tokens are opaque 64-char hex
// strings (generateAccessToken()) stored under a distinct KV namespace
// (partner:session:*) — no collision risk with JWTs (dot-delimited) or
// cdb_-prefixed API keys.
export async function resolvePartnerSession(request, env) {
  if (!env.KV) return null;
  const token = request.headers.get('x-partner-token') ||
                request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || '';
  if (!token || token.length < 32) return null; // too short to be a session token — skip the KV round-trip

  const raw = await env.KV.get(`partner:session:${token}`).catch(() => null);
  if (!raw) return null;

  let session;
  try { session = JSON.parse(raw); } catch { return null; }
  if (!session?.partnerId) return null;

  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  return {
    authenticated: true,
    method:        'partner_session',
    identity:      `partner:${session.partnerId}`,
    user_id:       null,
    partnerId:     session.partnerId,
    email:         session.email,
    tier:          session.tier || 'RESELLER',
    label:         `${session.company || 'Partner'} (MSSP Partner)`,
    key_id:        null,
    ip,
  };
}
