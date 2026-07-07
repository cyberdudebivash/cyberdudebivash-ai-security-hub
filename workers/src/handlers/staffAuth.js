// =============================================================================
// CYBERDUDEBIVASH AI Security Hub | handlers/staffAuth.js
//
// Real platform-staff authentication — passwordless magic-link login for
// Platform Administrators / Super Administrators, replacing the hardcoded
// shared password ('cyberdudebivash2024admin') that was the entire access
// gate on mssp-command-center.html, revenue-command-center.html, and
// proposal-generator.html — readable via view-source, or bypassable outright
// with `localStorage.setItem('cdb_owner','true')` in devtools. Modeled
// directly on the proven, already-tested handlers/partnerAuth.js pattern:
// short-lived one-time link -> exchanged for a longer-lived session token.
//
// Eligibility to receive a login link (checked at request time only):
//   - the configured platform-owner email(s) (see the local ownerEmails()
//     note below), OR
//   - any user with at least one row in user_roles (auth/rbac.js)
// Both cases resolve to the SAME generic response — no account enumeration.
//
// Routes:
//   POST /api/staff/login   -> request a login link
//   POST /api/staff/verify  -> exchange the one-time token for a session
//   POST /api/staff/logout  -> invalidate the current session
//   GET  /api/staff/me      -> the logged-in staff member's own roles
//
// resolveStaffSession() is imported by auth/middleware.js and wired into
// resolveAuthV5() as a first-class auth path, alongside JWT/partner
// session/API key. A SUPERADMIN (or owner-email) session sets `isAdmin: true`
// on the resolved authCtx — the exact same field the ADMIN_KEY bypass already
// sets — so it's automatically isOwner()-equivalent everywhere that's already
// checked, without touching isOwner() itself. A plain ADMIN (Platform
// Administrator) session does NOT get isAdmin:true, preserving least
// privilege — it only satisfies the narrower isPlatformAdmin() check
// (auth/rbac.js).
//
// Deliberately does NOT import from auth/middleware.js (which imports THIS
// file's resolveStaffSession — importing back would be circular). The tiny
// owner-email check below intentionally mirrors middleware.js's
// ownerEmails()/isOwner() logic rather than importing it.
// =============================================================================

import { sendEmail } from '../services/emailEngine.js';
import { generateAccessToken } from '../lib/razorpay.js';

const LOGIN_TOKEN_TTL = 900;         // 15 minutes, single-use
const SESSION_TTL     = 86400 * 7;   // 7 days — tighter than the 30-day partner session; admin access is higher-privilege
const MAX_LOGIN_REQUESTS_PER_HOUR = 5;
const PORTAL_BASE_URL = 'https://cyberdudebivash.in';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// Mirrors auth/middleware.js's ownerEmails() exactly — duplicated (not
// imported) solely to avoid a circular import; see file header.
function ownerEmailsLocal(env) {
  const raw = (env && env.OWNER_EMAILS) || 'bivash@cyberdudebivash.com';
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

// ── POST /api/staff/login ─────────────────────────────────────────────────
// Body: { email }. Always returns the same generic 200 — no account
// enumeration, same anti-enumeration pattern as handlers/partnerAuth.js.
export async function handleStaffLoginRequest(request, env) {
  try {
    const body  = await request.json().catch(() => ({}));
    const email = String(body.email || '').toLowerCase().trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: 'Valid email required' }, 400);
    }
    if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

    const GENERIC_OK = {
      success: true,
      message: 'If that email belongs to a registered platform staff account, a login link has been sent.',
    };

    const rlKey = `staff:login:ratelimit:${email}`;
    const count = parseInt((await env.KV.get(rlKey)) || '0', 10);
    if (count >= MAX_LOGIN_REQUESTS_PER_HOUR) return jsonResponse(GENERIC_OK);
    await env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

    let userId = null;
    let roles = [];

    if (ownerEmailsLocal(env).includes(email)) {
      // Bootstrap path: the legacy single-owner-email concept (isOwner() in
      // auth/middleware.js) can always log in and is treated as SUPERADMIN,
      // even before any user_roles row exists — this is how the owner grants
      // the very first real roles to other staff via POST /api/admin/roles/grant.
      const user = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first().catch(() => null);
      userId = user?.id || null;
      roles = ['SUPERADMIN'];
    } else {
      const user = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first().catch(() => null);
      if (user) {
        const roleRows = await env.DB.prepare(`SELECT role FROM user_roles WHERE user_id = ?`).bind(user.id).all().catch(() => ({ results: [] }));
        roles = (roleRows.results || []).map(r => r.role);
        userId = user.id;
      }
    }

    if (roles.length === 0) return jsonResponse(GENERIC_OK); // not eligible — no link sent, same response either way

    const token = generateAccessToken();
    await env.KV.put(
      `staff:login_token:${token}`,
      JSON.stringify({ userId, email, roles }),
      { expirationTtl: LOGIN_TOKEN_TTL }
    );

    const loginUrl = `${PORTAL_BASE_URL}/admin-portal.html?token=${token}`;
    sendEmail(env, {
      to: email,
      subject: 'Your CYBERDUDEBIVASH platform staff login link',
      html: `<p>Click below to log in to the platform staff console. This link expires in 15 minutes and can only be used once.</p><p><a href="${loginUrl}">${loginUrl}</a></p><p>If you didn't request this, you can safely ignore this email.</p>`,
      text: `Log in to the platform staff console: ${loginUrl}\n\nThis link expires in 15 minutes and can only be used once. If you didn't request this, ignore this email.`,
    }).catch(e => console.error('[Staff Auth] login email send failed:', e.message));

    return jsonResponse(GENERIC_OK);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/staff/verify ────────────────────────────────────────────────
export async function handleStaffLoginVerify(request, env) {
  try {
    const body  = await request.json().catch(() => ({}));
    const token = String(body.token || '').trim();
    if (!token) return jsonResponse({ error: 'token required' }, 400);

    const raw = await env.KV.get(`staff:login_token:${token}`);
    if (!raw) return jsonResponse({ error: 'This login link is invalid or has expired. Request a new one.' }, 401);
    await env.KV.delete(`staff:login_token:${token}`); // single-use

    const { userId, email, roles } = JSON.parse(raw);

    const sessionToken = generateAccessToken();
    await env.KV.put(
      `staff:session:${sessionToken}`,
      JSON.stringify({ userId, email, roles }),
      { expirationTtl: SESSION_TTL }
    );

    return jsonResponse({ success: true, session_token: sessionToken, expires_in: SESSION_TTL, email, roles });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/staff/logout ────────────────────────────────────────────────
export async function handleStaffLogout(request, env) {
  const token = request.headers.get('x-staff-token') ||
                request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || '';
  if (token) await env.KV.delete(`staff:session:${token}`).catch(() => {});
  return jsonResponse({ success: true });
}

// ── GET /api/staff/me ──────────────────────────────────────────────────────
export async function handleStaffMe(request, env, authCtx = {}) {
  if (!authCtx.platformRoles || authCtx.platformRoles.length === 0) {
    return jsonResponse({ error: 'Not logged in as platform staff. Use POST /api/staff/login.' }, 401);
  }
  return jsonResponse({ success: true, email: authCtx.email, roles: authCtx.platformRoles });
}

// ── Auth-layer resolver ────────────────────────────────────────────────────
// Reads a staff session token (Authorization: Bearer <token> or
// x-staff-token) and returns an authCtx-shaped object, or null. Called from
// resolveAuthV5() between the partner-session and API-key checks — opaque
// 64-char hex token (generateAccessToken()) under a distinct KV namespace
// (staff:session:*), no collision risk with partner/API-key tokens.
export async function resolveStaffSession(request, env) {
  if (!env.KV) return null;
  const token = request.headers.get('x-staff-token') ||
                request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || '';
  if (!token || token.length < 32) return null;

  const raw = await env.KV.get(`staff:session:${token}`).catch(() => null);
  if (!raw) return null;

  let session;
  try { session = JSON.parse(raw); } catch { return null; }
  if (!session?.roles?.length) return null;

  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  return {
    authenticated:  true,
    method:         'staff_session',
    identity:       `staff:${session.email}`,
    user_id:        session.userId,
    email:          session.email,
    tier:           'ENTERPRISE',
    label:          `${session.roles.join('/')} (Platform Staff)`,
    key_id:         null,
    ip,
    platformRoles:  session.roles,
    // SUPERADMIN is architecturally equivalent to the ADMIN_KEY bypass — see
    // file header. A plain ADMIN (Platform Administrator) session does NOT
    // get isAdmin:true, so it stays scoped to isPlatformAdmin()-gated
    // resources only (auth/rbac.js), not every isOwner()-gated one.
    isAdmin:        session.roles.includes('SUPERADMIN'),
  };
}
