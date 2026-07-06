/**
 * CYBERDUDEBIVASH AI Security Hub — Auth Handler v5.0
 * POST /api/auth/signup    — create account
 * POST /api/auth/login     — get access + refresh tokens
 * POST /api/auth/refresh   — rotate access token
 * POST /api/auth/logout    — revoke refresh token
 * GET  /api/auth/me        — current user profile
 * PUT  /api/auth/profile   — update profile (name, company, telegram_chat_id)
 * POST /api/auth/alerts    — configure alert settings
 * POST /api/auth/test-alert — fire a test alert
 */

import { hashPassword, verifyPassword, validatePasswordStrength, validateEmail } from '../auth/password.js';
import { createAccessToken, createRefreshToken, storeRefreshToken, validateRefreshToken, revokeRefreshToken, revokeAllUserTokens, extractBearerToken, hashToken } from '../auth/jwt.js';
import { createApiKey } from '../auth/apiKeys.js';
import { checkLoginRateLimit, recordLoginAttempt } from '../auth/middleware.js';
import { parseBody } from '../middleware/validation.js';
import { inspectForAttacks } from '../middleware/security.js';
import { sendTestAlert } from '../lib/alerts.js';
import { issueMFAChallenge } from './mfa.js';
import { sendEmail } from '../services/emailEngine.js';

const CONTACT_EMAIL = 'contact@cyberdudebivash.in';
const PLATFORM_URL  = 'https://tools.cyberdudebivash.com';

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
}

function getUA(request) {
  return (request.headers.get('User-Agent') || '').slice(0, 200);
}

// ─── POST /api/auth/signup ────────────────────────────────────────────────────
export async function handleSignup(request, env) {
  if (!env?.DB) {
    return Response.json({ error: 'Database unavailable' }, { status: 503 });
  }

  const body = await parseBody(request);
  const rawEmail = body?.email || '';
  const rawPass  = body?.password || '';
  const fullName = body?.full_name || '';
  const company  = body?.company || '';

  // Input sanitization
  if (inspectForAttacks(rawEmail) || inspectForAttacks(fullName)) {
    return Response.json({ error: 'Invalid input detected' }, { status: 400 });
  }

  const emailVal = validateEmail(rawEmail);
  if (!emailVal.valid) {
    return Response.json({ error: emailVal.message, field: 'email' }, { status: 422 });
  }
  const passVal = validatePasswordStrength(rawPass);
  if (!passVal.valid) {
    return Response.json({ error: passVal.message, field: 'password' }, { status: 422 });
  }

  const email = emailVal.value;

  // Duplicate check
  try {
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) {
      return Response.json({ error: 'Email already registered', hint: 'Use /api/auth/login instead' }, { status: 409 });
    }
  } catch {
    return Response.json({ error: 'Registration unavailable — try again' }, { status: 503 });
  }

  // Hash password (PBKDF2 — takes ~30ms at 50k iterations on paid Workers)
  const { hash, salt } = await hashPassword(rawPass);

  // Pre-generate UUID (users.id is TEXT PRIMARY KEY — must supply value)
  const userId = crypto.randomUUID();

  // Insert user
  try {
    await env.DB.prepare(
      `INSERT INTO users (id, email, password_hash, password_salt, full_name, company, tier, status)
       VALUES (?, ?, ?, ?, ?, ?, 'FREE', 'active')`
    ).bind(userId, email, hash, salt, fullName.slice(0,100) || null, company.slice(0,100) || null).run();
  } catch (e) {
    if (e?.message?.includes('UNIQUE')) {
      return Response.json({ error: 'Email already registered' }, { status: 409 });
    }
    return Response.json({ error: 'Registration failed — try again', detail: e?.message?.slice(0,80) }, { status: 500 });
  }

  // Auto-create the first API key and surface it ONCE in this response, so the
  // user has an immediately-usable key (otherwise it consumed a key slot but its
  // raw value was discarded — an unusable phantom key). Non-fatal on failure.
  let firstKey = null;
  try { firstKey = await createApiKey(env.DB, userId, 'FREE', 'Default Key'); } catch (_) {}

  // Generate tokens. If anything after the user INSERT fails, roll the
  // half-created account back — otherwise the customer's retry is met with
  // "Email already registered" for an account they never received
  // credentials for (observed live in Phase VII: signup 500 → stranded row).
  let accessToken, refreshData;
  try {
    accessToken = await createAccessToken({ id: userId, email, tier: 'FREE' }, env.JWT_SECRET);
    refreshData = await createRefreshToken();
    const ip = getClientIP(request);
    const ua = getUA(request);
    await storeRefreshToken(env.DB, userId, refreshData, ip, ua);
  } catch (e) {
    try {
      await env.DB.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').bind(userId).run().catch(() => {});
      await env.DB.prepare('DELETE FROM api_keys WHERE user_id = ?').bind(userId).run().catch(() => {});
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
    } catch (_) { /* best-effort — duplicate check on retry still guards */ }
    console.error('[Auth] signup token issuance failed — account rolled back:', e?.message);
    return Response.json(
      { error: 'Registration could not be completed — no account was created. Please try again.', code: 'ERR_SIGNUP_INCOMPLETE' },
      { status: 500 },
    );
  }

  // Fire-and-forget welcome email (non-blocking)
  try {
    const { sendEmail } = await import('../services/emailEngine.js');
    await sendEmail(env, {
      to:      email,
      subject: 'Welcome to CYBERDUDEBIVASH AI Security Hub™',
      html: `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f0f1a;color:#e2e8f0;padding:40px;border-radius:12px">
        <h1 style="background:linear-gradient(135deg,#7c3aed,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0 0 8px">CYBERDUDEBIVASH®</h1>
        <p style="color:#64748b;margin:0 0 32px;font-size:13px">AI Security Intelligence Platform</p>
        <h2 style="color:#e2e8f0">Welcome${fullName ? ', ' + fullName : ''}!</h2>
        <p style="color:#94a3b8">Your account has been created successfully. You're now part of an elite community of security professionals using AI-native cyber defense.</p>
        <div style="background:#1a1a2e;border:1px solid #2d2d4e;border-radius:8px;padding:20px;margin:24px 0">
          <p style="margin:0 0 8px;color:#7c3aed;font-weight:600">Your first API key:</p>
          <code style="color:#e2e8f0;font-size:12px">${firstKey?.raw_key || 'Visit /api/keys to generate'}</code>
          ${firstKey?.raw_key ? '<p style="color:#ef4444;font-size:12px;margin:8px 0 0">⚠️ Save this key now — it cannot be retrieved again.</p>' : ''}
        </div>
        <h3 style="color:#e2e8f0">Quick Start</h3>
        <ul style="color:#94a3b8;padding-left:20px;line-height:1.8">
          <li>Explore <a href="https://cyberdudebivash.in" style="color:#7c3aed">cyberdudebivash.in</a></li>
          <li>API docs: <a href="https://cyberdudebivash.in/api-docs.html" style="color:#7c3aed">Full API Reference</a></li>
          <li>Support: <a href="mailto:support@cyberdudebivash.in" style="color:#7c3aed">support@cyberdudebivash.in</a></li>
        </ul>
        <p style="color:#475569;font-size:12px;margin-top:32px;border-top:1px solid #2d2d4e;padding-top:16px">
          CYBERDUDEBIVASH Pvt Ltd · AI Security · Threat Intelligence · DevSecOps<br>
          <a href="https://cyberdudebivash.in" style="color:#475569">cyberdudebivash.in</a>
        </p>
      </div>`,
    }).catch(() => {}); // non-fatal
  } catch (_) {}

  return Response.json({
    success:       true,
    message:       'Account created successfully. A welcome email has been sent.',
    user: {
      id:        userId,
      email,
      tier:      'FREE',
      full_name: fullName || null,
    },
    access_token:  accessToken,
    refresh_token: refreshData.token,
    token_type:    'Bearer',
    expires_in:    900, // 15 minutes
    api_key:       firstKey?.raw_key || null,  // shown ONCE — store it now
    api_key_note:  firstKey?.raw_key ? 'Your first API key — save it now; it cannot be retrieved again.' : null,
    next_steps: [
      'Use access_token in Authorization: Bearer <token> header',
      'Enterprise onboarding guide: GET /api/enterprise/onboarding',
      'Platform capabilities: GET /api/enterprise/welcome',
      `Manage API keys at GET /api/keys`,
      `Start scanning at POST /api/scan/domain`,
    ],
    support: 'support@cyberdudebivash.in | Enterprise: enterprise@cyberdudebivash.in',
  }, { status: 201 });
}

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
export async function handleLogin(request, env) {
  if (!env?.DB) {
    return Response.json({ error: 'Database unavailable' }, { status: 503 });
  }

  const ip   = getClientIP(request);
  const body = await parseBody(request);
  const rawEmail = body?.email || '';
  const rawPass  = body?.password || '';

  const emailVal = validateEmail(rawEmail);
  if (!emailVal.valid) {
    return Response.json({ error: emailVal.message, field: 'email' }, { status: 422 });
  }
  const email = emailVal.value;

  // Brute-force protection
  const rateCheck = await checkLoginRateLimit(env.DB, email, ip);
  if (!rateCheck.allowed) {
    return Response.json({
      error: 'Too many failed attempts',
      message: rateCheck.reason,
      retry_after: 900,
    }, { status: 429, headers: { 'Retry-After': '900' } });
  }

  // Fetch user
  let user;
  try {
    user = await env.DB.prepare(
      'SELECT id, email, password_hash, password_salt, tier, status, full_name FROM users WHERE email = ?'
    ).bind(email).first();
  } catch {
    return Response.json({ error: 'Login unavailable — try again' }, { status: 503 });
  }

  // Constant-time: always run verifyPassword even if user not found (prevent timing oracle)
  const dummyHash = '0'.repeat(64);
  const dummySalt = '0'.repeat(64);
  const passwordOk = user
    ? await verifyPassword(rawPass, user.password_hash, user.password_salt)
    : await verifyPassword(rawPass, dummyHash, dummySalt).then(() => false);

  if (!user || !passwordOk) {
    await recordLoginAttempt(env.DB, email, ip, false);
    return Response.json({ error: 'Invalid email or password' }, { status: 401 });
  }

  if (user.status !== 'active') {
    await recordLoginAttempt(env.DB, email, ip, false);
    return Response.json({
      error: 'Account suspended',
      hint: `Contact ${CONTACT_EMAIL}`,
    }, { status: 403 });
  }

  await recordLoginAttempt(env.DB, email, ip, true);

  // Update last_login
  env.DB.prepare('UPDATE users SET last_login_at = datetime(\'now\'), login_count = login_count + 1 WHERE id = ?')
    .bind(user.id).run().catch(() => {});

  // MFA check — if enabled, issue a challenge token instead of real tokens
  const mfaChallenge = await issueMFAChallenge(env, user.id, user.email, user.tier);
  if (mfaChallenge) {
    return Response.json({
      mfa_required:        true,
      mfa_challenge_token: mfaChallenge,
      expires_in:          300,
      next_step:           'POST /api/auth/mfa/authenticate with { mfa_challenge_token, totp_code } or { mfa_challenge_token, backup_code }',
    }, { status: 200 });
  }

  // Issue tokens
  const accessToken = await createAccessToken(user, env.JWT_SECRET);
  const refreshData = await createRefreshToken();
  await storeRefreshToken(env.DB, user.id, refreshData, ip, getUA(request));

  return Response.json({
    success:       true,
    access_token:  accessToken,
    refresh_token: refreshData.token,
    token_type:    'Bearer',
    expires_in:    900,
    user: {
      id:        user.id,
      email:     user.email,
      tier:      user.tier,
      full_name: user.full_name || null,
    },
  }, { status: 200 });
}

// ─── POST /api/auth/refresh ───────────────────────────────────────────────────
export async function handleRefresh(request, env) {
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body  = await parseBody(request);
  const token = body?.refresh_token || '';

  if (!token || token.length < 40) {
    return Response.json({ error: 'refresh_token required' }, { status: 400 });
  }

  const row = await validateRefreshToken(env.DB, token);
  if (!row) {
    return Response.json({
      error: 'Invalid or expired refresh token',
      hint:  'Re-authenticate via /api/auth/login',
    }, { status: 401 });
  }

  // Rotate: revoke old, issue new
  await revokeRefreshToken(env.DB, token);
  const newRefresh = await createRefreshToken();
  const newAccess  = await createAccessToken(
    { id: row.uid, email: row.email, tier: row.tier },
    env.JWT_SECRET
  );
  await storeRefreshToken(env.DB, row.uid, newRefresh, getClientIP(request), getUA(request));

  return Response.json({
    access_token:  newAccess,
    refresh_token: newRefresh.token,
    token_type:    'Bearer',
    expires_in:    900,
  }, { status: 200 });
}

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
export async function handleLogout(request, env, authCtx) {
  if (!env?.DB) return Response.json({ success: true }, { status: 200 });

  const body    = await parseBody(request);
  const logoutAll = body?.all === true;

  if (logoutAll && authCtx.user_id) {
    await revokeAllUserTokens(env.DB, authCtx.user_id);
    return Response.json({ success: true, message: 'All sessions revoked' });
  }

  const token = body?.refresh_token || '';
  if (token) await revokeRefreshToken(env.DB, token);

  return Response.json({ success: true, message: 'Logged out' });
}

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
export async function handleGetProfile(request, env, authCtx) {
  if (!authCtx.user_id) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const user = await env.DB.prepare(
    `SELECT id, email, tier, status, full_name, company, telegram_chat_id, alert_email,
            email_verified, created_at, last_login_at, login_count
     FROM users WHERE id = ?`
  ).bind(authCtx.user_id).first();

  if (!user) return Response.json({ error: 'User not found' }, { status: 404 });

  // Scan stats
  let scanStats = null;
  try {
    scanStats = await env.DB.prepare(
      `SELECT module, COUNT(*) as count FROM scan_history
       WHERE user_id = ? GROUP BY module ORDER BY count DESC`
    ).bind(authCtx.user_id).all();
  } catch {}

  return Response.json({
    id:              user.id,
    email:           user.email,
    tier:            user.tier,
    status:          user.status,
    full_name:       user.full_name,
    company:         user.company,
    telegram_chat_id: user.telegram_chat_id,
    alert_email:     user.alert_email,
    email_verified:  !!user.email_verified,
    member_since:    user.created_at,
    last_login_at:   user.last_login_at,
    login_count:     user.login_count,
    scan_stats:      scanStats?.results ?? [],
    platform_url:    PLATFORM_URL,
  });
}

// ─── PUT /api/auth/profile ────────────────────────────────────────────────────
export async function handleUpdateProfile(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body = await parseBody(request);
  const updates = {};

  if (typeof body?.full_name === 'string')  updates.full_name  = body.full_name.slice(0, 100);
  if (typeof body?.company    === 'string')  updates.company    = body.company.slice(0, 100);
  if (typeof body?.telegram_chat_id === 'string') updates.telegram_chat_id = body.telegram_chat_id.slice(0, 50);
  if (typeof body?.alert_email === 'string') {
    const ev = validateEmail(body.alert_email);
    if (ev.valid) updates.alert_email = ev.value;
  }

  if (Object.keys(updates).length === 0) {
    return Response.json({ error: 'No valid fields to update' }, { status: 400 });
  }

  updates.updated_at = new Date().toISOString().replace('T',' ').replace('Z','');
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values     = [...Object.values(updates), authCtx.user_id];

  try {
    await env.DB.prepare(`UPDATE users SET ${setClauses} WHERE id = ?`).bind(...values).run();
  } catch (e) {
    console.error('[Auth] updateProfile DB error:', e?.message);
    return Response.json({ error: 'Profile update failed', detail: 'Database error' }, { status: 500 });
  }

  return Response.json({ success: true, updated: Object.keys(updates) });
}

// ─── POST /api/auth/alerts ────────────────────────────────────────────────────
export async function handleAlertConfig(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body = await parseBody(request);

  const config = {
    telegram_enabled: body?.telegram_enabled === true ? 1 : 0,
    telegram_chat_id: (body?.telegram_chat_id || '').toString().slice(0, 50) || null,
    email_enabled:    body?.email_enabled === true ? 1 : 0,
    alert_email:      null,
    min_risk_score:   Math.min(100, Math.max(0, parseInt(body?.min_risk_score ?? 70, 10))),
    alert_on_blacklist: body?.alert_on_blacklist !== false ? 1 : 0,
    alert_on_critical_cve: body?.alert_on_critical_cve !== false ? 1 : 0,
    updated_at: new Date().toISOString().replace('T',' ').replace('Z',''),
  };

  if (body?.alert_email) {
    const ev = validateEmail(body.alert_email);
    if (ev.valid) config.alert_email = ev.value;
  }

  await env.DB.prepare(
    `INSERT INTO alert_configs
     (user_id, telegram_enabled, telegram_chat_id, email_enabled, alert_email, min_risk_score, alert_on_blacklist, alert_on_critical_cve)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       telegram_enabled = excluded.telegram_enabled,
       telegram_chat_id = excluded.telegram_chat_id,
       email_enabled    = excluded.email_enabled,
       alert_email      = excluded.alert_email,
       min_risk_score   = excluded.min_risk_score,
       alert_on_blacklist = excluded.alert_on_blacklist,
       alert_on_critical_cve = excluded.alert_on_critical_cve,
       updated_at       = excluded.updated_at`
  ).bind(
    authCtx.user_id,
    config.telegram_enabled, config.telegram_chat_id,
    config.email_enabled, config.alert_email,
    config.min_risk_score, config.alert_on_blacklist, config.alert_on_critical_cve,
  ).run();

  return Response.json({ success: true, config: { ...config, user_id: authCtx.user_id } });
}

// ─── POST /api/auth/test-alert ────────────────────────────────────────────────
export async function handleTestAlert(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  const result = await sendTestAlert(env, authCtx.user_id);
  return Response.json(result, { status: result.success ? 200 : 422 });
}

// ─── POST /api/auth/change-password ───────────────────────────────────────────
// Was called by user-dashboard.html's Account Settings page with no backend
// route ever registered — every "Change Password" click 404'd in production.
export async function handleChangePassword(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body = await parseBody(request);
  const currentPassword = body?.current_password || '';
  const newPassword     = body?.new_password || '';
  if (!currentPassword || !newPassword) {
    return Response.json({ error: 'current_password and new_password are required' }, { status: 400 });
  }

  const strength = validatePasswordStrength(newPassword);
  if (!strength.valid) {
    return Response.json({ error: strength.message || 'Password does not meet strength requirements' }, { status: 400 });
  }

  const user = await env.DB.prepare(
    `SELECT id, password_hash, password_salt FROM users WHERE id = ?`
  ).bind(authCtx.user_id).first();
  if (!user) return Response.json({ error: 'User not found' }, { status: 404 });

  const currentValid = await verifyPassword(currentPassword, user.password_hash, user.password_salt);
  if (!currentValid) return Response.json({ error: 'Current password is incorrect' }, { status: 403 });

  const { hash, salt } = await hashPassword(newPassword);
  await env.DB.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`
  ).bind(hash, salt, authCtx.user_id).run();

  // Revoke all other sessions — a password change should not leave old
  // refresh tokens (e.g. from a compromised device) valid.
  await revokeAllUserTokens(env.DB, authCtx.user_id).catch(() => {});

  return Response.json({ success: true, message: 'Password updated. Other sessions have been signed out.' });
}

// ─── POST /api/auth/forgot-password ───────────────────────────────────────────
// Phase X GA gap: there was NO credential recovery — a customer who forgot
// their password permanently lost the account (all standard reset paths 404'd
// in production and the login UI had no affordance). Tokens are single-use,
// KV-stored by SHA-256 hash with a 30-minute TTL — no schema migration needed.
// The response is identical whether or not the account exists (no enumeration
// oracle), and requests are rate-limited per email.
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

const RESET_GENERIC = {
  success: true,
  message: 'If that email has an account, a password-reset link has been sent. It expires in 30 minutes.',
};

export async function handleForgotPassword(request, env) {
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body  = await parseBody(request);
  const email = (body?.email || '').trim().toLowerCase();
  const emailVal = validateEmail(email);
  if (!emailVal.valid) {
    return Response.json({ error: emailVal.message || 'A valid email is required' }, { status: 400 });
  }

  // Everything below returns the same generic 200 — existence is never revealed.
  if (!env.SECURITY_HUB_KV) return Response.json(RESET_GENERIC);

  const rlKey = `pwreset-rl:${email}`;
  const attempts = parseInt(await env.SECURITY_HUB_KV.get(rlKey) || '0', 10);
  if (attempts >= 3) return Response.json(RESET_GENERIC);
  await env.SECURITY_HUB_KV.put(rlKey, String(attempts + 1), { expirationTtl: 3600 });

  const user = await env.DB.prepare(
    `SELECT id, email, status FROM users WHERE email = ?`
  ).bind(email).first();
  if (!user || user.status !== 'active') return Response.json(RESET_GENERIC);

  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const token = [...tokenBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  await env.SECURITY_HUB_KV.put(
    `pwreset:${await sha256Hex(token)}`,
    JSON.stringify({ user_id: user.id, email: user.email }),
    { expirationTtl: 1800 }
  );

  const resetUrl = `https://cyberdudebivash.in/user-dashboard.html?reset_token=${token}`;
  await sendEmail(env, {
    to: user.email,
    subject: 'Reset your CYBERDUDEBIVASH password',
    text: `A password reset was requested for this account.\n\nReset link (valid 30 minutes, single use):\n${resetUrl}\n\nIf you did not request this, ignore this email — your password is unchanged.`,
    html: `<p>A password reset was requested for this account.</p><p><a href="${resetUrl}">Reset your password</a> (valid 30 minutes, single use).</p><p>If you did not request this, ignore this email — your password is unchanged.</p>`,
  }).catch(() => {});

  return Response.json(RESET_GENERIC);
}

// ─── POST /api/auth/reset-password ──────────────────────────────────────────
export async function handleResetPassword(request, env) {
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!env?.SECURITY_HUB_KV) return Response.json({ error: 'Password reset unavailable' }, { status: 503 });

  const body        = await parseBody(request);
  const token       = body?.token || '';
  const newPassword = body?.new_password || '';
  if (!token || !newPassword) {
    return Response.json({ error: 'token and new_password are required' }, { status: 400 });
  }

  const strength = validatePasswordStrength(newPassword);
  if (!strength.valid) {
    return Response.json({ error: strength.message || 'Password does not meet strength requirements' }, { status: 400 });
  }

  const kvKey = `pwreset:${await sha256Hex(token)}`;
  const rec   = await env.SECURITY_HUB_KV.get(kvKey, { type: 'json' });
  if (!rec?.user_id) {
    return Response.json({ error: 'Invalid or expired reset link. Request a new one.' }, { status: 400 });
  }
  // Single use: consume the token before changing anything.
  await env.SECURITY_HUB_KV.delete(kvKey);

  const { hash, salt } = await hashPassword(newPassword);
  await env.DB.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`
  ).bind(hash, salt, rec.user_id).run();

  // A recovered account must not leave possibly-compromised sessions alive.
  await revokeAllUserTokens(env.DB, rec.user_id).catch(() => {});

  return Response.json({
    success: true,
    message: 'Password reset. Sign in with your new password. All previous sessions have been signed out.',
  });
}

// ─── DELETE /api/auth/delete-account ──────────────────────────────────────────
// Was called by user-dashboard.html's danger-zone "Delete Account" action with
// no backend route ever registered — a real DPDP/GDPR-relevant gap: the site
// markets DPDP Act 2023 compliance while the account-deletion button 404'd.
// Anonymizes PII rather than hard-deleting the row, preserving billing/audit
// records required for tax and dispute-resolution retention, consistent with
// how the platform already retains scan_history/payments for other users.
export async function handleDeleteAccount(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const userId = authCtx.user_id;
  const anonEmail = `deleted-${userId}@deleted.cyberdudebivash.in`;

  // users.status has a CHECK constraint of ('active','suspended','unverified')
  // — there is no 'deleted' state without a schema migration. 'suspended'
  // (already used to lock out accounts elsewhere) plus PII anonymization is
  // the correct existing-schema representation of a deleted account.
  await env.DB.prepare(
    `UPDATE users SET
       email = ?, password_hash = 'DELETED', password_salt = 'DELETED',
       full_name = NULL, company = NULL, telegram_chat_id = NULL,
       alert_email = NULL, status = 'suspended', updated_at = datetime('now')
     WHERE id = ?`
  ).bind(anonEmail, userId).run();

  await revokeAllUserTokens(env.DB, userId).catch(() => {});

  // GDPR right-to-erasure: purge the user's personal, non-legally-retained data
  // keyed by user_id, not just the (now-anonymized) users row. Previously these
  // survived deletion — the user's scan targets/findings, async job records,
  // generated reports, and (most sensitively) their MFA/TOTP secret. Each is
  // fault-isolated so a missing table can't abort the erasure. Payments /
  // GST invoices are intentionally RETAINED (statutory tax-record retention).
  const purge = ['api_keys', 'scan_history', 'scan_jobs', 'report_jobs', 'mfa_secrets'];
  const purged = {};
  for (const table of purge) {
    try {
      const r = await env.DB.prepare(`DELETE FROM ${table} WHERE user_id = ?`).bind(userId).run();
      purged[table] = r?.meta?.changes ?? 0;
    } catch { purged[table] = 'skipped'; }
  }

  return Response.json({
    success: true,
    message: 'Account deleted. Your personal data has been erased and you have been signed out.',
    erased: purged,
    retained: 'Payment/GST invoice records are retained where required by tax law (anonymized where possible).',
  });
}
