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

const CONTACT_EMAIL = 'bivash@cyberdudebivash.com';
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

  // Hash password (PBKDF2 — takes ~50ms on paid Workers)
  const { hash, salt } = await hashPassword(rawPass);

  // Insert user
  let userId;
  try {
    const result = await env.DB.prepare(
      `INSERT INTO users (email, password_hash, password_salt, full_name, company, tier, status)
       VALUES (?, ?, ?, ?, ?, 'FREE', 'active')
       RETURNING id`
    ).bind(email, hash, salt, fullName.slice(0,100) || null, company.slice(0,100) || null).first();
    userId = result?.id;
  } catch (e) {
    if (e?.message?.includes('UNIQUE')) {
      return Response.json({ error: 'Email already registered' }, { status: 409 });
    }
    return Response.json({ error: 'Registration failed — try again' }, { status: 500 });
  }

  if (!userId) {
    return Response.json({ error: 'Registration failed' }, { status: 500 });
  }

  // Auto-create first API key (fire-and-forget)
  createApiKey(env.DB, userId, 'FREE', 'Default Key').catch(() => {});

  // Generate tokens
  const accessToken  = await createAccessToken({ id: userId, email, tier: 'FREE' }, env.JWT_SECRET);
  const refreshData  = await createRefreshToken();
  const ip           = getClientIP(request);
  const ua           = getUA(request);
  await storeRefreshToken(env.DB, userId, refreshData, ip, ua);

  return Response.json({
    success:       true,
    message:       'Account created successfully',
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
    next_steps: [
      'Use access_token in Authorization: Bearer header',
      `Generate API keys at ${PLATFORM_URL}/keys`,
      `Start scanning at POST /api/scan/domain`,
    ],
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

  await env.DB.prepare(`UPDATE users SET ${setClauses} WHERE id = ?`).bind(...values).run();

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
