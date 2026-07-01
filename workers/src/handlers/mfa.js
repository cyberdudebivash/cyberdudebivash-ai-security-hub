/**
 * CYBERDUDEBIVASH AI Security Hub — MFA Handler (TOTP)
 *
 * POST /api/auth/mfa/setup           — generate secret + QR URL (auth required)
 * POST /api/auth/mfa/enable          — confirm TOTP code → enable + return backup codes
 * POST /api/auth/mfa/authenticate    — exchange mfa_challenge_token + TOTP/backup code for real tokens
 * POST /api/auth/mfa/disable         — disable MFA (requires TOTP + password re-confirm)
 * GET  /api/auth/mfa/status          — is MFA enabled for the current user?
 */

import {
  generateSecret, verifyTOTP, buildOtpauthUrl,
  generateBackupCodes, hashBackupCode, verifyBackupCode,
} from '../lib/totp.js';
import { createAccessToken, createRefreshToken, storeRefreshToken } from '../auth/jwt.js';
import { verifyPassword } from '../auth/password.js';
import { parseBody } from '../middleware/validation.js';
import { logSystemError } from '../lib/errorLog.js';

function getClientIP(r) {
  return r.headers.get('CF-Connecting-IP') || r.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
}

// KV key for MFA setup pending secret (TTL 10 min — user must confirm within 10 min of setup)
const SETUP_TTL   = 600;
// KV key for MFA challenge token issued during login (TTL 5 min)
const CHALLENGE_TTL = 300;

// ─── GET /api/auth/mfa/status ─────────────────────────────────────────────────
export async function handleMFAStatus(request, env, authCtx) {
  const row = await env.DB.prepare(
    'SELECT enabled, created_at FROM mfa_secrets WHERE user_id = ?'
  ).bind(authCtx.userId).first().catch(() => null);

  return Response.json({
    mfa_enabled: !!(row?.enabled),
    enrolled_at: row?.enabled ? row.created_at : null,
  });
}

// ─── POST /api/auth/mfa/setup ─────────────────────────────────────────────────
// Generates a fresh TOTP secret and stores it pending confirmation.
// Does NOT enable MFA yet — user must call /enable with a valid code.
export async function handleMFASetup(request, env, authCtx) {
  const existing = await env.DB.prepare(
    'SELECT enabled FROM mfa_secrets WHERE user_id = ?'
  ).bind(authCtx.userId).first().catch(() => null);

  if (existing?.enabled) {
    return Response.json({ error: 'MFA is already enabled. Disable it first.' }, { status: 409 });
  }

  const secret = generateSecret();
  const otpauthUrl = buildOtpauthUrl(secret, authCtx.email);

  // Store pending secret in KV (not D1 — not committed until user confirms)
  await env.KV.put(`mfa_setup:${authCtx.userId}`, JSON.stringify({ secret }), { expirationTtl: SETUP_TTL });

  return Response.json({
    secret,
    otpauth_url: otpauthUrl,
    qr_hint: `Scan the otpauth_url with your authenticator app (Google Authenticator, Authy, 1Password, Bitwarden, etc.) or manually enter the secret.`,
    expires_in: SETUP_TTL,
    next_step: 'POST /api/auth/mfa/enable with { totp_code: "<6-digit code from your app>" }',
  });
}

// ─── POST /api/auth/mfa/enable ────────────────────────────────────────────────
// User scanned the QR code and provides a valid TOTP to confirm setup.
// On success: persists the secret, marks enabled=1, returns one-time backup codes.
export async function handleMFAEnable(request, env, authCtx) {
  const body = await parseBody(request);
  const token = (body?.totp_code || '').trim();
  if (!/^\d{6}$/.test(token)) {
    return Response.json({ error: 'totp_code must be 6 digits' }, { status: 400 });
  }

  const pending = await env.KV.get(`mfa_setup:${authCtx.userId}`, 'json');
  if (!pending?.secret) {
    return Response.json({
      error: 'No pending MFA setup found. Call POST /api/auth/mfa/setup first.',
    }, { status: 400 });
  }

  const valid = await verifyTOTP(pending.secret, token);
  if (!valid) {
    return Response.json({ error: 'Invalid TOTP code. Check your authenticator app clock.' }, { status: 401 });
  }

  // Generate backup codes — shown once, never retrievable again
  const backupCodes = generateBackupCodes(8);
  const hashedCodes = await Promise.all(backupCodes.map(hashBackupCode));

  try {
    await env.DB.prepare(`
      INSERT INTO mfa_secrets (user_id, secret, backup_codes, enabled, created_at, updated_at)
      VALUES (?, ?, ?, 1, datetime('now'), datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        secret = excluded.secret,
        backup_codes = excluded.backup_codes,
        enabled = 1,
        updated_at = datetime('now')
    `).bind(authCtx.userId, pending.secret, JSON.stringify(hashedCodes)).run();
  } catch (e) {
    await logSystemError(env, { area: 'mfa.enable', message: e.message, context: { userId: authCtx.userId }, notify: false });
    return Response.json({ error: 'Failed to enable MFA — try again' }, { status: 500 });
  }

  // Clean up pending setup key
  await env.KV.delete(`mfa_setup:${authCtx.userId}`).catch(() => {});

  return Response.json({
    success: true,
    message: 'MFA enabled successfully.',
    backup_codes: backupCodes,
    backup_codes_warning: 'Store these backup codes securely. They will NOT be shown again. Each code can only be used once.',
  });
}

// ─── POST /api/auth/mfa/authenticate ─────────────────────────────────────────
// Called after a successful password login when MFA is required.
// Body: { mfa_challenge_token, totp_code } OR { mfa_challenge_token, backup_code }
export async function handleMFAAuthenticate(request, env) {
  const body = await parseBody(request);
  const challengeToken = (body?.mfa_challenge_token || '').trim().slice(0, 128);
  const totpCode       = (body?.totp_code   || '').trim().slice(0, 8);   // TOTP is always 6 digits
  const backupCode     = (body?.backup_code || '').trim().slice(0, 20);  // XXXX-XXXX format = 9 chars

  if (!challengeToken) {
    return Response.json({ error: 'mfa_challenge_token required' }, { status: 400 });
  }
  if (!totpCode && !backupCode) {
    return Response.json({ error: 'totp_code or backup_code required' }, { status: 400 });
  }
  // Validate lengths after trimming — reject obviously wrong values early
  if (totpCode && !/^\d{6}$/.test(totpCode)) {
    return Response.json({ error: 'totp_code must be 6 digits' }, { status: 400 });
  }
  if (backupCode && backupCode.length > 20) {
    return Response.json({ error: 'backup_code invalid format' }, { status: 400 });
  }

  const kvKey = `mfa_challenge:${challengeToken}`;
  const challenge = await env.KV.get(kvKey, 'json');
  if (!challenge?.userId) {
    return Response.json({
      error: 'MFA challenge expired or invalid. Please log in again.',
      hint: 'POST /api/auth/login',
    }, { status: 401 });
  }

  // One-time use — delete immediately before verifying to prevent replay
  await env.KV.delete(kvKey).catch(() => {});

  const mfaRow = await env.DB.prepare(
    'SELECT secret, backup_codes FROM mfa_secrets WHERE user_id = ? AND enabled = 1'
  ).bind(challenge.userId).first().catch(() => null);

  if (!mfaRow) {
    return Response.json({ error: 'MFA configuration not found' }, { status: 500 });
  }

  let authenticated = false;
  let usedBackupCode = false;

  if (totpCode) {
    authenticated = await verifyTOTP(mfaRow.secret, totpCode);
  } else if (backupCode) {
    const hashedCodes = JSON.parse(mfaRow.backup_codes || '[]');
    authenticated = await verifyBackupCode(backupCode, hashedCodes);
    if (authenticated) {
      usedBackupCode = true;
      // Burn the used backup code so it can't be replayed
      const { hashBackupCode: hbc } = await import('../lib/totp.js');
      const usedHash = await hbc(backupCode);
      const remaining = hashedCodes.filter(h => h !== usedHash);
      await env.DB.prepare(
        'UPDATE mfa_secrets SET backup_codes = ?, updated_at = datetime(\'now\') WHERE user_id = ?'
      ).bind(JSON.stringify(remaining), challenge.userId).run().catch(() => {});
    }
  }

  if (!authenticated) {
    return Response.json({ error: 'Invalid MFA code' }, { status: 401 });
  }

  // Issue real tokens
  const user = await env.DB.prepare(
    'SELECT id, email, tier, full_name FROM users WHERE id = ?'
  ).bind(challenge.userId).first();

  const accessToken = await createAccessToken(user, env.JWT_SECRET);
  const refreshData = await createRefreshToken();
  await storeRefreshToken(env.DB, user.id, refreshData, getClientIP(request), request.headers.get('User-Agent') || '');

  return Response.json({
    success: true,
    access_token:  accessToken,
    refresh_token: refreshData.token,
    token_type:    'Bearer',
    expires_in:    900,
    user: { id: user.id, email: user.email, tier: user.tier, full_name: user.full_name || null },
    ...(usedBackupCode ? { warning: 'Backup code used and burned. Please generate new backup codes if running low.' } : {}),
  });
}

// ─── POST /api/auth/mfa/disable ───────────────────────────────────────────────
// Requires current TOTP code AND password re-confirmation — cannot be disabled accidentally.
export async function handleMFADisable(request, env, authCtx) {
  const body      = await parseBody(request);
  const totpCode  = (body?.totp_code || '').trim();
  const password  = body?.password || '';

  if (!totpCode || !password) {
    return Response.json({ error: 'totp_code and password required to disable MFA' }, { status: 400 });
  }

  // Re-verify password
  const user = await env.DB.prepare(
    'SELECT password_hash, password_salt FROM users WHERE id = ?'
  ).bind(authCtx.userId).first().catch(() => null);

  if (!user) return Response.json({ error: 'User not found' }, { status: 404 });

  const passwordOk = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!passwordOk) {
    return Response.json({ error: 'Incorrect password' }, { status: 401 });
  }

  const mfaRow = await env.DB.prepare(
    'SELECT secret FROM mfa_secrets WHERE user_id = ? AND enabled = 1'
  ).bind(authCtx.userId).first().catch(() => null);

  if (!mfaRow) {
    return Response.json({ error: 'MFA is not enabled' }, { status: 400 });
  }

  const valid = await verifyTOTP(mfaRow.secret, totpCode);
  if (!valid) {
    return Response.json({ error: 'Invalid TOTP code' }, { status: 401 });
  }

  await env.DB.prepare(
    'UPDATE mfa_secrets SET enabled = 0, updated_at = datetime(\'now\') WHERE user_id = ?'
  ).bind(authCtx.userId).run();

  return Response.json({ success: true, message: 'MFA disabled.' });
}

// ─── Exported helper used by auth/login ──────────────────────────────────────
// Returns a challenge token if MFA is enabled for this user; null otherwise.
export async function issueMFAChallenge(env, userId, email, tier) {
  const mfaRow = await env.DB.prepare(
    'SELECT id FROM mfa_secrets WHERE user_id = ? AND enabled = 1'
  ).bind(userId).first().catch(() => null);

  if (!mfaRow) return null;

  const token = Array.from(crypto.getRandomValues(new Uint8Array(24)))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  await env.KV.put(
    `mfa_challenge:${token}`,
    JSON.stringify({ userId, email, tier }),
    { expirationTtl: CHALLENGE_TTL }
  );
  return token;
}
