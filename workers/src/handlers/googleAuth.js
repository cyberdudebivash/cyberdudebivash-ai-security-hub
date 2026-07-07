/**
 * CYBERDUDEBIVASH AI Security Hub — Google OAuth2 SSO Handler
 * GET /api/auth/google          → initiate OAuth2 flow (redirect to Google)
 * GET /api/auth/google/callback → exchange code, provision user, issue JWT
 *
 * Requires Wrangler secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 * Redirect URI registered in Google Cloud Console:
 *   https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/google/callback
 */

import { createAccessToken, createRefreshToken, storeRefreshToken } from '../auth/jwt.js';
import { createApiKey } from '../auth/apiKeys.js';

const GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO  = 'https://www.googleapis.com/oauth2/v3/userinfo';
const SCOPES           = 'openid email profile';
const STATE_TTL        = 600; // 10 minutes

const CALLBACK_URL     = 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/google/callback';

function getFrontendURL(env) {
  // WEBSITE is the Cloudflare Pages site (cyberdudebivash.in) — use it for auth callbacks
  // TOOLS_URL (tools.cyberdudebivash.com) is on Gumroad and can't host custom pages
  return (env?.WEBSITE || 'https://cyberdudebivash.in').replace(/\/$/, '');
}

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
}

// ─── GET /api/auth/google — initiate OAuth2 redirect ─────────────────────────
export async function handleGoogleOAuth(request, env) {
  if (!env.GOOGLE_CLIENT_ID) {
    return Response.json({
      error: 'Google SSO not configured. Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET secrets.',
    }, { status: 503 });
  }

  // Generate cryptographically random state token → store in KV with 10-min TTL
  const stateBytes = new Uint8Array(32);
  crypto.getRandomValues(stateBytes);
  const state = [...stateBytes].map(b => b.toString(16).padStart(2, '0')).join('');

  if (env.KV) {
    await env.KV.put(`google_oauth_state:${state}`, '1', { expirationTtl: STATE_TTL });
  }

  const params = new URLSearchParams({
    client_id:     env.GOOGLE_CLIENT_ID,
    redirect_uri:  CALLBACK_URL,
    response_type: 'code',
    scope:         SCOPES,
    state,
    access_type:   'offline',
    prompt:        'select_account',
  });

  return Response.redirect(`${GOOGLE_AUTH_URL}?${params.toString()}`, 302);
}

// ─── GET /api/auth/google/callback — exchange code + provision user ───────────
export async function handleGoogleCallback(request, env) {
  const url   = new URL(request.url);
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  const FRONTEND_URL = getFrontendURL(env);
  const redirectFail = (msg) =>
    Response.redirect(`${FRONTEND_URL}/auth/callback?reason=${encodeURIComponent(msg)}`, 302);

  if (error) return redirectFail(error);
  if (!code || !state) return redirectFail('missing_params');

  // Verify CSRF state
  if (env.KV) {
    const stored = await env.KV.get(`google_oauth_state:${state}`);
    if (!stored) return redirectFail('invalid_state');
    await env.KV.delete(`google_oauth_state:${state}`); // one-time use
  }

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    return redirectFail('sso_not_configured');
  }

  // Exchange code for tokens
  let googleTokens;
  try {
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri:  CALLBACK_URL,
        grant_type:    'authorization_code',
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      throw new Error(`Token exchange failed: ${txt.slice(0, 200)}`);
    }
    googleTokens = await tokenRes.json();
  } catch (e) {
    return redirectFail('token_exchange_failed');
  }

  // Fetch user info
  let googleUser;
  try {
    const uiRes = await fetch(GOOGLE_USERINFO, {
      headers: { Authorization: `Bearer ${googleTokens.access_token}` },
      signal: AbortSignal.timeout(8000),
    });
    if (!uiRes.ok) throw new Error('userinfo_fetch_failed');
    googleUser = await uiRes.json();
  } catch {
    return redirectFail('userinfo_failed');
  }

  const email    = googleUser.email?.toLowerCase();
  const name     = googleUser.name || '';
  const googleId = googleUser.sub;
  const avatar   = googleUser.picture || null;

  if (!email || !googleId) return redirectFail('invalid_google_user');

  if (!env.DB) return redirectFail('database_unavailable');

  // Find or create user
  let userId, tier;
  try {
    const existing = await env.DB.prepare(
      `SELECT id, tier FROM users WHERE email = ? OR google_id = ?`
    ).bind(email, googleId).first();

    if (existing) {
      userId = existing.id;
      tier   = existing.tier || 'FREE';
      // Update google_id + avatar if missing
      await env.DB.prepare(
        `UPDATE users SET google_id = ?, avatar_url = ?, updated_at = datetime('now')
         WHERE id = ? AND (google_id IS NULL OR google_id != ?)`
      ).bind(googleId, avatar, userId, googleId).run().catch(() => {});
    } else {
      userId = crypto.randomUUID();
      tier   = 'FREE';
      await env.DB.prepare(
        `INSERT INTO users (id, email, full_name, google_id, avatar_url, tier, status, created_at)
         VALUES (?, ?, ?, ?, ?, 'FREE', 'active', datetime('now'))`
      ).bind(userId, email, name, googleId, avatar).run();

      // Auto-provision first API key for new SSO users
      try { await createApiKey(env.DB, userId, 'FREE', 'SSO Default Key'); } catch (_) {}
    }
  } catch (e) {
    return redirectFail('db_error');
  }

  // Issue platform JWT + refresh token
  const accessToken = await createAccessToken(
    { id: userId, email, tier, sso: 'google' },
    env.JWT_SECRET
  );
  const refreshData = await createRefreshToken();
  const ip          = getClientIP(request);
  await storeRefreshToken(env.DB, userId, refreshData, ip, 'google-sso').catch(() => {});

  // Store refresh token in KV for fast lookup (7-day TTL)
  if (env.KV) {
    await env.KV.put(`sso_session:${refreshData.token}`, JSON.stringify({
      user_id:       userId,
      email,
      tier,
      access_token:  accessToken,
      refresh_token: refreshData.token,
    }), { expirationTtl: 7 * 24 * 3600 });
  }

  // Redirect to frontend with tokens in URL fragment (never in query string)
  const successUrl = `${FRONTEND_URL}/auth/callback#access_token=${encodeURIComponent(accessToken)}&refresh_token=${encodeURIComponent(refreshData.token)}&tier=${tier}&sso=google`;
  return Response.redirect(successUrl, 302);
}
