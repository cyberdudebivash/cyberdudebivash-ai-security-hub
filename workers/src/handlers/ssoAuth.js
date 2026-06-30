/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise SSO (OIDC) Handler v1.0
 *
 * Customer-facing login:
 *   GET  /api/auth/sso/login?org=<slug>       → discover IdP, redirect with PKCE
 *   GET  /api/auth/sso/callback               → exchange code, verify, issue JWT
 *
 * Owner-only configuration (each enterprise customer's org registers their own IdP):
 *   POST   /api/admin/sso/config              → upsert an org's OIDC config
 *   GET    /api/admin/sso/config?org=<slug>   → view config (secret redacted)
 *   DELETE /api/admin/sso/config?org=<slug>   → disable SSO for an org
 *
 * Requires no platform-wide secrets — each org brings its own IdP client_id/secret,
 * stored per-org in D1 (sso_configs table), entered via the owner-only config API.
 */

import { discoverOIDC, generatePKCE, generateState, buildAuthUrl, exchangeCode, verifyIdToken } from '../lib/oidc.js';
import { createAccessToken, createRefreshToken, storeRefreshToken } from '../auth/jwt.js';
import { createApiKey } from '../auth/apiKeys.js';
import { isOwner } from '../auth/middleware.js';
import { logSystemError } from '../lib/errorLog.js';

// Matches the existing googleAuth.js pattern: the Workers subdomain is the
// registered redirect URI (the IdP must allow-list this exact URL), not the
// Pages frontend — Pages can't host the OIDC token-exchange callback.
const SSO_CALLBACK_URL = 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/sso/callback';

function getFrontendURL(env) {
  return (env?.WEBSITE || 'https://cyberdudebivash.in').replace(/\/$/, '');
}
function getCallbackURL() {
  return SSO_CALLBACK_URL;
}
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
}
function json(data, status = 200) {
  return Response.json(data, { status });
}

// ─── GET /api/auth/sso/login?org=<slug> ────────────────────────────────────
export async function handleSSOLogin(request, env) {
  const url = new URL(request.url);
  const orgSlug = url.searchParams.get('org');
  if (!orgSlug) return json({ error: 'org query parameter required (your organization slug)' }, 400);
  if (!env.DB) return json({ error: 'Service temporarily unavailable' }, 503);

  const org = await env.DB.prepare(`SELECT id, slug, name FROM organizations WHERE slug = ?`).bind(orgSlug).first();
  if (!org) return json({ error: 'Organization not found' }, 404);

  const config = await env.DB.prepare(
    `SELECT * FROM sso_configs WHERE org_id = ? AND enabled = 1`
  ).bind(org.id).first();
  if (!config) return json({ error: 'SSO is not configured for this organization. Contact your account administrator.' }, 404);

  let discovery;
  try {
    discovery = await discoverOIDC(config.issuer, env.SECURITY_HUB_KV);
  } catch (e) {
    await logSystemError(env, { area: 'sso.discovery', message: e.message, context: { org: orgSlug, issuer: config.issuer } });
    return json({ error: 'Unable to reach your identity provider. Please try again or contact support.' }, 502);
  }

  const { codeVerifier, codeChallenge } = await generatePKCE();
  const state = generateState();
  const nonce = generateState();

  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`sso_state:${state}`, JSON.stringify({
      org_id: org.id, org_slug: orgSlug, code_verifier: codeVerifier, nonce,
    }), { expirationTtl: 600 });
  }

  const authUrl = buildAuthUrl(discovery, {
    clientId:      config.client_id,
    redirectUri:   getCallbackURL(env),
    state,
    codeChallenge,
  });

  return Response.redirect(`${authUrl}&nonce=${encodeURIComponent(nonce)}`, 302);
}

// ─── GET /api/auth/sso/callback ─────────────────────────────────────────────
export async function handleSSOCallback(request, env) {
  const url   = new URL(request.url);
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  const FRONTEND_URL = getFrontendURL(env);
  const redirectFail = (reason) =>
    Response.redirect(`${FRONTEND_URL}/auth/callback?reason=${encodeURIComponent(reason)}`, 302);

  if (error) return redirectFail(`sso_error:${error}`);
  if (!code || !state) return redirectFail('missing_params');
  if (!env.DB || !env.SECURITY_HUB_KV) return redirectFail('service_unavailable');

  const stateData = await env.SECURITY_HUB_KV.get(`sso_state:${state}`, 'json').catch(() => null);
  if (!stateData) return redirectFail('invalid_or_expired_state');
  await env.SECURITY_HUB_KV.delete(`sso_state:${state}`); // one-time use

  const config = await env.DB.prepare(
    `SELECT * FROM sso_configs WHERE org_id = ? AND enabled = 1`
  ).bind(stateData.org_id).first();
  if (!config) return redirectFail('sso_disabled');

  let discovery;
  try {
    discovery = await discoverOIDC(config.issuer, env.SECURITY_HUB_KV);
  } catch (e) {
    await logSystemError(env, { area: 'sso.callback_discovery', message: e.message, context: { org_id: stateData.org_id } });
    return redirectFail('idp_unreachable');
  }

  let tokens;
  try {
    tokens = await exchangeCode(discovery, {
      clientId:     config.client_id,
      clientSecret: config.client_secret,
      redirectUri:  getCallbackURL(env),
      code,
      codeVerifier: stateData.code_verifier,
    });
  } catch (e) {
    await logSystemError(env, { area: 'sso.token_exchange', message: e.message, context: { org_id: stateData.org_id } });
    return redirectFail('token_exchange_failed');
  }

  let claims;
  try {
    claims = await verifyIdToken(tokens.id_token, discovery, {
      clientId: config.client_id, kv: env.SECURITY_HUB_KV, expectedNonce: stateData.nonce,
    });
  } catch (e) {
    await logSystemError(env, { area: 'sso.id_token_verify', message: e.message, context: { org_id: stateData.org_id } });
    return redirectFail('id_token_invalid');
  }

  const email = claims.email?.toLowerCase();
  if (!email) return redirectFail('no_email_claim');

  // Domain enforcement: if the org restricts SSO to specific email domains, reject mismatches.
  if (config.allowed_domains) {
    const allowed = JSON.parse(config.allowed_domains || '[]');
    const emailDomain = email.split('@')[1];
    if (allowed.length > 0 && !allowed.includes(emailDomain)) {
      return redirectFail('domain_not_allowed');
    }
  }

  const org = await env.DB.prepare(`SELECT id, plan FROM organizations WHERE id = ?`).bind(stateData.org_id).first();
  if (!org) return redirectFail('org_not_found');

  // Find or create user, then ensure org membership (SSO-authenticated → trusted member).
  let userId, tier;
  try {
    const existing = await env.DB.prepare(`SELECT id, tier FROM users WHERE email = ?`).bind(email).first();
    if (existing) {
      userId = existing.id;
      tier   = existing.tier === 'FREE' ? org.plan : existing.tier; // SSO users get at least the org's plan
    } else {
      userId = crypto.randomUUID();
      tier   = org.plan || 'ENTERPRISE';
      await env.DB.prepare(
        `INSERT INTO users (id, email, full_name, tier, status, email_verified, created_at)
         VALUES (?, ?, ?, ?, 'active', 1, datetime('now'))`
      ).bind(userId, email, claims.name || '', tier).run();
      try { await createApiKey(env.DB, userId, tier, 'SSO Default Key'); } catch (_) {}
    }

    await env.DB.prepare(
      `INSERT INTO org_members (id, org_id, user_id, role, status, joined_at)
       VALUES (?, ?, ?, 'MEMBER', 'active', datetime('now'))
       ON CONFLICT(org_id, user_id) DO UPDATE SET status = 'active'`
    ).bind(crypto.randomUUID(), org.id, userId).run().catch(() => {});
  } catch (e) {
    await logSystemError(env, { area: 'sso.user_provision', message: e.message, context: { org_id: stateData.org_id, email } });
    return redirectFail('db_error');
  }

  const accessToken = await createAccessToken({ id: userId, email, tier, sso: 'oidc' }, env.JWT_SECRET);
  const refreshData = await createRefreshToken();
  await storeRefreshToken(env.DB, userId, refreshData, getClientIP(request), 'enterprise-sso').catch(() => {});

  const successUrl = `${FRONTEND_URL}/auth/callback#access_token=${encodeURIComponent(accessToken)}&refresh_token=${encodeURIComponent(refreshData.token)}&tier=${tier}&sso=oidc`;
  return Response.redirect(successUrl, 302);
}

// ─── POST /api/admin/sso/config (owner-only) — upsert an org's OIDC config ─
export async function handleSSOConfigUpsert(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return json({ error: 'Owner authorization required' }, 403);
  if (!env.DB) return json({ error: 'Service temporarily unavailable' }, 503);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const { org: orgSlug, issuer, client_id, client_secret, allowed_domains, provider_name } = body;
  if (!orgSlug || !issuer || !client_id || !client_secret) {
    return json({ error: 'org, issuer, client_id, client_secret are required' }, 400);
  }

  const org = await env.DB.prepare(`SELECT id FROM organizations WHERE slug = ?`).bind(orgSlug).first();
  if (!org) return json({ error: 'Organization not found' }, 404);

  // Validate the issuer is actually a working OIDC provider before saving — fail fast
  // rather than letting customers discover a typo'd issuer URL during their first login.
  try {
    await discoverOIDC(issuer, env.SECURITY_HUB_KV);
  } catch (e) {
    return json({ error: `Issuer validation failed: ${e.message}` }, 400);
  }

  const existing = await env.DB.prepare(`SELECT id FROM sso_configs WHERE org_id = ?`).bind(org.id).first();
  if (existing) {
    await env.DB.prepare(`
      UPDATE sso_configs SET issuer=?, client_id=?, client_secret=?, allowed_domains=?, provider_name=?, enabled=1, updated_at=datetime('now')
      WHERE org_id=?
    `).bind(issuer, client_id, client_secret, JSON.stringify(allowed_domains || []), provider_name || 'custom', org.id).run();
  } else {
    await env.DB.prepare(`
      INSERT INTO sso_configs (id, org_id, provider_name, issuer, client_id, client_secret, allowed_domains, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).bind(crypto.randomUUID(), org.id, provider_name || 'custom', issuer, client_id, client_secret, JSON.stringify(allowed_domains || [])).run();
  }

  return json({ success: true, org: orgSlug, login_url: `/api/auth/sso/login?org=${encodeURIComponent(orgSlug)}` });
}

// ─── GET /api/admin/sso/config?org=<slug> (owner-only) ─────────────────────
export async function handleSSOConfigGet(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return json({ error: 'Owner authorization required' }, 403);
  const orgSlug = new URL(request.url).searchParams.get('org');
  if (!orgSlug || !env.DB) return json({ error: 'org query parameter required' }, 400);

  const row = await env.DB.prepare(`
    SELECT sc.org_id, sc.provider_name, sc.issuer, sc.client_id, sc.allowed_domains, sc.enabled, sc.updated_at
    FROM sso_configs sc JOIN organizations o ON o.id = sc.org_id WHERE o.slug = ?
  `).bind(orgSlug).first();
  if (!row) return json({ error: 'No SSO config for this organization' }, 404);

  return json({ success: true, config: { ...row, client_secret: '••••••••' } });
}

// ─── DELETE /api/admin/sso/config?org=<slug> (owner-only) ──────────────────
export async function handleSSOConfigDelete(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return json({ error: 'Owner authorization required' }, 403);
  const orgSlug = new URL(request.url).searchParams.get('org');
  if (!orgSlug || !env.DB) return json({ error: 'org query parameter required' }, 400);

  const org = await env.DB.prepare(`SELECT id FROM organizations WHERE slug = ?`).bind(orgSlug).first();
  if (!org) return json({ error: 'Organization not found' }, 404);

  await env.DB.prepare(`UPDATE sso_configs SET enabled = 0, updated_at = datetime('now') WHERE org_id = ?`).bind(org.id).run();
  return json({ success: true, message: 'SSO disabled for this organization' });
}
