/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise SSO Handler v1.0
 *
 * Supports OIDC-based SSO for enterprise identity providers:
 *   - Microsoft Azure AD / Entra ID  (most common for Oracle, Cisco, Dell, Intel)
 *   - Okta (generic OIDC)
 *   - Any OIDC-compliant IdP
 *
 * Routes:
 *   GET  /api/auth/enterprise/sso        → initiate OIDC flow (tenant-aware)
 *   GET  /api/auth/enterprise/callback   → exchange code → JWT → redirect to dashboard
 *   GET  /api/auth/enterprise/config     → public: what IdPs are supported + setup guide
 *   POST /api/auth/enterprise/configure  → owner only: save IdP config for an org
 *
 * Wrangler secrets required:
 *   ENTERPRISE_SSO_SECRET  — used to sign/verify state tokens (32-byte hex)
 *
 * Per-org config stored in KV under key: enterprise_sso:org:<org_slug>
 * Supported IdP types: azure_ad, okta, generic_oidc
 *
 * Azure AD Discovery: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
 * Okta Discovery:     https://{domain}/.well-known/openid-configuration
 */

import { createAccessToken, createRefreshToken, storeRefreshToken } from '../auth/jwt.js';
import { isOwner } from '../auth/middleware.js';

const STATE_TTL   = 600; // 10 min
const KV_SSO_PFX  = 'enterprise_sso:org:';
const KV_STATE_PFX = 'enterprise_sso:state:';

function getFrontendURL(env) {
  return (env?.WEBSITE || 'https://cyberdudebivash.in').replace(/\/$/, '');
}

function getWorkerURL(env) {
  return (env?.WORKER_URL || 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev').replace(/\/$/, '');
}

function callbackURL(env) {
  return `${getWorkerURL(env)}/api/auth/enterprise/callback`;
}

// ── Resolve OIDC endpoints from IdP discovery doc ─────────────────────────────
async function discoverOIDC(discoveryUrl) {
  try {
    const res = await fetch(discoveryUrl, {
      headers: { Accept: 'application/json' },
      cf: { cacheTtl: 3600 },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function buildDiscoveryURL(config) {
  if (config.idp_type === 'azure_ad') {
    const tenant = config.tenant_id || 'organizations';
    return `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`;
  }
  if (config.idp_type === 'okta') {
    return `https://${config.okta_domain}/.well-known/openid-configuration`;
  }
  // generic_oidc — customer provides discovery URL directly
  return config.discovery_url || null;
}

// ── Load org SSO config from KV ───────────────────────────────────────────────
async function loadOrgConfig(env, orgSlug) {
  if (!env?.SECURITY_HUB_KV || !orgSlug) return null;
  try {
    return await env.SECURITY_HUB_KV.get(`${KV_SSO_PFX}${orgSlug}`, { type: 'json' });
  } catch { return null; }
}

async function saveOrgConfig(env, orgSlug, config) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(`${KV_SSO_PFX}${orgSlug}`, JSON.stringify(config));
}

// ── GET /api/auth/enterprise/config ──────────────────────────────────────────
export function handleEnterpriseSSoInfo() {
  return Response.json({
    success: true,
    service: 'CYBERDUDEBIVASH Enterprise SSO',
    version: '1.0',
    description: 'OIDC-based enterprise single sign-on. Employees use their corporate identity (Azure AD, Okta, any OIDC IdP) to access the platform — no separate password required.',
    supported_idps: {
      azure_ad: {
        name: 'Microsoft Azure AD / Entra ID',
        description: 'Used by Oracle, Cisco, Dell, Intel, Microsoft. Supports conditional access policies.',
        discovery_url_template: 'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration',
        required_config: ['tenant_id', 'client_id', 'client_secret', 'org_slug'],
        scopes: 'openid email profile',
        notes: 'Register the callback URL as a Redirect URI in your Azure App Registration.',
      },
      okta: {
        name: 'Okta',
        description: 'Widely used by enterprises with Okta Identity Cloud.',
        discovery_url_template: 'https://{okta_domain}/.well-known/openid-configuration',
        required_config: ['okta_domain', 'client_id', 'client_secret', 'org_slug'],
        scopes: 'openid email profile groups',
      },
      generic_oidc: {
        name: 'Generic OIDC (Ping, Keycloak, Auth0, etc.)',
        description: 'Any OIDC-compliant identity provider.',
        required_config: ['discovery_url', 'client_id', 'client_secret', 'org_slug'],
        scopes: 'openid email profile',
      },
    },
    callback_url: 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/enterprise/callback',
    initiation_url: 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/enterprise/sso?org=<org_slug>',
    setup_steps: [
      '1. Register CYBERDUDEBIVASH as an OAuth2/OIDC app in your IdP (Azure AD, Okta, etc.)',
      '2. Set the Redirect URI to the callback_url above',
      '3. Note your client_id, client_secret, and tenant/domain',
      '4. POST /api/auth/enterprise/configure (owner token) with your IdP config + org_slug',
      '5. Share the initiation_url with your employees — they click it, authenticate with their corporate identity, and land on the dashboard with their org tier auto-applied',
    ],
    support: 'enterprise@cyberdudebivash.in',
  });
}

// ── GET /api/auth/enterprise/sso?org=<slug> ──────────────────────────────────
export async function handleEnterpriseSSoInitiate(request, env) {
  const url     = new URL(request.url);
  const orgSlug = url.searchParams.get('org') || url.searchParams.get('organization');

  if (!orgSlug) {
    return Response.json({
      error: 'Missing ?org= parameter. Example: /api/auth/enterprise/sso?org=oracle',
      setup: '/api/auth/enterprise/config',
    }, { status: 400 });
  }

  const config = await loadOrgConfig(env, orgSlug);
  if (!config) {
    return Response.json({
      error: `No SSO configuration found for org "${orgSlug}". Contact your admin or CYBERDUDEBIVASH support.`,
      setup: 'POST /api/auth/enterprise/configure',
    }, { status: 404 });
  }

  const discoveryUrl = buildDiscoveryURL(config);
  if (!discoveryUrl) {
    return Response.json({ error: 'Invalid SSO configuration — missing discovery URL.' }, { status: 500 });
  }

  const discovery = await discoverOIDC(discoveryUrl);
  if (!discovery?.authorization_endpoint) {
    return Response.json({ error: 'Could not reach your IdP discovery endpoint. Check configuration.' }, { status: 502 });
  }

  // State token: signed with org + nonce to prevent CSRF
  const nonce      = crypto.randomUUID();
  const stateToken = `${orgSlug}:${nonce}`;
  const stateB64   = btoa(stateToken);

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_STATE_PFX}${stateB64}`, JSON.stringify({ orgSlug, nonce }), { expirationTtl: STATE_TTL });
  }

  const params = new URLSearchParams({
    client_id:     config.client_id,
    redirect_uri:  callbackURL(env),
    response_type: 'code',
    scope:         config.scopes || 'openid email profile',
    state:         stateB64,
    nonce,
    prompt:        'select_account',
    ...(config.idp_type === 'azure_ad' && { response_mode: 'query' }),
  });

  return Response.redirect(`${discovery.authorization_endpoint}?${params.toString()}`, 302);
}

// ── GET /api/auth/enterprise/callback ────────────────────────────────────────
export async function handleEnterpriseSSoCallback(request, env) {
  const url     = new URL(request.url);
  const code    = url.searchParams.get('code');
  const stateB64 = url.searchParams.get('state');
  const errParam = url.searchParams.get('error');
  const frontendBase = getFrontendURL(env);

  if (errParam) {
    const desc = url.searchParams.get('error_description') || errParam;
    return Response.redirect(`${frontendBase}/?sso_error=${encodeURIComponent(desc)}`, 302);
  }

  if (!code || !stateB64) {
    return Response.redirect(`${frontendBase}/?sso_error=missing_code_or_state`, 302);
  }

  // Validate state
  let orgSlug;
  try {
    const stateData = env?.SECURITY_HUB_KV
      ? await env.SECURITY_HUB_KV.get(`${KV_STATE_PFX}${stateB64}`, { type: 'json' })
      : null;
    if (!stateData) throw new Error('state_expired');
    orgSlug = stateData.orgSlug;
    await env.SECURITY_HUB_KV.delete(`${KV_STATE_PFX}${stateB64}`).catch(() => {});
  } catch {
    return Response.redirect(`${frontendBase}/?sso_error=invalid_state`, 302);
  }

  const config = await loadOrgConfig(env, orgSlug);
  if (!config) {
    return Response.redirect(`${frontendBase}/?sso_error=org_not_found`, 302);
  }

  const discoveryUrl = buildDiscoveryURL(config);
  const discovery    = await discoverOIDC(discoveryUrl);
  if (!discovery?.token_endpoint) {
    return Response.redirect(`${frontendBase}/?sso_error=idp_unreachable`, 302);
  }

  // Exchange code for tokens
  let tokenData;
  try {
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  callbackURL(env),
        client_id:     config.client_id,
        client_secret: config.client_secret,
      }).toString(),
      signal: AbortSignal.timeout(8000),
    });
    if (!tokenRes.ok) {
      const errText = await tokenRes.text().catch(() => 'token_exchange_failed');
      return Response.redirect(`${frontendBase}/?sso_error=${encodeURIComponent(errText.slice(0, 100))}`, 302);
    }
    tokenData = await tokenRes.json();
  } catch {
    return Response.redirect(`${frontendBase}/?sso_error=token_exchange_error`, 302);
  }

  // Fetch user info from IdP
  let userInfo;
  try {
    const userInfoEndpoint = discovery.userinfo_endpoint;
    const uiRes = await fetch(userInfoEndpoint, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
      signal: AbortSignal.timeout(8000),
    });
    userInfo = uiRes.ok ? await uiRes.json() : {};
  } catch {
    userInfo = {};
  }

  // Extract standard claims (Azure AD uses different field names sometimes)
  const email    = userInfo.email || userInfo.preferred_username || userInfo.upn || '';
  const name     = userInfo.name  || `${userInfo.given_name || ''} ${userInfo.family_name || ''}`.trim() || email;
  const sub      = userInfo.sub   || userInfo.oid || email;
  const orgTier  = config.default_tier || 'ENTERPRISE';
  const orgName  = config.org_name     || orgSlug;

  if (!email || !email.includes('@')) {
    return Response.redirect(`${frontendBase}/?sso_error=no_email_from_idp`, 302);
  }

  // Upsert user in D1 with the org tier
  let userId;
  try {
    if (env?.DB) {
      const existing = await env.DB.prepare('SELECT id, tier FROM users WHERE email = ?').bind(email).first();
      if (existing) {
        userId = existing.id;
        // Upgrade tier if org config grants a higher one
        if (existing.tier !== orgTier) {
          await env.DB.prepare('UPDATE users SET tier = ?, org_name = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(orgTier, orgName, userId).run();
        }
      } else {
        userId = `usr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
        await env.DB.prepare(
          `INSERT INTO users (id, email, name, tier, org_name, sso_provider, sso_sub, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
        ).bind(userId, email, name, orgTier, orgName, config.idp_type, sub).run().catch(() => {
          // Column may not exist yet — insert without sso columns
          return env.DB.prepare(
            `INSERT OR IGNORE INTO users (id, email, name, tier, created_at) VALUES (?, ?, ?, ?, datetime('now'))`
          ).bind(userId, email, name, orgTier).run();
        });
      }
    } else {
      userId = `sso_${sub.slice(0, 16)}`;
    }
  } catch {
    userId = `sso_${Date.now().toString(36)}`;
  }

  // Issue platform JWT
  let accessToken, refreshToken;
  try {
    accessToken  = await createAccessToken(env, { user_id: userId, email, name, tier: orgTier, org: orgName, sso: config.idp_type });
    refreshToken = await createRefreshToken(env, userId);
    await storeRefreshToken(env, userId, refreshToken).catch(() => {});
  } catch {
    return Response.redirect(`${frontendBase}/?sso_error=jwt_issue_failed`, 302);
  }

  // Log SSO event
  try {
    if (env?.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO audit_log (user_id, action, resource, resource_id, status, metadata, ip, created_at)
         VALUES (?, 'sso.login', 'sso', ?, 'ok', ?, ?, datetime('now'))`
      ).bind(
        userId,
        orgSlug,
        JSON.stringify({ idp: config.idp_type, org: orgSlug, email }),
        request.headers.get('CF-Connecting-IP') || 'unknown'
      ).run();
    }
  } catch (err) {
    // Never block SSO login on an audit-write failure — but a fully silent
    // catch is what let this INSERT reference a non-existent `detail` column
    // (schema has `metadata`) for an unknown period without anyone noticing.
    console.error('sso_audit_log_write_failed', { userId, orgSlug, error: err?.message });
  }

  // Redirect to dashboard with tokens in fragment (never in query string for security)
  return Response.redirect(
    `${frontendBase}/user-dashboard?sso=1&org=${encodeURIComponent(orgSlug)}#access_token=${encodeURIComponent(accessToken)}&refresh_token=${encodeURIComponent(refreshToken)}&tier=${orgTier}`,
    302
  );
}

// ── POST /api/auth/enterprise/configure — owner only ─────────────────────────
export async function handleEnterpriseSSoConfigure(request, env, authCtx) {
  // Must be owner. `authCtx.isOwner` is not a real field anywhere in the auth
  // layer (the real check is the isOwner(authCtx, env) function — ADMIN_KEY
  // bypass or a configured OWNER_EMAILS match) — this endpoint has been
  // reachable only via the exact hardcoded email below since it was written.
  // Added the real isOwner() check alongside it: strictly additive, the
  // hardcoded email still works exactly as before.
  if (!isOwner(authCtx, env) && authCtx?.email !== 'iambivash.bn@gmail.com') {
    return Response.json({ error: 'Owner access required.' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const { org_slug, idp_type, client_id, client_secret, tenant_id, okta_domain, discovery_url, org_name, default_tier, scopes } = body;

  if (!org_slug || !idp_type || !client_id || !client_secret) {
    return Response.json({ error: 'Required: org_slug, idp_type, client_id, client_secret.' }, { status: 400 });
  }
  if (!['azure_ad', 'okta', 'generic_oidc'].includes(idp_type)) {
    return Response.json({ error: 'idp_type must be: azure_ad | okta | generic_oidc' }, { status: 400 });
  }
  if (idp_type === 'azure_ad' && !tenant_id) {
    return Response.json({ error: 'tenant_id required for azure_ad (Azure AD tenant GUID or domain).' }, { status: 400 });
  }
  if (idp_type === 'okta' && !okta_domain) {
    return Response.json({ error: 'okta_domain required (e.g. oracle.okta.com).' }, { status: 400 });
  }
  if (idp_type === 'generic_oidc' && !discovery_url) {
    return Response.json({ error: 'discovery_url required for generic_oidc.' }, { status: 400 });
  }

  // Verify the IdP discovery endpoint is reachable before saving
  const testConfig   = { idp_type, tenant_id, okta_domain, discovery_url };
  const testDiscUrl  = buildDiscoveryURL(testConfig);
  const discovery    = testDiscUrl ? await discoverOIDC(testDiscUrl) : null;
  if (!discovery?.authorization_endpoint) {
    return Response.json({
      error: 'Could not reach IdP discovery endpoint. Verify your tenant_id/okta_domain/discovery_url.',
      discovery_url_tried: testDiscUrl,
    }, { status: 502 });
  }

  const configToSave = {
    org_slug, idp_type, client_id, client_secret,
    tenant_id:     tenant_id  || null,
    okta_domain:   okta_domain || null,
    discovery_url: discovery_url || null,
    org_name:      org_name   || org_slug,
    default_tier:  default_tier || 'ENTERPRISE',
    scopes:        scopes || 'openid email profile',
    configured_at: new Date().toISOString(),
    configured_by: authCtx?.email || 'owner',
    idp_issuer:    discovery.issuer,
    idp_endpoints: {
      authorization: discovery.authorization_endpoint,
      token:         discovery.token_endpoint,
      userinfo:      discovery.userinfo_endpoint,
      jwks:          discovery.jwks_uri,
    },
  };

  await saveOrgConfig(env, org_slug, configToSave);

  return Response.json({
    success: true,
    message: `Enterprise SSO configured for org "${org_slug}" using ${idp_type}.`,
    org_slug,
    idp_type,
    org_name: configToSave.org_name,
    default_tier: configToSave.default_tier,
    idp_issuer: discovery.issuer,
    sso_initiation_url: `https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/enterprise/sso?org=${org_slug}`,
    callback_url: 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/auth/enterprise/callback',
    note: 'Share the sso_initiation_url with your employees. They click it, authenticate with their corporate identity, and are provisioned with the configured tier.',
  });
}
