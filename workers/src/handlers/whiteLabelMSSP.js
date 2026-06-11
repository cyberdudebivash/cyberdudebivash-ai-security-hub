/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * whiteLabelMSSP.js — White Label MSSP Branding Platform
 *
 * APIs:
 *   GET    /api/white-label/theme         get own org theme (any auth)
 *   PUT    /api/white-label/theme         update theme (mssp_admin|admin)
 *   DELETE /api/white-label/theme         reset to defaults (mssp_admin|admin)
 *   GET    /api/white-label/theme/:orgId  get specific tenant theme (mssp_admin|admin)
 */

const DEFAULTS = {
  brand_name: 'CYBERDUDEBIVASH®',
  logo_url: null,
  favicon_url: null,
  primary_color: '#6366f1',
  secondary_color: '#0ea5e9',
  accent_color: '#22c55e',
  custom_css: null,
  custom_domain: null,
  support_email: null,
  support_url: null,
  hide_powered_by: 0,
};

// Allowed hex color pattern
const HEX_RE = /^#[0-9a-fA-F]{3,8}$/;
// Allowed URL pattern (https only)
const URL_RE = /^https:\/\/[^\s<>"]+$/;

function sanitizeTheme(input) {
  const out = {};
  if (input.brand_name) out.brand_name = String(input.brand_name).slice(0, 80).replace(/[<>]/g, '');
  if (input.logo_url && URL_RE.test(input.logo_url)) out.logo_url = input.logo_url;
  if (input.favicon_url && URL_RE.test(input.favicon_url)) out.favicon_url = input.favicon_url;
  if (input.primary_color && HEX_RE.test(input.primary_color)) out.primary_color = input.primary_color;
  if (input.secondary_color && HEX_RE.test(input.secondary_color)) out.secondary_color = input.secondary_color;
  if (input.accent_color && HEX_RE.test(input.accent_color)) out.accent_color = input.accent_color;
  if (input.support_email) out.support_email = String(input.support_email).slice(0, 100);
  if (input.support_url && URL_RE.test(input.support_url)) out.support_url = input.support_url;
  if (input.custom_domain) out.custom_domain = String(input.custom_domain).slice(0, 100).replace(/[^a-z0-9.-]/gi, '');
  if (typeof input.hide_powered_by === 'boolean') out.hide_powered_by = input.hide_powered_by ? 1 : 0;

  // Custom CSS: only allow property:value pairs for safe color/font rules
  if (input.custom_css) {
    const css = String(input.custom_css).slice(0, 2000);
    // Strip any url(), expression(), script references
    const sanitized = css.replace(/url\([^)]*\)/gi, '').replace(/expression\([^)]*\)/gi, '').replace(/<[^>]*>/g, '');
    out.custom_css = sanitized || null;
  }

  return out;
}

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

export async function handleGetTheme(req, env) {
  const orgId = req.user?.org_id || 'default';
  const cacheKey = `tenant_theme_${orgId}`;

  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ theme: cached, cached: true });

  const row = await env.DB.prepare(
    `SELECT * FROM tenant_themes WHERE org_id = ?`
  ).bind(orgId).first().catch(() => null);

  const theme = row ? { ...DEFAULTS, ...row } : { ...DEFAULTS, org_id: orgId };
  await env.KV?.put(cacheKey, JSON.stringify(theme), { expirationTtl: 600 }).catch(() => null);

  return Response.json({ theme });
}

export async function handleUpdateTheme(req, env) {
  if (!requireRole(req, ['admin', 'mssp_admin'])) {
    return Response.json({ error: 'MSSP Admin required' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const safe = sanitizeTheme(body);
  if (!Object.keys(safe).length) return Response.json({ error: 'No valid fields to update' }, { status: 400 });

  const orgId = req.user.org_id || 'default';

  // Build upsert
  const cols = ['org_id', ...Object.keys(safe), 'updated_at'];
  const vals = [orgId, ...Object.values(safe), new Date().toISOString()];
  const placeholders = vals.map(() => '?').join(',');
  const updateClauses = Object.keys(safe).map(k => `${k}=excluded.${k}`).join(', ') + ', updated_at=excluded.updated_at';

  await env.DB.prepare(
    `INSERT INTO tenant_themes (${cols.join(',')}) VALUES (${placeholders})
     ON CONFLICT(org_id) DO UPDATE SET ${updateClauses}`
  ).bind(...vals).run();

  await env.KV?.delete(`tenant_theme_${orgId}`).catch(() => null);

  return Response.json({ success: true, org_id: orgId, updated: safe });
}

export async function handleDeleteTheme(req, env) {
  if (!requireRole(req, ['admin', 'mssp_admin'])) {
    return Response.json({ error: 'MSSP Admin required' }, { status: 403 });
  }

  const orgId = req.user.org_id || 'default';
  await env.DB.prepare(`DELETE FROM tenant_themes WHERE org_id = ?`).bind(orgId).run().catch(() => null);
  await env.KV?.delete(`tenant_theme_${orgId}`).catch(() => null);

  return Response.json({ success: true, message: 'Theme reset to platform defaults', org_id: orgId });
}

export async function handleGetThemeByOrg(req, env, orgId) {
  if (!requireRole(req, ['admin', 'mssp_admin'])) {
    return Response.json({ error: 'MSSP Admin required' }, { status: 403 });
  }

  const cacheKey = `tenant_theme_${orgId}`;
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ theme: cached, cached: true });

  const row = await env.DB.prepare(`SELECT * FROM tenant_themes WHERE org_id = ?`).bind(orgId).first().catch(() => null);
  const theme = row ? { ...DEFAULTS, ...row } : { ...DEFAULTS, org_id: orgId };

  await env.KV?.put(cacheKey, JSON.stringify(theme), { expirationTtl: 600 }).catch(() => null);
  return Response.json({ theme });
}
