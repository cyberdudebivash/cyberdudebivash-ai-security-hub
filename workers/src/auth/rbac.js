// =============================================================================
// CYBERDUDEBIVASH AI Security Hub | auth/rbac.js
//
// Central platform-staff RBAC layer — additive to the existing auth model, not
// a replacement. Everything this file builds on already exists and is
// untouched: resolveAuthV5()/withAuthAliases()/isOwner()/ownerEmails() in
// auth/middleware.js, the `authCtx.role` derivation (admin/mssp_admin/partner),
// and the MSSP tenant-isolation pattern in handlers/msspWorkspace.js.
//
// What was missing: "admin" access has exactly one path today — the shared
// ADMIN_KEY secret, or a single hardcoded owner email (isOwner()). There is no
// way to have a SECOND real admin user. The schema already has an unused,
// never-wired `user_roles` table (user_id, role CHECK(SUPERADMIN|ADMIN|
// SOC_ANALYST|THREAT_HUNTER|VIEWER|API_USER), granted_by, granted_at) — this
// module wires it in as the foundation for real, multi-user Platform
// Administrator / Super Administrator roles, plus a small declarative
// permission registry so the ~4 duplicated per-file requireRole()/
// enterpriseOnly() implementations found across the codebase
// (customerSuccess.js, reliabilityEngineering.js, executiveRiskHandlers.js,
// whiteLabelMSSP.js) can delegate to ONE place instead of four.
//
// Role hierarchy (role inheritance, least-privilege):
//   SUPERADMIN → everything ADMIN can do, plus infrastructure/RBAC/audit/
//                billing-config/production-ops. Equivalent in reach to the
//                ADMIN_KEY bypass and the legacy single-owner-email path
//                (isOwner()) — NOT a replacement for either, an alternative
//                way to reach the same trust level for a real named user.
//   ADMIN      → platform health/users/products/pricing/feature-flags/
//                analytics/marketplace/reports/APIs — "Platform
//                Administrator" per the RBAC spec. A strict subset of
//                SUPERADMIN.
//   SOC_ANALYST / THREAT_HUNTER / VIEWER / API_USER → reserved for future
//                phases (not consumed by any predicate yet in this phase).
//
// isOwner()/ownerEmails()/authCtx.role in auth/middleware.js are NOT modified
// by this file — a SUPERADMIN-role user or an ADMIN_KEY holder is already
// treated as `isOwner()`-equivalent because resolveStaffSession()
// (handlers/staffAuth.js) sets `isAdmin: true` on the resolved authCtx for a
// SUPERADMIN session, the exact same field the ADMIN_KEY bypass already sets
// — no existing isOwner() call site needed to change.
// =============================================================================

import { isOwner } from './middleware.js';

const ROLE_CACHE_TTL = 120; // seconds — short enough that a revoke takes effect fast, long enough to spare D1 on every admin-panel click

function roleCacheKey(userId) {
  return `staff_roles:${userId}`;
}

// ── Read a user's granted platform roles (user_roles table) ────────────────
// KV-cached so this never adds a D1 round-trip to the hot path of ordinary
// (non-admin-route) requests — callers only invoke this from routes that
// actually need a platform-role check, not eagerly on every request.
export async function getPlatformRoles(env, userId) {
  if (!userId || !env?.DB) return [];
  const cacheKey = roleCacheKey(userId);
  if (env.KV) {
    const cached = await env.KV.get(cacheKey, 'json').catch(() => null);
    if (cached) return cached;
  }
  const rows = await env.DB.prepare(
    `SELECT role FROM user_roles WHERE user_id = ?`
  ).bind(userId).all().catch(() => ({ results: [] }));
  const roles = (rows.results || []).map(r => r.role);
  if (env.KV) await env.KV.put(cacheKey, JSON.stringify(roles), { expirationTtl: ROLE_CACHE_TTL }).catch(() => {});
  return roles;
}

async function invalidatePlatformRoleCache(env, userId) {
  if (env.KV) await env.KV.delete(roleCacheKey(userId)).catch(() => {});
}

// ── Role predicates ──────────────────────────────────────────────────────────
export async function isSuperAdmin(authCtx, env) {
  if (!authCtx) return false;
  if (authCtx.isAdmin === true) return true;   // ADMIN_KEY bypass
  if (isOwner(authCtx, env)) return true;      // legacy single-owner-email path, untouched
  if (authCtx.platformRoles) return authCtx.platformRoles.includes('SUPERADMIN'); // already resolved this request (e.g. staff session)
  const uid = authCtx.user_id ?? authCtx.userId;
  if (!uid) return false;
  const roles = await getPlatformRoles(env, uid);
  return roles.includes('SUPERADMIN');
}

export async function isPlatformAdmin(authCtx, env) {
  if (await isSuperAdmin(authCtx, env)) return true; // role inheritance: SUPERADMIN implies ADMIN
  if (!authCtx) return false;
  if (authCtx.platformRoles) return authCtx.platformRoles.includes('ADMIN');
  const uid = authCtx.user_id ?? authCtx.userId;
  if (!uid) return false;
  const roles = await getPlatformRoles(env, uid);
  return roles.includes('ADMIN');
}

// ── Declarative permission registry ─────────────────────────────────────────
// Add new capabilities here rather than writing another bespoke requireRole()
// in a handler file — one place to audit "who can do what."
export const PERMISSIONS = {
  'admin:analytics:read':  (ctx, env) => isPlatformAdmin(ctx, env), // executiveCommandCenter, productAnalytics growth/funnel/adoption
  'admin:business:read':   (ctx, env) => isSuperAdmin(ctx, env),   // revenue/CRM/proposals — business-critical, super-admin only
  'admin:roles:manage':    (ctx, env) => isSuperAdmin(ctx, env),   // grant/revoke platform roles
  'admin:infra:operate':   (ctx, env) => isSuperAdmin(ctx, env),   // god-mode / autonomous orchestration
};

export async function can(authCtx, env, permission) {
  const predicate = PERMISSIONS[permission];
  if (!predicate) {
    console.warn(`[RBAC] Unknown permission "${permission}" — denying by default (fail closed)`);
    return false;
  }
  return predicate(authCtx, env);
}

// Returns a 403 Response if denied, or null if the caller may proceed —
// mirrors the existing forbidden()/isOwner() call-site shape so adopting
// this at a route is a 2-line change.
export async function requireCan(authCtx, env, permission, message) {
  const allowed = await can(authCtx, env, permission);
  if (allowed) return null;
  return Response.json({
    error: 'Forbidden',
    message: message || 'This resource requires elevated platform permissions.',
    permission,
  }, { status: 403 });
}

// ── Role management (Super Admin only) ──────────────────────────────────────
const GRANTABLE_ROLES = ['SUPERADMIN', 'ADMIN', 'SOC_ANALYST', 'THREAT_HUNTER', 'VIEWER', 'API_USER'];

// POST /api/admin/roles/grant  { user_id, role }
export async function handleGrantRole(request, env, authCtx) {
  const deny = await requireCan(authCtx, env, 'admin:roles:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body = await request.json().catch(() => ({}));
  const { user_id, role } = body;
  if (!user_id || !GRANTABLE_ROLES.includes(role)) {
    return Response.json({ error: `user_id and a valid role required (${GRANTABLE_ROLES.join('|')})` }, { status: 400 });
  }

  const target = await env.DB.prepare(`SELECT id, email FROM users WHERE id = ?`).bind(user_id).first().catch(() => null);
  if (!target) return Response.json({ error: 'No such user' }, { status: 404 });

  await env.DB.prepare(
    `INSERT INTO user_roles (user_id, role, granted_by) VALUES (?, ?, ?)
     ON CONFLICT(user_id, role) DO UPDATE SET granted_by = excluded.granted_by, granted_at = datetime('now')`
  ).bind(user_id, role, authCtx.email || authCtx.identity || 'unknown').run();

  await invalidatePlatformRoleCache(env, user_id);

  return Response.json({ success: true, user_id, email: target.email, role, granted_by: authCtx.email || authCtx.identity });
}

// DELETE /api/admin/roles/revoke  { user_id, role }
export async function handleRevokeRole(request, env, authCtx) {
  const deny = await requireCan(authCtx, env, 'admin:roles:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body = await request.json().catch(() => ({}));
  const { user_id, role } = body;
  if (!user_id || !role) return Response.json({ error: 'user_id and role required' }, { status: 400 });

  await env.DB.prepare(`DELETE FROM user_roles WHERE user_id = ? AND role = ?`).bind(user_id, role).run();
  await invalidatePlatformRoleCache(env, user_id);

  return Response.json({ success: true, user_id, role, revoked: true });
}

// GET /api/admin/roles — list every granted role (Super Admin only)
export async function handleListRoles(request, env, authCtx) {
  const deny = await requireCan(authCtx, env, 'admin:roles:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const rows = await env.DB.prepare(
    `SELECT ur.user_id, ur.role, ur.granted_by, ur.granted_at, u.email
     FROM user_roles ur JOIN users u ON u.id = ur.user_id
     ORDER BY ur.granted_at DESC LIMIT 200`
  ).all().catch(() => ({ results: [] }));

  return Response.json({ success: true, roles: rows.results || [] });
}
