// =============================================================================
// CYBERDUDEBIVASH AI Security Hub | handlers/staffUserOrgAdmin.js
//
// CAP-ADMIN-004 (Users + Organizations slice) — staff oversight of customer
// accounts and organizations. Additive: does not touch orgManagement.js (the
// customer-self-service org handlers, unchanged) or any existing customer
// route. Gated entirely through auth/rbac.js's requireCan(), same as the
// existing /api/admin/roles* routes.
//
// Scope decision, made deliberately narrow: Users gets a real mutating action
// (suspend/reactivate) because users.status already exists in schema AND is
// already fully enforced end-to-end (handlers/auth.js handleLogin rejects
// non-'active' users with 403 "Account suspended") — this wires a control
// plane onto enforcement that was already live, the same "backend built, no
// door" bug class as the rest of this program, just inverted. Organizations
// gets read-only oversight only: the organizations table has no status/
// suspended column, so "suspend an org" is not representable without a
// schema migration — that's out of scope for this pass and not invented here.
// =============================================================================

import { requireCan } from '../auth/rbac.js';
import { revokeAllUserTokens } from '../auth/jwt.js';
import { writeOpsAudit } from './opsEngine.js';

const ALLOWED_USER_STATUS = ['active', 'suspended'];

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// GET /api/admin/users?q=&limit= — search/list customer accounts (Super Admin only)
export async function handleListUsers(request, env, authCtx) {
  const deny = await requireCan(authCtx, env, 'admin:users:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const url = new URL(request.url);
  const q = (url.searchParams.get('q') || '').trim().toLowerCase();
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);

  const cols = `id, email, full_name, company, tier, status, email_verified, created_at, last_login_at, login_count`;
  let rows;
  try {
    rows = q
      ? await env.DB.prepare(
          `SELECT ${cols} FROM users
           WHERE lower(email) LIKE ? OR lower(full_name) LIKE ? OR lower(company) LIKE ?
           ORDER BY created_at DESC LIMIT ?`
        ).bind(`%${q}%`, `%${q}%`, `%${q}%`, limit).all()
      : await env.DB.prepare(`SELECT ${cols} FROM users ORDER BY created_at DESC LIMIT ?`).bind(limit).all();
  } catch (e) {
    console.error('[StaffUserOrgAdmin] listUsers query failed:', e?.message);
    return Response.json({ error: 'Unable to load users' }, { status: 500 });
  }

  return Response.json({ success: true, users: rows.results || [] });
}

// GET /api/admin/users/:id — one customer account, with org memberships (Super Admin only)
export async function handleGetUserAdmin(request, env, authCtx, userId) {
  const deny = await requireCan(authCtx, env, 'admin:users:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!userId) return Response.json({ error: 'user id required' }, { status: 400 });

  const user = await env.DB.prepare(
    `SELECT id, email, full_name, company, tier, status, email_verified, created_at, updated_at, last_login_at, login_count
     FROM users WHERE id = ?`
  ).bind(userId).first().catch((e) => { console.error('[StaffUserOrgAdmin] getUser query failed:', e?.message); return undefined; });
  if (user === undefined) return Response.json({ error: 'Unable to load user' }, { status: 500 });
  if (!user) return Response.json({ error: 'No such user' }, { status: 404 });

  const orgs = await env.DB.prepare(
    `SELECT o.id, o.name, o.slug, o.plan, om.role
     FROM org_members om JOIN organizations o ON o.id = om.org_id
     WHERE om.user_id = ? ORDER BY o.created_at DESC`
  ).bind(userId).all().catch(() => ({ results: [] }));

  return Response.json({ success: true, user, organizations: orgs.results || [] });
}

// PATCH /api/admin/users/:id/status  { status: 'active' | 'suspended' } (Super Admin only)
export async function handleUpdateUserStatus(request, env, authCtx, userId) {
  const deny = await requireCan(authCtx, env, 'admin:users:manage');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!userId) return Response.json({ error: 'user id required' }, { status: 400 });

  const body = await request.json().catch(() => ({}));
  const status = body?.status;
  if (!ALLOWED_USER_STATUS.includes(status)) {
    return Response.json({ error: `status must be one of: ${ALLOWED_USER_STATUS.join(', ')}` }, { status: 400 });
  }

  const target = await env.DB.prepare(`SELECT id, email, status FROM users WHERE id = ?`).bind(userId).first().catch(() => null);
  if (!target) return Response.json({ error: 'No such user' }, { status: 404 });

  if (target.status === status) {
    return Response.json({ success: true, user_id: userId, email: target.email, status, unchanged: true });
  }

  await env.DB.prepare(`UPDATE users SET status = ?, updated_at = datetime('now') WHERE id = ?`).bind(status, userId).run();

  // handlers/auth.js handleLogin already rejects any non-'active' user at the
  // password check — that blocks future logins immediately. It does NOT by
  // itself invalidate a refresh token issued before this change, so a
  // suspension additionally revokes every outstanding token for this user
  // right now, the same helper used by "log out everywhere" and password
  // change (auth/jwt.js revokeAllUserTokens) — otherwise "suspend" would only
  // take effect the next time the session naturally expired.
  if (status === 'suspended') {
    await revokeAllUserTokens(env.DB, userId).catch((e) => console.error('[StaffUserOrgAdmin] token revoke failed:', e?.message));
  }

  await writeOpsAudit(env, {
    type: 'staff_action',
    actor: authCtx.email || authCtx.identity || 'unknown',
    actorTier: 'staff',
    ip: clientIp(request),
    resource: `user:${userId}`,
    action: 'update_user_status',
    outcome: 'success',
    details: { from: target.status, to: status, target_email: target.email },
  });

  return Response.json({ success: true, user_id: userId, email: target.email, status });
}

// GET /api/admin/orgs?q=&limit= — staff oversight list of every organization (Admin+)
export async function handleListOrgsAdmin(request, env, authCtx) {
  const deny = await requireCan(authCtx, env, 'admin:orgs:read');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const url = new URL(request.url);
  const q = (url.searchParams.get('q') || '').trim().toLowerCase();
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);

  const base = `SELECT o.id, o.name, o.slug, o.plan, o.owner_id, u.email AS owner_email,
                       o.max_members, o.max_daily_scans, o.created_at,
                       (SELECT COUNT(*) FROM org_members om WHERE om.org_id = o.id) AS member_count
                FROM organizations o LEFT JOIN users u ON u.id = o.owner_id`;
  let rows;
  try {
    rows = q
      ? await env.DB.prepare(`${base} WHERE lower(o.name) LIKE ? OR lower(o.slug) LIKE ? ORDER BY o.created_at DESC LIMIT ?`)
          .bind(`%${q}%`, `%${q}%`, limit).all()
      : await env.DB.prepare(`${base} ORDER BY o.created_at DESC LIMIT ?`).bind(limit).all();
  } catch (e) {
    console.error('[StaffUserOrgAdmin] listOrgs query failed:', e?.message);
    return Response.json({ error: 'Unable to load organizations' }, { status: 500 });
  }

  return Response.json({ success: true, organizations: rows.results || [] });
}

// GET /api/admin/orgs/:id — staff oversight detail of one organization, with members (Admin+)
export async function handleGetOrgAdmin(request, env, authCtx, orgId) {
  const deny = await requireCan(authCtx, env, 'admin:orgs:read');
  if (deny) return deny;
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!orgId) return Response.json({ error: 'org id required' }, { status: 400 });

  const org = await env.DB.prepare(
    `SELECT o.id, o.name, o.slug, o.plan, o.owner_id, u.email AS owner_email, o.max_members,
            o.max_daily_scans, o.domain, o.industry, o.created_at, o.updated_at
     FROM organizations o LEFT JOIN users u ON u.id = o.owner_id WHERE o.id = ?`
  ).bind(orgId).first().catch((e) => { console.error('[StaffUserOrgAdmin] getOrg query failed:', e?.message); return undefined; });
  if (org === undefined) return Response.json({ error: 'Unable to load organization' }, { status: 500 });
  if (!org) return Response.json({ error: 'No such organization' }, { status: 404 });

  const members = await env.DB.prepare(
    `SELECT om.user_id, om.role, om.status, om.joined_at, u.email, u.full_name, u.status AS account_status
     FROM org_members om JOIN users u ON u.id = om.user_id
     WHERE om.org_id = ? ORDER BY om.joined_at ASC`
  ).bind(orgId).all().catch(() => ({ results: [] }));

  return Response.json({ success: true, organization: org, members: members.results || [] });
}
