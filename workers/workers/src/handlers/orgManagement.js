/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Multi-Tenant Management v8.0
 *
 * Organizations, teams, roles, and org-wide security dashboards.
 *
 * Routes:
 *   POST  /api/orgs                      — create organization
 *   GET   /api/orgs                      — list user's orgs
 *   GET   /api/orgs/:slug                — get org detail
 *   PUT   /api/orgs/:id                  — update org settings
 *   DELETE /api/orgs/:id                 — delete org (owner only)
 *   GET   /api/orgs/:id/dashboard        — aggregate security dashboard
 *   POST  /api/orgs/:id/members          — invite member
 *   GET   /api/orgs/:id/members          — list members
 *   PUT   /api/orgs/:id/members/:userId  — update member role
 *   DELETE /api/orgs/:id/members/:userId — remove member
 *   GET   /api/orgs/:id/scans            — org-wide scan history
 *   GET   /api/orgs/:id/monitors         — org-wide monitors
 */

const ORG_PLAN_LIMITS = {
  STARTER:    { max_members: 5,  max_daily_scans: 100, max_monitors: 5,  api_keys: 5  },
  PRO:        { max_members: 25, max_daily_scans: 1000, max_monitors: 25, api_keys: 20 },
  ENTERPRISE: { max_members: -1, max_daily_scans: -1,   max_monitors: -1, api_keys: -1 },
};

const ROLE_PERMISSIONS = {
  OWNER:    ['all'],
  ADMIN:    ['read','write','invite','delete_content','manage_monitors'],
  ANALYST:  ['read','write','create_scans'],
  MEMBER:   ['read','create_scans'],
  VIEWER:   ['read'],
};

// ─── Create organization ──────────────────────────────────────────────────────
export async function handleCreateOrg(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { name, industry, domain } = body;
  if (!name || name.length < 2 || name.length > 100) {
    return Response.json({ error: 'name must be 2-100 characters' }, { status: 400 });
  }

  // Generate slug
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50)
    + '-' + Math.random().toString(36).slice(2, 6);

  // Check max orgs (1 per user for FREE, 3 for PRO, unlimited for ENTERPRISE)
  const maxOrgs = authCtx.tier === 'ENTERPRISE' ? 999 : authCtx.tier === 'PRO' ? 3 : 1;
  const existing = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM organizations WHERE owner_id = ?`
  ).bind(authCtx.userId).first();
  if ((existing?.n || 0) >= maxOrgs) {
    return Response.json({
      error: `Organization limit reached. Upgrade to create more.`,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const orgId = crypto.randomUUID();
  const plan  = authCtx.tier === 'ENTERPRISE' ? 'ENTERPRISE' : authCtx.tier === 'PRO' ? 'PRO' : 'STARTER';
  const limits = ORG_PLAN_LIMITS[plan];

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO organizations (id, name, slug, plan, owner_id, max_members, max_daily_scans, industry, domain)
      VALUES (?,?,?,?,?,?,?,?,?)
    `).bind(orgId, name, slug, plan, authCtx.userId, limits.max_members, limits.max_daily_scans, industry || null, domain || null),
    env.DB.prepare(`
      INSERT INTO org_members (org_id, user_id, role, status)
      VALUES (?,?,?,?)
    `).bind(orgId, authCtx.userId, 'OWNER', 'active'),
  ]);

  return Response.json({
    success:  true,
    org_id:   orgId,
    slug,
    name,
    plan,
    limits,
    message:  `Organization "${name}" created. You are the OWNER.`,
  }, { status: 201 });
}

// ─── List user's orgs ─────────────────────────────────────────────────────────
export async function handleListOrgs(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const { results } = await env.DB.prepare(`
    SELECT o.id, o.name, o.slug, o.plan, o.industry, o.domain,
           om.role, o.created_at,
           (SELECT COUNT(*) FROM org_members WHERE org_id = o.id AND status = 'active') as member_count
    FROM organizations o
    JOIN org_members om ON om.org_id = o.id AND om.user_id = ? AND om.status = 'active'
    ORDER BY o.created_at DESC
    LIMIT 50
  `).bind(authCtx.userId).all();

  return Response.json({ organizations: results || [] });
}

// ─── Get org detail ───────────────────────────────────────────────────────────
export async function handleGetOrg(request, env, authCtx, orgSlugOrId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  // Try slug first, then ID
  const org = await env.DB.prepare(
    `SELECT * FROM organizations WHERE slug = ? OR id = ?`
  ).bind(orgSlugOrId, orgSlugOrId).first();

  if (!org) return Response.json({ error: 'Organization not found' }, { status: 404 });

  // Verify membership
  const membership = await env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(org.id, authCtx.userId).first();
  if (!membership) return Response.json({ error: 'Access denied' }, { status: 403 });

  const members = await env.DB.prepare(`
    SELECT om.user_id, u.full_name, u.email, om.role, om.joined_at, om.status
    FROM org_members om
    LEFT JOIN users u ON u.id = om.user_id
    WHERE om.org_id = ?
    ORDER BY om.joined_at ASC
  `).bind(org.id).all();

  return Response.json({
    ...org,
    settings: JSON.parse(org.settings_json || '{}'),
    member_count: members.results?.length || 0,
    members:    members.results || [],
    your_role:  membership.role,
    limits:     ORG_PLAN_LIMITS[org.plan] || ORG_PLAN_LIMITS.STARTER,
  });
}

// ─── Org security dashboard ───────────────────────────────────────────────────
export async function handleOrgDashboard(request, env, authCtx, orgId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const membership = await env.DB.prepare(
    `SELECT om.role, o.name, o.plan FROM org_members om
     JOIN organizations o ON o.id = om.org_id
     WHERE om.org_id = ? AND om.user_id = ? AND om.status = 'active'`
  ).bind(orgId, authCtx.userId).first();
  if (!membership) return Response.json({ error: 'Access denied' }, { status: 403 });

  // Get all member IDs
  const { results: memberRows } = await env.DB.prepare(
    `SELECT user_id FROM org_members WHERE org_id = ? AND status = 'active'`
  ).bind(orgId).all();
  const memberIds = (memberRows || []).map(m => m.user_id);

  if (!memberIds.length) {
    return Response.json({ org_id: orgId, name: membership.name, message: 'No members yet', members: 0 });
  }

  const memberPlaceholders = memberIds.map(() => '?').join(',');

  // Aggregate scan stats for all members
  const [scanStats, riskStats, moduleBreakdown, recentScans, monitorStats] = await Promise.all([
    // Total scans
    env.DB.prepare(
      `SELECT COUNT(*) as total, SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) as critical_count
       FROM scan_history WHERE user_id IN (${memberPlaceholders}) AND created_at > datetime('now', '-30 days')`
    ).bind(...memberIds).first(),

    // Risk distribution
    env.DB.prepare(
      `SELECT risk_level, COUNT(*) as count, AVG(risk_score) as avg_score
       FROM scan_history WHERE user_id IN (${memberPlaceholders})
       GROUP BY risk_level`
    ).bind(...memberIds).all(),

    // Module breakdown
    env.DB.prepare(
      `SELECT module, COUNT(*) as count, AVG(risk_score) as avg_score, MAX(risk_score) as max_score
       FROM scan_history WHERE user_id IN (${memberPlaceholders})
       GROUP BY module ORDER BY count DESC`
    ).bind(...memberIds).all(),

    // Recent scans (last 5)
    env.DB.prepare(
      `SELECT sh.id, sh.module, sh.target_summary, sh.risk_score, sh.risk_level,
              u.full_name as scanned_by, sh.created_at
       FROM scan_history sh
       LEFT JOIN users u ON u.id = sh.user_id
       WHERE sh.user_id IN (${memberPlaceholders})
       ORDER BY sh.created_at DESC LIMIT 5`
    ).bind(...memberIds).all(),

    // Monitor stats
    env.DB.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as active_count
       FROM monitor_configs WHERE org_id = ?`
    ).bind(orgId).first(),
  ]);

  // Calculate overall org risk score
  const allModuleStats = moduleBreakdown.results || [];
  const totalScans     = scanStats?.total || 0;
  const avgRisk        = totalScans > 0
    ? Math.round(allModuleStats.reduce((s, m) => s + (m.avg_score * m.count), 0) /
        allModuleStats.reduce((s, m) => s + m.count, 0) || 0)
    : 0;

  return Response.json({
    org_id:           orgId,
    org_name:         membership.name,
    plan:             membership.plan,
    member_count:     memberIds.length,
    period_days:      30,
    summary: {
      total_scans_30d:    totalScans,
      critical_count_30d: scanStats?.critical_count || 0,
      avg_risk_score:     avgRisk,
      active_monitors:    monitorStats?.active_count || 0,
      total_monitors:     monitorStats?.total || 0,
    },
    risk_distribution:  riskStats.results || [],
    module_breakdown:   allModuleStats,
    recent_scans:       recentScans.results || [],
    generated_at:       new Date().toISOString(),
  });
}

// ─── Invite member ────────────────────────────────────────────────────────────
export async function handleInviteMember(request, env, authCtx, orgId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  // Must be OWNER or ADMIN
  const membership = await env.DB.prepare(
    `SELECT om.role, o.max_members, o.plan FROM org_members om
     JOIN organizations o ON o.id = om.org_id
     WHERE om.org_id = ? AND om.user_id = ? AND om.status = 'active'`
  ).bind(orgId, authCtx.userId).first();

  if (!membership || !['OWNER','ADMIN'].includes(membership.role)) {
    return Response.json({ error: 'Only OWNER or ADMIN can invite members' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { email, role = 'MEMBER' } = body;
  if (!email) return Response.json({ error: 'email is required' }, { status: 400 });
  if (!['ADMIN','ANALYST','MEMBER','VIEWER'].includes(role)) {
    return Response.json({ error: 'role must be: ADMIN, ANALYST, MEMBER, or VIEWER' }, { status: 400 });
  }

  // Check member limit
  const currentCount = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM org_members WHERE org_id = ? AND status IN ('active','invited')`
  ).bind(orgId).first();
  const maxMembers = membership.max_members;
  if (maxMembers > 0 && (currentCount?.n || 0) >= maxMembers) {
    return Response.json({ error: `Member limit reached (${maxMembers} for ${membership.plan} plan)` }, { status: 429 });
  }

  // Look up user by email
  const invitee = await env.DB.prepare(`SELECT id, full_name FROM users WHERE email = ?`).bind(email).first();
  if (!invitee) {
    return Response.json({
      success: false,
      message: `No account found for ${email}. Ask them to sign up at https://cyberdudebivash.in first.`,
      invite_url: 'https://cyberdudebivash.in/signup',
    }, { status: 404 });
  }

  // Check if already a member
  const alreadyMember = await env.DB.prepare(
    `SELECT id FROM org_members WHERE org_id = ? AND user_id = ?`
  ).bind(orgId, invitee.id).first();
  if (alreadyMember) {
    return Response.json({ error: 'User is already a member of this organization' }, { status: 409 });
  }

  await env.DB.prepare(`
    INSERT INTO org_members (org_id, user_id, role, invited_by, invite_email, status)
    VALUES (?,?,?,?,?,'active')
  `).bind(orgId, invitee.id, role, authCtx.userId, email).run();

  return Response.json({
    success: true,
    message: `${invitee.full_name || email} added to the organization as ${role}`,
    user_id: invitee.id,
    role,
  }, { status: 201 });
}

// ─── Update member role ───────────────────────────────────────────────────────
export async function handleUpdateMemberRole(request, env, authCtx, orgId, targetUserId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const membership = await env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, authCtx.userId).first();
  if (!membership || membership.role !== 'OWNER') {
    return Response.json({ error: 'Only OWNER can change member roles' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { role } = body;
  if (!['ADMIN','ANALYST','MEMBER','VIEWER'].includes(role)) {
    return Response.json({ error: 'Invalid role' }, { status: 400 });
  }

  const result = await env.DB.prepare(
    `UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(role, orgId, targetUserId).run();

  if (!result.meta?.changes) return Response.json({ error: 'Member not found' }, { status: 404 });
  return Response.json({ success: true, message: `Member role updated to ${role}` });
}

// ─── Remove member ────────────────────────────────────────────────────────────
export async function handleRemoveMember(request, env, authCtx, orgId, targetUserId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const membership = await env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, authCtx.userId).first();

  const isSelf  = authCtx.userId === targetUserId;
  const canEdit = membership?.role === 'OWNER' || membership?.role === 'ADMIN' || isSelf;
  if (!canEdit) return Response.json({ error: 'Insufficient permissions' }, { status: 403 });

  const result = await env.DB.prepare(
    `UPDATE org_members SET status = 'suspended' WHERE org_id = ? AND user_id = ? AND role != 'OWNER'`
  ).bind(orgId, targetUserId).run();

  if (!result.meta?.changes) return Response.json({ error: 'Member not found or cannot remove OWNER' }, { status: 404 });
  return Response.json({ success: true, message: 'Member removed from organization' });
}

// ─── Org-wide scan history ────────────────────────────────────────────────────
export async function handleOrgScans(request, env, authCtx, orgId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const membership = await env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, authCtx.userId).first();
  if (!membership) return Response.json({ error: 'Access denied' }, { status: 403 });

  const { results: memberRows } = await env.DB.prepare(
    `SELECT user_id FROM org_members WHERE org_id = ? AND status = 'active'`
  ).bind(orgId).all();
  const memberIds = (memberRows || []).map(m => m.user_id);
  if (!memberIds.length) return Response.json({ scans: [], total: 0 });

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
  const offset = parseInt(url.searchParams.get('offset') || '0');
  const module = url.searchParams.get('module');

  const placeholders = memberIds.map(() => '?').join(',');
  let query  = `SELECT sh.id, sh.module, sh.target_summary, sh.risk_score, sh.risk_level,
                       u.full_name as scanned_by, sh.created_at
                FROM scan_history sh LEFT JOIN users u ON u.id = sh.user_id
                WHERE sh.user_id IN (${placeholders})`;
  const params = [...memberIds];

  if (module) { query += ' AND sh.module = ?'; params.push(module); }
  query += ' ORDER BY sh.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return Response.json({ scans: results || [], total: results?.length || 0, limit, offset });
}

// ─── Update org settings ──────────────────────────────────────────────────────
export async function handleUpdateOrg(request, env, authCtx, orgId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const membership = await env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, authCtx.userId).first();
  if (!membership || !['OWNER','ADMIN'].includes(membership.role)) {
    return Response.json({ error: 'Only OWNER or ADMIN can update organization settings' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const updates = [];
  const params  = [];

  if (body.name)     { updates.push('name = ?');     params.push(body.name); }
  if (body.domain)   { updates.push('domain = ?');   params.push(body.domain); }
  if (body.industry) { updates.push('industry = ?'); params.push(body.industry); }
  if (body.settings) { updates.push('settings_json = ?'); params.push(JSON.stringify(body.settings)); }
  if (!updates.length) return Response.json({ error: 'Nothing to update' }, { status: 400 });

  updates.push(`updated_at = datetime('now')`);
  params.push(orgId);

  await env.DB.prepare(
    `UPDATE organizations SET ${updates.join(', ')} WHERE id = ?`
  ).bind(...params).run();

  return Response.json({ success: true, message: 'Organization updated' });
}

// ─── Delete organization ──────────────────────────────────────────────────────
export async function handleDeleteOrg(request, env, authCtx, orgId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const org = await env.DB.prepare(
    `SELECT id, name FROM organizations WHERE id = ? AND owner_id = ?`
  ).bind(orgId, authCtx.userId).first();
  if (!org) return Response.json({ error: 'Organization not found or you are not the owner' }, { status: 404 });

  await env.DB.prepare(`DELETE FROM organizations WHERE id = ?`).bind(orgId).run();
  return Response.json({ success: true, message: `Organization "${org.name}" deleted` });
}
