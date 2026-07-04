import { isRealUser } from '../auth/middleware.js';
/**
 * CYBERDUDEBIVASH® AI Security Hub
 * MSSP Workspace — Multi-Tenant Customer Management
 *
 * Uses mssp_customers table (schema_phase2.sql).
 * Requires: mssp_admin role for cross-customer views,
 *           enterprise/admin for own-org views.
 *
 * P9.1 / P9.2 extensions:
 *  - ensureMsspCustomersExtended(): migrates suspended_at, archived_at,
 *    deleted_at, suspension_reason, parent_customer_id columns
 *  - handleGetCustomer:      GET  /api/mssp/customers/:id
 *  - handleDeleteCustomer:   DELETE /api/mssp/customers/:id  (soft delete)
 *  - handleSuspendCustomer:  POST /api/mssp/customers/:id/suspend
 *  - handleArchiveCustomer:  POST /api/mssp/customers/:id/archive
 *  - handleRestoreCustomer:  POST /api/mssp/customers/:id/restore
 *  - handleListCustomers:    extended with ?q= ?tier= ?label= ?status=all
 */

const nanoid = (n = 21) => crypto.randomUUID().replace(/-/g, '').slice(0, n);

function requireMSSPAdmin(authCtx) {
  return authCtx?.role === 'admin' || authCtx?.role === 'mssp_admin';
}

function requireAuth(authCtx) {
  return isRealUser(authCtx);
}

// ─── Per-partner isolation scope ──────────────────────────────────────────────────────
function partnerScope(authCtx) {
  return authCtx?.userId ?? authCtx?.user_id ?? null;
}

function emptyList(limit, offset) {
  return { success: true, customers: [], total: 0, limit, offset };
}

// P9.1: Migrate extended columns onto mssp_customers if not yet present.
async function ensureMsspCustomersExtended(db) {
  const cols = ['suspended_at', 'archived_at', 'deleted_at', 'suspension_reason', 'parent_customer_id'];
  for (const col of cols) {
    try { await db.prepare(`ALTER TABLE mssp_customers ADD COLUMN ${col} TEXT`).run(); } catch (_) {}
  }
}

// Ensure label table exists so label-filter in handleListCustomers doesn't throw.
async function ensureLabelTable(db) {
  try {
    await db.prepare(`CREATE TABLE IF NOT EXISTS mssp_customer_labels (
      id TEXT PRIMARY KEY, partner_id TEXT NOT NULL, customer_id TEXT NOT NULL,
      label TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(partner_id, customer_id, label)
    )`).run();
  } catch (_) {}
}

// GET /api/mssp/customers
export async function handleListCustomers(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required', code: 403 }, { status: 403 });
  }

  const url    = new URL(request.url);
  const status = url.searchParams.get('status') || 'active';
  const tier   = url.searchParams.get('tier')   || null;
  const q      = url.searchParams.get('q')      || null;
  const label  = url.searchParams.get('label')  || null;
  const limit  = Math.min(parseInt(url.searchParams.get('limit')  || '50'),  200);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const scope = partnerScope(authCtx);
  if (!scope) return Response.json(emptyList(limit, offset));

  if (label) await ensureLabelTable(env.SECURITY_HUB_DB);

  try {
    // Build WHERE clause with status first so bind order is [status, partner_id, ...]
    // matching the convention expected by unit-test mocks (msspIsolation.test.mjs).
    const whereBinds = [];
    const conditions = [];

    if (status !== 'all') {
      conditions.push('status = ?');
      whereBinds.push(status);
    }
    conditions.push('partner_id = ?');
    whereBinds.push(scope);

    if (tier) {
      conditions.push('tier = ?');
      whereBinds.push(tier);
    }
    if (q) {
      conditions.push('(org_name LIKE ? OR contact_name LIKE ? OR contact_email LIKE ?)');
      const p = `%${q}%`;
      whereBinds.push(p, p, p);
    }
    if (label) {
      conditions.push('id IN (SELECT customer_id FROM mssp_customer_labels WHERE partner_id = ? AND label = ?)');
      whereBinds.push(scope, label);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const rows = await env.SECURITY_HUB_DB.prepare(`
      SELECT id, org_name, org_slug, contact_name, contact_email,
             tier, status, risk_score, compliance_score,
             mrr_cents, created_at, updated_at, last_activity_at
      FROM mssp_customers
      ${where}
      ORDER BY risk_score DESC
      LIMIT ? OFFSET ?
    `).bind(...whereBinds, limit, offset).all();

    const totalQ = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as total FROM mssp_customers ${where}`
    ).bind(...whereBinds).first();

    return Response.json({
      success:   true,
      customers: rows?.results || [],
      total:     totalQ?.total || 0,
      limit,
      offset,
      filters: { status, tier, q, label },
    });
  } catch (e) {
    return Response.json({ ...emptyList(limit, offset), degraded: true });
  }
}

// POST /api/mssp/customers
export async function handleCreateCustomer(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { org_name, contact_email, tier = 'starter', contact_name, notes } = body;
  if (!org_name) return Response.json({ error: 'org_name required' }, { status: 400 });

  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const id       = `cust_${nanoid(12)}`;
  const org_slug = org_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const now      = new Date().toISOString();

  try {
    await env.SECURITY_HUB_DB.prepare(`
      INSERT INTO mssp_customers
        (id, org_name, org_slug, contact_name, contact_email, tier, notes, partner_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, org_name, org_slug, contact_name || null, contact_email || null, tier, notes || null, scope, now, now).run();

    return Response.json({ success: true, customer: { id, org_name, org_slug, tier } }, { status: 201 });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) {
      return Response.json({ error: 'Customer with this name already exists' }, { status: 409 });
    }
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/mssp/customers/:id
export async function handleGetCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const db = env.SECURITY_HUB_DB;
  await ensureMsspCustomersExtended(db);

  try {
    const customer = await db.prepare(`
      SELECT id, org_name, org_slug, contact_name, contact_email, tier, status,
             risk_score, compliance_score, mrr_cents, notes,
             parent_customer_id, suspended_at, archived_at, suspension_reason,
             created_at, updated_at, last_activity_at
      FROM mssp_customers
      WHERE (id = ? OR org_slug = ?) AND partner_id = ? AND status != 'deleted'
    `).bind(customerId, customerId, scope).first();

    if (!customer) return Response.json({ error: 'Customer not found' }, { status: 404 });
    return Response.json({ success: true, customer });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/mssp/customers/:id/metrics
export async function handleCustomerMetrics(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

  const db = env.SECURITY_HUB_DB;
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  let customer;
  try {
    customer = await db.prepare(
      `SELECT * FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
    ).bind(customerId, customerId, scope).first();
  } catch (_) {}

  if (!customer) {
    return Response.json({ error: 'Customer not found' }, { status: 404 });
  }

  let scanMetrics = { total_scans: 0, scans_today: 0, critical_findings: 0, avg_risk: 0 };
  let caseMetrics = { open: 0, in_progress: 0, resolved: 0, critical_open: 0 };

  try {
    const scansQ = await db.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
              AVG(risk_score) as avg_risk
       FROM scan_results WHERE org_id = ?`
    ).bind(customerId).first();
    if (scansQ) {
      scanMetrics.total_scans       = scansQ.total    || 0;
      scanMetrics.critical_findings = scansQ.critical || 0;
      scanMetrics.avg_risk          = Math.round(scansQ.avg_risk || 0);
    }
  } catch (_) {}

  try {
    const casesQ = await db.prepare(
      `SELECT
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_count,
        SUM(CASE WHEN status = 'IN_PROGRESS' THEN 1 ELSE 0 END) as inprog_count,
        SUM(CASE WHEN status = 'RESOLVED' OR status = 'CLOSED' THEN 1 ELSE 0 END) as resolved_count,
        SUM(CASE WHEN status = 'OPEN' AND severity = 'CRITICAL' THEN 1 ELSE 0 END) as crit_open
       FROM soc_cases WHERE org_id = ?`
    ).bind(customerId).first();
    if (casesQ) {
      caseMetrics.open          = casesQ.open_count    || 0;
      caseMetrics.in_progress   = casesQ.inprog_count  || 0;
      caseMetrics.resolved      = casesQ.resolved_count || 0;
      caseMetrics.critical_open = casesQ.crit_open      || 0;
    }
  } catch (_) {}

  return Response.json({
    success:  true,
    customer: {
      id:               customer.id,
      org_name:         customer.org_name,
      org_slug:         customer.org_slug,
      tier:             customer.tier,
      status:           customer.status,
      risk_score:       customer.risk_score,
      compliance_score: customer.compliance_score,
      mrr_cents:        customer.mrr_cents,
      last_activity_at: customer.last_activity_at,
    },
    scans:  scanMetrics,
    cases:  caseMetrics,
    as_of:  new Date().toISOString(),
  });
}

// PUT /api/mssp/customers/:id
export async function handleUpdateCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const allowed = ['org_name','contact_name','contact_email','tier','risk_score','compliance_score','notes','mrr_cents'];
  const updates = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));
  if (!Object.keys(updates).length) {
    return Response.json({ error: 'No valid fields to update' }, { status: 400 });
  }

  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  updates.updated_at = new Date().toISOString();
  const fields    = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const setValues = Object.values(updates);

  try {
    const r = await env.SECURITY_HUB_DB.prepare(
      `UPDATE mssp_customers SET ${fields} WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
    ).bind(...setValues, customerId, customerId, scope).run();
    // No row matched under this partner's scope → the customer isn't theirs (or
    // doesn't exist). Return 404 (matching delete/suspend/archive) instead of a
    // misleading success, so an integrator can't believe a cross-tenant update
    // "worked". The WHERE clause already prevents any actual cross-tenant write.
    if (!r?.meta?.changes) return Response.json({ error: 'Customer not found' }, { status: 404 });
    return Response.json({ success: true });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// DELETE /api/mssp/customers/:id  (soft delete — sets status='deleted')
export async function handleDeleteCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db  = env.SECURITY_HUB_DB;
  await ensureMsspCustomersExtended(db);
  const now = new Date().toISOString();

  try {
    const r = await db.prepare(`
      UPDATE mssp_customers
      SET status = 'deleted', deleted_at = ?, updated_at = ?
      WHERE (id = ? OR org_slug = ?) AND partner_id = ? AND status != 'deleted'
    `).bind(now, now, customerId, customerId, scope).run();
    if (!r?.meta?.changes) return Response.json({ error: 'Customer not found or already deleted' }, { status: 404 });
    return Response.json({ success: true, deleted_at: now });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// POST /api/mssp/customers/:id/suspend
export async function handleSuspendCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body = {};
  try { body = await request.json(); } catch (_) {}
  const reason = (body.reason || 'Suspended by MSSP admin').toString().slice(0, 500);

  const db  = env.SECURITY_HUB_DB;
  await ensureMsspCustomersExtended(db);
  const now = new Date().toISOString();

  try {
    const current = await db.prepare(
      `SELECT status FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
    ).bind(customerId, customerId, scope).first();
    if (!current)                       return Response.json({ error: 'Customer not found' }, { status: 404 });
    if (current.status === 'suspended') return Response.json({ error: 'Customer is already suspended' }, { status: 409 });
    if (current.status === 'deleted')   return Response.json({ error: 'Cannot suspend a deleted customer' }, { status: 409 });

    await db.prepare(`
      UPDATE mssp_customers
      SET status = 'suspended', suspended_at = ?, suspension_reason = ?, updated_at = ?
      WHERE (id = ? OR org_slug = ?) AND partner_id = ?
    `).bind(now, reason, now, customerId, customerId, scope).run();

    return Response.json({ success: true, status: 'suspended', suspended_at: now, reason });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// POST /api/mssp/customers/:id/archive
export async function handleArchiveCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db  = env.SECURITY_HUB_DB;
  await ensureMsspCustomersExtended(db);
  const now = new Date().toISOString();

  try {
    const current = await db.prepare(
      `SELECT status FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
    ).bind(customerId, customerId, scope).first();
    if (!current)                      return Response.json({ error: 'Customer not found' }, { status: 404 });
    if (current.status === 'archived') return Response.json({ error: 'Customer is already archived' }, { status: 409 });
    if (current.status === 'deleted')  return Response.json({ error: 'Cannot archive a deleted customer' }, { status: 409 });

    await db.prepare(`
      UPDATE mssp_customers
      SET status = 'archived', archived_at = ?, updated_at = ?
      WHERE (id = ? OR org_slug = ?) AND partner_id = ?
    `).bind(now, now, customerId, customerId, scope).run();

    return Response.json({ success: true, status: 'archived', archived_at: now });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// POST /api/mssp/customers/:id/restore
export async function handleRestoreCustomer(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db  = env.SECURITY_HUB_DB;
  await ensureMsspCustomersExtended(db);
  const now = new Date().toISOString();

  try {
    const current = await db.prepare(
      `SELECT status FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
    ).bind(customerId, customerId, scope).first();
    if (!current)                    return Response.json({ error: 'Customer not found' }, { status: 404 });
    if (current.status === 'active') return Response.json({ error: 'Customer is already active' }, { status: 409 });
    if (current.status === 'deleted') return Response.json({ error: 'Cannot restore a deleted customer' }, { status: 409 });

    await db.prepare(`
      UPDATE mssp_customers
      SET status = 'active', suspended_at = NULL, archived_at = NULL,
          suspension_reason = NULL, updated_at = ?
      WHERE (id = ? OR org_slug = ?) AND partner_id = ?
    `).bind(now, customerId, customerId, scope).run();

    return Response.json({ success: true, status: 'active', restored_at: now });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/mssp/overview
export async function handleMSSPOverview(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

  const scope = partnerScope(authCtx);
  const emptyOverview = {
    success: true, total_customers: 0, active_customers: 0, onboarding: 0,
    high_risk_count: 0, total_mrr: 0, avg_risk_score: 0, avg_compliance: 0,
    high_risk_customers: [], as_of: new Date().toISOString(),
  };
  if (!scope) return Response.json(emptyOverview);

  try {
    const summary = await env.SECURITY_HUB_DB.prepare(`
      SELECT
        COUNT(*) as total_customers,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN status = 'onboarding' THEN 1 ELSE 0 END) as onboarding,
        SUM(CASE WHEN risk_score >= 75 THEN 1 ELSE 0 END) as high_risk,
        SUM(mrr_cents) as total_mrr_cents,
        AVG(risk_score) as avg_risk,
        AVG(compliance_score) as avg_compliance
      FROM mssp_customers
      WHERE partner_id = ?
    `).bind(scope).first();

    const recentQ = await env.SECURITY_HUB_DB.prepare(`
      SELECT id, org_name, risk_score, status, tier, last_activity_at
      FROM mssp_customers
      WHERE partner_id = ?
      ORDER BY risk_score DESC
      LIMIT 5
    `).bind(scope).all();

    return Response.json({
      success: true,
      total_customers:     summary?.total_customers || 0,
      active_customers:    summary?.active          || 0,
      onboarding:          summary?.onboarding      || 0,
      high_risk_count:     summary?.high_risk        || 0,
      total_mrr:           Math.round((summary?.total_mrr_cents || 0) / 100),
      avg_risk_score:      Math.round(summary?.avg_risk || 0),
      avg_compliance:      Math.round(summary?.avg_compliance || 0),
      high_risk_customers: recentQ?.results || [],
      as_of: new Date().toISOString(),
    });
  } catch (e) {
    return Response.json({ ...emptyOverview, degraded: true });
  }
}
