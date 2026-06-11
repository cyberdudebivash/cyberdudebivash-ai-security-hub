/**
 * CYBERDUDEBIVASH® AI Security Hub
 * MSSP Workspace — Multi-Tenant Customer Management
 *
 * Uses mssp_customers table (schema_phase2.sql).
 * Requires: mssp_admin role for cross-customer views,
 *           enterprise/admin for own-org views.
 */

// Use native CF Workers crypto — no external package needed
const nanoid = (n = 21) => crypto.randomUUID().replace(/-/g, '').slice(0, n);

function requireMSSPAdmin(authCtx) {
  return authCtx?.role === 'admin' || authCtx?.role === 'mssp_admin';
}

function requireAuth(authCtx) {
  return authCtx?.authenticated === true;
}

// GET /api/mssp/customers
export async function handleListCustomers(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required', code: 403 }, { status: 403 });
  }

  const url    = new URL(request.url);
  const status = url.searchParams.get('status') || 'active';
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(`
      SELECT id, org_name, org_slug, contact_name, contact_email,
             tier, status, risk_score, compliance_score,
             mrr_cents, created_at, updated_at, last_activity_at
      FROM mssp_customers
      WHERE status = ?
      ORDER BY risk_score DESC
      LIMIT ? OFFSET ?
    `).bind(status, limit, offset).all();

    const totalQ = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as total FROM mssp_customers WHERE status = ?`
    ).bind(status).first();

    return Response.json({
      success:   true,
      customers: rows?.results || [],
      total:     totalQ?.total || 0,
      limit,
      offset,
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
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

  const id       = `cust_${nanoid(12)}`;
  const org_slug = org_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const now      = new Date().toISOString();

  try {
    await env.SECURITY_HUB_DB.prepare(`
      INSERT INTO mssp_customers
        (id, org_name, org_slug, contact_name, contact_email, tier, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, org_name, org_slug, contact_name || null, contact_email || null, tier, notes || null, now, now).run();

    return Response.json({ success: true, customer: { id, org_name, org_slug, tier } }, { status: 201 });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) {
      return Response.json({ error: 'Customer with this name already exists' }, { status: 409 });
    }
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/mssp/customers/:id/metrics
export async function handleCustomerMetrics(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

  const db = env.SECURITY_HUB_DB;

  // Get customer record
  let customer;
  try {
    customer = await db.prepare(
      `SELECT * FROM mssp_customers WHERE id = ? OR org_slug = ?`
    ).bind(customerId, customerId).first();
  } catch (_) {}

  if (!customer) {
    return Response.json({ error: 'Customer not found' }, { status: 404 });
  }

  // Aggregate scan metrics for this customer's assigned users
  let scanMetrics = { total_scans: 0, scans_today: 0, critical_findings: 0, avg_risk: 0 };
  let caseMetrics = { open: 0, in_progress: 0, resolved: 0, critical_open: 0 };

  try {
    // Scans: attempt to query by org_id if column exists
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
      caseMetrics.open       = casesQ.open_count   || 0;
      caseMetrics.in_progress= casesQ.inprog_count || 0;
      caseMetrics.resolved   = casesQ.resolved_count || 0;
      caseMetrics.critical_open = casesQ.crit_open || 0;
    }
  } catch (_) {}

  return Response.json({
    success:  true,
    customer: {
      id:           customer.id,
      org_name:     customer.org_name,
      org_slug:     customer.org_slug,
      tier:         customer.tier,
      status:       customer.status,
      risk_score:   customer.risk_score,
      compliance_score: customer.compliance_score,
      mrr_cents:    customer.mrr_cents,
      last_activity_at: customer.last_activity_at,
    },
    scans:    scanMetrics,
    cases:    caseMetrics,
    as_of:    new Date().toISOString(),
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

  const allowed = ['org_name','contact_name','contact_email','tier','status','risk_score','compliance_score','notes','mrr_cents'];
  const updates = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));
  if (!Object.keys(updates).length) {
    return Response.json({ error: 'No valid fields to update' }, { status: 400 });
  }

  updates.updated_at = new Date().toISOString();
  const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = [...Object.values(updates), customerId];

  try {
    await env.SECURITY_HUB_DB.prepare(
      `UPDATE mssp_customers SET ${fields} WHERE id = ? OR org_slug = ?`
    ).bind(...values, customerId).run();
    return Response.json({ success: true });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/mssp/overview
export async function handleMSSPOverview(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) {
    return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  }

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
    `).first();

    const recentQ = await env.SECURITY_HUB_DB.prepare(`
      SELECT id, org_name, risk_score, status, tier, last_activity_at
      FROM mssp_customers
      ORDER BY risk_score DESC
      LIMIT 5
    `).all();

    return Response.json({
      success: true,
      total_customers:    summary?.total_customers || 0,
      active_customers:   summary?.active          || 0,
      onboarding:         summary?.onboarding      || 0,
      high_risk_count:    summary?.high_risk        || 0,
      total_mrr:          Math.round((summary?.total_mrr_cents || 0) / 100),
      avg_risk_score:     Math.round(summary?.avg_risk || 0),
      avg_compliance:     Math.round(summary?.avg_compliance || 0),
      high_risk_customers: recentQ?.results || [],
      as_of: new Date().toISOString(),
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}
