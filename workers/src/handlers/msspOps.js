/**
 * MSSP Operations Handler — Phase 3 P0
 * Provides the specific API routes consumed by mssp-command-center.html
 *
 * Routes:
 *   GET  /api/mssp/metrics          — Partner count, MRR, active clients, alerts
 *   GET  /api/mssp/partners         — List all MSSP partners with stats
 *   POST /api/mssp/partners         — Onboard a new MSSP partner
 *   GET  /api/mssp/wl-status        — White-label configuration status
 *   GET  /api/mssp/usage            — Usage metrics across all partners
 *   GET  /api/mssp/revenue-trend    — Monthly MRR trend (6 months)
 *   GET  /api/mssp/expansion-opps   — Partners eligible for tier upgrade
 */

import { triggerMsspOnboarding } from '../services/lifecycleEngine.js';

function ok(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/* ── GET /api/mssp/metrics ──────────────────────────────────────────────────── */
export async function handleMsspMetrics(request, env) {
  const db = env.DB;
  if (!db) return ok({ partners: 0, mrr: 0, active_clients: 0, open_alerts: 0 });

  try {
    const [partnerRow, clientRow, alertRow, billingRow] = await Promise.all([
      db.prepare(`SELECT COUNT(*) as cnt, COUNT(CASE WHEN status='active' THEN 1 END) as active FROM mssp_partners`).first().catch(() => ({ cnt: 0, active: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM mssp_clients WHERE status='active'`).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COALESCE(SUM(open_alerts),0) as total FROM mssp_clients WHERE status='active'`).first().catch(() => ({ total: 0 })),
      db.prepare(`
        SELECT COALESCE(SUM(mrr_inr),0) as total_mrr
        FROM mssp_billing
        WHERE period = strftime('%Y-%m', 'now') AND status IN ('paid','invoiced')
      `).first().catch(() => ({ total_mrr: 0 })),
    ]);

    // Also grab MRR from mssp_customers (alternative table)
    const customerMrr = await db.prepare(`
      SELECT COALESCE(SUM(mrr_cents),0) as total FROM mssp_customers WHERE status='active'
    `).first().catch(() => ({ total: 0 }));

    const totalMrr = (billingRow?.total_mrr || 0) + Math.round((customerMrr?.total || 0) / 100);

    return ok({
      partners:       partnerRow?.cnt || 0,
      active_partners: partnerRow?.active || 0,
      active_clients:  clientRow?.cnt || 0,
      open_alerts:    alertRow?.total || 0,
      mrr_inr:        totalMrr,
      arr_inr:        totalMrr * 12,
    });
  } catch (e) {
    return ok({ partners: 0, mrr: 0, active_clients: 0, open_alerts: 0, error: e.message });
  }
}

/* ── GET /api/mssp/partners ─────────────────────────────────────────────────── */
export async function handleListMsspPartners(request, env) {
  const db = env.DB;
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
  const status = url.searchParams.get('status') || null;

  if (!db) return ok({ partners: [], total: 0 });

  try {
    let query = `
      SELECT p.*,
        (SELECT COUNT(*) FROM mssp_clients c WHERE c.partner_id = p.id) as client_count_live,
        (SELECT COALESCE(SUM(b.mrr_inr),0) FROM mssp_billing b
         WHERE b.mssp_user_id = p.id AND b.period = strftime('%Y-%m','now')) as mrr_this_month
      FROM mssp_partners p
    `;
    const params = [];
    if (status) { query += ` WHERE p.status = ?`; params.push(status); }
    query += ` ORDER BY p.created_at DESC LIMIT ?`;
    params.push(limit);

    const rows = await db.prepare(query).bind(...params).all().catch(() => ({ results: [] }));
    const countRow = await db.prepare(`SELECT COUNT(*) as cnt FROM mssp_partners${status ? ' WHERE status=?' : ''}`).bind(...(status ? [status] : [])).first().catch(() => ({ cnt: 0 }));

    return ok({
      partners: (rows?.results || []).map(p => ({
        ...p,
        api_key: p.api_key ? '****' + p.api_key.slice(-4) : null, // mask for security
      })),
      total: countRow?.cnt || 0,
    });
  } catch (e) {
    return ok({ partners: [], total: 0, error: e.message });
  }
}

/* ── POST /api/mssp/partners ────────────────────────────────────────────────── */
export async function handleAddMsspPartner(request, env) {
  const db = env.DB;
  const body = await request.json().catch(() => ({}));

  const {
    company = '', contact_email = '', tier = 'RESELLER',
    plan = 'reseller', brand_name = '', custom_domain = '',
    primary_color = '#00d4ff', margin_pct = 20,
  } = body;

  if (!company || !contact_email) {
    return ok({ error: 'company and contact_email are required' }, 400);
  }

  const id = 'mp_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const apiKey = 'cdb_mssp_' + Math.random().toString(36).slice(2, 18);

  if (db) {
    try {
      await db.prepare(`
        INSERT INTO mssp_partners
          (id, company, contact_email, tier, plan, brand_name, custom_domain,
           primary_color, api_key, client_count, max_clients, margin_pct,
           status, onboarded_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 10, ?, 'pending', unixepoch(), unixepoch())
      `).bind(
        id, company, contact_email, tier.toUpperCase(), plan,
        brand_name, custom_domain, primary_color, apiKey, parseFloat(margin_pct) || 20,
      ).run();

      // Write to subscriptions table for revenue tracking and renewal engine
      await db.prepare(`
        INSERT OR IGNORE INTO subscriptions
          (id, email, plan, status, processor, external_id, price_inr, activated_at, expires_at, created_at)
        VALUES (?, ?, ?, 'active', 'mssp', ?, 0, datetime('now'), datetime('now', '+1 year'), datetime('now'))
      `).bind('sub_mssp_' + id, contact_email, tier.toUpperCase(), id).run().catch(() => {});
    } catch (e) {
      if (e.message?.includes('UNIQUE')) {
        return ok({ error: 'A partner with this email already exists' }, 409);
      }
      return ok({ error: 'Database error: ' + e.message }, 500);
    }
  }

  // Trigger MSSP onboarding lifecycle: revenue attribution + email sequence (fire-and-forget)
  triggerMsspOnboarding(env, {
    email: contact_email, company, tier: tier.toUpperCase(), partner_id: id,
  }).catch(() => {});

  return ok({
    success: true,
    partner: { id, company, contact_email, tier, plan, status: 'pending', api_key: apiKey },
    message: 'MSSP partner onboarded. Portal credentials sent to ' + contact_email,
  }, 201);
}

/* ── GET /api/mssp/wl-status ────────────────────────────────────────────────── */
export async function handleMsspWlStatus(request, env) {
  const db = env.DB;
  if (!db) return ok({ total: 0, configured: 0, pending: 0, partners: [] });

  try {
    const rows = await db.prepare(`
      SELECT id, company, brand_name, custom_domain, primary_color, status,
        CASE WHEN brand_name IS NOT NULL AND brand_name != '' THEN 1 ELSE 0 END as has_brand,
        CASE WHEN custom_domain IS NOT NULL AND custom_domain != '' THEN 1 ELSE 0 END as has_domain
      FROM mssp_partners
      ORDER BY created_at DESC LIMIT 100
    `).all().catch(() => ({ results: [] }));

    const partners = rows?.results || [];
    const configured = partners.filter(p => p.has_brand && p.has_domain).length;
    const pending = partners.filter(p => !p.has_brand || !p.has_domain).length;

    return ok({
      total:      partners.length,
      configured,
      pending,
      partners:   partners.map(p => ({
        id:          p.id,
        company:     p.company,
        brand_name:  p.brand_name || null,
        custom_domain: p.custom_domain || null,
        primary_color: p.primary_color,
        status:      p.status,
        wl_ready:    !!(p.has_brand && p.has_domain),
      })),
    });
  } catch (e) {
    return ok({ total: 0, configured: 0, pending: 0, error: e.message });
  }
}

/* ── GET /api/mssp/usage ────────────────────────────────────────────────────── */
export async function handleMsspUsage(request, env) {
  const db = env.DB;
  if (!db) return ok({ total_scans: 0, total_api_calls: 0, total_reports: 0 });

  try {
    const thisMonth = new Date().toISOString().slice(0, 7); // YYYY-MM

    const [usageRow, clientsRow, scanRow] = await Promise.all([
      db.prepare(`
        SELECT
          COALESCE(SUM(scans_used),0) as total_scans,
          COALESCE(SUM(api_calls_used),0) as total_api_calls,
          COALESCE(SUM(reports_generated),0) as total_reports
        FROM mssp_billing WHERE period = ?
      `).bind(thisMonth).first().catch(() => ({ total_scans: 0, total_api_calls: 0, total_reports: 0 })),

      db.prepare(`
        SELECT COUNT(*) as active, SUM(open_alerts) as alerts
        FROM mssp_clients WHERE status='active'
      `).first().catch(() => ({ active: 0, alerts: 0 })),

      // Count scans done for MSSP clients this month (from scan_jobs table if it exists)
      db.prepare(`
        SELECT COUNT(*) as cnt FROM api_usage
        WHERE created_at >= ? AND plan IN ('MSSP','mssp')
      `).bind(thisMonth + '-01').first().catch(() => ({ cnt: 0 })),
    ]);

    return ok({
      month:           thisMonth,
      total_scans:     (usageRow?.total_scans || 0) + (scanRow?.cnt || 0),
      total_api_calls: usageRow?.total_api_calls || 0,
      total_reports:   usageRow?.total_reports || 0,
      active_clients:  clientsRow?.active || 0,
      total_alerts:    clientsRow?.alerts || 0,
    });
  } catch (e) {
    return ok({ total_scans: 0, total_api_calls: 0, total_reports: 0, error: e.message });
  }
}

/* ── GET /api/mssp/revenue-trend ────────────────────────────────────────────── */
export async function handleMsspRevenueTrend(request, env) {
  const db = env.DB;
  if (!db) return ok({ months: [], trend: 'insufficient_data' });

  try {
    // Build last 6 months of MRR data from mssp_billing
    const months = [];
    const now = new Date();
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push(d.toISOString().slice(0, 7));
    }

    const rows = await db.prepare(`
      SELECT period, COALESCE(SUM(mrr_inr),0) as mrr
      FROM mssp_billing
      WHERE period IN (${months.map(() => '?').join(',')})
        AND status IN ('paid','invoiced','pending')
      GROUP BY period
      ORDER BY period ASC
    `).bind(...months).all().catch(() => ({ results: [] }));

    // Also query mssp_customers for MRR (alternate source)
    const customerMrr = await db.prepare(`
      SELECT COALESCE(SUM(mrr_cents),0) as total FROM mssp_customers WHERE status='active'
    `).first().catch(() => ({ total: 0 }));
    const currentCustomerMrr = Math.round((customerMrr?.total || 0) / 100);

    const mrrByMonth = {};
    for (const r of (rows?.results || [])) {
      mrrByMonth[r.period] = r.mrr;
    }

    const trend = months.map((m, i) => ({
      month:   m,
      label:   new Date(m + '-15').toLocaleString('en-IN', { month: 'short', year: '2-digit' }),
      mrr_inr: mrrByMonth[m] || (i === months.length - 1 ? currentCustomerMrr : 0),
    }));

    const lastMrr = trend[trend.length - 2]?.mrr_inr || 0;
    const thisMrr = trend[trend.length - 1]?.mrr_inr || 0;
    const trendDir = thisMrr > lastMrr ? 'up' : thisMrr < lastMrr ? 'down' : 'flat';
    const growthPct = lastMrr > 0 ? Math.round(((thisMrr - lastMrr) / lastMrr) * 100) : 0;

    return ok({
      months:     trend,
      trend:      trendDir,
      growth_pct: growthPct,
      current_mrr: thisMrr,
    });
  } catch (e) {
    return ok({ months: [], trend: 'error', error: e.message });
  }
}

/* ── GET /api/mssp/expansion-opps ──────────────────────────────────────────── */
export async function handleMsspExpansionOpps(request, env) {
  const db = env.DB;
  if (!db) return ok({ opportunities: [], total: 0 });

  try {
    // Partners eligible for tier upgrade: client_count at or above 80% of max_clients
    // or active but on lower tiers with good billing history
    const rows = await db.prepare(`
      SELECT p.id, p.company, p.contact_email, p.tier, p.plan,
        p.client_count, p.max_clients, p.margin_pct, p.status,
        (SELECT COALESCE(SUM(b.mrr_inr),0) FROM mssp_billing b
         WHERE b.mssp_user_id = p.id AND b.status IN ('paid','invoiced')
           AND b.period >= strftime('%Y-%m', 'now', '-3 months')) as mrr_3m,
        ROUND(CAST(p.client_count AS REAL) / NULLIF(p.max_clients, 0) * 100) as capacity_pct
      FROM mssp_partners p
      WHERE p.status = 'active'
      ORDER BY capacity_pct DESC, mrr_3m DESC
      LIMIT 20
    `).all().catch(() => ({ results: [] }));

    const opportunities = (rows?.results || []).map(p => {
      const capacityPct = p.capacity_pct || 0;
      let recommendation = null;
      let reason = null;

      if (capacityPct >= 80 && p.tier === 'RESELLER') {
        recommendation = 'SILVER';
        reason = `At ${capacityPct}% client capacity — upgrade to SILVER unlocks more seats`;
      } else if (capacityPct >= 80 && p.tier === 'SILVER') {
        recommendation = 'GOLD';
        reason = `At ${capacityPct}% capacity — GOLD tier doubles limit and reduces margin`;
      } else if (capacityPct >= 80 && p.tier === 'GOLD') {
        recommendation = 'PLATINUM';
        reason = `Full capacity — PLATINUM tier for unlimited clients + dedicated support`;
      } else if (p.mrr_3m > 50000 && p.tier === 'RESELLER') {
        recommendation = 'SILVER';
        reason = `Strong billing performance (₹${p.mrr_3m.toLocaleString('en-IN')} MRR, 3m avg)`;
      }

      return recommendation ? {
        id:             p.id,
        company:        p.company,
        contact_email:  p.contact_email,
        current_tier:   p.tier,
        current_plan:   p.plan,
        recommended_tier: recommendation,
        reason,
        client_count:   p.client_count,
        max_clients:    p.max_clients,
        capacity_pct:   capacityPct,
        mrr_3m_inr:     p.mrr_3m || 0,
      } : null;
    }).filter(Boolean);

    return ok({
      opportunities,
      total: opportunities.length,
    });
  } catch (e) {
    return ok({ opportunities: [], total: 0, error: e.message });
  }
}
