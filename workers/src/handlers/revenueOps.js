/**
 * Revenue Operations Handler — Phase 3 P0
 * Provides the specific API routes consumed by revenue-command-center.html
 * and fills attribution/lead tracking gaps in the existing pipeline.
 *
 * Routes:
 *   GET  /api/revenue/breakdown       — Revenue by product type (Assessment/API/Enterprise)
 *   GET  /api/revenue/leads           — Lead source breakdown
 *   GET  /api/revenue/funnel          — Conversion funnel rates
 *   GET  /api/revenue/transactions    — Recent payment transactions
 *   GET  /api/revenue/forecast        — Sales forecast (current month vs target)
 *   GET  /api/enterprise/pipeline     — Enterprise deal pipeline board
 *   POST /api/enterprise/pipeline     — Add new enterprise deal
 *   POST /api/enterprise/inquiry      — Alias for /api/enterprise/inquire (spelling fix)
 *   POST /api/attribution/track       — Track visitor→lead→customer attribution
 */

function ok(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function empty(label) {
  return { data: [], total: 0, note: `No ${label} data yet — revenue will appear as transactions occur.` };
}

/* ── GET /api/revenue/breakdown ────────────────────────────────────────────── */
export async function handleRevenueBreakdown(request, env) {
  const db = env.DB;
  if (!db) return ok({ assessment: { count: 0, total: 0, avg: 0 }, api: { count: 0, total: 0, avg: 0 }, enterprise: { count: 0, total: 0, avg: 0 } });

  try {
    // Assessments: scan_orders + service_orders where service_ref like 'ASSESSMENT'
    const [assessmentRow, apiRow, enterpriseRow, totalRow] = await Promise.all([
      db.prepare(`
        SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as total
        FROM payments
        WHERE status='success' AND (
          LOWER(plan) LIKE '%assessment%' OR LOWER(plan) LIKE '%scan%' OR LOWER(plan) LIKE '%security%'
        )
      `).first().catch(() => ({ cnt: 0, total: 0 })),

      db.prepare(`
        SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as total
        FROM payments
        WHERE status='success' AND (
          LOWER(plan) IN ('starter','pro','enterprise','mssp','community','api','sentinel')
          OR LOWER(plan) LIKE '%api%'
        )
      `).first().catch(() => ({ cnt: 0, total: 0 })),

      db.prepare(`
        SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as total
        FROM payments
        WHERE status='success' AND amount_inr >= 24999
      `).first().catch(() => ({ cnt: 0, total: 0 })),

      db.prepare(`
        SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as total
        FROM payments
        WHERE status='success'
      `).first().catch(() => ({ cnt: 0, total: 0 })),
    ]);

    return ok({
      assessment: {
        count: assessmentRow?.cnt || 0,
        total: assessmentRow?.total || 0,
        avg: assessmentRow?.cnt > 0 ? Math.round((assessmentRow?.total || 0) / assessmentRow.cnt) : 0,
      },
      api: {
        count: apiRow?.cnt || 0,
        total: apiRow?.total || 0,
        avg: apiRow?.cnt > 0 ? Math.round((apiRow?.total || 0) / apiRow.cnt) : 0,
      },
      enterprise: {
        count: enterpriseRow?.cnt || 0,
        total: enterpriseRow?.total || 0,
        avg: enterpriseRow?.cnt > 0 ? Math.round((enterpriseRow?.total || 0) / enterpriseRow.cnt) : 0,
      },
      all: {
        count: totalRow?.cnt || 0,
        total: totalRow?.total || 0,
      },
    });
  } catch (e) {
    return ok({ assessment: { count: 0, total: 0, avg: 0 }, api: { count: 0, total: 0, avg: 0 }, enterprise: { count: 0, total: 0, avg: 0 }, error: e.message });
  }
}

/* ── GET /api/revenue/leads ─────────────────────────────────────────────────── */
export async function handleRevenueLeads(request, env) {
  const db = env.DB;
  if (!db) return ok(empty('leads'));

  try {
    const rows = await db.prepare(`
      SELECT source, COUNT(*) as count
      FROM leads
      GROUP BY source
      ORDER BY count DESC
      LIMIT 10
    `).all().catch(() => ({ results: [] }));

    // Supplement with enterprise leads
    const entRows = await db.prepare(`
      SELECT 'enterprise_inquiry' as source, COUNT(*) as count
      FROM enterprise_leads
    `).all().catch(() => ({ results: [] }));

    // Supplement with funnel events for visit tracking
    const visitRow = await db.prepare(`
      SELECT COUNT(DISTINCT email) as count FROM funnel_events WHERE stage='visit'
    `).first().catch(() => ({ count: 0 }));

    const sources = {};
    for (const r of (rows?.results || [])) {
      sources[r.source || 'website'] = (sources[r.source || 'website'] || 0) + r.count;
    }
    for (const r of (entRows?.results || [])) {
      sources['enterprise_inquiry'] = (sources['enterprise_inquiry'] || 0) + r.count;
    }

    const total = Object.values(sources).reduce((a, b) => a + b, 0);
    const breakdown = Object.entries(sources).map(([source, count]) => ({
      source,
      count,
      pct: total > 0 ? Math.round((count / total) * 100) : 0,
    })).sort((a, b) => b.count - a.count);

    return ok({
      total,
      breakdown,
      visitors: visitRow?.count || 0,
      conversion_rate: total > 0 && visitRow?.count > 0
        ? ((total / visitRow.count) * 100).toFixed(1)
        : '0.0',
    });
  } catch (e) {
    return ok({ total: 0, breakdown: [], error: e.message });
  }
}

/* ── GET /api/revenue/funnel ────────────────────────────────────────────────── */
export async function handleRevenueFunnelOps(request, env) {
  const db = env.DB;
  if (!db) return ok({ stages: [], note: 'No funnel data yet' });

  try {
    const stages = ['visit', 'scan_start', 'scan_done', 'email_capture', 'product_view', 'checkout_start', 'purchase'];

    const counts = await Promise.all(
      stages.map(stage =>
        db.prepare(`SELECT COUNT(DISTINCT email) as cnt FROM funnel_events WHERE stage=?`)
          .bind(stage).first().catch(() => ({ cnt: 0 }))
      )
    );

    const stageCounts = stages.map((stage, i) => ({
      stage,
      label: stage.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      count: counts[i]?.cnt || 0,
    }));

    // Calculate drop-off rates between steps
    const funnelData = stageCounts.map((s, i) => ({
      ...s,
      conversion_from_prev: i === 0 || stageCounts[i - 1].count === 0
        ? 100
        : Math.round((s.count / stageCounts[i - 1].count) * 100),
      drop_off: i === 0 || stageCounts[i - 1].count === 0
        ? 0
        : Math.round(((stageCounts[i - 1].count - s.count) / stageCounts[i - 1].count) * 100),
    }));

    const visitorCount = stageCounts[0].count;
    const purchaseCount = stageCounts[stageCounts.length - 1].count;
    const overallConversion = visitorCount > 0
      ? ((purchaseCount / visitorCount) * 100).toFixed(2)
      : '0.00';

    return ok({
      stages: funnelData,
      overall_conversion_pct: overallConversion,
      visitor_count: visitorCount,
      purchase_count: purchaseCount,
    });
  } catch (e) {
    return ok({ stages: [], error: e.message });
  }
}

/* ── GET /api/revenue/transactions ─────────────────────────────────────────── */
export async function handleRevenueTransactions(request, env) {
  const db = env.DB;
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);

  if (!db) return ok({ transactions: [], total: 0 });

  try {
    const rows = await db.prepare(`
      SELECT
        id, email, plan as product, amount_inr as amount,
        currency, status, payment_method,
        razorpay_id as payment_ref,
        created_at, paid_at
      FROM payments
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(limit).all().catch(() => ({ results: [] }));

    const countRow = await db.prepare(`SELECT COUNT(*) as total FROM payments WHERE status='success'`).first().catch(() => ({ total: 0 }));

    return ok({
      transactions: rows?.results || [],
      total: countRow?.total || 0,
    });
  } catch (e) {
    return ok({ transactions: [], total: 0, error: e.message });
  }
}

/* ── GET /api/revenue/forecast ─────────────────────────────────────────────── */
export async function handleRevenueForecastOps(request, env) {
  const db = env.DB;
  if (!db) return ok({ insufficient_data: true, current_month: { actual: 0, target: 0 } });

  try {
    const now = new Date();
    const thisMonthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
    const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().slice(0, 10);
    const lastMonthEnd   = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().slice(0, 10);
    const prevMonthStart = new Date(now.getFullYear(), now.getMonth() - 2, 1).toISOString().slice(0, 10);
    const prevMonthEnd   = new Date(now.getFullYear(), now.getMonth() - 1, 0).toISOString().slice(0, 10);

    const [currentRow, lastRow, prevRow, dayInMonth] = await Promise.all([
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at >= ?`).bind(thisMonthStart).first().catch(() => ({ total: 0 })),
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at BETWEEN ? AND ?`).bind(lastMonthStart, lastMonthEnd + 'T23:59:59').first().catch(() => ({ total: 0 })),
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at BETWEEN ? AND ?`).bind(prevMonthStart, prevMonthEnd + 'T23:59:59').first().catch(() => ({ total: 0 })),
      Promise.resolve(now.getDate()),
    ]);

    const currentActual = currentRow?.total || 0;
    const lastMonthTotal = lastRow?.total || 0;
    const prevMonthTotal = prevRow?.total || 0;
    const daysInMonth    = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();

    // Linear projection based on run rate
    const dailyRunRate     = dayInMonth > 0 ? currentActual / dayInMonth : 0;
    const projectedMonth   = Math.round(dailyRunRate * daysInMonth);
    const growthPct        = lastMonthTotal > 0 ? ((currentActual - lastMonthTotal) / lastMonthTotal * 100).toFixed(1) : 0;
    const trend            = lastMonthTotal > prevMonthTotal ? 'up' : lastMonthTotal < prevMonthTotal ? 'down' : 'flat';

    // Target = 20% above last month (conservative growth target)
    const monthTarget      = Math.max(lastMonthTotal * 1.2, 50000);
    const quarterlyForecast = projectedMonth * 3;

    const insufficient = currentActual === 0 && lastMonthTotal === 0;

    return ok({
      insufficient_data: insufficient,
      current_month: {
        actual:          currentActual,
        target:          Math.round(monthTarget),
        projected:       projectedMonth,
        day_in_month:    dayInMonth,
        days_in_month:   daysInMonth,
        progress_pct:    monthTarget > 0 ? Math.min(Math.round((currentActual / monthTarget) * 100), 100) : 0,
        daily_run_rate:  Math.round(dailyRunRate),
      },
      last_month:        lastMonthTotal,
      prev_month:        prevMonthTotal,
      growth_pct:        parseFloat(growthPct),
      trend,
      next_month:        { projected: projectedMonth, growth_pct: parseFloat(growthPct) },
      quarterly:         { projected: quarterlyForecast },
    });
  } catch (e) {
    return ok({ insufficient_data: true, current_month: { actual: 0, target: 0 }, error: e.message });
  }
}

/* ── GET /api/enterprise/pipeline ──────────────────────────────────────────── */
export async function handleGetEnterprisePipeline(request, env) {
  const db = env.DB;
  const url = new URL(request.url);
  const type = url.searchParams.get('type'); // optional: 'mssp'

  if (!db) return ok({ stages: {}, deals: [], total_value: 0 });

  try {
    let query = `SELECT * FROM deal_pipeline ORDER BY created_at DESC LIMIT 200`;
    if (type === 'mssp') {
      query = `SELECT COUNT(*) as cnt FROM deal_pipeline WHERE LOWER(industry) LIKE '%mssp%' OR LOWER(plan_target) LIKE '%mssp%'`;
      const row = await db.prepare(query).first().catch(() => ({ cnt: 0 }));
      return ok({ count: row?.cnt || 0 });
    }

    const rows = await db.prepare(query).all().catch(() => ({ results: [] }));
    const deals = rows?.results || [];

    // Group by stage
    const stages = {
      lead:        [],
      qualified:   [],
      demo:        [],
      proposal:    [],
      negotiation: [],
      closed_won:  [],
      closed_lost: [],
    };

    let totalValue = 0;
    for (const deal of deals) {
      const stage = deal.stage || 'lead';
      if (stages[stage]) stages[stage].push(deal);
      if (['lead','qualified','demo','proposal','negotiation'].includes(stage)) {
        totalValue += (deal.deal_value_inr || 0) * ((deal.probability_pct || 20) / 100);
      }
    }

    const stageMetrics = {};
    for (const [stage, items] of Object.entries(stages)) {
      stageMetrics[stage] = {
        count: items.length,
        value: items.reduce((sum, d) => sum + (d.deal_value_inr || 0), 0),
        deals: items,
      };
    }

    return ok({
      stages:      stageMetrics,
      total_deals: deals.length,
      pipeline_value: Math.round(totalValue),
      weighted_pipeline: Math.round(totalValue),
    });
  } catch (e) {
    return ok({ stages: {}, deals: [], error: e.message });
  }
}

/* ── POST /api/enterprise/pipeline ─────────────────────────────────────────── */
export async function handleAddEnterpriseDeal(request, env) {
  const db = env.DB;
  const body = await request.json().catch(() => ({}));

  const {
    company = '', contact_name = '', contact_email = '', contact_title = '',
    industry = '', company_size = '', deal_value_inr = 0,
    stage = 'lead', notes = '', plan_target = 'ENTERPRISE',
    source = 'manual',
  } = body;

  if (!company || !contact_email) {
    return ok({ error: 'company and contact_email are required' }, 400);
  }

  const id = 'dp_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

  if (db) {
    try {
      await db.prepare(`
        INSERT INTO deal_pipeline
          (id, company, contact_name, contact_email, contact_title,
           industry, company_size, deal_value_inr, stage, plan_target, source,
           probability_pct, created_at, updated_at)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(
        id, company, contact_name, contact_email, contact_title,
        industry, company_size, parseInt(deal_value_inr) || 0,
        stage, plan_target, source,
        stage === 'lead' ? 10 : stage === 'qualified' ? 25 : stage === 'demo' ? 40 :
        stage === 'proposal' ? 60 : stage === 'negotiation' ? 75 : 0,
      ).run();

      // Also create a CRM lead entry if stage is lead/qualified
      if (['lead', 'qualified'].includes(stage)) {
        await db.prepare(`
          INSERT OR IGNORE INTO crm_leads
            (id, email, company, sector, icp_score, icp_tier, source, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          'cld_' + id, contact_email, company, industry,
          stage === 'qualified' ? 60 : 30,
          stage === 'qualified' ? 'B' : 'C',
          source, stage,
        ).run().catch(() => {});
      }
    } catch (e) {
      return ok({ error: 'Database error: ' + e.message }, 500);
    }
  }

  return ok({ success: true, id, company, stage, deal_value_inr });
}

/* ── POST /api/enterprise/inquiry (spelling alias) ──────────────────────────── */
export async function handleEnterpriseInquiryAlias(request, env) {
  const db = env.DB;
  const body = await request.json().catch(() => ({}));

  const {
    name = '', email = '', company = '', title = '',
    industry = '', size = '', phone = '',
    interest = '', message = '', source = 'website',
  } = body;

  if (!company || !email) {
    return ok({ error: 'company and email are required' }, 400);
  }

  // Store in enterprise_leads table
  if (db) {
    try {
      await db.prepare(`
        INSERT INTO enterprise_leads
          (id, company_name, contact_name, contact_title, email, phone,
           industry, company_size, requirements, package_interest, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', datetime('now'))
      `).bind(
        'enq_' + Date.now().toString(36),
        company, name, title, email, phone,
        industry, size,
        message?.slice(0, 1000),
        interest,
      ).run().catch(() => {});

      // Also create deal_pipeline entry as 'lead' stage
      await db.prepare(`
        INSERT OR IGNORE INTO deal_pipeline
          (id, company, contact_name, contact_email, contact_title,
           industry, company_size, stage, plan_target, source,
           probability_pct, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'lead', 'ENTERPRISE', ?, 10, datetime('now'), datetime('now'))
      `).bind(
        'dp_' + Date.now().toString(36),
        company, name, email, title,
        industry, size, source,
      ).run().catch(() => {});

      // Also ensure lead exists
      await db.prepare(`
        INSERT OR IGNORE INTO leads
          (id, email, name, domain, source, is_enterprise, funnel_stage, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, 'lead', datetime('now'), datetime('now'))
      `).bind(
        'ld_' + Date.now().toString(36),
        email, name,
        email.includes('@') ? email.split('@')[1] : '',
        source,
      ).run().catch(() => {});
    } catch { /* non-blocking */ }
  }

  return ok({
    success: true,
    message: 'Enterprise inquiry received. We will respond within 4 business hours.',
    inquiry: { company, name, email, interest },
    next_steps: [
      'Expect a response within 4 business hours on bivash@cyberdudebivash.com',
      'For urgent matters, WhatsApp +91 81798 81447',
      'Or book a discovery call: https://wa.me/918179881447',
    ],
  });
}

/* ── POST /api/attribution/track ────────────────────────────────────────────── */
export async function handleAttributionTrack(request, env) {
  const db = env.DB;
  const body = await request.json().catch(() => ({}));

  const {
    email = '', visitor_id = '', session_id = '',
    event = 'visit', // visit | lead | proposal | customer | revenue
    source = 'organic', campaign = '', landing_page = '',
    revenue_inr = 0, product = '',
  } = body;

  if (!event) return ok({ error: 'event is required' }, 400);

  if (db) {
    try {
      // Record in analytics_events (universal attribution table)
      await db.prepare(`
        INSERT INTO analytics_events
          (id, event_type, session_id, properties_json, ip_country, occurred_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        'attr_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
        'attribution_' + event,
        session_id || visitor_id,
        JSON.stringify({ email, source, campaign, landing_page, revenue_inr, product }),
        request.headers.get('CF-IPCountry') || 'IN',
      ).run().catch(() => {});

      // If this is a revenue event, also record in cac_events
      if (event === 'customer' || event === 'revenue') {
        await db.prepare(`
          INSERT INTO cac_events
            (id, channel, campaign, email, cost_inr, converted, plan_converted, mrr_generated, event_date)
          VALUES (?, ?, ?, ?, 0, 1, ?, ?, date('now'))
        `).bind(
          'cac_' + Date.now().toString(36),
          source, campaign, email,
          product, revenue_inr,
        ).run().catch(() => {});

        // Also record revenue event
        if (revenue_inr > 0) {
          await db.prepare(`
            INSERT INTO revenue_events
              (id, source, amount_inr, email, event_type, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
          `).bind(
            'rev_' + Date.now().toString(36),
            source, revenue_inr, email, product || 'attribution_purchase',
          ).run().catch(() => {});
        }
      }

      // Update lead record if email provided
      if (email && event === 'lead') {
        await db.prepare(`
          UPDATE leads SET funnel_stage='lead', source=?, updated_at=datetime('now') WHERE email=?
        `).bind(source, email).run().catch(() => {});
      }
    } catch { /* non-blocking */ }
  }

  return ok({ success: true, event, email: email || '(anonymous)' });
}
