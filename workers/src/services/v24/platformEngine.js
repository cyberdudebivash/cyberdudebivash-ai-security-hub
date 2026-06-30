/**
 * CYBERDUDEBIVASH AI Security Hub — v24 Scanner Revenue + Trust Center + CEO Dashboard
 */

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 4: SCANNER REVENUE ENGINE
// scan → tier selection → payment → automated delivery
// ═══════════════════════════════════════════════════════════════════════════════

export const SCAN_TIERS = {
  basic: {
    name:        'Security Report',
    price_inr:   199,
    price_usd:   3,
    description: 'Risk score + top 5 findings',
    includes:    ['Risk score (0-100)', 'Top 5 vulnerabilities', 'Basic recommendations', 'PDF export'],
    delivery:    'instant',
    report_type: 'basic',
  },
  pro: {
    name:        'Pro Security Report',
    price_inr:   999,
    price_usd:   12,
    description: 'Full findings + MITRE mapping + remediation',
    includes:    ['Full vulnerability report', 'MITRE ATT&CK mapping', 'Detailed remediation plan', 'Executive summary', 'CVSS scoring', 'PDF + raw data'],
    delivery:    'instant',
    report_type: 'pro',
  },
  enterprise_review: {
    name:        'Enterprise Security Review',
    price_inr:   4999,
    price_usd:   60,
    description: 'Deep-dive review + custom recommendations + 30min consultation',
    includes:    ['All Pro features', 'Custom security recommendations', 'Compliance gap mapping', 'Attack chain simulation', '30-min consultation call', 'Action plan document', 'Re-scan after 30 days'],
    delivery:    '2 business hours',
    report_type: 'enterprise_review',
  },
  security_assessment: {
    name:        'Security Assessment',
    price_inr:   9999,
    price_usd:   120,
    description: '50-page assessment + remediation roadmap + 1hr consultation',
    includes:    ['50-page assessment report', 'Executive risk summary', 'Top 10 CVEs prioritized', '90-day remediation roadmap', 'Compliance gap analysis', 'Custom SIGMA/YARA rules', '1-hour analyst consultation', 'Follow-up scan'],
    delivery:    '3 business days',
    report_type: 'security_assessment',
  },
};

// Create scan order (before payment)
export async function createScanOrder(db, params) {
  if (!db) return { ok: false };
  const { userId, email, target, module, tier } = params;
  const tierConfig = SCAN_TIERS[tier];
  if (!tierConfig) return { ok: false, error: 'Invalid tier' };

  try {
    const orderId = `so-${Date.now().toString(36)}`;
    const reportToken = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const reportExpires = new Date(Date.now() + 7 * 86400000).toISOString();

    await db.prepare(`
      INSERT INTO scan_orders
        (id, user_id, email, target, module, tier, price_inr, report_token, report_expires)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(orderId, userId || null, email || '', target, module || 'domain', tier, tierConfig.price_inr, reportToken, reportExpires).run();

    return { ok: true, order_id: orderId, report_token: reportToken, tier_config: tierConfig };
  } catch (e) { return { ok: false, error: e.message }; }
}

// Mark scan order as paid and trigger report generation
export async function fulfillScanOrder(db, orderId, paymentId) {
  if (!db) return { ok: false };
  try {
    await db.prepare(`
      UPDATE scan_orders SET payment_status='paid', payment_id=?, delivered_at=datetime('now') WHERE id=?
    `).bind(paymentId, orderId).run();

    const order = await db.prepare(`SELECT * FROM scan_orders WHERE id=?`).bind(orderId).first();
    return { ok: true, order, report_token: order?.report_token };
  } catch (e) { return { ok: false, error: e.message }; }
}

// Get scan order by report token (for download)
export async function getScanOrderByToken(db, token) {
  if (!db || !token) return null;
  try {
    const order = await db.prepare(`
      SELECT * FROM scan_orders
      WHERE report_token=? AND payment_status='paid' AND report_expires > datetime('now')
    `).bind(token).first();
    return order || null;
  } catch { return null; }
}

// Revenue stats for scanner
export async function getScannerRevenue(db, period) {
  if (!db) return {};
  const p = period || new Date().toISOString().slice(0, 7);
  try {
    const [stats, byTier] = await Promise.all([
      db.prepare(`
        SELECT COUNT(*) as total_orders, SUM(price_inr) as total_revenue,
               COUNT(CASE WHEN payment_status='paid' THEN 1 END) as paid_orders
        FROM scan_orders WHERE substr(created_at, 1, 7)=?
      `).bind(p).first(),
      db.prepare(`
        SELECT tier, COUNT(*) as orders, SUM(price_inr) as revenue
        FROM scan_orders WHERE payment_status='paid' AND substr(created_at,1,7)=?
        GROUP BY tier ORDER BY revenue DESC
      `).bind(p).all(),
    ]);
    return {
      period:        p,
      total_orders:  stats?.total_orders || 0,
      paid_orders:   stats?.paid_orders || 0,
      total_revenue: stats?.total_revenue || 0,
      conversion_rate: stats?.total_orders > 0 ? Math.round((stats.paid_orders / stats.total_orders) * 100) : 0,
      by_tier:       byTier.results || [],
    };
  } catch { return {}; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 9: TRUST CENTER
// Public trust portal: status, uptime, releases, advisories, testimonials
// ═══════════════════════════════════════════════════════════════════════════════

const SERVICES = ['api', 'scanner', 'threat_intel', 'marketplace', 'mssp', 'auth'];

// Get full trust center data. Every field reflects real D1 state — no seeded/fabricated
// testimonials, no default-to-99.9% uptime, no invented metrics. A service with zero
// uptime_log samples reports status:'no_data', not a fake "operational" claim.
export async function getTrustCenterData(db, kv) {
  try {
    // Check KV cache first (5 min TTL)
    if (kv) {
      const cached = await kv.get('trust:center:v1', 'json').catch(() => null);
      if (cached) return { ...cached, cached: true };
    }

    const [incidents, releases, uptime, testimonials, cveCount] = await Promise.all([
      // Active incidents
      db?.prepare(`
        SELECT * FROM trust_incidents
        WHERE status != 'resolved' OR resolved_at > datetime('now','-7 days')
        ORDER BY started_at DESC LIMIT 10
      `).all().catch(() => ({ results: [] })),

      // Recent releases
      db?.prepare(`
        SELECT * FROM release_notes ORDER BY published_at DESC LIMIT 10
      `).all().catch(() => ({ results: [] })),

      // Uptime (last 90 days per service)
      db?.prepare(`
        SELECT service,
          COUNT(*) as checks,
          COUNT(CASE WHEN status='operational' THEN 1 END) as ok_checks,
          AVG(latency_ms) as avg_latency,
          MAX(CASE WHEN status!='operational' THEN 1 ELSE 0 END) as had_issues
        FROM uptime_log
        WHERE checked_at > datetime('now','-90 days')
        GROUP BY service
      `).all().catch(() => ({ results: [] })),

      // Testimonials — only real, customer-submitted rows. Never seeded with fabricated quotes.
      db?.prepare(`
        SELECT * FROM testimonials WHERE featured=1 ORDER BY rating DESC LIMIT 6
      `).all().catch(() => ({ results: [] })),

      // Real CVE count actually tracked in threat_intel
      db?.prepare(`SELECT COUNT(*) as c FROM threat_intel`).first().catch(() => null),
    ]);

    // Build uptime map per service — no data means no claim, not an assumed 99.9%.
    const uptimeMap = {};
    const uptimeResults = uptime?.results || [];
    for (const svc of SERVICES) {
      const row = uptimeResults.find(r => r.service === svc);
      uptimeMap[svc] = row
        ? {
            status:         row.had_issues ? 'degraded' : 'operational',
            uptime_pct:     Math.round((row.ok_checks / row.checks) * 1000) / 10,
            avg_latency_ms: Math.round(row.avg_latency || 0),
          }
        : { status: 'no_data', uptime_pct: null, avg_latency_ms: null };
    }

    const knownStatuses = Object.values(uptimeMap).filter(s => s.status !== 'no_data');
    const overallStatus = knownStatuses.length === 0
      ? 'Monitoring data not yet available'
      : knownStatuses.every(s => s.status === 'operational')
        ? 'All Systems Operational'
        : 'Partial Service Degradation';

    const data = {
      overall_status:  overallStatus,
      services:        uptimeMap,
      incidents:       (incidents?.results || []).filter(i => i.status !== 'resolved'),
      recent_releases: releases?.results || [],
      testimonials:    testimonials?.results || [],
      metrics: {
        cves_tracked: cveCount?.c ?? 0,
      },
      generated_at: new Date().toISOString(),
    };

    // Cache for 5 minutes
    kv?.put('trust:center:v1', JSON.stringify(data), { expirationTtl: 300 }).catch(() => {});
    return data;
  } catch (e) { return { error: e.message, overall_status: 'unknown', services: {}, incidents: [], recent_releases: [], testimonials: [], metrics: {} }; }
}

// Log uptime check (called by cron)
export async function logUptimeCheck(db, service, statusCode, latencyMs) {
  if (!db) return;
  const status = statusCode < 400 ? 'operational' : statusCode < 500 ? 'degraded' : 'major_outage';
  await db.prepare(`
    INSERT INTO uptime_log (service, status, latency_ms) VALUES (?, ?, ?)
  `).bind(service, status, latencyMs).run().catch(() => {});
}

// Seed initial release notes for v24
export async function seedReleaseNotes(db) {
  if (!db) return;
  const releases = [
    { version: '24.0.0', title: 'Revenue Dominance Update', type: 'feature', description: 'Full billing engine, enterprise sales OS, proposal factory, trust center, CEO command center.' },
    { version: '23.0.0', title: 'RevOS Launch', type: 'feature', description: 'Revenue Operating System: MRR/ARR tracking, MSSP command center, AI customer success copilot.' },
    { version: '22.0.0', title: 'Production Fixes', type: 'fix', description: 'Scan tracking D1 write, apt_groups parse fix, route aliases, schema compatibility.' },
    { version: '21.0.0', title: 'Adaptive Cyber Brain', type: 'feature', description: 'v21 AI engine, autonomous SOC mode, MYTHOS orchestrator v3.0, defense marketplace.' },
  ];
  for (const r of releases) {
    await db.prepare(`
      INSERT OR IGNORE INTO release_notes (version, title, type, description)
      VALUES (?, ?, ?, ?)
    `).bind(r.version, r.title, r.type, r.description).run().catch(() => {});
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 10: CEO REVENUE COMMAND CENTER
// Single source of truth for all revenue streams
// ═══════════════════════════════════════════════════════════════════════════════

export async function getCEODashboard(db, kv) {
  if (!db) return { success: false };
  try {
    const period = new Date().toISOString().slice(0, 7);
    const prevPeriod = (() => {
      const d = new Date();
      d.setMonth(d.getMonth() - 1);
      return d.toISOString().slice(0, 7);
    })();

    const [
      mrrData, streamData, scanRevenue, apiRevenue,
      msspRevenue, activeTrials, pipeline, churnRisk,
      renewalsDue, proposals, customers,
    ] = await Promise.all([
      // MRR snapshot
      db.prepare(`SELECT * FROM mrr_snapshots ORDER BY snapshot_date DESC LIMIT 1`).first().catch(() => null),

      // Revenue by stream this month
      db.prepare(`SELECT stream, revenue_inr, transaction_count FROM revenue_streams WHERE period=?`)
        .bind(period).all().catch(() => ({ results: [] })),

      // Scanner revenue this month
      db.prepare(`SELECT SUM(price_inr) as rev, COUNT(*) as cnt FROM scan_orders WHERE payment_status='paid' AND substr(created_at,1,7)=?`)
        .bind(period).first().catch(() => ({ rev: 0, cnt: 0 })),

      // API revenue
      db.prepare(`SELECT SUM(total_cost_paise) as paise, SUM(total_calls) as calls FROM api_usage_summary WHERE period=?`)
        .bind(period).first().catch(() => ({ paise: 0, calls: 0 })),

      // MSSP MRR
      db.prepare(`SELECT SUM(mrr_inr) as rev FROM mssp_clients WHERE status='active'`).first().catch(() => ({ rev: 0 })),

      // Active trials
      db.prepare(`SELECT COUNT(*) as cnt FROM subscriptions WHERE status='trialing'`).first().catch(() => ({ cnt: 0 })),

      // Pipeline value
      db.prepare(`SELECT SUM(deal_value_inr * probability_pct / 100) as weighted FROM deal_pipeline WHERE stage NOT IN ('closed_won','closed_lost')`)
        .first().catch(() => ({ weighted: 0 })),

      // Churn risk count
      db.prepare(`SELECT COUNT(*) as cnt FROM cs_signals WHERE signal_type='churn_risk' AND resolved=0`).first().catch(() => ({ cnt: 0 })),

      // Renewals due this week
      db.prepare(`SELECT SUM(amount_inr) as rev, COUNT(*) as cnt FROM renewal_queue WHERE renewal_date <= datetime('now','+7 days') AND status='upcoming'`)
        .first().catch(() => ({ rev: 0, cnt: 0 })),

      // Proposals sent this month
      db.prepare(`SELECT COUNT(*) as sent, COUNT(CASE WHEN status='accepted' THEN 1 END) as accepted, COALESCE(SUM(value_inr),0) as total_value FROM proposals WHERE substr(created_at,1,7)=?`)
        .bind(period).first().catch(() => ({ sent: 0, accepted: 0, total_value: 0 })),

      // Paying customers
      db.prepare(`SELECT COUNT(*) as cnt FROM subscriptions WHERE status='active'`).first().catch(() => ({ cnt: 0 })),
    ]);

    // Build revenue streams breakdown
    const streams = {};
    for (const s of (streamData.results || [])) {
      streams[s.stream] = s.revenue_inr;
    }
    streams.reports   = (streams.reports || 0) + (scanRevenue?.rev || 0);
    streams.api       = (streams.api || 0) + Math.round((apiRevenue?.paise || 0) / 100);
    streams.mssp      = (streams.mssp || 0) + (msspRevenue?.rev || 0);

    const totalRevenue = Object.values(streams).reduce((s, v) => s + v, 0);
    const mrr = mrrData?.mrr_inr || 0;
    const arr = mrr * 12;

    // MoM growth
    const prevMRR = await db.prepare(`SELECT mrr_inr FROM mrr_snapshots WHERE snapshot_date < date('now','start of month') ORDER BY snapshot_date DESC LIMIT 1`)
      .first().catch(() => ({ mrr_inr: mrr }));
    const mrrGrowth = prevMRR?.mrr_inr > 0
      ? Math.round(((mrr - prevMRR.mrr_inr) / prevMRR.mrr_inr) * 100 * 10) / 10 : 0;

    return {
      success: true,
      period,
      kpis: {
        mrr_inr:             mrr,
        arr_inr:             arr,
        mrr_growth_pct:      mrrGrowth,
        paying_customers:    customers?.cnt || 0,
        active_trials:       activeTrials?.cnt || 0,
        total_revenue_month: totalRevenue,
        churn_risk_count:    churnRisk?.cnt || 0,
        nrr_pct:             mrrData?.nrr || 100,
        churn_rate_pct:      mrrData?.churn_rate || 0,
        pipeline_value_inr:  Math.round(pipeline?.weighted || 0),
        proposals_sent:      proposals?.sent || 0,
        proposals_accepted:  proposals?.accepted || 0,
        proposal_value_inr:  proposals?.total_value || 0,
        renewals_due_7d:     renewalsDue?.cnt || 0,
        renewals_value_inr:  renewalsDue?.rev || 0,
        api_calls_month:     apiRevenue?.calls || 0,
      },
      revenue_streams: {
        subscriptions: streams.subscriptions || 0,
        marketplace:   streams.marketplace || 0,
        api:           streams.api || 0,
        reports:       streams.reports || 0,
        consulting:    streams.consulting || 0,
        training:      streams.training || 0,
        mssp:          streams.mssp || 0,
        total:         totalRevenue,
      },
      targets: {
        mrr_target_inr:       100000,
        mrr_progress_pct:     mrr > 0 ? Math.round((mrr / 100000) * 100) : 0,
        customer_target:      100,
        customer_progress_pct: customers?.cnt > 0 ? Math.round((customers.cnt / 100) * 100) : 0,
        mssp_target:          25,
        arr_target_inr:       1000000,
      },
      generated_at: new Date().toISOString(),
    };
  } catch (e) { return { success: false, error: e.message }; }
}
