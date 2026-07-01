/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Operations Dashboard & Analytics (Phase 8 + 10)
 *
 * GET /api/admin/ops/dashboard — executive ops dashboard (owner-only)
 * GET /api/admin/ops/report?period=daily|weekly|monthly — operational report (owner-only)
 *
 * All numbers come from D1 queries. No fabrication.
 * Displays "null" or "no data" for any metric without real evidence.
 */

import { isOwner } from '../../auth/middleware.js';

// ─── GET /api/admin/ops/dashboard ────────────────────────────────────────────
export async function handleOpsDashboard(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });

  const t0 = Date.now();

  const [
    platform, security, payments, intelligence, users,
    incidents, deployments, errors, uptime, alerts,
  ] = await Promise.all([
    fetchPlatformMetrics(env.DB),
    fetchSecurityMetrics(env.DB),
    fetchPaymentMetrics(env.DB),
    fetchIntelligenceMetrics(env.DB),
    fetchUserMetrics(env.DB),
    fetchIncidentMetrics(env.DB),
    fetchDeploymentMetrics(env.DB),
    fetchErrorMetrics(env.DB),
    fetchUptimeMetrics(env.DB),
    fetchAlertMetrics(env.DB),
  ]);

  return Response.json({
    generated_at: new Date().toISOString(),
    query_ms:     Date.now() - t0,
    version:      env.VERSION || '40.0.0',
    environment:  env.ENVIRONMENT || 'production',
    sections: {
      platform,
      security,
      payments,
      intelligence,
      users,
      incidents,
      deployments,
      errors,
      uptime,
      alerts,
    },
  });
}

// ─── GET /api/admin/ops/report ────────────────────────────────────────────────
export async function handleOpsReport(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });

  const url    = new URL(request.url);
  const period = url.searchParams.get('period') || 'daily';
  const days   = period === 'monthly' ? 30 : period === 'weekly' ? 7 : 1;

  const [availability, incidents, performance, payments, intelligence, errors] = await Promise.all([
    fetchAvailabilityReport(env.DB, days),
    fetchIncidentReport(env.DB, days),
    fetchPerformanceReport(env.DB, days),
    fetchPaymentReport(env.DB, days),
    fetchIntelReport(env.DB, days),
    fetchErrorReport(env.DB, days),
  ]);

  return Response.json({
    period,
    window_days: days,
    generated_at: new Date().toISOString(),
    availability,
    incidents,
    performance,
    payments,
    intelligence,
    errors,
    summary: buildTextSummary({ period, availability, incidents, payments }),
  });
}

// ─── Dashboard section fetchers ───────────────────────────────────────────────

async function fetchPlatformMetrics(db) {
  if (!db) return null;
  try {
    const [scanCount, apiKeys, orgs] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM scan_results`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM api_keys WHERE status = 'active'`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM organizations`).first().catch(() => null),
    ]);
    return {
      total_scans:   scanCount?.c ?? null,
      active_api_keys: apiKeys?.c ?? null,
      organizations: orgs?.c ?? null,
    };
  } catch (_) { return null; }
}

async function fetchSecurityMetrics(db) {
  if (!db) return null;
  try {
    const [mfa, sso, errors24h] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM mfa_secrets WHERE enabled = 1`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM sso_configs WHERE enabled = 1`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM system_errors WHERE created_at > datetime('now','-24 hours')`).first().catch(() => null),
    ]);
    return {
      mfa_enrolled_users: mfa?.c ?? null,
      sso_configs:        sso?.c ?? null,
      errors_24h:         errors24h?.c ?? null,
    };
  } catch (_) { return null; }
}

async function fetchPaymentMetrics(db) {
  if (!db) return null;
  try {
    const [orders, refunds, subscriptions] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS total, COUNT(CASE WHEN status='paid' THEN 1 END) AS paid FROM orders WHERE created_at > datetime('now','-30 days')`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c, SUM(amount) AS total_amount FROM refunds WHERE status='completed' AND created_at > datetime('now','-30 days')`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM subscriptions WHERE status='active'`).first().catch(() => null),
    ]);
    return {
      orders_30d:        orders?.total ?? null,
      paid_orders_30d:   orders?.paid ?? null,
      payment_rate_30d:  orders?.total > 0 ? Math.round((orders.paid / orders.total) * 100) : null,
      refunds_completed: refunds?.c ?? null,
      refund_amount_inr: refunds?.total_amount ?? null,
      active_subscriptions: subscriptions?.c ?? null,
    };
  } catch (_) { return null; }
}

async function fetchIntelligenceMetrics(db) {
  if (!db) return null;
  try {
    const [total, recent, cve] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM threat_intel`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM threat_intel WHERE ingested_at > datetime('now','-7 days')`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM threat_intel WHERE source LIKE '%CVE%' OR cve_id IS NOT NULL`).first().catch(() => null),
    ]);
    return {
      total_advisories: total?.c ?? null,
      ingested_7d:      recent?.c ?? null,
      cve_count:        cve?.c ?? null,
    };
  } catch (_) { return null; }
}

async function fetchUserMetrics(db) {
  if (!db) return null;
  try {
    const [total, active, new7d, byTier] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM users`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM users WHERE status = 'active'`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM users WHERE created_at > datetime('now','-7 days')`).first().catch(() => null),
      db.prepare(`SELECT tier, COUNT(*) AS c FROM users GROUP BY tier`).all().catch(() => ({ results: [] })),
    ]);
    const tiers = {};
    for (const r of (byTier.results || [])) tiers[r.tier] = r.c;
    return {
      total:   total?.c ?? null,
      active:  active?.c ?? null,
      new_7d:  new7d?.c ?? null,
      by_tier: tiers,
    };
  } catch (_) { return null; }
}

async function fetchIncidentMetrics(db) {
  if (!db) return null;
  try {
    const [open, resolved30d, mttr] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM incidents WHERE status != 'resolved'`).first().catch(() => null),
      db.prepare(`SELECT COUNT(*) AS c FROM incidents WHERE status='resolved' AND resolved_at > datetime('now','-30 days')`).first().catch(() => null),
      db.prepare(`SELECT AVG((julianday(resolved_at)-julianday(started_at))*24*60) AS avg FROM incidents WHERE status='resolved' AND resolved_at > datetime('now','-90 days')`).first().catch(() => null),
    ]);
    return {
      open:             open?.c ?? null,
      resolved_30d:     resolved30d?.c ?? null,
      mttr_minutes_90d: mttr?.avg ? Math.round(mttr.avg) : null,
    };
  } catch (_) { return null; }
}

async function fetchDeploymentMetrics(db) {
  if (!db) return null;
  try {
    const [total, last] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM deployments WHERE deployed_at > datetime('now','-30 days')`).first().catch(() => null),
      db.prepare(`SELECT version, commit_sha, deployed_at, status, test_count FROM deployments ORDER BY deployed_at DESC LIMIT 1`).first().catch(() => null),
    ]);
    return {
      deploys_30d: total?.c ?? null,
      latest:      last || null,
    };
  } catch (_) { return null; }
}

async function fetchErrorMetrics(db) {
  if (!db) return null;
  try {
    const [count24h, byArea] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM system_errors WHERE created_at > datetime('now','-24 hours')`).first().catch(() => null),
      db.prepare(`SELECT area, COUNT(*) AS c FROM system_errors WHERE created_at > datetime('now','-7 days') GROUP BY area ORDER BY c DESC LIMIT 5`).all().catch(() => ({ results: [] })),
    ]);
    return {
      count_24h: count24h?.c ?? null,
      top_areas_7d: (byArea.results || []).map(r => ({ area: r.area, count: r.c })),
    };
  } catch (_) { return null; }
}

async function fetchUptimeMetrics(db) {
  if (!db) return null;
  try {
    const row = await db.prepare(`
      SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN status='operational' THEN 1 END) AS ok,
        AVG(latency_ms) AS avg_lat
      FROM operational_history
      WHERE checked_at > datetime('now','-7 days')
        AND component = 'D1 Database'
    `).first().catch(() => null);
    if (!row || row.total < 3) return { uptime_7d: null, note: 'insufficient_data' };
    return {
      uptime_7d:     Math.round((row.ok / row.total) * 1000) / 10,
      avg_latency_ms: row.avg_lat ? Math.round(row.avg_lat) : null,
      samples:       row.total,
    };
  } catch (_) { return null; }
}

async function fetchAlertMetrics(db) {
  if (!db) return null;
  try {
    const [count24h, byType] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM ops_alert_log WHERE sent_at > datetime('now','-24 hours')`).first().catch(() => null),
      db.prepare(`SELECT alert_type, COUNT(*) AS c FROM ops_alert_log WHERE sent_at > datetime('now','-7 days') GROUP BY alert_type ORDER BY c DESC LIMIT 5`).all().catch(() => ({ results: [] })),
    ]);
    return {
      alerts_24h:    count24h?.c ?? null,
      by_type_7d:    (byType.results || []).map(r => ({ type: r.alert_type, count: r.c })),
    };
  } catch (_) { return null; }
}

// ─── Report period fetchers ───────────────────────────────────────────────────

async function fetchAvailabilityReport(db, days) {
  if (!db) return null;
  try {
    const row = await db.prepare(`
      SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN status='operational' THEN 1 END) AS ok,
        COUNT(CASE WHEN status IN ('partial_outage','major_outage') THEN 1 END) AS outage
      FROM operational_history
      WHERE checked_at > datetime('now', '-${days} days')
    `).first();
    if (!row || row.total < 3) return { uptime_pct: null, note: 'insufficient_data' };
    const pct = Math.round((row.ok / row.total) * 1000) / 10;
    return {
      uptime_pct:      pct,
      downtime_pct:    Math.round((100 - pct) * 10) / 10,
      outage_samples:  row.outage,
      total_samples:   row.total,
    };
  } catch (_) { return null; }
}

async function fetchIncidentReport(db, days) {
  if (!db) return null;
  try {
    const rows = await db.prepare(`
      SELECT severity, status, COUNT(*) AS c
      FROM incidents WHERE started_at > datetime('now', '-${days} days')
      GROUP BY severity, status
    `).all();
    const summary = {};
    for (const r of (rows.results || [])) {
      if (!summary[r.severity]) summary[r.severity] = {};
      summary[r.severity][r.status] = r.c;
    }
    return { by_severity_status: summary };
  } catch (_) { return null; }
}

async function fetchPerformanceReport(db, days) {
  if (!db) return null;
  try {
    const rows = await db.prepare(`
      SELECT component, AVG(latency_ms) AS avg, MAX(latency_ms) AS peak, COUNT(*) AS samples
      FROM operational_history
      WHERE checked_at > datetime('now', '-${days} days')
      GROUP BY component ORDER BY avg DESC
    `).all();
    return {
      components: (rows.results || []).map(r => ({
        component: r.component,
        avg_latency_ms: Math.round(r.avg),
        peak_latency_ms: r.peak,
        samples: r.samples,
      })),
    };
  } catch (_) { return null; }
}

async function fetchPaymentReport(db, days) {
  if (!db) return null;
  try {
    const row = await db.prepare(`
      SELECT COUNT(*) AS total, COUNT(CASE WHEN status='paid' THEN 1 END) AS paid
      FROM orders WHERE created_at > datetime('now', '-${days} days')
    `).first().catch(() => null);
    return {
      orders:      row?.total ?? null,
      paid:        row?.paid ?? null,
      success_rate: row?.total > 0 ? Math.round((row.paid / row.total) * 100) : null,
    };
  } catch (_) { return null; }
}

async function fetchIntelReport(db, days) {
  if (!db) return null;
  try {
    const row = await db.prepare(`
      SELECT COUNT(*) AS c FROM threat_intel
      WHERE ingested_at > datetime('now', '-${days} days')
    `).first().catch(() => null);
    return { ingested: row?.c ?? null };
  } catch (_) { return null; }
}

async function fetchErrorReport(db, days) {
  if (!db) return null;
  try {
    const [count, top] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM system_errors WHERE created_at > datetime('now', '-${days} days')`).first().catch(() => null),
      db.prepare(`SELECT area, COUNT(*) AS c FROM system_errors WHERE created_at > datetime('now', '-${days} days') GROUP BY area ORDER BY c DESC LIMIT 5`).all().catch(() => ({ results: [] })),
    ]);
    return {
      total: count?.c ?? null,
      top_areas: (top.results || []).map(r => ({ area: r.area, count: r.c })),
    };
  } catch (_) { return null; }
}

// ─── Text summary ─────────────────────────────────────────────────────────────

function buildTextSummary({ period, availability, incidents, payments }) {
  const lines = [`${period.toUpperCase()} OPERATIONS REPORT — ${new Date().toISOString().slice(0, 10)}`];

  if (availability?.uptime_pct != null) {
    lines.push(`Availability: ${availability.uptime_pct}% (${availability.downtime_pct}% downtime)`);
  } else {
    lines.push('Availability: Insufficient data — monitoring is accumulating baseline.');
  }

  if (incidents?.by_severity_status) {
    const inc = incidents.by_severity_status;
    const total = Object.values(inc).reduce((s, o) => s + Object.values(o).reduce((a, b) => a + b, 0), 0);
    lines.push(`Incidents: ${total} total`);
  }

  if (payments?.orders != null) {
    lines.push(`Payments: ${payments.orders} orders, ${payments.success_rate ?? 'n/a'}% success rate`);
  }

  return lines.join('\n');
}
