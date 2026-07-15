/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * productAnalytics.js — Growth Intelligence Platform
 *
 * APIs:
 *   POST /api/analytics/p3/event    ingest analytics event (auth required)
 *   GET  /api/analytics/p3/growth   growth KPIs (admin)
 *   GET  /api/analytics/p3/funnel   conversion funnel (admin)
 *   GET  /api/analytics/p3/adoption feature adoption matrix (admin)
 *   POST /api/analytics/p3/prune    prune old events (admin, cron)
 */

const ALLOWED_EVENTS = new Set([
  'scan.completed','scan.started','case.created','case.resolved',
  'report.generated','search.executed','workflow.executed',
  'upgrade.viewed','upgrade.converted','login.success',
  'asset.registered','ioc.searched','monitor.created',
]);

function genId() { return 'evt_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

export async function handleIngestEvent(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { event_type, properties = {}, session_id } = body;
  if (!event_type || !ALLOWED_EVENTS.has(event_type)) {
    return Response.json({ error: 'Unknown or disallowed event_type' }, { status: 400 });
  }

  const id     = genId();
  const orgId  = req.user.org_id || 'default';
  const userId = req.user.id || null;
  const tier   = req.user.tier || 'FREE';
  const country = req.headers?.get('CF-IPCountry') || null;

  await env.DB.prepare(
    `INSERT INTO analytics_events (id, event_type, user_id, org_id, tier, session_id, properties_json, ip_country, occurred_at)
     VALUES (?,?,?,?,?,?,?,?,datetime('now'))`
  ).bind(id, event_type, userId, orgId, tier, session_id || null, JSON.stringify(properties), country).run().catch(() => null);

  return Response.json({ success: true, id });
}

export async function handleGrowthMetrics(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  const cacheKey = 'growth_metrics_v4';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ ...cached, cached: true });

  try {
    // DAU/WAU/MAU from analytics_events
    const [dau, wau, mau] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events WHERE occurred_at >= datetime('now','-1 day') AND user_id IS NOT NULL`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events WHERE occurred_at >= datetime('now','-7 days') AND user_id IS NOT NULL`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events WHERE occurred_at >= datetime('now','-30 days') AND user_id IS NOT NULL`).first().catch(() => ({ cnt: 0 })),
    ]);

    // Activation rate (users who ran scan within 7d of first seen)
    const activation = await env.DB.prepare(
      `SELECT COUNT(DISTINCT user_id) as activated FROM analytics_events
       WHERE event_type = 'scan.completed' AND user_id IN (
         SELECT DISTINCT user_id FROM analytics_events
         WHERE occurred_at >= datetime('now','-7 days') AND user_id IS NOT NULL
       )`
    ).first().catch(() => ({ activated: 0 }));

    // Conversion events
    const conversions = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM analytics_events WHERE event_type = 'upgrade.converted' AND occurred_at >= datetime('now','-30 days')`
    ).first().catch(() => ({ cnt: 0 }));

    // Total events last 30d
    const totalEvents = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM analytics_events WHERE occurred_at >= datetime('now','-30 days')`
    ).first().catch(() => ({ cnt: 0 }));

    // Event type breakdown
    const eventBreakdown = await env.DB.prepare(
      `SELECT event_type, COUNT(*) as cnt FROM analytics_events
       WHERE occurred_at >= datetime('now','-30 days')
       GROUP BY event_type ORDER BY cnt DESC LIMIT 10`
    ).all().catch(() => ({ results: [] }));

    // Top countries
    const countries = await env.DB.prepare(
      `SELECT ip_country, COUNT(*) as cnt FROM analytics_events
       WHERE occurred_at >= datetime('now','-30 days') AND ip_country IS NOT NULL
       GROUP BY ip_country ORDER BY cnt DESC LIMIT 5`
    ).all().catch(() => ({ results: [] }));

    // Tier distribution of active users
    const tierDist = await env.DB.prepare(
      `SELECT tier, COUNT(DISTINCT user_id) as cnt FROM analytics_events
       WHERE occurred_at >= datetime('now','-30 days') AND user_id IS NOT NULL
       GROUP BY tier`
    ).all().catch(() => ({ results: [] }));

    const metrics = {
      dau: dau?.cnt ?? 0,
      wau: wau?.cnt ?? 0,
      mau: mau?.cnt ?? 0,
      activation_rate_7d: wau?.cnt ? Math.round((activation?.activated ?? 0) / wau.cnt * 100) : 0,
      conversions_30d: conversions?.cnt ?? 0,
      total_events_30d: totalEvents?.cnt ?? 0,
      event_breakdown: eventBreakdown.results || [],
      top_countries: countries.results || [],
      tier_distribution: tierDist.results || [],
      computed_at: new Date().toISOString(),
    };

    const payload = { metrics, period: '30d' };
    await env.KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 }).catch(() => null);
    return Response.json(payload);
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleConversionFunnel(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  try {
    const [signups, firstScan, paid, enterprise] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM users WHERE created_at >= datetime('now','-30 days')`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events WHERE event_type='scan.completed' AND user_id IN (SELECT id FROM users WHERE created_at >= datetime('now','-30 days'))`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM users WHERE tier IN ('pro','enterprise') AND created_at >= datetime('now','-30 days')`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM users WHERE tier='enterprise' AND created_at >= datetime('now','-30 days')`).first().catch(() => ({ cnt: 0 })),
    ]);

    const s = signups?.cnt ?? 0;
    const fs = firstScan?.cnt ?? 0;
    const p = paid?.cnt ?? 0;
    const e = enterprise?.cnt ?? 0;

    const funnel = [
      { stage: 'Signup', count: s, pct: 100 },
      { stage: 'First Scan', count: fs, pct: s ? Math.round(fs / s * 100) : 0 },
      { stage: 'Paid', count: p, pct: s ? Math.round(p / s * 100) : 0 },
      { stage: 'Enterprise', count: e, pct: s ? Math.round(e / s * 100) : 0 },
    ];

    return Response.json({ funnel, period: '30d' });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleFeatureAdoption(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  try {
    const mau = await env.DB.prepare(
      `SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events
       WHERE occurred_at >= datetime('now','-30 days') AND user_id IS NOT NULL`
    ).first().catch(() => ({ cnt: 1 }));
    const total = Math.max(mau?.cnt ?? 1, 1);

    const features = [
      { feature: 'Domain Scan', event: 'scan.completed' },
      { feature: 'AI Security Scan', event: 'asset.registered' },
      { feature: 'SOC Cases', event: 'case.created' },
      { feature: 'CTI / IOC Search', event: 'ioc.searched' },
      { feature: 'Reporting', event: 'report.generated' },
      { feature: 'Global Search', event: 'search.executed' },
      { feature: 'Workflows', event: 'workflow.executed' },
      { feature: 'Monitoring', event: 'monitor.created' },
    ];

    const adoption = await Promise.all(features.map(async f => {
      const row = await env.DB.prepare(
        `SELECT COUNT(DISTINCT user_id) as cnt FROM analytics_events
         WHERE event_type = ? AND occurred_at >= datetime('now','-30 days') AND user_id IS NOT NULL`
      ).bind(f.event).first().catch(() => ({ cnt: 0 }));
      const count = row?.cnt ?? 0;
      return { ...f, users: count, adoption_pct: Math.round(count / total * 100) };
    }));

    return Response.json({ adoption, total_mau: total, period: '30d' });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handlePruneEvents(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  try {
    const evtResult = await env.DB.prepare(
      `DELETE FROM analytics_events WHERE occurred_at < datetime('now','-90 days')`
    ).run();
    const notifResult = await env.DB.prepare(
      `DELETE FROM notification_log WHERE created_at < datetime('now','-30 days')`
    ).run();
    const execResult = await env.DB.prepare(
      `DELETE FROM workflow_executions WHERE completed_at < datetime('now','-180 days') AND status IN ('COMPLETED','FAILED','CANCELLED')`
    ).run();

    return Response.json({
      success: true,
      pruned: {
        analytics_events: evtResult.meta?.changes ?? 0,
        notification_log: notifResult.meta?.changes ?? 0,
        workflow_executions: execResult.meta?.changes ?? 0,
      },
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
