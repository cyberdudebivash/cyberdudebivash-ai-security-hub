/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Uptime Engine (Phase 6)
 *
 * GET /api/uptime — public uptime statistics
 *   Calculates from operational_history and uptime_log (real data only).
 *   Windows: 24h, 7d, 30d, 90d.
 *   Reports null for any window with insufficient data rather than fabricating.
 *
 * MTTR = avg(resolved_at - started_at) over resolved incidents.
 */

// ─── Public: GET /api/uptime ──────────────────────────────────────────────────
export async function handlePublicUptime(request, env) {
  if (!env.DB) return Response.json({ error: 'Unavailable' }, { status: 503 });

  const url    = new URL(request.url);
  const comp   = url.searchParams.get('component') || null; // optional filter

  const [w24h, w7d, w30d, w90d, mttr, incidentStats] = await Promise.all([
    calcWindowUptime(env.DB, 1,  comp),
    calcWindowUptime(env.DB, 7,  comp),
    calcWindowUptime(env.DB, 30, comp),
    calcWindowUptime(env.DB, 90, comp),
    calcMTTR(env.DB),
    calcIncidentStats(env.DB),
  ]);

  // List of tracked components
  const components = await listTrackedComponents(env.DB);

  return Response.json({
    uptime: {
      '24h':  w24h,
      '7d':   w7d,
      '30d':  w30d,
      '90d':  w90d,
    },
    mttr_minutes:    mttr,
    incident_stats:  incidentStats,
    components,
    methodology: 'Calculated from health check probes recorded every ~60 minutes by the platform cron. Windows with fewer than 3 samples report null rather than a potentially misleading percentage.',
    as_of: new Date().toISOString(),
  });
}

// ─── Core calculation ─────────────────────────────────────────────────────────

async function calcWindowUptime(db, days, component = null) {
  try {
    const compFilter = component ? `AND component = '${component.replace(/'/g, "''")}'` : '';
    const row = await db.prepare(`
      SELECT
        COUNT(*)                                                AS total,
        COUNT(CASE WHEN status = 'operational' THEN 1 END)     AS ok,
        AVG(latency_ms)                                         AS avg_latency,
        MIN(latency_ms)                                         AS min_latency,
        MAX(latency_ms)                                         AS max_latency,
        COUNT(CASE WHEN status IN ('partial_outage','major_outage') THEN 1 END) AS outage_count
      FROM operational_history
      WHERE checked_at > datetime('now', '-${days} days')
        ${compFilter}
    `).first();

    if (!row || row.total < 3) {
      // Also try uptime_log as fallback (populated by cron self-probe)
      const fallback = await db.prepare(`
        SELECT
          COUNT(*)                                            AS total,
          COUNT(CASE WHEN status = 'operational' THEN 1 END) AS ok,
          AVG(latency_ms)                                     AS avg_latency
        FROM uptime_log
        WHERE checked_at > datetime('now', '-${days} days')
      `).first().catch(() => null);

      if (!fallback || fallback.total < 3) return { uptime_pct: null, sample_count: row?.total || 0, note: 'insufficient_data' };

      return {
        uptime_pct:    Math.round((fallback.ok / fallback.total) * 1000) / 10,
        sample_count:  fallback.total,
        avg_latency_ms: fallback.avg_latency ? Math.round(fallback.avg_latency) : null,
        source:        'uptime_log',
      };
    }

    const uptimePct = Math.round((row.ok / row.total) * 1000) / 10;
    const downtimePct = 100 - uptimePct;
    const downtimeMinutes = Math.round(downtimePct * days * 24 * 60 / 100);

    return {
      uptime_pct:      uptimePct,
      downtime_minutes: downtimeMinutes,
      sample_count:    row.total,
      outage_events:   row.outage_count,
      avg_latency_ms:  row.avg_latency ? Math.round(row.avg_latency) : null,
      min_latency_ms:  row.min_latency ?? null,
      max_latency_ms:  row.max_latency ?? null,
      source:          'operational_history',
    };
  } catch (_) {
    return { uptime_pct: null, error: 'calculation_failed' };
  }
}

async function calcMTTR(db) {
  try {
    const row = await db.prepare(`
      SELECT AVG(
        (julianday(resolved_at) - julianday(started_at)) * 24 * 60
      ) AS avg_minutes
      FROM incidents
      WHERE status = 'resolved'
        AND resolved_at IS NOT NULL
        AND resolved_at > datetime('now', '-90 days')
    `).first();
    return row?.avg_minutes ? Math.round(row.avg_minutes) : null;
  } catch (_) { return null; }
}

async function calcIncidentStats(db) {
  try {
    const [total, bySeverity, last30d] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS c FROM incidents WHERE status = 'resolved'`).first(),
      db.prepare(`
        SELECT severity, COUNT(*) AS c FROM incidents
        WHERE started_at > datetime('now','-90 days')
        GROUP BY severity
      `).all(),
      db.prepare(`SELECT COUNT(*) AS c FROM incidents WHERE started_at > datetime('now','-30 days')`).first(),
    ]);
    const byS = {};
    for (const r of (bySeverity.results || [])) byS[r.severity] = r.c;
    return {
      total_resolved:  total?.c || 0,
      last_30d:        last30d?.c || 0,
      by_severity_90d: byS,
    };
  } catch (_) { return null; }
}

async function listTrackedComponents(db) {
  try {
    const rows = await db.prepare(`
      SELECT component,
             COUNT(*)                                            AS checks,
             COUNT(CASE WHEN status='operational' THEN 1 END)   AS ok,
             MAX(checked_at)                                     AS last_check,
             AVG(latency_ms)                                     AS avg_latency
      FROM operational_history
      WHERE checked_at > datetime('now', '-7 days')
      GROUP BY component
      ORDER BY component ASC
    `).all();

    return (rows.results || []).map(r => ({
      component:      r.component,
      uptime_7d_pct:  r.checks >= 3 ? Math.round((r.ok / r.checks) * 1000) / 10 : null,
      avg_latency_ms: r.avg_latency ? Math.round(r.avg_latency) : null,
      last_check:     r.last_check,
      sample_count:   r.checks,
    }));
  } catch (_) { return []; }
}
