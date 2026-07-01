/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Public Status Platform (Phase 3 + 11)
 *
 * GET /api/status           — JSON by default; HTML if Accept: text/html
 * GET /api/status.html      — always HTML (bookmarkable status page)
 *
 * Includes: overall status, component health, active incidents,
 *           scheduled maintenance, recent deployments, uptime summary.
 *
 * Never fabricates uptime. All metrics come from D1 operational_history.
 */

const STATUS_COLORS = {
  operational:    '#22c55e',
  degraded:       '#eab308',
  partial_outage: '#f97316',
  critical:       '#ef4444',
  unknown:        '#64748b',
};

const STATUS_LABELS = {
  operational:    'All Systems Operational',
  degraded:       'Degraded Performance',
  partial_outage: 'Partial Outage',
  critical:       'Major Outage',
  unknown:        'Monitoring',
};

export async function handlePublicStatus(request, env) {
  const wantsHtml = request.headers.get('Accept')?.includes('text/html') ||
    new URL(request.url).pathname.endsWith('.html');

  const data = await buildStatusData(env);

  if (wantsHtml) {
    return new Response(renderHTML(data), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=30',
      },
    });
  }

  return Response.json(data, {
    headers: { 'Cache-Control': 'public, max-age=30' },
  });
}

// ─── Data assembly ────────────────────────────────────────────────────────────

async function buildStatusData(env) {
  const [health, incidents, maintenance, uptime7d, deployment] = await Promise.all([
    fetchHealthSummary(env),
    fetchPublicIncidents(env),
    fetchMaintenance(env),
    fetchUptimeSummary(env, 7),
    fetchLatestDeployment(env),
  ]);

  const overallColor  = STATUS_COLORS[health.status] || STATUS_COLORS.unknown;
  const overallLabel  = STATUS_LABELS[health.status] || 'Monitoring';
  const hasActiveIncident = incidents.active.length > 0;

  return {
    page_title:      'CYBERDUDEBIVASH® Status',
    platform:        'CYBERDUDEBIVASH AI Security Hub',
    status:          health.status,
    status_label:    overallLabel,
    status_color:    overallColor,
    has_incident:    hasActiveIncident,
    version:         env.VERSION || '40.0.0',
    components:      health.components,
    active_incidents: incidents.active,
    recent_incidents: incidents.recent,
    maintenance_windows: maintenance,
    uptime_7d:       uptime7d,
    latest_deployment: deployment,
    timestamp:       new Date().toISOString(),
  };
}

async function fetchHealthSummary(env) {
  // Quick health probe without writing to history (read-only for status page)
  if (!env.DB) return { status: 'unknown', components: [] };
  try {
    // Read the most recent operational_history snapshot per component
    const rows = await env.DB.prepare(`
      SELECT component, status, latency_ms, checked_at
      FROM operational_history
      WHERE (component, checked_at) IN (
        SELECT component, MAX(checked_at) FROM operational_history
        WHERE checked_at > datetime('now','-2 hours')
        GROUP BY component
      )
      ORDER BY component
    `).all().catch(() => ({ results: [] }));

    const components = (rows.results || []).map(r => ({
      name:       r.component,
      status:     r.status,
      latency_ms: r.latency_ms,
      last_check: r.checked_at,
    }));

    if (components.length === 0) {
      // No recent history — do a live fallback probe so the status page is never "unknown"
      return await fetchHealthLiveFallback(env);
    }

    const hasOutage   = components.some(c => c.status === 'major_outage');
    const hasPartial  = components.some(c => c.status === 'partial_outage');
    const hasDegraded = components.some(c => c.status === 'degraded');

    const status = hasOutage ? 'critical'
      : hasPartial  ? 'partial_outage'
      : hasDegraded ? 'degraded'
      : 'operational';

    return { status, components };
  } catch (_) {
    return { status: 'unknown', components: [] };
  }
}

async function fetchHealthLiveFallback(env) {
  // Called when operational_history has no recent data (e.g. first deploy, cron not yet run).
  // Performs live probes of the most critical components so the status page shows real state.
  const t0 = Date.now();
  const components = [];
  let dbOk = false;

  // D1 probe
  try {
    const row = await env.DB.prepare('SELECT 1 AS alive').first();
    const latency = Date.now() - t0;
    dbOk = row?.alive === 1;
    components.push({ name: 'D1 Database', status: dbOk ? 'operational' : 'degraded', latency_ms: latency, last_check: 'live' });
  } catch (_) {
    components.push({ name: 'D1 Database', status: 'major_outage', latency_ms: Date.now() - t0, last_check: 'live' });
  }

  // Worker is executing, so it's operational by definition
  components.push({ name: 'Worker', status: 'operational', latency_ms: 0, last_check: 'live' });

  // Intel probe (requires DB)
  if (dbOk) {
    try {
      const row = await env.DB.prepare("SELECT COUNT(*) AS c FROM threat_intel WHERE ingested_at > datetime('now','-7 days')").first().catch(() => null);
      components.push({ name: 'Threat Intelligence', status: (row?.c ?? 0) > 0 ? 'operational' : 'degraded', latency_ms: 0, last_check: 'live' });
    } catch (_) {
      components.push({ name: 'Threat Intelligence', status: 'unknown', latency_ms: 0, last_check: 'live' });
    }
  }

  const hasOutage   = components.some(c => c.status === 'major_outage');
  const hasDegraded = components.some(c => c.status === 'degraded');
  const status = hasOutage ? 'critical' : hasDegraded ? 'degraded' : 'operational';

  return { status, components, note: 'live_probe' };
}

async function fetchPublicIncidents(env) {
  if (!env.DB) return { active: [], recent: [] };
  try {
    const [active, recent] = await Promise.all([
      env.DB.prepare(
        `SELECT id, title, severity, status, customer_message, started_at
         FROM incidents WHERE status != 'resolved' ORDER BY started_at DESC LIMIT 5`
      ).all(),
      env.DB.prepare(
        `SELECT id, title, severity, status, customer_message, started_at, resolved_at
         FROM incidents WHERE status = 'resolved'
           AND resolved_at > datetime('now','-30 days')
         ORDER BY resolved_at DESC LIMIT 5`
      ).all(),
    ]);
    return { active: active.results || [], recent: recent.results || [] };
  } catch (_) { return { active: [], recent: [] }; }
}

async function fetchMaintenance(env) {
  if (!env.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT id, title, description, scheduled_start, scheduled_end, status
       FROM maintenance_windows WHERE status IN ('scheduled','in_progress')
         AND scheduled_end > datetime('now')
       ORDER BY scheduled_start ASC LIMIT 5`
    ).all();
    return rows.results || [];
  } catch (_) { return []; }
}

async function fetchUptimeSummary(env, days) {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare(`
      SELECT COUNT(*) AS total, COUNT(CASE WHEN status='operational' THEN 1 END) AS ok
      FROM operational_history
      WHERE checked_at > datetime('now', '-${days} days')
    `).first();
    if (!row || row.total < 3) return null;
    return { days, pct: Math.round((row.ok / row.total) * 1000) / 10, samples: row.total };
  } catch (_) { return null; }
}

async function fetchLatestDeployment(env) {
  if (!env.DB) return null;
  try {
    return await env.DB.prepare(
      `SELECT version, commit_sha, deployed_at, status FROM deployments ORDER BY deployed_at DESC LIMIT 1`
    ).first().catch(() => null);
  } catch (_) { return null; }
}

// ─── HTML renderer ────────────────────────────────────────────────────────────

function renderHTML(d) {
  const incidentBanner = d.has_incident
    ? `<div style="background:#7f1d1d;border:1px solid #ef4444;border-radius:8px;padding:16px;margin-bottom:24px">
        <strong style="color:#fca5a5">⚠ Active Incident</strong>
        ${d.active_incidents.map(i => `<p style="color:#fca5a5;margin:8px 0 0">${escHtml(i.title)} — ${escHtml(i.customer_message || i.status)}</p>`).join('')}
       </div>` : '';

  const componentRows = d.components.map(c => {
    const color = STATUS_COLORS[c.status] || '#64748b';
    const label = c.status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    const latency = c.latency_ms >= 0 ? `${c.latency_ms}ms` : '—';
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #1e293b">
      <span style="color:#e2e8f0">${escHtml(c.name)}</span>
      <div style="display:flex;align-items:center;gap:16px">
        <span style="color:#475569;font-size:13px">${latency}</span>
        <span style="color:${color};font-weight:600;font-size:13px">● ${label}</span>
      </div>
    </div>`;
  }).join('');

  const noComponents = d.components.length === 0
    ? `<p style="color:#475569;font-size:14px">Health data will appear after the first monitoring cycle completes (~60 min).</p>`
    : '';

  const incidentSection = d.recent_incidents.length > 0 || d.active_incidents.length > 0
    ? `<div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:24px;margin-top:24px">
        <h2 style="color:#94a3b8;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin:0 0 16px">Incidents</h2>
        ${[...d.active_incidents, ...d.recent_incidents].map(i => `
          <div style="padding:12px 0;border-bottom:1px solid #1e293b">
            <div style="display:flex;justify-content:space-between">
              <span style="color:#e2e8f0;font-weight:500">${escHtml(i.title)}</span>
              <span style="color:#64748b;font-size:12px">${i.started_at ? i.started_at.slice(0,10) : ''}</span>
            </div>
            ${i.customer_message ? `<p style="color:#94a3b8;font-size:13px;margin:4px 0 0">${escHtml(i.customer_message)}</p>` : ''}
            <span style="font-size:11px;color:${i.status==='resolved'?'#22c55e':'#f97316'}">${i.status.toUpperCase()} · ${i.severity.toUpperCase()}</span>
          </div>`).join('')}
       </div>` : '';

  const maintSection = d.maintenance_windows.length > 0
    ? `<div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:24px;margin-top:24px">
        <h2 style="color:#94a3b8;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin:0 0 16px">Scheduled Maintenance</h2>
        ${d.maintenance_windows.map(m => `
          <div style="padding:12px 0;border-bottom:1px solid #1e293b">
            <span style="color:#e2e8f0">${escHtml(m.title)}</span>
            <p style="color:#64748b;font-size:13px;margin:4px 0 0">${escHtml(m.scheduled_start)} → ${escHtml(m.scheduled_end)}</p>
          </div>`).join('')}
       </div>` : '';

  const uptimeNote = d.uptime_7d
    ? `<span style="color:#94a3b8;font-size:14px">7-day uptime: <strong style="color:#22c55e">${d.uptime_7d.pct}%</strong></span>`
    : `<span style="color:#475569;font-size:13px">Uptime data accumulating</span>`;

  const deployNote = d.latest_deployment
    ? `<span style="color:#475569;font-size:13px">v${escHtml(d.latest_deployment.version)} · ${escHtml(d.latest_deployment.deployed_at?.slice(0,10) || '')}</span>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(d.page_title)}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#020617;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;padding:0 16px 48px}
  .wrap{max-width:720px;margin:0 auto}
</style>
</head>
<body>
<div class="wrap">
  <div style="padding:40px 0 24px;border-bottom:1px solid #1e293b;margin-bottom:32px">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
      <span style="background:linear-gradient(135deg,#7c3aed,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:22px;font-weight:800">CYBERDUDEBIVASH®</span>
    </div>
    <p style="color:#475569;font-size:13px">AI Security Hub · Status Page · v${escHtml(d.version || '')}</p>
  </div>

  ${incidentBanner}

  <div style="background:#0f172a;border:2px solid ${d.status_color};border-radius:12px;padding:28px;margin-bottom:24px;text-align:center">
    <div style="font-size:32px;margin-bottom:8px">${d.status === 'operational' ? '✅' : d.status === 'degraded' ? '⚠️' : '🔴'}</div>
    <h1 style="color:${d.status_color};font-size:24px;font-weight:700">${escHtml(d.status_label)}</h1>
    <div style="margin-top:16px;display:flex;justify-content:center;gap:24px">
      ${uptimeNote}
      ${deployNote}
    </div>
  </div>

  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:24px;margin-bottom:24px">
    <h2 style="color:#94a3b8;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px">Components</h2>
    ${noComponents}
    ${componentRows}
  </div>

  ${incidentSection}
  ${maintSection}

  <p style="color:#334155;font-size:12px;text-align:center;margin-top:32px">
    Updated: ${new Date(d.timestamp).toUTCString()} · <a href="/api/status" style="color:#475569">JSON API</a>
    · <a href="/api/uptime" style="color:#475569">Uptime</a>
    · <a href="/api/incidents" style="color:#475569">Incidents</a>
  </p>
</div>
</body>
</html>`;
}

function escHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
