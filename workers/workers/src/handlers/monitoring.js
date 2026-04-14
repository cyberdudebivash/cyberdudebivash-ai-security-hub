/**
 * CYBERDUDEBIVASH AI Security Hub — Continuous Monitoring Engine v8.0
 *
 * Provides:
 *   - CRUD for monitor configs (scheduled recurring scans)
 *   - Risk drift detection (compare current vs baseline score)
 *   - Real-time alerting when risk degrades
 *   - Historical monitoring trend data
 *   - Cron-driven scan execution (runs alongside Sentinel APEX)
 *
 * Routes:
 *   POST   /api/monitors              — create monitor config
 *   GET    /api/monitors              — list user monitors
 *   GET    /api/monitors/:id          — get monitor detail
 *   PUT    /api/monitors/:id          — update schedule/settings
 *   DELETE /api/monitors/:id          — remove monitor
 *   GET    /api/monitors/:id/history  — risk trend over time
 *   POST   /api/monitors/:id/run      — trigger manual run
 */

import { buildAttackGraph }  from '../lib/attackGraph.js';
import { buildMitreMapping, buildExecutiveBrief } from '../lib/aiBrain.js';
import { correlateThreatIntel } from '../lib/threatCorrelation.js';

// ─── Schedule intervals ───────────────────────────────────────────────────────
const SCHEDULE_INTERVALS = {
  hourly:  60 * 60 * 1000,
  daily:   24 * 60 * 60 * 1000,
  weekly:  7  * 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
};

const MAX_MONITORS_FREE       = 2;
const MAX_MONITORS_PRO        = 10;
const MAX_MONITORS_ENTERPRISE = 50;
const DRIFT_ALERT_THRESHOLD   = 10;  // default point threshold for alert

// ─── Create monitor config ────────────────────────────────────────────────────
export async function handleCreateMonitor(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required to create monitors' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { name, module, target_json, schedule = 'daily', alert_on_drift = true,
    alert_on_critical = true, drift_threshold = DRIFT_ALERT_THRESHOLD, org_id } = body;

  // Validation
  if (!name || name.length < 2 || name.length > 100) {
    return Response.json({ error: 'name must be 2-100 characters' }, { status: 400 });
  }
  if (!['domain','ai','redteam','identity','compliance'].includes(module)) {
    return Response.json({ error: 'Invalid module. Must be: domain, ai, redteam, identity, compliance' }, { status: 400 });
  }
  if (!target_json || typeof target_json !== 'object') {
    return Response.json({ error: 'target_json must be an object (e.g. {"domain":"example.com"})' }, { status: 400 });
  }
  if (!SCHEDULE_INTERVALS[schedule]) {
    return Response.json({ error: 'schedule must be: hourly, daily, weekly, monthly' }, { status: 400 });
  }

  // Enforce tier limits
  const maxMonitors = authCtx.tier === 'ENTERPRISE' ? MAX_MONITORS_ENTERPRISE
    : authCtx.tier === 'PRO' ? MAX_MONITORS_PRO : MAX_MONITORS_FREE;

  const existing = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM monitor_configs WHERE user_id = ? AND enabled = 1`
  ).bind(authCtx.userId).first();

  if ((existing?.n || 0) >= maxMonitors) {
    return Response.json({
      error:       `Monitor limit reached (${maxMonitors} for ${authCtx.tier} tier)`,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const id         = crypto.randomUUID();
  const nextRunAt  = new Date(Date.now() + SCHEDULE_INTERVALS[schedule]).toISOString();

  await env.DB.prepare(`
    INSERT INTO monitor_configs
      (id, user_id, org_id, name, module, target_json, schedule,
       alert_on_drift, alert_on_critical, drift_threshold, next_run_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    id,
    authCtx.userId,
    org_id || null,
    name,
    module,
    JSON.stringify(target_json),
    schedule,
    alert_on_drift ? 1 : 0,
    alert_on_critical ? 1 : 0,
    drift_threshold,
    nextRunAt,
  ).run();

  return Response.json({
    success:    true,
    monitor_id: id,
    name, module, schedule,
    next_run_at: nextRunAt,
    message:    `Monitor "${name}" created. First scan scheduled for ${new Date(nextRunAt).toLocaleString('en-IN')}.`,
  }, { status: 201 });
}

// ─── List monitors ────────────────────────────────────────────────────────────
export async function handleListMonitors(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const orgId  = url.searchParams.get('org_id');
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);

  let query  = `SELECT mc.*,
    (SELECT COUNT(*) FROM monitor_results WHERE config_id = mc.id) as run_count_actual,
    (SELECT risk_score FROM monitor_results WHERE config_id = mc.id ORDER BY created_at DESC LIMIT 1) as latest_score,
    (SELECT drift_type FROM monitor_results WHERE config_id = mc.id ORDER BY created_at DESC LIMIT 1) as latest_drift
    FROM monitor_configs mc WHERE mc.user_id = ?`;
  const params = [authCtx.userId];

  if (orgId) { query += ' AND mc.org_id = ?'; params.push(orgId); }
  query += ' ORDER BY mc.created_at DESC LIMIT ?';
  params.push(limit);

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return Response.json({
    monitors: (results || []).map(m => ({
      id:              m.id,
      name:            m.name,
      module:          m.module,
      target_summary:  summarizeTarget(m.target_json),
      schedule:        m.schedule,
      enabled:         m.enabled === 1,
      latest_score:    m.latest_score,
      baseline_score:  m.baseline_risk_score,
      latest_drift:    m.latest_drift,
      last_run_at:     m.last_run_at,
      next_run_at:     m.next_run_at,
      run_count:       m.run_count_actual || 0,
      created_at:      m.created_at,
    })),
    total: results?.length || 0,
  });
}

// ─── Get monitor detail ───────────────────────────────────────────────────────
export async function handleGetMonitor(request, env, authCtx, monitorId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const monitor = await env.DB.prepare(
    `SELECT * FROM monitor_configs WHERE id = ? AND user_id = ?`
  ).bind(monitorId, authCtx.userId).first();

  if (!monitor) {
    return Response.json({ error: 'Monitor not found' }, { status: 404 });
  }

  // Get latest 5 results
  const { results: history } = await env.DB.prepare(`
    SELECT id, risk_score, risk_level, findings_count, critical_count,
           drift_delta, drift_type, ai_narrative, alert_sent, created_at
    FROM monitor_results WHERE config_id = ? ORDER BY created_at DESC LIMIT 5
  `).bind(monitorId).all();

  return Response.json({
    ...monitor,
    target_parsed:  JSON.parse(monitor.target_json || '{}'),
    recent_history: history || [],
  });
}

// ─── Update monitor ───────────────────────────────────────────────────────────
export async function handleUpdateMonitor(request, env, authCtx, monitorId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM monitor_configs WHERE id = ? AND user_id = ?`
  ).bind(monitorId, authCtx.userId).first();
  if (!existing) return Response.json({ error: 'Monitor not found' }, { status: 404 });

  const updates = [];
  const params  = [];

  if (body.name !== undefined)             { updates.push('name = ?');             params.push(body.name); }
  if (body.schedule !== undefined)         { updates.push('schedule = ?');         params.push(body.schedule); }
  if (body.enabled !== undefined)          { updates.push('enabled = ?');          params.push(body.enabled ? 1 : 0); }
  if (body.alert_on_drift !== undefined)   { updates.push('alert_on_drift = ?');   params.push(body.alert_on_drift ? 1 : 0); }
  if (body.alert_on_critical !== undefined){ updates.push('alert_on_critical = ?');params.push(body.alert_on_critical ? 1 : 0); }
  if (body.drift_threshold !== undefined)  { updates.push('drift_threshold = ?');  params.push(body.drift_threshold); }

  if (body.schedule) {
    const nextRun = new Date(Date.now() + SCHEDULE_INTERVALS[body.schedule]).toISOString();
    updates.push('next_run_at = ?');
    params.push(nextRun);
  }

  if (!updates.length) return Response.json({ error: 'No valid fields to update' }, { status: 400 });

  updates.push(`updated_at = datetime('now')`);
  params.push(monitorId, authCtx.userId);

  await env.DB.prepare(
    `UPDATE monitor_configs SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`
  ).bind(...params).run();

  return Response.json({ success: true, message: 'Monitor updated successfully' });
}

// ─── Delete monitor ───────────────────────────────────────────────────────────
export async function handleDeleteMonitor(request, env, authCtx, monitorId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const result = await env.DB.prepare(
    `DELETE FROM monitor_configs WHERE id = ? AND user_id = ?`
  ).bind(monitorId, authCtx.userId).run();

  if (!result.meta?.changes) {
    return Response.json({ error: 'Monitor not found' }, { status: 404 });
  }

  return Response.json({ success: true, message: 'Monitor deleted' });
}

// ─── Monitor history (risk trend) ────────────────────────────────────────────
export async function handleMonitorHistory(request, env, authCtx, monitorId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const monitor = await env.DB.prepare(
    `SELECT id, name, module, baseline_risk_score FROM monitor_configs WHERE id = ? AND user_id = ?`
  ).bind(monitorId, authCtx.userId).first();
  if (!monitor) return Response.json({ error: 'Monitor not found' }, { status: 404 });

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '30'), 90);

  const { results } = await env.DB.prepare(`
    SELECT id, risk_score, risk_level, findings_count, critical_count,
           drift_delta, drift_type, ai_narrative, alert_sent, created_at
    FROM monitor_results WHERE config_id = ? ORDER BY created_at DESC LIMIT ?
  `).bind(monitorId, limit).all();

  const history = (results || []).reverse(); // Chronological order
  const trend   = calculateTrend(history, monitor.baseline_risk_score);

  return Response.json({
    monitor_id:     monitorId,
    name:           monitor.name,
    module:         monitor.module,
    baseline_score: monitor.baseline_risk_score,
    history,
    trend,
  });
}

// ─── Manual trigger ───────────────────────────────────────────────────────────
export async function handleTriggerMonitor(request, env, authCtx, monitorId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const monitor = await env.DB.prepare(
    `SELECT * FROM monitor_configs WHERE id = ? AND user_id = ?`
  ).bind(monitorId, authCtx.userId).first();
  if (!monitor) return Response.json({ error: 'Monitor not found' }, { status: 404 });

  // Run the scan for this monitor
  const result = await executeMonitorScan(monitor, env, authCtx);

  return Response.json({
    success:       true,
    monitor_id:    monitorId,
    risk_score:    result.risk_score,
    risk_level:    result.risk_level,
    drift_type:    result.drift_type,
    drift_delta:   result.drift_delta,
    findings_count: result.findings_count,
    message:       `Monitor scan completed. Risk: ${result.risk_score}/100 (${result.drift_type})`,
  });
}

// ─── Cron: run all due monitors ───────────────────────────────────────────────
/**
 * Called from the scheduled cron handler.
 * Processes monitors whose next_run_at is in the past.
 */
export async function runMonitoringCron(env) {
  const now = new Date().toISOString();
  console.log('[Monitor CRON] Starting at', now);

  try {
    // Get all enabled monitors due for execution (up to 20 per cron run)
    const { results: dueMonitors } = await env.DB.prepare(`
      SELECT mc.*, u.email, u.telegram_chat_id
      FROM monitor_configs mc
      LEFT JOIN users u ON u.id = mc.user_id
      WHERE mc.enabled = 1 AND mc.next_run_at <= ? AND mc.fail_count < 5
      ORDER BY mc.next_run_at ASC
      LIMIT 20
    `).bind(now).all();

    if (!dueMonitors?.length) {
      console.log('[Monitor CRON] No monitors due');
      return { processed: 0 };
    }

    console.log(`[Monitor CRON] Processing ${dueMonitors.length} monitors`);
    let processed = 0, alerted = 0, errors = 0;

    for (const monitor of dueMonitors) {
      try {
        const authCtx = { userId: monitor.user_id, tier: 'PRO', authenticated: true, method: 'monitor_cron' };
        const result  = await executeMonitorScan(monitor, env, authCtx);

        // Send alert if drift detected
        if (result.should_alert && (monitor.email || monitor.telegram_chat_id)) {
          await sendMonitorAlert(env, monitor, result);
          alerted++;
        }

        processed++;
      } catch (err) {
        console.error(`[Monitor CRON] Error on monitor ${monitor.id}:`, err?.message);
        // Increment fail count
        await env.DB.prepare(
          `UPDATE monitor_configs SET fail_count = fail_count + 1 WHERE id = ?`
        ).bind(monitor.id).run();
        errors++;
      }
    }

    return { processed, alerted, errors };

  } catch (err) {
    console.error('[Monitor CRON] Fatal error:', err?.message);
    return { processed: 0, error: err?.message };
  }
}

// ─── Core: execute a single monitor scan ─────────────────────────────────────
async function executeMonitorScan(monitor, env, authCtx) {
  const targetPayload = JSON.parse(monitor.target_json || '{}');
  const module        = monitor.module;

  // Dynamic import of scan handler
  const { SCAN_HANDLERS } = await getScanHandlers(module);
  if (!SCAN_HANDLERS[module]) {
    throw new Error(`No scan handler for module: ${module}`);
  }

  // Build synthetic request
  const synthRequest = new Request('https://internal/monitor', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(targetPayload),
  });

  const monitorAuthCtx = { ...authCtx, tier: 'ENTERPRISE', limits: { daily_limit: -1 } };
  const scanResponse   = await SCAN_HANDLERS[module](synthRequest, env, monitorAuthCtx);
  const scanData       = await scanResponse.json();

  // Calculate drift
  const currentScore   = scanData.risk_score || 0;
  const previousScore  = monitor.last_scan_score || monitor.baseline_risk_score;
  const driftDelta     = previousScore !== null ? currentScore - previousScore : 0;
  const driftType      = calculateDriftType(driftDelta, currentScore, monitor);

  // Build AI narrative for the result
  const aiNarrative = buildMonitorNarrative(scanData, module, driftType, driftDelta, monitor);

  // Count findings
  const findings       = scanData.findings || [];
  const lockedFindings = scanData.locked_findings || [];
  const allFindings    = [...findings, ...lockedFindings];
  const critCount      = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount      = allFindings.filter(f => f.severity === 'HIGH').length;

  const shouldAlert = (
    (monitor.alert_on_drift && Math.abs(driftDelta) >= (monitor.drift_threshold || DRIFT_ALERT_THRESHOLD)) ||
    (monitor.alert_on_critical && critCount > 0 && driftType === 'degraded')
  );

  // Persist result in D1
  const resultId  = crypto.randomUUID();
  const nextRunAt = new Date(Date.now() + (SCHEDULE_INTERVALS[monitor.schedule] || SCHEDULE_INTERVALS.daily)).toISOString();
  const targetSummary = summarizeTarget(monitor.target_json);

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO monitor_results
        (id, config_id, user_id, module, target_summary, risk_score, risk_level,
         findings_count, critical_count, high_count, drift_delta, drift_type,
         ai_narrative, alert_sent)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      resultId, monitor.id, monitor.user_id, module, targetSummary,
      currentScore, scanData.risk_level || 'MEDIUM',
      allFindings.length, critCount, highCount,
      driftDelta, driftType, aiNarrative, shouldAlert ? 1 : 0,
    ),
    env.DB.prepare(`
      UPDATE monitor_configs SET
        last_scan_score = ?, last_run_at = datetime('now'), next_run_at = ?,
        run_count = run_count + 1, fail_count = 0,
        baseline_risk_score = COALESCE(baseline_risk_score, ?),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(currentScore, nextRunAt, currentScore, monitor.id),
  ]);

  return {
    result_id:      resultId,
    risk_score:     currentScore,
    risk_level:     scanData.risk_level,
    findings_count: allFindings.length,
    critical_count: critCount,
    drift_delta:    driftDelta,
    drift_type:     driftType,
    should_alert:   shouldAlert,
    ai_narrative:   aiNarrative,
  };
}

// ─── Drift calculation ────────────────────────────────────────────────────────
function calculateDriftType(delta, currentScore, monitor) {
  if (monitor.baseline_risk_score === null) return 'new';
  if (Math.abs(delta) < 3)  return 'stable';
  if (delta > 0)  return 'degraded';
  if (delta < 0)  return 'improved';
  return 'stable';
}

function buildMonitorNarrative(scanData, module, driftType, delta, monitor) {
  const score    = scanData.risk_score || 0;
  const targetStr = summarizeTarget(monitor.target_json);

  const driftMsg = {
    new:       `First scan completed for ${targetStr}. Baseline risk score set to ${score}/100.`,
    stable:    `Security posture stable for ${targetStr}. Risk score ${score}/100 — no significant change from previous scan.`,
    improved:  `✅ Security improvement detected! Risk score dropped by ${Math.abs(delta)} points to ${score}/100 for ${targetStr}.`,
    degraded:  `⚠️ Risk degradation detected! Score increased by ${delta} points to ${score}/100 for ${targetStr}. Review new findings immediately.`,
  };

  return driftMsg[driftType] || driftMsg.stable;
}

// ─── Alert sender ─────────────────────────────────────────────────────────────
async function sendMonitorAlert(env, monitor, result) {
  const msg = buildAlertMessage(monitor, result);

  // Telegram alert
  if (monitor.telegram_chat_id && env.TELEGRAM_BOT_TOKEN) {
    try {
      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:    monitor.telegram_chat_id,
          text:       msg.telegram,
          parse_mode: 'HTML',
        }),
      });
    } catch (err) {
      console.error('[Monitor Alert] Telegram send failed:', err?.message);
    }
  }
}

function buildAlertMessage(monitor, result) {
  const driftEmoji = result.drift_type === 'degraded' ? '🚨' : result.drift_type === 'improved' ? '✅' : '📊';
  const targetStr  = summarizeTarget(monitor.target_json);

  const telegram = `${driftEmoji} <b>Monitor Alert: ${monitor.name}</b>

📌 Target: <code>${targetStr}</code>
🎯 Module: <b>${monitor.module?.toUpperCase()}</b>
📊 Risk Score: <b>${result.risk_score}/100</b> (${result.risk_level})
${result.drift_type === 'degraded' ? `⬆️ Score increased by ${result.drift_delta} points` : result.drift_type === 'improved' ? `⬇️ Score improved by ${Math.abs(result.drift_delta)} points` : ''}
${result.critical_count > 0 ? `🔴 Critical Findings: ${result.critical_count}` : ''}

${result.ai_narrative}

🔗 Review at https://cyberdudebivash.in`;

  return { telegram };
}

// ─── Trend analytics ─────────────────────────────────────────────────────────
function calculateTrend(history, baseline) {
  if (!history.length) return { direction: 'no_data', change: 0, average: null };

  const latest   = history[history.length - 1];
  const oldest   = history[0];
  const avg      = Math.round(history.reduce((s, h) => s + h.risk_score, 0) / history.length);
  const change   = latest ? latest.risk_score - oldest.risk_score : 0;
  const direction = change > 3 ? 'degrading' : change < -3 ? 'improving' : 'stable';
  const baseDelta = baseline && latest ? latest.risk_score - baseline : null;

  return {
    direction,
    change_over_period: change,
    average_score:      avg,
    baseline_delta:     baseDelta,
    worst_score:        Math.max(...history.map(h => h.risk_score)),
    best_score:         Math.min(...history.map(h => h.risk_score)),
    degradation_events: history.filter(h => h.drift_type === 'degraded').length,
    improvement_events: history.filter(h => h.drift_type === 'improved').length,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function summarizeTarget(targetJson) {
  try {
    const t = typeof targetJson === 'string' ? JSON.parse(targetJson) : targetJson;
    return t.domain || t.model_name || t.target_org || t.org_name || 'unknown';
  } catch {
    return 'unknown';
  }
}

// Dynamic module-to-handler mapping (avoids circular imports)
async function getScanHandlers(module) {
  const handlerMap = {
    domain:     () => import('./domain.js').then(m => ({ handler: m.handleDomainScan })),
    ai:         () => import('./ai.js').then(m => ({ handler: m.handleAIScan })),
    redteam:    () => import('./redteam.js').then(m => ({ handler: m.handleRedteamScan })),
    identity:   () => import('./identity.js').then(m => ({ handler: m.handleIdentityScan })),
    compliance: () => import('./compliance.js').then(m => ({ handler: m.handleCompliance })),
  };

  const mod = await handlerMap[module]?.();
  return {
    SCAN_HANDLERS: {
      [module]: mod?.handler || null,
    },
  };
}
