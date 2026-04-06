/**
 * CYBERDUDEBIVASH AI Security Hub — Real-Time Threat Feed (SSE) v1.0
 * Server-Sent Events endpoint for live threat intelligence streaming
 *
 * Endpoints:
 *   GET /api/realtime/feed       → SSE stream of live threat events
 *   GET /api/realtime/posture    → Current global defense posture (JSON)
 *   GET /api/realtime/stats      → Live platform stats (scans/min, active alerts)
 *
 * Plan gates:
 *   FREE       → posture + stats only (no SSE stream)
 *   PRO        → SSE stream (threat events, 50/min)
 *   ENTERPRISE → Full SSE stream (all event types, unlimited)
 *
 * Uses Cloudflare TransformStream for low-latency edge delivery.
 * No polling required — push model with 30s heartbeat.
 */

import { SEED_ENTRIES }   from '../services/threatIngestion.js';
import { runDetection }   from '../services/detectionEngine.js';
import { enrichBatch }    from '../services/enrichment.js';

// ─── Event types ──────────────────────────────────────────────────────────────
const EVENT_TYPES = {
  THREAT_ALERT:    'threat_alert',
  CVE_PUBLISHED:   'cve_published',
  SCAN_COMPLETED:  'scan_completed',
  POSTURE_CHANGE:  'posture_change',
  IOC_DETECTED:    'ioc_detected',
  HEARTBEAT:       'heartbeat',
  PLATFORM_STAT:   'platform_stat',
};

// ─── Severity colors for UI ───────────────────────────────────────────────────
const SEV_CONFIG = {
  CRITICAL: { color: '#ef4444', icon: '🔴', priority: 4 },
  HIGH:     { color: '#f97316', icon: '🟠', priority: 3 },
  MEDIUM:   { color: '#f59e0b', icon: '🟡', priority: 2 },
  LOW:      { color: '#10b981', icon: '🟢', priority: 1 },
};

// ─── Plan gates ───────────────────────────────────────────────────────────────
const STREAM_CAPS = {
  FREE:       { events_per_min: 0,   event_types: [] },
  STARTER:    { events_per_min: 5,   event_types: [EVENT_TYPES.HEARTBEAT, EVENT_TYPES.PLATFORM_STAT] },
  PRO:        { events_per_min: 50,  event_types: Object.values(EVENT_TYPES) },
  ENTERPRISE: { events_per_min: -1,  event_types: Object.values(EVENT_TYPES) },
};

// ─── GET /api/realtime/feed (SSE) ─────────────────────────────────────────────
export async function handleRealtimeFeed(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = STREAM_CAPS[tier] || STREAM_CAPS.FREE;

  if (caps.events_per_min === 0) {
    return Response.json({
      error:       'Real-time feed requires PRO or ENTERPRISE plan',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
      feature:     'real_time_threat_feed',
      current_plan: tier,
    }, { status: 403 });
  }

  // SSE requires a streaming response
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc    = new TextEncoder();

  // Start async streaming (non-blocking)
  streamThreatEvents(writer, enc, env, authCtx, caps).catch(() => {
    writer.close().catch(() => {});
  });

  return new Response(readable, {
    headers: {
      'Content-Type':                 'text/event-stream',
      'Cache-Control':                'no-cache',
      'Connection':                   'keep-alive',
      'Access-Control-Allow-Origin':  '*',
      'X-Accel-Buffering':            'no',
      'X-Plan':                       tier,
    },
  });
}

// ─── SSE streaming engine ─────────────────────────────────────────────────────
async function streamThreatEvents(writer, enc, env, authCtx, caps) {
  const write = (data) => writer.write(enc.encode(data));

  // Send connected event
  await write(formatSSE(EVENT_TYPES.HEARTBEAT, {
    message:    'Connected to CYBERDUDEBIVASH Sentinel APEX threat stream',
    plan:       authCtx?.tier || 'PRO',
    server:     'Cloudflare Edge',
    timestamp:  new Date().toISOString(),
  }));

  // Pull threat intel from D1 or seed data
  const rawEntries = await fetchRecentThreats(env, 20);
  const enriched   = enrichBatch(rawEntries);
  const detection  = runDetection(enriched);
  const alerts     = detection.alerts || [];

  // Stream each alert as an SSE event
  let sentCount = 0;
  for (const alert of alerts) {
    if (caps.events_per_min > 0 && sentCount >= caps.events_per_min) break;

    const sevCfg = SEV_CONFIG[alert.severity] || SEV_CONFIG.MEDIUM;
    const event  = {
      id:          alert.id || `evt_${Date.now()}_${sentCount}`,
      type:        EVENT_TYPES.THREAT_ALERT,
      severity:    alert.severity,
      color:       sevCfg.color,
      icon:        sevCfg.icon,
      title:       alert.title || alert.name || 'Unknown Threat',
      description: alert.description || alert.summary || '',
      cve_id:      alert.cve_id || null,
      cvss:        alert.cvss || alert.cvss_score || null,
      source:      alert.source || 'Sentinel APEX',
      mitre_tactic: alert.mitre_tactic || null,
      iocs:        alert.iocs || [],
      timestamp:   new Date().toISOString(),
      action_url:  `https://cyberdudebivash.in/?module=domain`,
    };

    await write(formatSSE(EVENT_TYPES.THREAT_ALERT, event));
    sentCount++;

    // Small delay to avoid overwhelming client
    await sleep(150);
  }

  // Stream platform stats
  const stats = await buildPlatformStats(env);
  await write(formatSSE(EVENT_TYPES.PLATFORM_STAT, stats));

  // Global defense posture
  const posture = buildDefensePosture(alerts);
  await write(formatSSE(EVENT_TYPES.POSTURE_CHANGE, posture));

  // Heartbeat every 25s to keep connection alive (Workers max CPU: 30s per request)
  await sleep(25000);
  await write(formatSSE(EVENT_TYPES.HEARTBEAT, {
    alive:     true,
    timestamp: new Date().toISOString(),
    alerts_streamed: sentCount,
  }));

  // Close stream
  await writer.close();
}

// ─── GET /api/realtime/posture ────────────────────────────────────────────────
export async function handleRealtimePosture(request, env, authCtx = {}) {
  const rawEntries = await fetchRecentThreats(env, 50);
  const enriched   = enrichBatch(rawEntries);
  const detection  = runDetection(enriched);
  const posture    = buildDefensePosture(detection.alerts || []);

  return Response.json({
    posture,
    generated_at: new Date().toISOString(),
    plan:         authCtx?.tier || 'FREE',
  });
}

// ─── GET /api/realtime/stats ──────────────────────────────────────────────────
export async function handleRealtimeStats(request, env, authCtx = {}) {
  const stats = await buildPlatformStats(env);
  return Response.json({
    ...stats,
    generated_at: new Date().toISOString(),
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatSSE(eventType, data) {
  const payload = JSON.stringify(data);
  return `event: ${eventType}\ndata: ${payload}\n\n`;
}

function sleep(ms) {
  return new Promise(res => setTimeout(res, ms));
}

async function fetchRecentThreats(env, limit = 50) {
  if (env?.DB) {
    try {
      const rows = await env.DB.prepare(
        `SELECT * FROM threat_intel
         WHERE severity IN ('CRITICAL','HIGH','MEDIUM')
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, cvss DESC
         LIMIT ?`
      ).bind(limit).all();
      if (rows?.results?.length > 0) return rows.results;
    } catch {}
  }
  return SEED_ENTRIES.slice(0, limit).map(e => ({ ...e }));
}

async function buildPlatformStats(env) {
  const stats = {
    total_scans_today:    0,
    active_threats:       0,
    critical_cves:        0,
    high_cves:            0,
    scans_per_hour:       0,
    users_online:         0,
    threat_level:         'ELEVATED',
    last_scan_ago_sec:    null,
  };

  if (env?.DB) {
    try {
      const [scans, threats, crits, highs] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as n FROM scan_history WHERE scanned_at > datetime('now', '-1 day')`).first(),
        env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE severity IN ('CRITICAL','HIGH')`).first().catch(() => ({ n: 0 })),
        env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE severity = 'CRITICAL'`).first().catch(() => ({ n: 0 })),
        env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE severity = 'HIGH'`).first().catch(() => ({ n: 0 })),
      ]);
      stats.total_scans_today = scans?.n    || 0;
      stats.active_threats    = threats?.n  || 0;
      stats.critical_cves     = crits?.n    || 0;
      stats.high_cves         = highs?.n    || 0;
      stats.scans_per_hour    = Math.round((scans?.n || 0) / 24);
    } catch {}
  }

  // Derive threat level
  if (stats.critical_cves > 5)      stats.threat_level = 'CRITICAL';
  else if (stats.critical_cves > 2)  stats.threat_level = 'HIGH';
  else if (stats.high_cves > 10)     stats.threat_level = 'ELEVATED';
  else                               stats.threat_level = 'MODERATE';

  return stats;
}

function buildDefensePosture(alerts = []) {
  const critCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const total     = alerts.length;

  let overall_score = 100;
  overall_score -= critCount * 15;
  overall_score -= highCount * 5;
  overall_score = Math.max(0, Math.min(100, overall_score));

  const level =
    overall_score < 30 ? 'CRITICAL' :
    overall_score < 50 ? 'HIGH'     :
    overall_score < 70 ? 'ELEVATED' :
    overall_score < 85 ? 'MODERATE' : 'HEALTHY';

  return {
    overall_score,
    level,
    total_threats:   total,
    critical:        critCount,
    high:            highCount,
    medium:          alerts.filter(a => a.severity === 'MEDIUM').length,
    low:             alerts.filter(a => a.severity === 'LOW').length,
    top_threats:     alerts.filter(a => a.severity === 'CRITICAL').slice(0, 3).map(a => ({
      title:    a.title || a.name,
      cve_id:   a.cve_id,
      cvss:     a.cvss || a.cvss_score,
    })),
    recommendations: buildRecommendations(critCount, highCount),
    timestamp:       new Date().toISOString(),
  };
}

function buildRecommendations(critCount, highCount) {
  const recs = [];
  if (critCount > 0) recs.push({ priority: 'CRITICAL', action: `Patch ${critCount} critical CVEs immediately — active exploitation likely` });
  if (highCount > 0) recs.push({ priority: 'HIGH',     action: `Review ${highCount} high-severity findings within 24 hours` });
  recs.push({ priority: 'MEDIUM', action: 'Run domain vulnerability scan to check your exposure surface' });
  recs.push({ priority: 'LOW',    action: 'Enable continuous monitoring to get real-time drift alerts' });
  return recs;
}
