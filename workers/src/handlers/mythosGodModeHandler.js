/**
 * CYBERDUDEBIVASH MYTHOS GOD MODE — HTTP Handler v4.0
 * ════════════════════════════════════════════════════
 * Routes:
 *   POST /api/mythos/god-mode/run         — Trigger full 12-phase autonomous run
 *   GET  /api/mythos/god-mode/status      — Live pipeline status
 *   GET  /api/mythos/god-mode/report      — Full last-run report
 *   GET  /api/mythos/god-mode/report/:id  — Specific job report
 *   GET  /api/mythos/god-mode/ciso        — CISO intel pack
 *   GET  /api/mythos/god-mode/hunt-pack   — Latest SOAR hunt pack (KQL + Sigma)
 *   GET  /api/mythos/god-mode/compliance  — Compliance posture snapshot
 *   GET  /api/mythos/god-mode/aspm        — AI security posture summary
 */

import {
  runGodMode,
  getGodModeStatus,
  getGodModeReport,
} from '../services/mythosGodMode.js';
import { buildFreshnessContract } from '../lib/contracts.js';
import { isValidAdminKey } from '../auth/middleware.js';
import { can } from '../auth/rbac.js';

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
});

// ── POST /api/mythos/god-mode/run ─────────────────────────────────────────────
export async function handleGodModeRun(request, env, authCtx, ctx) {
  // Auth: ADMIN_KEY, ENTERPRISE tier, or the admin:infra:operate RBAC
  // permission (SUPERADMIN role / isOwner) — added as an additional valid
  // path alongside the two pre-existing ones, not a replacement, so no
  // existing ADMIN_KEY/ENTERPRISE access is narrowed.
  const isAdmin = isValidAdminKey(request, env)
    || authCtx?.tier === 'ENTERPRISE'
    || await can(authCtx, env, 'admin:infra:operate');
  if (!isAdmin) {
    return json({ success: false, error: 'Admin access required' }, 403);
  }

  // Block concurrent runs
  const current = await env.SECURITY_HUB_KV?.get('mythos:god_mode:status', 'json').catch(() => null);
  if (current?.running) {
    return json({
      success: false,
      error:   'God Mode already running',
      job_id:  current.job_id,
      started_at: current.started_at,
    }, 409);
  }

  const body     = await request.json().catch(() => ({}));
  const maxItems = Math.min(parseInt(body.max_items || '10'), 20);

  // Register with ctx.waitUntil so Cloudflare keeps the worker alive for the full pipeline
  const runPromise = runGodMode(env, { maxItems, trigger: 'api' });
  if (ctx?.waitUntil) ctx.waitUntil(runPromise);
  runPromise.catch(err => console.error('[GOD MODE API] run error:', err.message));

  // Give KV 200ms to record the new job_id
  await new Promise(r => setTimeout(r, 200));
  const newStatus = await env.SECURITY_HUB_KV?.get('mythos:god_mode:status', 'json').catch(() => null);

  return json({
    success:      true,
    message:      `MYTHOS GOD MODE started — 12-phase autonomous platform sweep`,
    job_id:       newStatus?.job_id || 'starting',
    max_items:    maxItems,
    status_url:   '/api/mythos/god-mode/status',
    report_url:   '/api/mythos/god-mode/report',
    phases: [
      'Intel Sweep', 'Cyber Brain', 'Tool Generation', 'AI Security Sweep',
      'Threat Hunt', 'Zero Trust Sweep', 'Compliance Refresh', 'CISO Intel Pack',
      'SOAR Deployment', 'Metrics Hydration', 'Revenue Triggers', 'Finalize',
    ],
  });
}

// ── GET /api/mythos/god-mode/status ──────────────────────────────────────────
export async function handleGodModeStatus(request, env, authCtx) {
  try {
    const status = await getGodModeStatus(env);
    return json({
      success: true,
      ...status,
      // Cron cadence: wrangler.toml "0 */6 * * *" — every 6 hours.
      freshness: buildFreshnessContract({
        source: 'MYTHOS GOD MODE v5.0 APEX NEXUS (god-mode-d1)',
        latestRecordAt: status?.last_run?.last_run_at || null,
        expectedIntervalSec: 21600,
        recordsDisplayed: status?.lifetime_metrics?.total_runs ?? 0,
        recordsAvailable: status?.lifetime_metrics?.total_runs ?? null,
        autoRefreshSec: 0, // homepage widget loads once on page load, no polling interval
      }),
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/god-mode/report[/:jobId] ─────────────────────────────────
export async function handleGodModeReport(request, env, authCtx, jobId) {
  try {
    const report = await getGodModeReport(env, jobId || 'latest');
    if (!report) return json({ success: false, error: 'No god mode report found yet' }, 404);
    return json({ success: true, report });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/god-mode/ciso ────────────────────────────────────────────
export async function handleGodModeCISOIntel(request, env, authCtx) {
  try {
    const [cisoIntel, boardReport] = await Promise.all([
      env.SECURITY_HUB_KV?.get('ciso:intel:latest',   'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('ciso:board:report',   'json').catch(() => null),
    ]);
    if (!cisoIntel && !boardReport) {
      return json({ success: false, error: 'No CISO intel pack available — trigger a God Mode run first' }, 404);
    }
    return json({ success: true, ciso_intel: cisoIntel, board_report: boardReport });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/god-mode/hunt-pack ───────────────────────────────────────
export async function handleGodModeHuntPack(request, env, authCtx) {
  try {
    const [huntPack, sigmaRules, kqlRules, yaraRules] = await Promise.all([
      env.SECURITY_HUB_KV?.get('mythos:hunt:pack:latest', 'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('soar:rules:sigma:latest', 'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('soar:rules:kql:latest',   'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('soar:rules:yara:latest',  'json').catch(() => null),
    ]);
    return json({
      success:    true,
      hunt_pack:  huntPack,
      soar_rules: {
        sigma: sigmaRules,
        kql:   kqlRules,
        yara:  yaraRules,
        total: (sigmaRules?.count || 0) + (kqlRules?.count || 0) + (yaraRules?.count || 0),
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/god-mode/compliance ──────────────────────────────────────
export async function handleGodModeCompliance(request, env, authCtx) {
  try {
    const posture = await env.SECURITY_HUB_KV?.get('compliance:posture:latest', 'json').catch(() => null);
    if (!posture) return json({ success: false, error: 'No compliance posture available' }, 404);
    return json({ success: true, compliance_posture: posture });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/god-mode/aspm ────────────────────────────────────────────
export async function handleGodModeASPM(request, env, authCtx) {
  try {
    const [aspmSummary, ztAnomalies] = await Promise.all([
      env.SECURITY_HUB_KV?.get('aspm:summary:latest', 'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('zt:anomalies:latest', 'json').catch(() => null),
    ]);
    return json({
      success:      true,
      aspm_summary: aspmSummary,
      zt_anomalies: ztAnomalies,
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
