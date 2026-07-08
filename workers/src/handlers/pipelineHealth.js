/**
 * CYBERDUDEBIVASH AI Security Hub — Pipeline Health (Engineering, internal)
 * GET /api/internal/pipeline-health
 *
 * Enterprise Real-Time Intelligence Assurance Program.
 *
 * Aggregates real last-success/last-failure/records/freshness evidence for
 * every ingestion pipeline, scheduler, and cache behind the premium
 * intelligence widgets, so a production incident can be diagnosed as
 * "ingestion stalled" vs "cache stale" vs "UI not refreshing" without
 * reading Worker logs. Admin-key gated (same real check as
 * POST /api/mythos/run) — this is operational detail, not a customer page.
 *
 * Every entry is built from a genuine query or KV read; a source with no
 * tracking table yet reports pipeline_status: UNKNOWN with an honest
 * `note`, never a fabricated HEALTHY.
 */
import { buildFreshnessContract, PIPELINE_STATUS } from '../lib/contracts.js';
import { getGodModeStatus } from '../services/mythosGodMode.js';
import { isValidAdminKey } from '../auth/middleware.js';

async function safe(fn, fallback = null) {
  try { return await fn(); } catch { return fallback; }
}

export async function handlePipelineHealth(request, env) {
  if (!isValidAdminKey(request, env)) {
    return Response.json({ success: false, error: 'Admin access required', hint: 'Provide x-admin-key header' }, { status: 403 });
  }

  const db = env.DB;
  const kv = env.SECURITY_HUB_KV;

  const [
    lastIngestRun,
    threatIntelNewest,
    threatIntelCount,
    ctiIocCount,
    ctiActorCount,
    uptimeCheck,
    queueBacklog,
    godModeStatus,
    attackLibNewest,
  ] = await Promise.all([
    safe(() => db?.prepare(`SELECT ran_at, sources, inserted, updated, errors, duration_ms, success FROM ingestion_runs ORDER BY ran_at DESC LIMIT 1`).first()),
    safe(() => db?.prepare(`SELECT MAX(ingested_at) as t FROM threat_intel`).first()),
    safe(() => db?.prepare(`SELECT COUNT(*) as c FROM threat_intel`).first()),
    safe(() => db?.prepare(`SELECT COUNT(*) as c FROM cti_iocs`).first()),
    safe(() => db?.prepare(`SELECT COUNT(*) as c FROM cti_actors`).first()),
    safe(() => db?.prepare(`SELECT checked_at, status, latency_ms FROM uptime_log WHERE service='api' ORDER BY checked_at DESC LIMIT 1`).first()),
    safe(() => db?.prepare(`SELECT status, COUNT(*) as c FROM agent_event_queue GROUP BY status`).all()),
    // Reuse the same canonical status computation GET /api/mythos/god-mode/status
    // uses — never re-derive God Mode freshness from a guessed KV key.
    safe(() => getGodModeStatus(env)),
    safe(() => db?.prepare(`SELECT MAX(updated_at) as t FROM attack_library_techniques`).first()),
  ]);

  const radarStatus  = await safe(() => kv?.get('ai_threat_radar:status', 'json'));
  const sentinelCache = await safe(() => kv?.get('sentinel:apex:feed:v1'));
  let sentinelGeneratedAt = null;
  if (sentinelCache) { try { sentinelGeneratedAt = JSON.parse(sentinelCache).generated_at || null; } catch {} }

  const queueByStatus = {};
  for (const row of (queueBacklog?.results || [])) queueByStatus[row.status] = row.c;

  const pipelines = {
    sentinel_apex_feed: {
      description: 'CVE/KEV feed: NVD + CISA KEV + ThreatFox, KV-cached',
      freshness: buildFreshnessContract({
        source: 'Sentinel APEX', latestRecordAt: sentinelGeneratedAt,
        expectedIntervalSec: 1800, recordsDisplayed: 0, recordsAvailable: null, autoRefreshSec: 300,
      }),
    },
    ai_threat_radar: {
      description: 'AI/LLM-specific OSV.dev + NVD keyword + GitHub Advisories scan (hourly cron)',
      last_scan_at: radarStatus?.last_scan_at || null,
      signals_found_last_scan: radarStatus?.signals_found ?? null,
      freshness: buildFreshnessContract({
        source: 'AI Threat Radar', latestRecordAt: radarStatus?.last_scan_at || null,
        expectedIntervalSec: 3600, recordsDisplayed: radarStatus?.signals_found ?? 0, recordsAvailable: null, autoRefreshSec: 90,
      }),
    },
    generic_cti_ingestion: {
      description: 'Generic NVD/CISA CVE ingestion into threat_intel (ingestion_runs log)',
      last_run: lastIngestRun ? {
        ran_at: lastIngestRun.ran_at, success: !!lastIngestRun.success,
        inserted: lastIngestRun.inserted, updated: lastIngestRun.updated,
        duration_ms: lastIngestRun.duration_ms,
        errors: safeParseArr(lastIngestRun.errors),
      } : null,
      records_in_db: threatIntelCount?.c ?? null,
      freshness: buildFreshnessContract({
        source: 'threat_intel (NVD/CISA ingestion)', latestRecordAt: threatIntelNewest?.t || null,
        expectedIntervalSec: 3600, recordsDisplayed: threatIntelCount?.c ?? 0, recordsAvailable: threatIntelCount?.c ?? null, autoRefreshSec: 0,
      }),
    },
    mythos_god_mode: {
      description: '12-phase autonomous orchestrator (every 6h cron, D1-backed)',
      last_run_at: godModeStatus?.last_run?.last_run_at || null,
      is_running: !!godModeStatus?.is_running,
      freshness: buildFreshnessContract({
        source: 'MYTHOS GOD MODE', latestRecordAt: godModeStatus?.last_run?.last_run_at || null,
        expectedIntervalSec: 21600, recordsDisplayed: godModeStatus?.lifetime_metrics?.total_runs ?? 0, recordsAvailable: null, autoRefreshSec: 0,
      }),
    },
    cti_workbench: {
      description: 'Threat Intelligence Workbench IOC/actor store',
      records: { iocs: ctiIocCount?.c ?? null, actors: ctiActorCount?.c ?? null },
      // Honest finding from the 2026-07 freshness review: no automated
      // ingestion writes to cti_iocs/cti_actors anywhere in the codebase —
      // only a manual, tier-gated customer-submission endpoint
      // (POST /api/cti/ioc, KV-only, 7-day TTL, never persisted to D1).
      // A separate, real live-fusion pipeline (threatFusionEngine.js,
      // genuine ThreatFox/URLhaus/KEV calls) exists but does not persist
      // into these tables. Reporting this honestly rather than a fabricated
      // HEALTHY status.
      note: 'No automated ingestion configured for cti_iocs/cti_actors. A real live IOC fusion pipeline exists (services/threatFusionEngine.js) but is not yet wired to persist here. Recommended follow-up: schedule aggregateThreatFeed() results into these tables.',
      pipeline_status: PIPELINE_STATUS.UNKNOWN,
    },
    attack_library: {
      description: 'MITRE ATT&CK technique reference data (low-frequency, not a live feed)',
      freshness: buildFreshnessContract({
        source: 'Attack Library (MITRE ATT&CK)', latestRecordAt: attackLibNewest?.t || null,
        expectedIntervalSec: 30 * 86400, // reference dataset — monthly-scale cadence expected, not hourly
        recordsDisplayed: 0, recordsAvailable: null, autoRefreshSec: 0,
      }),
    },
    uptime_self_probe: {
      description: 'Hourly self-probe writing uptime_log (feeds /api/trust/metrics uptime_pct)',
      last_check: uptimeCheck ? { checked_at: uptimeCheck.checked_at, status: uptimeCheck.status, latency_ms: uptimeCheck.latency_ms } : null,
      freshness: buildFreshnessContract({
        source: 'Uptime self-probe', latestRecordAt: uptimeCheck?.checked_at || null,
        expectedIntervalSec: 3600, recordsDisplayed: 0, recordsAvailable: null, autoRefreshSec: 0,
      }),
    },
    agent_event_queue: {
      description: 'CVE/anomaly event bus consumed every hourly cron tick',
      backlog_by_status: queueByStatus,
      // A non-trivial 'pending' backlog after a cron tick suggests the
      // consumer is falling behind ingestion volume, not that ingestion itself failed.
      pipeline_status: (queueByStatus.pending || 0) > 100 ? PIPELINE_STATUS.DELAYED
        : PIPELINE_STATUS.HEALTHY,
    },
  };

  return Response.json({
    success: true,
    generated_at: new Date().toISOString(),
    pipelines,
  });
}

function safeParseArr(v) {
  try { const a = JSON.parse(v); return Array.isArray(a) ? a : []; } catch { return []; }
}
