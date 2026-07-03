// Enterprise Real-Time Intelligence Assurance Program.
//
// Locks in buildFreshnessContract()'s core promise: PIPELINE_STATUS reflects
// whether the underlying DATA is current, not just whether the API responded
// — a cached-but-stale response must read DELAYED/OFFLINE, never a
// fabricated HEALTHY. Also locks in the hidden pipeline-health endpoint's
// admin gate and its honest reporting of the one real gap found this
// review (cti_iocs/cti_actors have no automated ingestion).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { buildFreshnessContract, PIPELINE_STATUS } from '../src/lib/contracts.js';
import { handlePipelineHealth } from '../src/handlers/pipelineHealth.js';

describe('buildFreshnessContract', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-07-03T12:00:00.000Z')); });
  afterEach(() => { vi.useRealTimers(); });

  it('HEALTHY when the newest record is within the expected interval', () => {
    const c = buildFreshnessContract({
      source: 'Test Feed',
      latestRecordAt: '2026-07-03T11:50:00.000Z', // 10 min old
      expectedIntervalSec: 3600, // hourly
      recordsDisplayed: 12,
    });
    expect(c.pipeline_status).toBe(PIPELINE_STATUS.HEALTHY);
    expect(c.latest_record_age_sec).toBe(600);
    expect(c.source).toBe('Test Feed');
  });

  it('DELAYED when older than expected but within the grace window', () => {
    const c = buildFreshnessContract({
      source: 'Test Feed',
      latestRecordAt: '2026-07-03T09:00:00.000Z', // 3h old
      expectedIntervalSec: 3600, // hourly — 2x grace = 2h, 6x = 6h
    });
    expect(c.pipeline_status).toBe(PIPELINE_STATUS.DELAYED);
  });

  it('OFFLINE when far beyond the expected interval — the exact class of bug this program exists to catch', () => {
    const c = buildFreshnessContract({
      source: 'Legacy MYTHOS tracker',
      latestRecordAt: '2026-06-16T00:00:34.411Z', // 17 days old, verified live this review
      expectedIntervalSec: 21600, // every 6h
    });
    expect(c.pipeline_status).toBe(PIPELINE_STATUS.OFFLINE);
  });

  it('UNKNOWN (not a fabricated HEALTHY) when there is genuinely no data yet', () => {
    const c = buildFreshnessContract({ source: 'New Feed', latestRecordAt: null });
    expect(c.pipeline_status).toBe(PIPELINE_STATUS.UNKNOWN);
    expect(c.latest_record_age_sec).toBeNull();
  });

  it('never reports HEALTHY for a null/invalid timestamp, no matter the other fields', () => {
    const c = buildFreshnessContract({ source: 'X', latestRecordAt: 'not-a-date', expectedIntervalSec: 60 });
    expect(c.pipeline_status).toBe(PIPELINE_STATUS.UNKNOWN);
  });

  it('carries records_displayed/available and auto_refresh_sec through untouched', () => {
    const c = buildFreshnessContract({
      source: 'X', latestRecordAt: '2026-07-03T11:59:00.000Z', expectedIntervalSec: 60,
      recordsDisplayed: 50, recordsAvailable: 1637, autoRefreshSec: 300,
    });
    expect(c.records_displayed).toBe(50);
    expect(c.records_available).toBe(1637);
    expect(c.auto_refresh_sec).toBe(300);
  });
});

describe('GET /api/internal/pipeline-health', () => {
  function req(headers = {}) {
    return new Request('https://x/api/internal/pipeline-health', { headers });
  }

  it('rejects without a valid x-admin-key — this is engineering-only, not a customer page', async () => {
    const env = { ADMIN_KEY: 'real-secret', DB: null, SECURITY_HUB_KV: null };
    const res = await handlePipelineHealth(req(), env);
    expect(res.status).toBe(403);
  });

  it('rejects a wrong key (not just a missing one)', async () => {
    const env = { ADMIN_KEY: 'real-secret', DB: null, SECURITY_HUB_KV: null };
    const res = await handlePipelineHealth(req({ 'x-admin-key': 'wrong' }), env);
    expect(res.status).toBe(403);
  });

  it('with a valid key, reports every named pipeline and honestly flags the cti_workbench ingestion gap', async () => {
    const rows = {};
    const db = {
      prepare(sql) {
        return {
          bind() { return this; },
          async first() {
            if (/ingestion_runs/.test(sql)) return { ran_at: '2026-07-03T11:00:00Z', sources: '["nvd","kev"]', inserted: 5, updated: 2, errors: '[]', duration_ms: 1200, success: 1 };
            if (/MAX\(ingested_at\)/.test(sql)) return { t: '2026-07-03T11:00:00Z' };
            if (/COUNT\(\*\) as c FROM threat_intel/.test(sql)) return { c: 1637 };
            if (/COUNT\(\*\) as c FROM cti_iocs/.test(sql)) return { c: 0 };
            if (/COUNT\(\*\) as c FROM cti_actors/.test(sql)) return { c: 0 };
            if (/uptime_log/.test(sql)) return { checked_at: '2026-07-03T11:30:00Z', status: 'operational', latency_ms: 45 };
            if (/attack_library_techniques/.test(sql)) return { t: '2026-07-01T06:00:00Z' };
            return null;
          },
          async all() {
            if (/agent_event_queue/.test(sql)) return { results: [{ status: 'pending', c: 3 }, { status: 'done', c: 500 }] };
            return { results: [] };
          },
        };
      },
    };
    const kv = { async get() { return null; } };
    const env = { ADMIN_KEY: 'real-secret', DB: db, SECURITY_HUB_KV: kv };

    const res = await handlePipelineHealth(req({ 'x-admin-key': 'real-secret' }), env);
    expect(res.status).toBe(200);
    const body = await res.json();

    for (const key of ['sentinel_apex_feed', 'ai_threat_radar', 'generic_cti_ingestion', 'mythos_god_mode', 'cti_workbench', 'attack_library', 'uptime_self_probe', 'agent_event_queue']) {
      expect(body.pipelines[key], `missing pipeline: ${key}`).toBeTruthy();
    }

    // The one genuine architectural gap this review found must be reported
    // honestly, not silently marked healthy.
    expect(body.pipelines.cti_workbench.pipeline_status).toBe('UNKNOWN');
    expect(body.pipelines.cti_workbench.note).toMatch(/No automated ingestion/);
    expect(body.pipelines.cti_workbench.records).toEqual({ iocs: 0, actors: 0 });

    expect(body.pipelines.generic_cti_ingestion.records_in_db).toBe(1637);
    expect(body.pipelines.generic_cti_ingestion.last_run.inserted).toBe(5);
  });
});
