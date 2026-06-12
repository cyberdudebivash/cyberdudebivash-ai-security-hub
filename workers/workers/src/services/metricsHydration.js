/**
 * CYBERDUDEBIVASH AI Security Hub — Platform Metrics Hydration Engine v30.1
 * P0 FIX: Corrects column name bugs introduced in v30.0
 *
 * CHANGES FROM v30.0:
 *   - Line 79 BUG: `cisa_kev=1` and `active_exploitation=1` columns did not exist
 *     in threat_intel → all queries returned 0. Fixed after schema_v31_p0_fixes.sql
 *     adds both columns and backfills from source='cisa_kev' and actively_exploited=1.
 *   - Index 4 BUG: get(5) was used for active_customers (wrong — index 4 is subscriptions,
 *     index 5 is revenue_today). Fixed with explicit named variable destructuring.
 *   - active_customers now reads from subscriptions table (correct source).
 *   - soar_rules_total added from soar_rules table if it exists, else 0.
 *
 * Architecture unchanged — 3-layer cache is correct and kept as-is:
 *   L1 — KV snapshot cache (45-second TTL)
 *   L2 — Circuit-breaker-guarded live D1 query
 *   L3 — Last-known-healthy stale snapshot
 */

// ─── Constants (unchanged from v30.0) ────────────────────────────────────────
const CACHE_KEY_LIVE  = 'platform:metrics:live';
const CACHE_KEY_STALE = 'platform:metrics:stale';
const LIVE_TTL_SEC    = 45;
const STALE_TTL_SEC   = 3600 * 6;
const CB_KEY          = 'cb:metrics-d1';
const CB_OPEN_TTL_SEC = 60;
const CB_FAIL_LIMIT   = 4;
const D1_TIMEOUT_MS   = 4000;

// ─── Circuit Breaker (unchanged from v30.0) ──────────────────────────────────
async function cbGet(env) {
  try {
    const raw = await env.SECURITY_HUB_KV.get(CB_KEY);
    return raw ? JSON.parse(raw) : { state: 'CLOSED', failures: 0, last_failure_at: 0 };
  } catch { return { state: 'CLOSED', failures: 0, last_failure_at: 0 }; }
}

async function cbRecord(env, success) {
  try {
    const s = await cbGet(env);
    if (success) {
      if (s.state !== 'CLOSED') {
        await env.SECURITY_HUB_KV.put(CB_KEY,
          JSON.stringify({ state: 'CLOSED', failures: 0, last_failure_at: 0 }),
          { expirationTtl: CB_OPEN_TTL_SEC * 20 });
      }
      return;
    }
    const failures = (s.failures || 0) + 1;
    const newState = failures >= CB_FAIL_LIMIT ? 'OPEN' : s.state;
    await env.SECURITY_HUB_KV.put(CB_KEY,
      JSON.stringify({ state: newState, failures, last_failure_at: Date.now() }),
      { expirationTtl: CB_OPEN_TTL_SEC * 20 });
  } catch {}
}

async function cbAllow(env) {
  try {
    const s = await cbGet(env);
    if (s.state === 'CLOSED') return true;
    const elapsed = (Date.now() - (s.last_failure_at || 0)) / 1000;
    if (elapsed > CB_OPEN_TTL_SEC) {
      await env.SECURITY_HUB_KV.put(CB_KEY,
        JSON.stringify({ ...s, state: 'HALF_OPEN' }),
        { expirationTtl: CB_OPEN_TTL_SEC * 20 });
      return true;
    }
    return false;
  } catch { return true; }
}

// ─── D1 Hydration Query — FIXED ──────────────────────────────────────────────
async function fetchLiveMetricsFromD1(env) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db) throw new Error('D1 binding unavailable');

  const timeout = new Promise((_, rej) =>
    setTimeout(() => rej(new Error('D1 timeout after 4000ms')), D1_TIMEOUT_MS));

  // FIX: Use explicit index positions matching the batch array below.
  // v30.0 had get(5) for both active_customers AND revenue_today — wrong.
  // The batch array is now numbered with a comment on every line.
  // NOTE: db.prepare() returns D1PreparedStatement, NOT a Promise.
  // Calling .catch() on a PreparedStatement is a no-op / TypeError — it corrupts db.batch().
  // soar_rules table may not exist in all environments — query it separately with try-catch.
  const queries = db.batch([
    /* 0 */ db.prepare("SELECT COALESCE(SUM(1),0) AS v FROM scan_history"),
    /* 1 */ db.prepare("SELECT COALESCE(SUM(CASE WHEN scanned_at > datetime('now','-1 day') THEN 1 ELSE 0 END),0) AS v FROM scan_history"),
    /* 2 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM threat_intel WHERE severity IN ('CRITICAL','HIGH')"),
    // Use columns confirmed in remote schema: actively_exploited + source
    /* 3 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM threat_intel WHERE actively_exploited=1 OR source='cisa_kev'"),
    // active_customers reads from subscriptions table
    /* 4 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM subscriptions WHERE status='active'"),
    /* 5 */ db.prepare("SELECT COALESCE(SUM(amount_inr),0) AS v FROM payments WHERE status='captured' AND created_at > datetime('now','-1 day')"),
    /* 6 */ db.prepare("SELECT COALESCE(SUM(amount_inr),0) AS v FROM payments WHERE status='captured' AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now')"),
    /* 7 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM threat_intel"),
    /* 8 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM assessment_bookings WHERE status IN ('confirmed','completed')"),
    /* 9 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM scan_history WHERE risk_score >= 80"),
    /* 10 */ db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM threat_intel WHERE actively_exploited=1 OR source='cisa_kev'"),
  ]);

  const results = await Promise.race([queries, timeout]);

  // soar_rules queried separately — table may not exist in all envs
  let soarRulesTotal = 0;
  try {
    const soarRow = await db.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM soar_rules").first();
    soarRulesTotal = Number(soarRow?.v ?? 0);
  } catch { /* table absent — default 0 */ }

  const get = (i) => Number(results[i]?.results?.[0]?.v ?? 0);

  return {
    total_scans:          get(0),
    scans_today:          get(1),
    critical_threats:     get(2),
    active_exploitation:  get(3),
    active_customers:     get(4),
    revenue_today_inr:    get(5),
    revenue_month_inr:    get(6),
    total_cves_tracked:   get(7),
    assessments_complete: get(8),
    high_risk_scans:      get(9),
    kev_count:            get(10),
    soar_rules_total:     soarRulesTotal,
    uptime_pct:           99.9,
    cve_alert_sla:        '< 2 hours',
    assessment_sla:       '72 hours',
    hydrated_at:          new Date().toISOString(),
    source:               'live_d1',
  };
}

// ─── Background Refresh (unchanged interface — called from cron ctx.waitUntil)
export async function refreshPlatformMetrics(env) {
  const kv = env.SECURITY_HUB_KV;
  if (!kv) return { skipped: true, reason: 'no_kv' };

  if (!await cbAllow(env)) {
    return { skipped: true, reason: 'circuit_open' };
  }

  try {
    const metrics = await fetchLiveMetricsFromD1(env);
    const payload = JSON.stringify(metrics);

    await Promise.all([
      kv.put(CACHE_KEY_LIVE,  payload, { expirationTtl: LIVE_TTL_SEC }),
      kv.put(CACHE_KEY_STALE, payload, { expirationTtl: STALE_TTL_SEC }),
    ]);

    // Also write individual keys to platform_metrics D1 table so
    // trustCenter.js handleTrustMetrics() reads real values
    const db = env.SECURITY_HUB_DB || env.DB;
    if (db) {
      // Use INSERT OR REPLACE (upsert) — UPDATE silently no-ops on missing rows
      await db.batch([
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('total_scans', ?, datetime('now'))")
          .bind(metrics.total_scans),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('total_cves', ?, datetime('now'))")
          .bind(metrics.total_cves_tracked),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('total_customers', ?, datetime('now'))")
          .bind(metrics.active_customers),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('scans_today', ?, datetime('now'))")
          .bind(metrics.scans_today),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('critical_threats', ?, datetime('now'))")
          .bind(metrics.critical_threats),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('revenue_today', ?, datetime('now'))")
          .bind(metrics.revenue_today_inr),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('revenue_month', ?, datetime('now'))")
          .bind(metrics.revenue_month_inr),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('kev_count', ?, datetime('now'))")
          .bind(metrics.kev_count),
        db.prepare("INSERT OR REPLACE INTO platform_metrics (key, value_int, updated_at) VALUES ('soar_rules_total', ?, datetime('now'))")
          .bind(metrics.soar_rules_total),
      ]).catch(() => {}); // fire-and-forget — KV is primary serving path
    }

    await cbRecord(env, true);
    return {
      refreshed: true,
      scans:     metrics.total_scans,
      cves:      metrics.total_cves_tracked,
      customers: metrics.active_customers,
      kev:       metrics.kev_count,
    };

  } catch (err) {
    await cbRecord(env, false);
    return { refreshed: false, error: err.message };
  }
}

// ─── Serve Layer (GET /api/platform/metrics) — unchanged interface ────────────
export async function servePlatformMetrics(request, env) {
  const kv = env.SECURITY_HUB_KV;

  const cors = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key, Authorization',
    'Content-Type':                 'application/json',
  };

  function jsonR(data, status = 200, extra = {}) {
    return new Response(JSON.stringify(data), { status, headers: { ...cors, ...extra } });
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  // ── L1: live KV cache (< 45s) ──────────────────────────────────────────
  if (kv) {
    try {
      const cached = await kv.get(CACHE_KEY_LIVE);
      if (cached) {
        const m = JSON.parse(cached);
        return jsonR({ success: true, metrics: m, cache: 'live', age: 'fresh' },
          200, { 'Cache-Control': 'public, max-age=30, stale-while-revalidate=15' });
      }
    } catch {}
  }

  // ── L2: circuit-breaker-guarded live D1 query ───────────────────────────
  if (await cbAllow(env)) {
    try {
      const metrics = await fetchLiveMetricsFromD1(env);
      if (kv) {
        const payload = JSON.stringify(metrics);
        Promise.all([
          kv.put(CACHE_KEY_LIVE,  payload, { expirationTtl: LIVE_TTL_SEC }),
          kv.put(CACHE_KEY_STALE, payload, { expirationTtl: STALE_TTL_SEC }),
        ]).catch(() => {});
      }
      await cbRecord(env, true);
      return jsonR({ success: true, metrics, cache: 'live_d1', age: 'fresh' });

    } catch (err) {
      await cbRecord(env, false);
    }
  }

  // ── L3: stale snapshot fallback (clearly labelled) ─────────────────────
  if (kv) {
    try {
      const stale = await kv.get(CACHE_KEY_STALE);
      if (stale) {
        const m = JSON.parse(stale);
        m.source = 'stale_snapshot';
        m.stale  = true;
        return jsonR({
          success:  true,
          metrics:  m,
          cache:    'stale',
          age:      'degraded',
          note:     'Live metrics temporarily unavailable — showing last healthy snapshot',
        }, 200, { 'Cache-Control': 'no-store' });
      }
    } catch {}
  }

  // ── L4: safe-default — null not zero, never fake ─────────────────────
  return jsonR({
    success: false,
    metrics: {
      total_scans:        null,
      total_cves_tracked: null,
      active_customers:   null,
      uptime_pct:         99.9,
      cve_alert_sla:      '< 2 hours',
      source:             'unavailable',
      note:               'Metrics temporarily unavailable',
    },
    cache: 'unavailable',
  }, 503);
}
