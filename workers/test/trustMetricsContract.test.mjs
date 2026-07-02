/* Behavioral contract for GET /api/trust/metrics (handleTrustMetrics).
 *
 * The pre-existing trustMetricsIntegrity.test.mjs only parses the static HTML —
 * it never invoked the handler, so two production defects shipped undetected:
 *
 *   1. Envelope shape diverged by cache state. Cache HITS spread the metrics to
 *      the TOP LEVEL (`...JSON.parse(cached)`); cache MISSES nested them under
 *      `metrics`. The frontend Trust Center reads `d.metrics.*`, so on every
 *      warm-cache load (10-min TTL — almost always) the tiles saw `undefined`
 *      and fell back to hardcoded baseline/HTML defaults. handleTrustCenter,
 *      which reads `metricsData.metrics`, returned `metrics: null` on cache hits.
 *
 *   2. Counts read platform_metrics keys `total_scans`/`total_cves`/
 *      `total_customers` that NO writer populates — structurally pinned to 0.
 *      The public Trust Center showed "0 scans / 0 CVEs" while 60+ scans and
 *      1600+ CVEs existed and /api/platform/metrics reported them correctly.
 *
 * These tests lock: (a) one nested `{ success, metrics }` shape regardless of
 * cache state, and (b) counts sourced from the canonical hydrated blend
 * (platform:metrics:live) / live D1 tables — never the unwritten keys.
 */
import { describe, it, expect } from 'vitest';
import { handleTrustMetrics } from '../src/handlers/trustCenter.js';

// KV stub with controllable seed contents.
function kvStub(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    _store: store,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
    async delete(k) { store.delete(k); },
  };
}

// D1 stub that routes by SQL substring. Throws if the caller ever queries the
// unwritten platform_metrics total_* keys — that path must never be used again.
function dbStub(counts = {}) {
  const {
    scan_history = 0, threat_intel = 0, subscriptions = 0,
    soar_rules_total = 0, uptime_checks = 0, uptime_ok = 0,
  } = counts;
  return {
    prepare(sql) {
      return {
        bind() { return this; },
        // Column-aware: the shared hydrator (fetchLiveMetricsFromD1) reads scalars
        // via `.first('v')` (D1 semantics), while trustCenter's residual queries
        // call `.first()` and read object properties. Support both.
        async first(col) {
          if (/platform_metrics WHERE key='total_scans'/.test(sql) ||
              /platform_metrics WHERE key='total_cves'/.test(sql) ||
              /platform_metrics WHERE key='total_customers'/.test(sql)) {
            throw new Error('regression: read an unwritten platform_metrics total_* key');
          }
          let row = null;
          if (/risk_score >= 80/.test(sql))                                   row = { v: 0 };
          else if (/FROM scan_history/.test(sql))                             row = { v: scan_history };
          else if (/FROM threat_intel/.test(sql))                            row = { v: threat_intel };
          else if (/FROM subscriptions/.test(sql))                           row = { v: subscriptions };
          else if (/FROM payments/.test(sql))                                row = { v: 0 };
          else if (/platform_metrics WHERE key='soar_rules_total'/.test(sql)) row = { v: soar_rules_total };
          else if (/FROM uptime_log/.test(sql))                              row = { checks: uptime_checks, ok_checks: uptime_ok };
          if (col && row) return row[col];   // .first('v') → scalar, matching D1
          return row;
        },
      };
    },
  };
}

const req = new Request('https://cyberdudebivash.in/api/trust/metrics');

describe('GET /api/trust/metrics — envelope shape', () => {
  it('cache MISS returns { success, metrics: {...} } (nested)', async () => {
    const env = {
      SECURITY_HUB_KV: kvStub(), // no cache, no hydrated blend
      DB: dbStub({ scan_history: 60, threat_intel: 1631, uptime_checks: 100, uptime_ok: 100 }),
    };
    const res = await handleTrustMetrics(req, env);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.metrics).toBeTypeOf('object');
    expect(body.metrics.total_scans).toBe(60);
    // The bug: counts must NOT be top-level (frontend reads d.metrics.*)
    expect(body.total_scans).toBeUndefined();
  });

  it('cache HIT returns the SAME nested shape (not spread to top level)', async () => {
    const seededMetrics = { total_scans: 77, total_cves: 1631, uptime_pct: 99.9 };
    const env = {
      SECURITY_HUB_KV: kvStub({ 'cache:trust:metrics:v2': JSON.stringify(seededMetrics) }),
      DB: dbStub(),
    };
    const res = await handleTrustMetrics(req, env);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.cached).toBe(true);
    expect(body.metrics).toEqual(seededMetrics);      // nested — frontend contract holds
    expect(body.total_scans).toBeUndefined();          // NOT spread to top level
  });
});

describe('GET /api/trust/metrics — real sourcing (no fabricated / no structural zero)', () => {
  it('sources counts from the hydrated platform:metrics:live blend when present', async () => {
    const live = { total_scans: 115, total_cves_tracked: 1631, active_customers: 0, soar_rules_total: 312 };
    const env = {
      SECURITY_HUB_KV: kvStub({ 'platform:metrics:live': JSON.stringify(live) }),
      DB: dbStub({ uptime_checks: 300, uptime_ok: 297 }),
    };
    const res = await handleTrustMetrics(req, env);
    const { metrics } = await res.json();
    expect(metrics.total_scans).toBe(115);            // matches /api/platform/metrics, not 0
    expect(metrics.total_cves).toBe(1631);
    expect(metrics.total_soar_rules).toBe(312);
    expect(metrics.total_customers).toBe(0);          // honest zero (no paying customers) is preserved
    expect(metrics.uptime_pct).toBe(99);              // 297/300 = 99.0, real measured
  });

  it('falls back to live D1 counts when the hydrated blend is cold — never the unwritten keys', async () => {
    // dbStub throws if the unwritten platform_metrics total_* keys are read.
    const env = {
      SECURITY_HUB_KV: kvStub(),                       // no hydrated blend
      DB: dbStub({ scan_history: 42, threat_intel: 900 }),
    };
    const res = await handleTrustMetrics(req, env);
    const { metrics } = await res.json();
    expect(metrics.total_scans).toBe(42);
    expect(metrics.total_cves).toBe(900);
  });

  it('cold-path total_scans equals the canonical platform blend (max KV counter, D1) — not scan_history-only', async () => {
    // The production defect: with the hydrated blend cold, trust returned the
    // scan_history-only count (21) while /api/platform/metrics returned the
    // KV+D1 blend (62). Trust now recomputes via the SAME shared hydrator, so a
    // higher KV rolling counter wins identically on both surfaces.
    const today = new Date().toISOString().slice(0, 10);
    const env = {
      SECURITY_HUB_KV: kvStub({ [`scan_count:total:${today}`]: '62' }), // KV rolling counter
      DB: dbStub({ scan_history: 21, threat_intel: 1637 }),             // lower D1 count
    };
    const res = await handleTrustMetrics(req, env);
    const { metrics } = await res.json();
    expect(metrics.total_scans).toBe(62);   // blend wins — matches /api/platform/metrics, not 21
    expect(metrics.total_cves).toBe(1637);
  });

  it('degrades to safe nested nulls (still { metrics }) if D1 is fully unavailable', async () => {
    const env = {
      SECURITY_HUB_KV: kvStub(),
      DB: { prepare() { throw new Error('D1 down'); } },
    };
    const res = await handleTrustMetrics(req, env);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.metrics).toBeTypeOf('object');
    expect(body.metrics.total_scans).toBeNull();
  });
});
