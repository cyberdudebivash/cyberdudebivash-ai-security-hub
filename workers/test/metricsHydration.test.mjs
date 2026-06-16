/* Tests — Platform Metrics Hydration (Cluster 2: Metric Integrity Engine).
 * The single-source-of-truth endpoint GET /api/platform/metrics must NEVER again
 * return "unavailable"/null just because one table or column drifted. Previously
 * all 10 counters were read in one atomic db.batch(), so a single missing table
 * (assessment_bookings) or wrong column (payments.amount_inr) aborted the whole
 * batch and zeroed the entire dashboard. These verify per-metric resilience and
 * that scan totals stay consistent with /api/scan/stats (the KV-counter blend). */
import { describe, it, expect } from 'vitest';
import { servePlatformMetrics, refreshPlatformMetrics } from '../src/services/metricsHydration.js';

const TODAY = new Date().toISOString().slice(0, 10);

// KV mock: backing Map, optional pre-seeded scan counters / snapshots.
function mockKV(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    store,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
  };
}

// D1 mock: each query resolved/thrown independently by SQL shape.
function mockDB({ failTables = [], failAll = false } = {}) {
  return {
    prepare(sql) {
      return {
        async first() {
          if (failAll) throw new Error('D1 unreachable');
          if (/FROM scan_history WHERE risk_score/.test(sql))   return 1;
          if (/scanned_at > datetime/.test(sql))                return 0;   // d1 scans today
          if (/FROM scan_history/.test(sql))                    return 11;  // d1 total scans
          if (/severity='CRITICAL'/.test(sql))                  return 8;   // = stats.critical
          if (/severity='HIGH'/.test(sql))                      return 37;  // = stats.high
          if (/published_at >= date/.test(sql))                 return 12;  // recent KEV (30d)
          if (/exploit_status='confirmed'/.test(sql))           return 41;  // = stats.confirmed_exploited (KEV)
          if (/FROM platform_metrics/.test(sql))                return 312; // soar_rules_total
          if (/FROM subscriptions/.test(sql)) {
            if (failTables.includes('subscriptions')) throw new Error('no such table: subscriptions');
            return 3;
          }
          if (/FROM payments/.test(sql)) {
            if (failTables.includes('payments')) throw new Error('no such column: amount');
            return 49900; // paise
          }
          if (/FROM threat_intel/.test(sql))                    return 45;  // total CVEs (after WHERE variants)
          return 0;
        },
      };
    },
  };
}

const call = (env) => servePlatformMetrics(new Request('https://x/api/platform/metrics'), env);

describe('platform metrics — single source of truth', () => {
  it('degrades drifted metrics to 0 without nuking the rest (the production bug)', async () => {
    const env = {
      DB: mockDB({ failTables: ['subscriptions', 'payments'] }),
      SECURITY_HUB_KV: mockKV({ [`scan_count:total:${TODAY}`]: '20' }),
    };
    const res = await call(env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.cache).toBe('live_d1');
    // Working metrics populate from real data...
    expect(body.metrics.total_cves_tracked).toBe(45);
    expect(body.metrics.kev_count).toBe(41);
    expect(body.metrics.high_risk_scans).toBe(1);
    // ...drifted ones degrade to 0 instead of crashing the endpoint.
    expect(body.metrics.active_customers).toBe(0);
    expect(body.metrics.revenue_today_inr).toBe(0);
  });

  it('critical/KEV counts agree exactly with /api/threat-intel/stats (no contradictions)', async () => {
    const env = { DB: mockDB(), SECURITY_HUB_KV: mockKV() };
    const body = await (await call(env)).json();
    expect(body.metrics.critical_threats).toBe(8);    // severity='CRITICAL'
    expect(body.metrics.high_threats).toBe(37);       // severity='HIGH'
    expect(body.metrics.kev_count).toBe(41);          // exploit_status='confirmed'
    expect(body.metrics.kev_recent).toBe(12);         // KEV added in last 30d
    expect(body.metrics.active_exploitation).toBe(41); // back-compat alias
    expect(body.metrics.soar_rules_total).toBe(312);  // platform_metrics key
  });

  it('total_scans blends KV counters with D1 (consistent with /api/scan/stats)', async () => {
    const env = {
      DB: mockDB(),
      SECURITY_HUB_KV: mockKV({ [`scan_count:total:${TODAY}`]: '20' }),
    };
    const body = await (await call(env)).json();
    expect(body.metrics.total_scans).toBe(20);   // max(KV 20, D1 11)
    expect(body.metrics.scans_today).toBe(20);    // max(KV 20, D1 0)
  });

  it('converts payment paise to INR correctly', async () => {
    const env = { DB: mockDB(), SECURITY_HUB_KV: mockKV() };
    const body = await (await call(env)).json();
    expect(body.metrics.revenue_today_inr).toBe(499);  // 49900 paise / 100
  });

  it('falls back to 503 (never fake) when D1 is fully down and no snapshot exists', async () => {
    const env = { DB: mockDB({ failAll: true }), SECURITY_HUB_KV: mockKV() };
    const res = await call(env);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.metrics.source).toBe('unavailable');
  });

  it('serves the last healthy snapshot when D1 is down but a stale snapshot exists', async () => {
    const snapshot = JSON.stringify({ total_scans: 31, total_cves_tracked: 45, source: 'live_d1' });
    const env = {
      DB: mockDB({ failAll: true }),
      SECURITY_HUB_KV: mockKV({ 'platform:metrics:stale': snapshot }),
    };
    const res = await call(env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.cache).toBe('stale');
    expect(body.metrics.stale).toBe(true);
    expect(body.metrics.total_scans).toBe(31);
  });

  it('refreshPlatformMetrics writes a live snapshot to KV', async () => {
    const kv = mockKV({ [`scan_count:total:${TODAY}`]: '20' });
    const env = { DB: mockDB(), SECURITY_HUB_KV: kv };
    const r = await refreshPlatformMetrics(env);
    expect(r.refreshed).toBe(true);
    expect(kv.store.has('platform:metrics:live')).toBe(true);
    const cached = JSON.parse(kv.store.get('platform:metrics:live'));
    expect(cached.total_cves_tracked).toBe(45);
  });
});
