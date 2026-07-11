/* workers/src/handlers/enterprisePortalHandlers.js — getLivePlatformMetrics()
 * previously computed its own "security_scans"/"scans_run" as a COUNT(*)
 * over `service_orders` (paid orders — a materially different, much smaller
 * number than real scan volume) and "cves_in_database"/"cves_tracked" from an
 * always-cold, unblended `threat_intel` COUNT(*), instead of the canonical
 * hydrated blend GET /api/trust/metrics already uses (handleTrustMetrics,
 * trustCenter.js). Two real, customer/prospect-facing surfaces displayed the
 * wrong numbers under those labels: the public Trust Center
 * (handleTrustCenter, GET /api/trust-center) and the Enterprise Sales Kit
 * sent to prospects evaluating this platform against competitors
 * (handleEnterpriseSalesKit, GET /api/enterprise/sales-kit) — the exact
 * "enterprise-visible contradiction" class trustCenter.js's own
 * handleTrustMetrics doc comment describes fixing on its sibling route.
 *
 * Fixed 2026-07-11: getLivePlatformMetrics() now calls handleTrustMetrics()
 * itself and both callers inherit the corrected numbers with no call-site
 * changes needed. These tests lock in that both surfaces show the SAME
 * canonical numbers as GET /api/trust/metrics, sourced from a low, distinct
 * service_orders count that would immediately expose a regression back to
 * the old behavior.
 */
import { describe, it, expect } from 'vitest';
import { handleTrustCenter, handleEnterpriseSalesKit } from '../src/handlers/enterprisePortalHandlers.js';

function kvStub(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
  };
}

// Real canonical scan/CVE volume is deliberately much larger than the old,
// wrong service_orders-based count — if a regression reintroduces that
// source, these tests would see the small number instead and fail.
const CANONICAL_SCANS = 4321;
const CANONICAL_CVES = 1631;
const WRONG_SERVICE_ORDERS_COUNT = 7; // what the old buggy code would have shown

function dbStub() {
  return {
    prepare(sql) {
      return {
        bind() { return this; },
        async first(col) {
          let row = null;
          if (/FROM users/.test(sql))                                        row = { cnt: 42 };
          else if (/FROM threat_actors/.test(sql))                           row = { cnt: 12 };
          else if (/FROM mythos_runs/.test(sql))                             row = { t: 300, runs: 10 };
          else if (/FROM service_orders/.test(sql)) {
            // Regression guard: nothing in the fixed code path should query
            // this table anymore for scan/CVE counts.
            throw new Error('regression: queried service_orders for a scan/CVE count');
          }
          else if (/FROM subscriptions/.test(sql))                           row = { v: 0 };
          else if (/platform_metrics WHERE key='soar_rules_total'/.test(sql)) row = { v: 0 };
          else if (/FROM uptime_log/.test(sql))                              row = { checks: 0, ok_checks: 0 };
          if (col && row) return row[col];
          return row;
        },
        async all() { return { results: [] }; },
      };
    },
  };
}

describe('GET /api/trust-center (handleTrustCenter) — platform_stats sourcing', () => {
  it('security_scans/cves_in_database match the canonical /api/trust/metrics blend, not service_orders/threat_intel', async () => {
    const env = {
      SECURITY_HUB_KV: kvStub({
        'platform:metrics:live': JSON.stringify({
          total_scans: CANONICAL_SCANS, total_cves_tracked: CANONICAL_CVES, active_customers: 5, soar_rules_total: 20,
        }),
      }),
      DB: dbStub(),
    };
    const res = await handleTrustCenter(new Request('https://x/api/trust-center'), env, {});
    const body = await res.json();
    expect(body.platform_stats.security_scans).toBe(CANONICAL_SCANS);
    expect(body.platform_stats.cves_in_database).toBe(CANONICAL_CVES);
    expect(body.platform_stats.security_scans).not.toBe(WRONG_SERVICE_ORDERS_COUNT);
    // Unrelated metrics are untouched by this fix — still their own real sources.
    expect(body.platform_stats.users_protected).toBe(42);
    expect(body.platform_stats.threat_actors_tracked).toBe(12);
  });

  it('uptime label uses the real measured percentage when available', async () => {
    const env = {
      SECURITY_HUB_KV: kvStub({
        'platform:metrics:live': JSON.stringify({ total_scans: 1, total_cves_tracked: 1, active_customers: 0, soar_rules_total: 0 }),
      }),
      DB: {
        prepare(sql) {
          return {
            bind() { return this; },
            async first(col) {
              if (/FROM uptime_log/.test(sql)) return { checks: 200, ok_checks: 199 };
              if (/FROM users|FROM threat_actors/.test(sql)) return { cnt: 0 };
              if (/FROM mythos_runs/.test(sql)) return { t: 0, runs: 0 };
              return { v: 0 };
            },
            async all() { return { results: [] }; },
          };
        },
      },
    };
    const res = await handleTrustCenter(new Request('https://x/api/trust-center'), env, {});
    const { platform_stats } = await res.json();
    expect(platform_stats.platform_uptime).toContain('99.5%');
    expect(platform_stats.platform_uptime).toContain('measured');
  });
});

describe('GET /api/enterprise/sales-kit (handleEnterpriseSalesKit) — the same fix applies here too', () => {
  it('scans_run/cves_tracked match the canonical blend — the prospect-facing sales kit no longer undersells real volume', async () => {
    const env = {
      SECURITY_HUB_KV: kvStub({
        'platform:metrics:live': JSON.stringify({
          total_scans: CANONICAL_SCANS, total_cves_tracked: CANONICAL_CVES, active_customers: 5, soar_rules_total: 20,
        }),
      }),
      DB: dbStub(),
    };
    const res = await handleEnterpriseSalesKit(new Request('https://x/api/enterprise/sales-kit'), env, {});
    const body = await res.json();
    expect(body.platform_stats.scans_run).toBe(CANONICAL_SCANS);
    expect(body.technical_specs.cves_tracked).toBe(`${CANONICAL_CVES}+`);
    expect(body.platform_stats.scans_run).not.toBe(WRONG_SERVICE_ORDERS_COUNT);
  });
});
