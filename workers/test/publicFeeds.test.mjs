/* Tests — public Sentinel APEX threat-intel feeds (Cluster 1 enhancement).
 * The five endpoints advertised in the platform footer previously 404'd; these
 * verify they return real-data JSON, filter correctly, and are drift-defensive
 * (a schema mismatch or missing DB must never 500 a public feed). */
import { describe, it, expect } from 'vitest';
import { handlePublicFeeds, PUBLIC_FEED_PATHS } from '../src/handlers/publicFeeds.js';

const ROWS = [
  { cve_id: 'CVE-2026-1', title: 'Critical RCE', description: 'x', severity: 'critical', cvss_score: 9.8, source: 'NVD',  published_at: '2026-06-15', created_at: '2026-06-15' },
  { cve_id: 'CVE-2026-2', title: 'High XSS',     description: 'y', severity: 'high',     cvss_score: 7.1, source: 'CISA', published_at: '2026-06-14', created_at: '2026-06-14' },
  { cve_id: 'CVE-2026-3', title: 'Medium info',  description: 'z', severity: 'medium',   cvss_score: 5.0, source: 'NVD',  published_at: '2026-06-13', created_at: '2026-06-13' },
];

function mockEnv({ tier1Throws = false } = {}) {
  return {
    SECURITY_HUB_DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async all() {
            if (/GROUP BY/.test(sql)) {
              return { results: [{ sev: 'CRITICAL', c: 1 }, { sev: 'HIGH', c: 1 }, { sev: 'MEDIUM', c: 1 }] };
            }
            // Tier-1 orders by published_at; simulate a drift error on that query.
            if (tier1Throws && /ORDER BY published_at/.test(sql)) throw new Error('no such column: published_at');
            let r = ROWS;
            if (/IN \(/.test(sql)) {
              const sevs = b.slice(0, b.length - 1).map(s => s.toUpperCase());
              r = ROWS.filter(x => sevs.includes(x.severity.toUpperCase()));
            }
            const lim = b.length ? b[b.length - 1] : undefined; // tier-2 has no binds
            return { results: r.slice(0, lim) };
          },
        };
      },
    },
  };
}

const call = (env, path) => handlePublicFeeds(new Request('https://x' + path), env, path);

describe('public threat-intel feeds', () => {
  it('exposes the advertised feeds plus the new monetized endpoints', () => {
    expect(PUBLIC_FEED_PATHS).toContain('/api/feed.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/latest.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/apex.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/ai_summary.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/reports/latest.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/kev.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/stix.json');
    expect(PUBLIC_FEED_PATHS).toContain('/api/v1/intel/pricing.json');
  });

  // FREE-accessible feeds (STIX is paid-only → covered separately).
  const FREE_OK = [
    '/api/feed.json', '/api/v1/intel/latest.json', '/api/v1/intel/apex.json',
    '/api/v1/intel/ai_summary.json', '/api/reports/latest.json',
    '/api/v1/intel/kev.json', '/api/v1/intel/pricing.json',
  ];

  it('all FREE-accessible feeds return 200 JSON with real data', async () => {
    for (const p of FREE_OK) {
      const res = await call(mockEnv(), p);
      expect(res.status).toBe(200);
      expect(res.headers.get('Content-Type')).toContain('application/json');
      const body = await res.json();
      expect(body.publisher).toMatch(/CYBERDUDEBIVASH/);
    }
  });

  it('/api/feed.json includes recent items', async () => {
    const body = await (await call(mockEnv(), '/api/feed.json')).json();
    expect(body.count).toBe(3);
    expect(body.items[0].cve).toBe('CVE-2026-1');
    expect(body.items[0].severity).toBe('CRITICAL');
    expect(body.data_source).toBe('d1');
    expect(body.live).toBe(true);
  });

  it('apex feed returns only CRITICAL/HIGH', async () => {
    const body = await (await call(mockEnv(), '/api/v1/intel/apex.json')).json();
    expect(body.items.every(i => ['CRITICAL', 'HIGH'].includes(i.severity))).toBe(true);
    expect(body.items.some(i => i.severity === 'MEDIUM')).toBe(false);
  });

  it('ai_summary derives a deterministic threat level + counts', async () => {
    const body = await (await call(mockEnv(), '/api/v1/intel/ai_summary.json')).json();
    expect(body.counts.total).toBe(3);
    expect(['LOW', 'MODERATE', 'HIGH', 'CRITICAL']).toContain(body.threat_level);
  });

  it('is drift-defensive — falls back to minimal columns when tier-1 query throws', async () => {
    const res = await call(mockEnv({ tier1Throws: true }), '/api/feed.json');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.count).toBe(3); // recovered via tier-2 (no-order) query
    expect(body.items[0].title).toBe('Critical RCE'); // real data still served
  });

  it('with no DB, serves the curated seed fallback (never empty, never 500) and flags it as not live', async () => {
    const res = await call({}, '/api/feed.json');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.count).toBeGreaterThan(0);          // seed fallback, platform-consistent
    expect(body.items.every(i => i.severity)).toBe(true);
    // Customer mandate: a fallback/reference baseline must never be reported
    // as live data — every public feed must honestly flag its provenance.
    expect(body.data_source).toBe('seed');
    expect(body.live).toBe(false);
  });

  it('flags data_source/live consistently across latest, apex, kev and reports feeds', async () => {
    for (const p of ['/api/v1/intel/latest.json', '/api/v1/intel/apex.json', '/api/v1/intel/kev.json']) {
      const live = await (await call(mockEnv(), p)).json();
      expect(live.data_source).toBe('d1');
      expect(live.live).toBe(true);

      const fallback = await (await call({}, p)).json();
      expect(fallback.data_source).toBe('seed');
      expect(fallback.live).toBe(false);
    }

    const liveReports = await (await call(mockEnv(), '/api/reports/latest.json')).json();
    expect(liveReports.data_source).toBe('d1');
    expect(liveReports.live).toBe(true);

    const fallbackReports = await (await call({}, '/api/reports/latest.json')).json();
    expect(fallbackReports.data_source).toBe('seed');
    expect(fallbackReports.live).toBe(false);
  });

  it('ai_summary falls back to seed counts when DB is empty', async () => {
    const res = await call({}, '/api/v1/intel/ai_summary.json');
    const body = await res.json();
    expect(body.counts.total).toBeGreaterThan(0);
    expect(body.threat_level).not.toBe('LOW');      // seed has CRITICAL/HIGH CVEs
    expect(body.data_source).toBe('seed');
    expect(body.live).toBe(false);
  });

  it('ai_summary reports live=true and data_source=d1 when DB has real rows', async () => {
    const body = await (await call(mockEnv(), '/api/v1/intel/ai_summary.json')).json();
    expect(body.data_source).toBe('d1');
    expect(body.live).toBe(true);
  });
});
