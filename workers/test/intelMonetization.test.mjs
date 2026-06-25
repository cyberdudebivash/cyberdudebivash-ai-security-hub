/* Tests — Sentinel APEX threat-intel API monetization.
 * FREE tier is gated (item cap + premium fields stripped + upgrade CTA); paid
 * tiers (resolved from an x-api-key in KV) get full detail, EPSS, full KEV and
 * STIX 2.1 export. STIX is paid-only (402 for FREE). Pure unit — no network. */
import { describe, it, expect } from 'vitest';
import { handlePublicFeeds } from '../src/handlers/publicFeeds.js';
import {
  entitlementsFor, gateItems, toStixBundle, pricingMatrix, FEED_TIERS,
} from '../src/handlers/intelMonetization.js';

const ROWS = Array.from({ length: 60 }, (_, i) => ({
  cve_id: `CVE-2026-${1000 + i}`, title: `Vuln ${i}`, description: 'x'.repeat(300),
  severity: i % 2 ? 'HIGH' : 'CRITICAL', cvss: 9.0, cvss_vector: 'CVSS:3.1/AV:N',
  epss_score: 0.7, epss_percentile: 0.9, exploit_status: 'confirmed',
  source: 'cisa_kev', published_at: '2026-06-15', weakness_types: '["CWE-77"]',
}));

// DB mock — SELECT * returns ROWS (optionally severity-filtered).
function mockDB() {
  return {
    prepare(sql) {
      let b = [];
      return {
        bind(...a) { b = a; return this; },
        async all() {
          let r = ROWS;
          if (/exploit_status='confirmed'/.test(sql)) r = ROWS.filter(x => x.exploit_status === 'confirmed');
          if (/IN \(/.test(sql)) {
            const sevs = b.slice(0, b.length - 1).map(s => String(s).toUpperCase());
            r = r.filter(x => sevs.includes(x.severity));
          }
          const lim = b.length ? b[b.length - 1] : ROWS.length;
          return { results: r.slice(0, lim) };
        },
      };
    },
  };
}

// KV mock that resolves a known api key to a tier (apikey:<key> → {tier}).
function mockKV(keyTier = {}) {
  const store = new Map();
  for (const [k, tier] of Object.entries(keyTier)) {
    store.set(`apikey:${k}`, JSON.stringify({ tier, active: true, owner_email: 'x@y.z' }));
  }
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put() {} };
}

const req = (path, headers = {}) => new Request('https://x' + path, { headers });
const call = (env, path, headers) => handlePublicFeeds(req(path, headers), env, path);

describe('feed tier entitlements', () => {
  it('maps tiers and degrades unknown to FREE', () => {
    expect(entitlementsFor('PRO').stix).toBe(true);
    expect(entitlementsFor('FREE').stix).toBe(false);
    expect(entitlementsFor('bogus').tier).toBe('FREE');
    expect(entitlementsFor('ENTERPRISE_SOC').tier).toBe('ENTERPRISE');
  });

  it('gateItems caps count and strips premium fields for FREE', () => {
    const items = ROWS.map(r => ({ id: r.cve_id, cve: r.cve_id, title: r.title, severity: r.severity,
      cvss: r.cvss, epss_score: r.epss_score, cvss_vector: r.cvss_vector, source: r.source, published_at: r.published_at }));
    const free = gateItems(items, entitlementsFor('FREE'));
    expect(free.length).toBe(FEED_TIERS.FREE.max_results); // capped at 25
    expect(free[0].epss_score).toBeUndefined();             // stripped
    expect(free[0]._premium).toMatch(/paid plan/);
    const pro = gateItems(items, entitlementsFor('PRO'));
    expect(pro.length).toBe(60);                            // under PRO cap (500)
    expect(pro[0].epss_score).toBe(0.7);                    // retained
  });
});

describe('public feeds — FREE gating', () => {
  it('FREE /api/feed.json is capped at 25 and strips EPSS, with an upgrade CTA', async () => {
    const env = { SECURITY_HUB_DB: mockDB() };
    const body = await (await call(env, '/api/feed.json')).json();
    expect(body.tier).toBe('FREE');
    expect(body.count).toBe(25);
    expect(body.items[0].epss_score).toBeUndefined();
    expect(body.upgrade.upgrade_url).toMatch(/pricing/);
    expect(body.upgrade.plans.length).toBeGreaterThan(0);
  });

  it('FREE KEV feed is a limited slice (not the full catalog)', async () => {
    const env = { SECURITY_HUB_DB: mockDB() };
    const body = await (await call(env, '/api/v1/intel/kev.json')).json();
    expect(body.full_catalog).toBe(false);
    expect(body.count).toBeLessThanOrEqual(25);
  });

  it('STIX export is blocked for FREE with 402 + upgrade', async () => {
    const env = { SECURITY_HUB_DB: mockDB() };
    const res = await call(env, '/api/v1/intel/stix.json');
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.upgrade_url).toMatch(/pricing/);
  });

  it('pricing endpoint lists every tier with prices', async () => {
    const env = { SECURITY_HUB_DB: mockDB() };
    const body = await (await call(env, '/api/v1/intel/pricing.json')).json();
    expect(body.tiers.find(t => t.tier === 'PRO').stix_export).toBe(true);
    expect(body.tiers.find(t => t.tier === 'FREE').price_inr).toBe(0);
  });
});

describe('public feeds — paid (keyed) access', () => {
  it('a PRO key unlocks full detail (EPSS) and rate-limit headers', async () => {
    const env = { SECURITY_HUB_DB: mockDB(), SECURITY_HUB_KV: mockKV({ cdb_prokey: 'PRO' }) };
    const res = await call(env, '/api/feed.json', { 'x-api-key': 'cdb_prokey' });
    expect(res.status).toBe(200);
    expect(res.headers.get('X-RateLimit-Tier')).toBe('PRO');
    const body = await res.json();
    expect(body.tier).toBe('PRO');
    expect(body.items[0].epss_score).toBe(0.7);   // full detail retained
    expect(body.upgrade).toBeUndefined();          // no upsell for paid
  });

  it('a PRO key can export a valid STIX 2.1 bundle', async () => {
    const env = { SECURITY_HUB_DB: mockDB(), SECURITY_HUB_KV: mockKV({ cdb_prokey: 'PRO' }) };
    const res = await call(env, '/api/v1/intel/stix.json', { 'x-api-key': 'cdb_prokey' });
    expect(res.status).toBe(200);
    const bundle = await res.json();
    expect(bundle.type).toBe('bundle');
    expect(bundle.spec_version).toBe('2.1');
    expect(bundle.objects.some(o => o.type === 'vulnerability')).toBe(true);
  });

  it('an invalid key is rejected with 401', async () => {
    const env = { SECURITY_HUB_DB: mockDB(), SECURITY_HUB_KV: mockKV({ cdb_prokey: 'PRO' }) };
    const res = await call(env, '/api/feed.json', { 'x-api-key': 'cdb_wrong' });
    expect(res.status).toBe(401);
  });
});

describe('STIX builder', () => {
  it('produces a 2.1 bundle with a TLP marking and per-CVE vulnerabilities', () => {
    const bundle = toStixBundle([{ cve: 'CVE-2026-1', title: 'x', severity: 'CRITICAL', cvss: 9.8, epss_score: 0.9 }]);
    expect(bundle.type).toBe('bundle');
    expect(bundle.objects.find(o => o.type === 'marking-definition')).toBeTruthy();
    const v = bundle.objects.find(o => o.type === 'vulnerability');
    expect(v.name).toBe('CVE-2026-1');
    expect(v.external_references[0].external_id).toBe('CVE-2026-1');
  });
});
