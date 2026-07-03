/* Global Intel monetization guard — verifies the firehose is tier-gated so it
 * is actually sellable: FREE gets a capped teaser (no IOC/actor/malware detail
 * + upgrade CTA), PRO gets the full feed, and the expensive recompute is not
 * reachable by an anonymous GET.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

let TIER = 'FREE';
vi.mock('../src/auth/middleware.js', () => ({
  resolveAuthV5: async () => ({ tier: TIER, identity: 'test:1', authenticated: TIER !== 'FREE' }),
  isOwner: () => false,
}));
vi.mock('../src/middleware/rateLimit.js', () => ({
  checkRateLimitV2: async () => ({ allowed: true, remaining: 100, tier: TIER }),
  rateLimitResponse: (r) => new Response(JSON.stringify(r), { status: 429 }),
}));

import { handleGlobalIntelFeed, handleGlobalIntelRefresh } from '../src/handlers/globalIntel.js';

// D1 shim: returns two enriched rows for SELECT *, a count for COUNT(*).
function makeDB() {
  const row = (id, sev) => ({
    intel_id: id, title: 'Test intel ' + id, summary: 'x'.repeat(300), url: 'https://ex.com/' + id,
    source: 'talos', source_name: 'Cisco Talos', category: 'apt', region: 'Global',
    severity: sev, threat_score: 80, is_breaking: 1,
    cve_ids: JSON.stringify(['CVE-2026-11111']), actors: JSON.stringify(['APT29']),
    malware: JSON.stringify(['Cobalt Strike']), iocs: JSON.stringify([{ type: 'ipv4', value: '8.8.8.8' }]),
    tags: JSON.stringify(['apt']), published_at: new Date().toISOString(), ingested_at: new Date().toISOString(),
  });
  return {
    prepare(sql) {
      const stmt = {
        bind() { return stmt; },
        async run() { return { meta: { changes: 0 } }; },
        async first() { return { total: 42 }; },
        async all() {
          if (/SELECT \* FROM global_intel/i.test(sql)) return { results: [row('a', 'CRITICAL'), row('b', 'HIGH')] };
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}
const req = (url = 'https://cyberdudebivash.in/api/global-intel?limit=50') => new Request(url);
const body = async (res) => (await res.json()).data ?? (await res.clone().json());

describe('Global Intel monetization gating', () => {
  beforeEach(() => { TIER = 'FREE'; });

  it('FREE caller gets a capped teaser with locked enrichment + upgrade CTA', async () => {
    TIER = 'FREE';
    const res = await handleGlobalIntelFeed(req(), { SECURITY_HUB_DB: makeDB() });
    const b = await body(res);
    expect(b.plan).toBe('FREE');
    expect(b.plan_limits.max_results).toBe(6);
    expect(b.upgrade_cta).toBeTruthy();
    const it0 = b.items[0];
    expect(it0.enrichment_gated).toBe(true);
    expect(it0.cve_ids).toEqual([]);          // detail withheld
    expect(it0.actors).toEqual([]);
    expect(it0.iocs.gated).toBe(true);        // IOCs locked
    expect(it0.enrichment_counts.cves).toBe(1); // but the count is shown (teaser)
    expect(it0.summary.length).toBeLessThanOrEqual(141);
  });

  it('PRO caller gets full enrichment (IOCs, actors, malware) and no CTA', async () => {
    TIER = 'PRO';
    const res = await handleGlobalIntelFeed(req(), { SECURITY_HUB_DB: makeDB() });
    const b = await body(res);
    expect(b.plan).toBe('PRO');
    expect(b.plan_limits.max_results).toBe(50);
    expect(b.upgrade_cta).toBeUndefined();
    const it0 = b.items[0];
    expect(it0.enrichment_gated).toBeUndefined();
    expect(it0.cve_ids).toContain('CVE-2026-11111');
    expect(it0.actors).toContain('APT29');
    expect(Array.isArray(it0.iocs)).toBe(true);
    expect(it0.iocs[0].value).toBe('8.8.8.8');
  });

  it('refresh (expensive recompute) is forbidden for a non-admin caller', async () => {
    TIER = 'PRO';
    const res = await handleGlobalIntelRefresh(new Request('https://x/api/global-intel/refresh', { method: 'POST' }), {});
    expect(res.status).toBe(403);
  });
});
