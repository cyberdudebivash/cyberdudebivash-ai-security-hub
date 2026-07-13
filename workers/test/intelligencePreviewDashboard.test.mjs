// CAP-TIH-014 — SENTINEL APEX Intelligence Preview System had 14 hardcoded
// references to external, non-platform storefronts (intel.cyberdudebivash.com,
// cyberdudebivash.gumroad.com) baked into API JSON responses — CVE/actor/
// malware preview conversion blocks, IOC sample upgrade links, report sample
// purchase links, unlock-endpoint upgrade products, and the rate-limit 429
// response. A customer hitting any of these free-tier teasers would be
// redirected off-platform to buy fake a-la-carte products (e.g. a "$249 APT
// Malware YARA Pack" via Gumroad) that this platform does not actually sell.
//
// FIX: every upgrade_url / purchase.url / conversion.products[].url now
// points to this platform's own /#pricing section, and fake one-time-product
// price labels tied to those links (e.g. "$249 one-time", "$499 IR Kit") were
// removed so the teaser copy is consistent with the real PRO/ENTERPRISE
// subscription tiers actually sold here.
//
// SCOPE NOTE: this fix closes the external-URL/dead-storefront issue only.
// It does NOT touch the deeper, separately-tracked data-fabrication issue in
// this same file (hardcoded IOC counts, invented breaking-news headlines,
// padded catalog totals, placeholder premium IOC/YARA/financial-impact
// payloads) — that is deliberately deferred; see the CAP-TIH-014 registry
// entry for the open finding and rationale.
//
// Also adds an "Intelligence Preview" dashboard tab to user-dashboard.html —
// this backend existed and was wired to real routes, but had zero UI for a
// customer to actually use it before this change.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const { handleIntelligencePreview } = await import('../src/handlers/intelligencePreview.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');
const backendSrc = readFileSync(resolve(root, 'src/handlers/intelligencePreview.js'), 'utf8');

function fakeEnv() {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
      async batch(stmts) { return stmts.map(() => ({ results: [] })); },
    },
    KV: { get: async () => null, put: async () => {} },
  };
}

function req(url, opts) { return new Request(url, opts); }

describe('CAP-TIH-014 — intelligencePreview.js no longer references external storefronts', () => {
  it('the source file contains zero references to intel.cyberdudebivash.com or gumroad.com', () => {
    expect(backendSrc).not.toMatch(/cyberdudebivash\.com|gumroad\.com/);
  });

  it('FREE-tier CVE preview conversion + report blocks point at this platform\'s own pricing', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/cve/CVE-2024-1234'), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.conversion.unlock_url).toBe('/#pricing');
    for (const p of data.conversion.products) expect(p.url).toBe('/#pricing');
  });

  it('PREMIUM CVE preview report_available block points at this platform\'s own pricing', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/cve/CVE-2024-1234'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.report_available.purchase_url).toBe('/#pricing');
    expect(data.report_available.price).toBeUndefined();
  });

  it('FREE-tier threat actor preview conversion block and locked fields all resolve to /#pricing', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/threat/apt29'), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.conversion.unlock_url).toBe('/#pricing');
    for (const p of data.conversion.products) expect(p.url).toBe('/#pricing');
    expect(data.yara_signatures.upgrade_url).toBe('/#pricing');
    expect(data.yara_signatures.unlock_price).toBe('$49/month');
  });

  it('FREE-tier malware preview conversion block and locked fields all resolve to /#pricing', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/malware/lockbit'), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.conversion.unlock_url).toBe('/#pricing');
    for (const p of data.conversion.products) expect(p.url).toBe('/#pricing');
    expect(data.full_yara_library.upgrade_url).toBe('/#pricing');
    expect(data.ir_playbook.upgrade_url).toBe('/#pricing');
  });

  it('IOC sample upgrade block points to /#pricing for FREE tier', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/ioc-sample'), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.upgrade.upgrade_url).toBe('/#pricing');
  });

  it('report sample purchase URL points to /#pricing', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/report-sample?type=tactical_dossier'), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.purchase.url).toBe('/#pricing');
  });

  it('unlock endpoint upgrade_url and upgrade_products all point to /#pricing for a non-premium user', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/unlock', { method: 'POST' }), fakeEnv(), { tier: 'FREE', userId: 'u1' });
    expect(res.status).toBe(402);
    const data = await res.json();
    expect(data.upgrade_url).toBe('/#pricing');
    for (const p of data.upgrade_products) expect(p.url).toBe('/#pricing');
  });

  it('the rate-limit 429 response points to /#pricing', async () => {
    const env = fakeEnv();
    let count = 0;
    env.KV = {
      get: async () => String(count),
      put: async (_k, v) => { count = parseInt(v, 10); },
    };
    let last;
    for (let i = 0; i < 11; i++) {
      last = await handleIntelligencePreview(req('https://x/api/preview/catalog'), env, { tier: 'FREE', userId: 'u1' });
    }
    expect(last.status).toBe(429);
    const data = await last.json();
    expect(data.upgrade_url).toBe('/#pricing');
  });
});

describe('CAP-TIH-014 — intelligencePreview.js backend still returns real, honest data (unchanged behavior)', () => {
  it('catalog endpoint responds with real category structure', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/catalog'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.type).toBe('preview_catalog');
    expect(data.categories).toBeTruthy();
  });

  it('featured endpoint responds with items', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/featured'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(Array.isArray(data.items)).toBe(true);
  });

  it('IOC sample returns an honest empty list (no fabricated IOCs) when the DB has none', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/ioc-sample'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.iocs).toEqual([]);
  });

  it('unlock endpoint grants access for a PRO-tier user', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/unlock', { method: 'POST' }), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.unlocked).toBe(true);
  });
});

describe('user-dashboard.html — Intelligence Preview tab (CAP-TIH-014)', () => {
  it('has a real nav-item', () => {
    expect(dash).toContain(`data-page="intel-preview" onclick="showPage('intel-preview',this)"`);
  });

  // 2026-07-13: intelPreviewFeatured() moved off the nav-item onclick and into
  // showPage()'s id-dispatch block — a deep link (?tab=intel-preview) calls
  // showPage() directly and never runs the nav item's onclick, so a browser
  // click-through pass (done while wiring the sibling Global Intel Graph tab)
  // caught the featured-intel card never loading on that path.
  it('auto-loads featured intel from showPage(), not a nav-item onclick side-call', () => {
    const showPageStart = dash.indexOf('function showPage(id, el)');
    const showPageFn = dash.slice(showPageStart, dash.indexOf('\n  }', showPageStart) + 4);
    expect(showPageFn).toContain(`id === 'intel-preview'`);
    expect(showPageFn).toContain('intelPreviewFeatured()');
  });

  it('has a real page section with all 8 preview tools', () => {
    expect(dash).toContain('id="page-intel-preview"');
    expect(dash).toContain('id="intel-preview-featured"');
    expect(dash).toContain('id="intel-preview-cve"');
    expect(dash).toContain('id="intel-preview-actor"');
    expect(dash).toContain('id="intel-preview-malware"');
    expect(dash).toContain('id="intel-preview-ioc-result"');
    expect(dash).toContain('id="intel-preview-report-type"');
    expect(dash).toContain('id="intel-preview-catalog-result"');
    expect(dash).toContain('id="intel-preview-unlock-result"');
  });

  it('each preview function calls its real backend endpoint', () => {
    expect(dash).toContain(`intelPreviewGet('/api/preview/featured')`);
    expect(dash).toContain('/api/preview/cve/${encodeURIComponent(cveId)}');
    expect(dash).toContain('/api/preview/threat/${encodeURIComponent(actorId)}');
    expect(dash).toContain('/api/preview/malware/${encodeURIComponent(familyId)}');
    expect(dash).toContain(`intelPreviewGet('/api/preview/ioc-sample')`);
    expect(dash).toContain('/api/preview/report-sample?type=${encodeURIComponent(type)}');
    expect(dash).toContain(`intelPreviewGet('/api/preview/catalog')`);
    expect(dash).toContain(`apiFetch('/api/preview/unlock', { method: 'POST' })`);
  });

  it('the dashboard tab itself contains no external storefront links for this feature', () => {
    const start = dash.indexOf('id="page-intel-preview"');
    const section = dash.slice(start, start + 6000);
    expect(section).not.toMatch(/cyberdudebivash\.com|gumroad\.com/);
  });

  it('the Threat Intel API and DPDP tabs are untouched', () => {
    expect(dash).toContain(`data-page="intel-api" onclick="showPage('intel-api',this);loadIntelAPIStatus()"`);
    expect(dash).toContain(`data-page="dpdp" onclick="showPage('dpdp',this);loadDPDPOverview()"`);
  });
});

// ─── CAP-TIH-014 follow-up: the data-fabrication issue deliberately deferred
// above (owner note: "genuinely fabricates substantive content and presents
// it as real intelligence") is now fixed. Four instances, closed here:
//   1. handleFeaturedIntelligence's defaultFeatured fallback (fake Cisco
//      "FIRESTARTER backdoor" headline + fabricated "surge 340%/180%" stats)
//   2. handlePreviewCatalog's invented total_previewable (+46 padding) and
//      hardcoded per-category counts (85/30/8/74/3)
//   3. handleIOCSample's hardcoded "784 additional IOCs locked" message
//   4. handleCVEPreview / handleMalwarePreview's templated placeholder IOCs
//      and generic MZ-header YARA stub served to PREMIUM (paying) users when
//      the real DB has no match
function mockDbWithData(opts = {}) {
  const { featuredRows = [], catalogRows = [], cveCount = 0, actorCount = 0, iocCount = 0 } = opts;
  return {
    DB: {
      prepare(sql) {
        const stmt = {
          _sql: sql,
          bind(...args) { stmt._args = args; return stmt; },
          async first() { return null; },
          async all() {
            if (/severity IN \('CRITICAL','HIGH'\)/.test(sql)) return { results: featuredRows };
            if (/FROM threat_intel_cache WHERE expires_at > datetime\('now'\) ORDER BY severity DESC/.test(sql)) return { results: catalogRows };
            return { results: [] };
          },
        };
        return stmt;
      },
      async batch(stmts) {
        return stmts.map((s) => {
          const sql = s._sql || '';
          if (/COUNT\(\*\) AS c FROM threat_intel_cache/.test(sql)) return { results: [{ c: cveCount }] };
          if (/COUNT\(\*\) AS c FROM cti_actors/.test(sql)) return { results: [{ c: actorCount }] };
          if (/COUNT\(\*\) AS c FROM cti_iocs/.test(sql)) return { results: [{ c: iocCount }] };
          return { results: [] };
        });
      },
    },
    KV: { get: async () => null, put: async () => {} },
  };
}

describe('CAP-TIH-014 follow-up — fabricated content removed, real/honest data only', () => {
  it('source file no longer contains any of the documented fabricated strings', () => {
    expect(backendSrc).not.toMatch(/FIRESTARTER/);
    expect(backendSrc).not.toMatch(/surge 340|surge 180/);
    expect(backendSrc).not.toMatch(/784 additional/);
    expect(backendSrc).not.toMatch(/10\.xx\.xx\.xx|c2\.\[REDACTED\]/);
    expect(backendSrc).not.toMatch(/MZ header/);
    expect(backendSrc).not.toMatch(/previewCards\.length \+ 46/);
  });

  it('featured intelligence: empty DB produces an honest empty state, not fake headlines', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/featured'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.items).toEqual([]);
    expect(data.total_active_threats).toBe(0);
    expect(data.critical_count).toBe(0);
    expect(data.note).toMatch(/no fabricated headlines shown/i);
  });

  it('featured intelligence: real DB rows drive real counts, not hardcoded 85/40', async () => {
    const env = mockDbWithData({
      featuredRows: [
        { id: 'a', title: 'CVE-2025-1111', severity: 'CRITICAL', source: 'CISA KEV', created_at: '2026-07-01' },
        { id: 'b', title: 'Some HIGH threat', severity: 'HIGH', source: 'SENTINEL APEX', created_at: '2026-07-02' },
      ],
    });
    const res = await handleIntelligencePreview(req('https://x/api/preview/featured'), env, { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.items.length).toBe(2);
    expect(data.total_active_threats).toBe(2);
    expect(data.critical_count).toBe(1);
    expect(data.note).toBeUndefined();
  });

  it('catalog: total_previewable matches real item count, no +46 padding', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/catalog'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.total_previewable).toBe(data.items.length);
  });

  it('catalog: category counts reflect real queries, not hardcoded 85/30/74', async () => {
    const env = mockDbWithData({ cveCount: 12, actorCount: 19, iocCount: 203 });
    const res = await handleIntelligencePreview(req('https://x/api/preview/catalog'), env, { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.categories.cve.count).toBe(12);
    expect(data.categories.threat_actors.count).toBe(19);
    expect(data.categories.ioc_feeds.count).toBe(203);
  });

  it('catalog: malware_families/reports counts derive from the real static catalogs (8 and 3), never an unrelated number', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/catalog'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.categories.malware_families.count).toBe(8);
    expect(data.categories.reports.count).toBe(3);
  });

  it('IOC sample: locked-count message matches real totalAvailable minus returned, not hardcoded 784', async () => {
    const env = mockDbWithData();
    env.DB.batch = async (stmts) => {
      // handleIOCSample batches [list, count] against cti_iocs
      return [{ results: [] }, { results: [{ c: 25 }] }];
    };
    const res = await handleIntelligencePreview(req('https://x/api/preview/ioc-sample'), env, { tier: 'FREE', userId: 'u1' });
    const data = await res.json();
    expect(data.upgrade.message).toContain('25 additional IOCs locked');
    expect(data.upgrade.message).not.toContain('784');
  });

  it('CVE preview: PREMIUM caller gets an honest empty IOC list (not placeholder IOCs) when the DB has no match', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/cve/CVE-2024-1234'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.full_ioc_list).toEqual([]);
    expect(data.full_ioc_list_note).toMatch(/no fabricated IOCs shown/i);
  });

  it('malware preview: PREMIUM caller gets an honest note (not a generic YARA stub) when no signatures are on file', async () => {
    const res = await handleIntelligencePreview(req('https://x/api/preview/malware/lockbit'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.full_yara_library.sample_rule).toBeUndefined();
    expect(data.full_yara_library.note).toMatch(/no fabricated rule shown/i);
  });
});
