/* Regression test — secureDownload.js's generateReportHTML() (paid, payment-
 * gated SENTINEL APEX intelligence reports) baked in fully invented trend
 * stats ("AI-Weaponized Attacks +187% YoY", "India-targeted attacks +78%
 * YoY"), and rendered 3 hardcoded APT29/Lazarus/APT41 actor write-ups
 * stamped with today's date on every single report — while the real
 * cti_actors data it fetched (`actors`) was silently discarded. Separately,
 * real D1 CVE rows use `is_exploited`, but the template read `is_kev`,
 * silently zeroing the KEV count/badge on genuine live data.
 *
 * Proves: the landscape section shows real current-dataset counts (no
 * fabricated % deltas), the actor section renders real cti_actors rows (or
 * an honest empty state), and a real is_exploited=1 CVE is correctly
 * counted/badged as KEV. */
import { describe, it, expect } from 'vitest';
import { handleSecureDownload } from '../src/handlers/secureDownload.js';

function makeDB({ cveRows = [], actorRows = [], landscapeRow = null, iocRows = [] } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async first() {
          if (/FROM marketplace_orders/.test(sql)) {
            return { id: bound[0], product_id: 'rpt-cve-critical-2026', status: 'paid', user_id: bound[1] };
          }
          if (/COUNT\(\*\) as total, MAX\(cvss_score\)/.test(sql)) return { total: 0, max_cvss: 0 };
          if (/SUM\(CASE WHEN is_ransomware/.test(sql)) return landscapeRow;
          return null;
        },
        async all() {
          if (/FROM cti_actors/.test(sql))   return { results: actorRows };
          if (/FROM cti_iocs/.test(sql))     return { results: iocRows };
          if (/FROM threat_intel/.test(sql)) return { results: cveRows };
          return { results: [] };
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, value); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
  };
}

async function generateAndDownload(env, authCtx = { userId: 'u_1', authenticated: true }) {
  const genReq = new Request('https://x/api/report/generate/order_abc', { method: 'POST' });
  const genRes = await handleSecureDownload(genReq, env, authCtx, '/api/report/generate/order_abc', 'POST');
  expect(genRes.status).toBe(200);
  const { token } = await genRes.json();

  const dlReq = new Request(`https://x/api/download/${token}`);
  const dlRes = await handleSecureDownload(dlReq, env, authCtx, `/api/download/${token}`, 'GET');
  expect(dlRes.status).toBe(200);
  return dlRes.text();
}

describe('SENTINEL APEX marketplace report — threat landscape & actor honesty', () => {
  it('renders real cti_actors profiles instead of the old hardcoded APT29/Lazarus/APT41 write-ups', async () => {
    const env = {
      DB: makeDB({
        actorRows: [{
          name: 'TEST-APT-99', aliases: '["Ghost Bear"]', nation_state: 'Testland',
          motivation: 'Espionage', sophistication: 'HIGH',
          target_sectors: '["Finance","Healthcare"]',
          description: 'A fictitious test-only threat actor for regression testing.',
          threat_level: 'CRITICAL', confidence_score: 88, last_active: '2026-07-01T00:00:00.000Z',
        }],
        landscapeRow: { total: 12, ransomware_count: 4, apt_attributed_count: 3, kev_count: 2 },
      }),
      SECURITY_HUB_KV: makeKV(),
    };
    const html = await generateAndDownload(env);

    expect(html).toContain('TEST-APT-99');
    expect(html).toContain('Ghost Bear');
    expect(html).toContain('Testland');
    expect(html).toContain('Finance, Healthcare');
    // The old hardcoded actor write-ups must be gone
    expect(html).not.toContain('APT29 (Cozy Bear)');
    expect(html).not.toContain('Lazarus Group remains the most active');
    expect(html).not.toContain('APT41 (Double Dragon)');
  });

  it('honestly discloses no cataloged actor profiles instead of fabricating APT29/Lazarus/APT41 write-ups when cti_actors is empty', async () => {
    const env = { DB: makeDB({ actorRows: [] }), SECURITY_HUB_KV: makeKV() };
    const html = await generateAndDownload(env);
    expect(html).toContain('No threat-actor profiles currently cataloged');
    // The fabricated per-actor profile prose must be gone — generic MITRE/
    // sector reference tables elsewhere in the report legitimately still
    // name real APT groups as example context, so assert on the specific
    // fabricated write-ups, not bare substring presence of "APT29" anywhere.
    expect(html).not.toContain('APT29 (Cozy Bear)');
    expect(html).not.toContain('Lazarus Group remains the most active');
    expect(html).not.toContain('APT41 (Double Dragon)');
  });

  it('threat landscape shows real dataset counts, not fabricated QoQ/YoY percentages', async () => {
    const env = {
      DB: makeDB({ landscapeRow: { total: 12, ransomware_count: 4, apt_attributed_count: 3, kev_count: 2 } }),
      SECURITY_HUB_KV: makeKV(),
    };
    const html = await generateAndDownload(env);

    expect(html).not.toContain('+34% QoQ');
    expect(html).not.toContain('+187% YoY');
    expect(html).not.toContain('78% year-over-year');
    expect(html).not.toContain('dark web monitoring');
    expect(html).toContain('>4</strong>');
    expect(html).toContain('>3</strong>');
  });

  it('a real D1 CVE with is_exploited=1 is correctly counted and badged as KEV (is_kev/is_exploited column mismatch fix)', async () => {
    const env = {
      DB: makeDB({
        cveRows: [{
          cve_id: 'CVE-2026-0001', title: 'Test Critical CVE', severity: 'CRITICAL',
          cvss_score: 9.8, description: 'Regression-test CVE.', is_exploited: 1, is_ransomware: 0, apt_groups: null,
        }],
      }),
      SECURITY_HUB_KV: makeKV(),
    };
    const html = await generateAndDownload(env);
    expect(html).toContain('CVE-2026-0001');
    expect(html).toContain('badge-kev');
    // Executive summary stat-row: 1 Critical CVE, 1 KEV-listed
    expect(html).toMatch(/<strong>1<\/strong>\s*<small>Critical CVEs/);
    expect(html).toMatch(/<strong>1<\/strong>\s*<small>CISA KEV Listed/);
  });
});
