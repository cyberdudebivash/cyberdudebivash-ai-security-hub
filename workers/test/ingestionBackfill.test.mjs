/* Tests — Phase-2 ingestion expansion (bulk backfill toward thousands of CVEs).
 * Verifies the full CISA KEV catalog is normalized + stored, the NVD page maps
 * correctly with cursor semantics, and the bulk runner is resilient. Uses a
 * stub global fetch + an in-memory D1/KV so nothing hits the network. */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  fetchCISAKEV, fetchNVDPage, runBulkBackfill, enrichUnscoredEPSS,
} from '../src/services/threatIngestion.js';

// ── Fixtures ────────────────────────────────────────────────────────────────────────────
const KEV_JSON = {
  count: 2,
  vulnerabilities: [
    { cveID: 'CVE-2026-0001', vendorProject: 'Acme', product: 'Gateway',
      vulnerabilityName: 'Acme Gateway RCE', dateAdded: '2026-06-10',
      shortDescription: 'Remote code execution in Acme Gateway.',
      knownRansomwareCampaignUse: 'Known', cwes: ['CWE-77'] },
    { cveID: 'CVE-2026-0002', vendorProject: 'Globex', product: 'VPN',
      vulnerabilityName: 'Globex VPN Auth Bypass', dateAdded: '2026-05-01',
      shortDescription: 'Authentication bypass in Globex VPN.',
      knownRansomwareCampaignUse: 'Unknown', cwes: ['CWE-288'] },
  ],
};

const NVD_JSON = {
  totalResults: 3,
  resultsPerPage: 2,
  vulnerabilities: [
    { cve: { id: 'CVE-2026-1000', published: '2026-06-01T00:00:00.000',
      descriptions: [{ lang: 'en', value: 'A critical buffer overflow.' }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N' } }] } } },
    { cve: { id: 'CVE-2026-1001', published: '2026-06-02T00:00:00.000',
      descriptions: [{ lang: 'en', value: 'Another critical issue.' }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.1, baseSeverity: 'CRITICAL' } }] } } },
  ],
};

const EPSS_JSON = { data: [{ cve: 'CVE-2026-0001', epss: '0.92', percentile: '0.99', date: '2026-06-16' }] };

// ── In-memory D1 / KV ─────────────────────────────────────────────────────────────────────────
function memDB() {
  const rows = new Map();
  const mk = (sql) => ({
    _sql: sql, _b: [],
    bind(...a) { this._b = a; return this; },
    async run() { applyWrite(sql, this._b, rows); return { success: true }; },
    async all() { return { results: queryRows(sql, this._b, rows) }; },
    async first(col) {
      const r = queryRows(sql, this._b, rows);
      const row = r[0] || null;
      if (!row) return col ? null : null;
      return col ? row[col] : row;
    },
  });
  return {
    rows,
    prepare(sql) { return mk(sql); },
    async batch(stmts) { for (const s of stmts) await s.run(); return stmts.map(() => ({ success: true })); },
  };
}
function applyWrite(sql, b, rows) {
  if (/^\s*INSERT INTO threat_intel/i.test(sql) || /INSERT OR REPLACE INTO threat_intel/i.test(sql)) {
    const id = b[0];
    const prev = rows.get(id) || {};
    rows.set(id, { ...prev, id, title: b[1], severity: b[2], epss_score: prev.epss_score ?? null,
      exploit_status: prev.exploit_status, published_at: prev.published_at });
  } else if (/UPDATE threat_intel\s+SET epss_score/i.test(sql)) {
    const id = b[b.length - 1];
    const r = rows.get(id); if (r) { r.epss_score = b[0]; r.epss_percentile = b[1]; }
  }
  // ALTER/CREATE/ingestion_runs → no-op
}
function queryRows(sql, b, rows) {
  if (/COUNT\(\*\) AS n FROM threat_intel/i.test(sql)) return [{ n: rows.size }];
  if (/SELECT id FROM threat_intel/i.test(sql) && /epss_score IS NULL/i.test(sql)) {
    return [...rows.values()].filter(r => r.epss_score == null && /^CVE-/.test(r.id)).map(r => ({ id: r.id }));
  }
  return [];
}
function memKV() {
  const m = new Map();
  return { m, async get(k) { return m.has(k) ? m.get(k) : null; }, async put(k, v) { m.set(k, v); } };
}

// ── fetch stub ────────────────────────────────────────────────────────────────────────────
function stubFetch() {
  return vi.fn(async (url) => {
    const u = String(url);
    const json = (o) => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => o, text: async () => JSON.stringify(o) });
    if (u.includes('known_exploited_vulnerabilities')) return json(KEV_JSON);
    if (u.includes('services.nvd.nist.gov')) return json(NVD_JSON);
    if (u.includes('api.first.org')) return json(EPSS_JSON);
    return { ok: false, headers: { get: () => '' }, json: async () => ({}), text: async () => '' };
  });
}

let origFetch;
beforeEach(() => { origFetch = globalThis.fetch; globalThis.fetch = stubFetch(); });
afterEach(() => { globalThis.fetch = origFetch; });

describe('Phase-2 ingestion expansion', () => {
  it('fetchCISAKEV normalizes the full catalog (confirmed, ransomware, cwes)', async () => {
    const kev = await fetchCISAKEV(5000);
    expect(kev).toHaveLength(2);
    const a = kev.find(k => k.id === 'CVE-2026-0001');
    expect(a.source).toBe('cisa_kev');
    expect(a.exploit_status).toBe('confirmed');
    expect(a.known_ransomware).toBe(1);
    expect(a.actively_exploited).toBe(1);
    expect(JSON.parse(a.weakness_types)).toContain('CWE-77');
  });

  it('fetchNVDPage maps entries and computes cursor/done', async () => {
    const p = await fetchNVDPage({ severity: 'CRITICAL', startIndex: 0, resultsPerPage: 2 });
    expect(p.entries).toHaveLength(2);
    expect(p.entries[0].severity).toBe('CRITICAL');
    expect(p.entries[0].cvss).toBe(9.8);
    expect(p.totalResults).toBe(3);
    expect(p.nextIndex).toBe(2);
    expect(p.done).toBe(false);  // 2 < 3
  });

  it('runBulkBackfill stores the KEV catalog and reports a real total', async () => {
    const env = { SECURITY_HUB_DB: memDB(), SECURITY_HUB_KV: memKV() };
    const r = await runBulkBackfill(env, { nvdBackfill: false });
    expect(r.success).toBe(true);
    expect(r.kev_inserted).toBe(2);
    expect(r.total_now).toBe(2);
    expect(env.SECURITY_HUB_DB.rows.has('CVE-2026-0001')).toBe(true);
  });

  it('runBulkBackfill advances the NVD cursor when nvdBackfill is on', async () => {
    const env = { SECURITY_HUB_DB: memDB(), SECURITY_HUB_KV: memKV() };
    const r = await runBulkBackfill(env, { nvdBackfill: true, nvdPerPage: 2 });
    expect(r.nvd_inserted).toBeGreaterThan(0);
    // cursor advanced (nextIndex 2, not done) for at least one severity
    const cur = await env.SECURITY_HUB_KV.get('nvd:backfill:cursor:CRITICAL');
    expect(cur).toBe('2');
  }, 20000);

  it('enrichUnscoredEPSS scores rows lacking an EPSS value', async () => {
    const env = { SECURITY_HUB_DB: memDB(), SECURITY_HUB_KV: memKV() };
    await runBulkBackfill(env, { nvdBackfill: false });
    const e = await enrichUnscoredEPSS(env, 50);
    expect(e.enriched).toBeGreaterThanOrEqual(1);
    expect(env.SECURITY_HUB_DB.rows.get('CVE-2026-0001').epss_score).toBe(0.92);
  });
});
