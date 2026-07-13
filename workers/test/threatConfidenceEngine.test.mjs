// CAP-TIH-011 — Threat Confidence & Exploitability Engine
// (workers/src/handlers/threatConfidence.js). Real, live capability embedded
// in 4 places on frontend/index.html's homepage ('AI Verdict' panel) — had
// zero test coverage despite scoring real customer-facing risk data. Pure
// test-addition: no production code changed for this capability.
//
// The module calls caches.default (Cloudflare Cache API) inside a try/catch
// that already swallows a missing global cleanly in Node's test environment,
// so no cache polyfill is needed — it just falls through to the KV/fetch path
// on every call here, which is what these tests exercise directly.
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  handleScoreThreats, handleGetKEV, handleEnrichThreat, handleGetFeed, handleGetStats,
} from '../src/handlers/threatConfidence.js';

// Real CISA KEV JSON shape (raw.vulnerabilities[].{cveID,vendorProject,product,
// vulnerabilityName,dateAdded,dueDate,knownRansomwareCampaignUse,notes}).
const MOCK_KEV_RAW = {
  catalogVersion: '2026.07.01',
  dateReleased:   '2026-07-01T00:00:00Z',
  vulnerabilities: [
    {
      cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j',
      vulnerabilityName: 'Log4Shell', dateAdded: '2021-12-10', dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Unknown', notes: '',
    },
    {
      cveID: 'CVE-2019-0708', vendorProject: 'Microsoft', product: 'RDP',
      vulnerabilityName: 'BlueKeep', dateAdded: '2019-05-14', dueDate: '2019-05-28',
      knownRansomwareCampaignUse: 'Unknown', notes: '',
    },
  ],
};

function makeMemoryKV() {
  const store = new Map();
  return {
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, typeof value === 'string' ? value : JSON.stringify(value)); },
    _store: store,
  };
}

function fetchMock({ kevOk = true, threatfoxData = null } = {}) {
  return vi.fn(async (url) => {
    // Real hostname check, not a substring match — `.includes('cisa.gov')` would
    // also match an attacker-shaped URL like https://cisa.gov.evil.example/,
    // which CodeQL correctly flags as incomplete URL substring sanitization
    // even in test-only stub code.
    let host = '';
    try { host = new URL(String(url)).hostname; } catch {}
    if (host === 'www.cisa.gov') {
      if (!kevOk) return { ok: false, status: 500 };
      return { ok: true, json: async () => MOCK_KEV_RAW };
    }
    if (host === 'threatfox-api.abuse.ch') {
      if (!threatfoxData) return { ok: true, json: async () => ({ query_status: 'no_result' }) };
      return { ok: true, json: async () => ({ query_status: 'ok', data: threatfoxData }) };
    }
    return { ok: false, status: 404 };
  });
}

function req(url, opts) { return new Request(`https://x${url}`, opts); }
async function readOk(res) { const b = await res.json(); return { status: res.status, body: b, data: b.data }; }

describe('CAP-TIH-011 — handleScoreThreats() POST /api/threat-confidence/score', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeMemoryKV() };
    vi.stubGlobal('fetch', fetchMock());
  });
  afterEach(() => vi.unstubAllGlobals());

  it('rejects an empty request with 400 NO_INPUT', async () => {
    const res = await handleScoreThreats(req('/api/threat-confidence/score', { method: 'POST', body: '{}' }), env);
    const { body } = await readOk(res);
    expect(res.status).toBe(400);
    expect(body.code).toBe('NO_INPUT');
  });

  it('rejects a batch over 20 threats with 429 BATCH_TOO_LARGE', async () => {
    const threats = Array.from({ length: 21 }, (_, i) => ({ cve_id: `CVE-2099-${i}`, cvss: 5 }));
    const res = await handleScoreThreats(req('/api/threat-confidence/score', { method: 'POST', body: JSON.stringify({ threats }) }), env);
    expect(res.status).toBe(429);
  });

  it('scores a real KEV-listed, APT-attributed CVE as CRITICAL_IMMINENT with a deterministic composite score', async () => {
    const res = await handleScoreThreats(req('/api/threat-confidence/score', {
      method: 'POST',
      body: JSON.stringify({ cve_id: 'CVE-2021-44228', cvss: 10.0, active_exp: true }),
    }), env);
    const { data } = await readOk(res);
    const r = data.results[0];

    // signals: kev_listed(35) + exploit_public(20, cvss>=9 && KEV) +
    // active_exploitation(20, explicit active_exp) + apt_attribution(10,
    // CVE-2021-44228 is in APT_SIGNALS) + cvss_critical(10) + threatfox(0) = 95/100
    expect(r.confidence_score).toBe(95);
    expect(r.exploitability_index).toBe(9.5);
    expect(r.risk_tier).toBe('CRITICAL_IMMINENT');
    expect(r.remediation.priority).toBe('P0');
    expect(r.remediation.sla_hours).toBe(4);
    expect(r.apt_attribution).toEqual(['APT41', 'Lazarus']);
    expect(r.vendor).toBe('Apache');
    expect(r.product).toBe('Log4j');
    expect(r.signals.kev_listed).toBe(true);
  });

  it('scores a low-severity, non-KEV CVE as LOW_THEORETICAL', async () => {
    const res = await handleScoreThreats(req('/api/threat-confidence/score', {
      method: 'POST', body: JSON.stringify({ cve_id: 'CVE-2099-0001', cvss: 3.0 }),
    }), env);
    const { data } = await readOk(res);
    const r = data.results[0];
    expect(r.confidence_score).toBe(0);
    expect(r.risk_tier).toBe('LOW_THEORETICAL');
    expect(r.remediation.priority).toBe('P3');
    expect(r.signals.kev_listed).toBe(false);
  });

  it('summary tier counts match the batch composition', async () => {
    const res = await handleScoreThreats(req('/api/threat-confidence/score', {
      method: 'POST',
      body: JSON.stringify({ threats: [
        { cve_id: 'CVE-2021-44228', cvss: 10.0, active_exp: true },
        { cve_id: 'CVE-2099-0001', cvss: 3.0 },
      ]}),
    }), env);
    const { data } = await readOk(res);
    expect(data.summary.critical_imminent).toBe(1);
    expect(data.summary.low_theoretical).toBe(1);
    expect(data.summary.high_likely).toBe(0);
  });

  it('only pushes CRITICAL/HIGH-tier results to the feed, not LOW/MEDIUM', async () => {
    await handleScoreThreats(req('/api/threat-confidence/score', {
      method: 'POST',
      body: JSON.stringify({ threats: [
        { cve_id: 'CVE-2021-44228', cvss: 10.0, active_exp: true },
        { cve_id: 'CVE-2099-0001', cvss: 3.0 },
      ]}),
    }), env);
    const feedRes = await handleGetFeed(req('/api/threat-confidence/feed'), env);
    const { data } = await readOk(feedRes);
    expect(data.total).toBe(1);
    expect(data.feed[0].cve_id).toBe('CVE-2021-44228');
  });
});

describe('CAP-TIH-011 — handleGetKEV() GET /api/threat-confidence/kev', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeMemoryKV() };
    vi.stubGlobal('fetch', fetchMock());
  });
  afterEach(() => vi.unstubAllGlobals());

  it('returns the real catalog with both seeded CVEs', async () => {
    const res = await handleGetKEV(req('/api/threat-confidence/kev'), env);
    const { data } = await readOk(res);
    expect(data.total_in_catalog).toBe(2);
    expect(data.catalog_version).toBe('2026.07.01');
    expect(data.filtered_count).toBe(2);
  });

  it('filters by q against CVE ID, vendor, product, and vuln name', async () => {
    const res = await handleGetKEV(req('/api/threat-confidence/kev?q=log4j'), env);
    const { data } = await readOk(res);
    expect(data.filtered_count).toBe(1);
    expect(data.entries[0].cve_id).toBe('CVE-2021-44228');
  });

  it('respects the limit param', async () => {
    const res = await handleGetKEV(req('/api/threat-confidence/kev?limit=1'), env);
    const { data } = await readOk(res);
    expect(data.entries.length).toBe(1);
    expect(data.filtered_count).toBe(2); // filtered_count is pre-limit
  });

  it('propagates a real CISA fetch failure as 503, never a silently-zeroed catalog', async () => {
    vi.stubGlobal('fetch', fetchMock({ kevOk: false }));
    const res = await handleGetKEV(req('/api/threat-confidence/kev'), env);
    const body = await res.json();
    expect(res.status).toBe(503);
    expect(body.success).toBe(false);
    expect(body.error).toBe('kev_fetch_failed');
  });
});

describe('CAP-TIH-011 — handleEnrichThreat() POST /api/threat-confidence/enrich', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeMemoryKV() };
    vi.stubGlobal('fetch', fetchMock({ threatfoxData: [{ malware_printable: 'Cobalt Strike', first_seen: '2026-01-01', threat_type: 'payload_delivery' }] }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('rejects a request with neither cve_id nor title as 400 MISSING_ID', async () => {
    const res = await handleEnrichThreat(req('/api/threat-confidence/enrich', { method: 'POST', body: '{}' }), env);
    const { body } = await readOk(res);
    expect(res.status).toBe(400);
    expect(body.code).toBe('MISSING_ID');
  });

  it('returns a real scored object plus a narrative mentioning KEV, ThreatFox, and remediation', async () => {
    const res = await handleEnrichThreat(req('/api/threat-confidence/enrich', {
      method: 'POST', body: JSON.stringify({ cve_id: 'CVE-2021-44228', cvss: 10.0 }),
    }), env);
    const { data } = await readOk(res);
    expect(data.risk_tier).toBe('CRITICAL_IMMINENT');
    expect(data.threatfox.found).toBe(true);
    expect(data.threatfox.malware_families).toEqual(['Cobalt Strike']);
    expect(data.narrative).toContain('CISA Known Exploited Vulnerabilities');
    expect(data.narrative).toContain('ThreatFox');
    expect(data.narrative).toContain('Cobalt Strike');
    expect(data.narrative).toContain('Remediation');
  });

  it('pushes to the feed unconditionally, even for a LOW_THEORETICAL result (unlike handleScoreThreats)', async () => {
    await handleEnrichThreat(req('/api/threat-confidence/enrich', {
      method: 'POST', body: JSON.stringify({ cve_id: 'CVE-2099-9999', cvss: 2.0 }),
    }), env);
    const feedRes = await handleGetFeed(req('/api/threat-confidence/feed'), env);
    const { data } = await readOk(feedRes);
    expect(data.total).toBe(1);
    expect(data.feed[0].cve_id).toBe('CVE-2099-9999');
  });
});

describe('CAP-TIH-011 — handleGetStats() GET /api/threat-confidence/stats', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeMemoryKV() };
    vi.stubGlobal('fetch', fetchMock());
  });
  afterEach(() => vi.unstubAllGlobals());

  it('reports zeroed stats with an empty feed but a real KEV catalog size', async () => {
    const res = await handleGetStats(req('/api/threat-confidence/stats'), env);
    const { data } = await readOk(res);
    expect(data.feed_depth).toBe(0);
    expect(data.kev_catalog_size).toBe(2);
    expect(data.avg_confidence_score).toBe(0);
    expect(data.high_priority_count).toBe(0);
  });

  it('computes real tier_distribution and high_priority_count from real fed data', async () => {
    await handleScoreThreats(req('/api/threat-confidence/score', {
      method: 'POST',
      body: JSON.stringify({ threats: [
        { cve_id: 'CVE-2021-44228', cvss: 10.0, active_exp: true },
        { cve_id: 'CVE-2019-0708', cvss: 9.8, active_exp: true },
      ]}),
    }), env);

    const res = await handleGetStats(req('/api/threat-confidence/stats'), env);
    const { data } = await readOk(res);
    expect(data.feed_depth).toBe(2);
    expect(data.tier_distribution.CRITICAL_IMMINENT).toBe(2);
    expect(data.high_priority_count).toBe(2);
    expect(data.avg_confidence_score).toBeGreaterThan(0);
  });
});
