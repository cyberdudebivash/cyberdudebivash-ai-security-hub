/* Regression test — workers/src/handlers/vulnManagement.js's handleCVELookup
 * (backend) and frontend/cyber-defense.html's IOC lookup tool (frontend)
 * (Tier 2 backlog item #4; see docs/capability-registry/PROGRAM_BOARD.md
 * session log).
 *
 * 1. handleCVELookup's live-NVD success path never included epss_score or
 *    in_kev at all — NVD's own API carries neither. Every consumer reading
 *    those fields (cyber-defense.html's "Live CVE Threat Intelligence
 *    Lookup") always showed "N/A" / "Not in KEV", even for the page's own
 *    default example (CVE-2024-3400, a real, famous, actively-exploited
 *    CISA KEV entry). Fixed by enriching the NVD result with a real EPSS
 *    score (fetchEPSS(), already used elsewhere in this codebase) and real
 *    KEV membership (a new small KV-cached helper, fetchKEVIds(), mirroring
 *    fetchEPSS's own caching pattern and reusing the same CISA feed URL
 *    handleKEVFeed already fetches).
 *
 * 2. cyber-defense.html's IOC-lookup branch read d.virustotal/d.abuseipdb
 *    directly off the top-level /api/hunt/ioc response — but that endpoint
 *    supports batch lookups, so the real per-IOC result is nested at
 *    d.results[0], and the real field names are raw_data.virustotal and
 *    abuse_score (a plain number), not virustotal/abuseipdb.
 *    abuse_confidence_score. d.virustotal/d.abuseipdb never existed at any
 *    level of the real response, so the tile always showed 0 / "checked"
 *    regardless of the real verdict.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { handleCVELookup } from '../src/handlers/vulnManagement.js';

function makeKV() {
  const store = new Map();
  return {
    get: vi.fn(async (key, opts) => {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    }),
    put: vi.fn(async (key, value) => { store.set(key, value); }),
    _store: store,
  };
}

const NVD_URL_RE  = /services\.nvd\.nist\.gov/;
const EPSS_URL_RE = /api\.first\.org\/data\/v1\/epss/;
const KEV_URL_RE  = /cisa\.gov.*known_exploited_vulnerabilities\.json/;

function nvdResponse(cveId, cvss = 9.8) {
  return {
    ok: true,
    json: async () => ({
      vulnerabilities: [{
        cve: {
          id: cveId,
          published: '2024-04-12T00:00:00.000',
          lastModified: '2024-04-15T00:00:00.000',
          vulnStatus: 'Analyzed',
          descriptions: [{ lang: 'en', value: 'A test vulnerability description.' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: cvss, vectorString: 'AV:N', version: '3.1', baseSeverity: 'CRITICAL' } }] },
          weaknesses: [], references: [], configurations: [],
        },
      }],
    }),
  };
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn());
});

describe('handleCVELookup — real EPSS/KEV enrichment on the live-NVD success path', () => {
  it('includes a real epss_score and in_kev:true for a CVE that is on the live CISA KEV list', async () => {
    const cveId = 'CVE-2024-3400';
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (NVD_URL_RE.test(u))  return Promise.resolve(nvdResponse(cveId));
      if (EPSS_URL_RE.test(u)) return Promise.resolve({ ok: true, json: async () => ({ data: [{ cve: cveId, epss: '0.94231' }] }) });
      if (KEV_URL_RE.test(u))  return Promise.resolve({ ok: true, json: async () => ({ vulnerabilities: [{ cveID: cveId }, { cveID: 'CVE-2021-44228' }] }) });
      return Promise.resolve({ ok: false });
    });

    const env = { SECURITY_HUB_KV: makeKV() };
    const req = new Request(`https://x/api/vulns/cve/${cveId}`);
    const res = await handleCVELookup(req, env, {}, cveId);
    const body = await res.json();

    expect(body.epss_score).toBeCloseTo(0.94231, 4);
    expect(body.in_kev).toBe(true);
  });

  it('returns in_kev:false for a real CVE that genuinely is not on the KEV list', async () => {
    const cveId = 'CVE-2024-9999';
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (NVD_URL_RE.test(u))  return Promise.resolve(nvdResponse(cveId, 5.3));
      if (EPSS_URL_RE.test(u)) return Promise.resolve({ ok: true, json: async () => ({ data: [{ cve: cveId, epss: '0.01' }] }) });
      if (KEV_URL_RE.test(u))  return Promise.resolve({ ok: true, json: async () => ({ vulnerabilities: [{ cveID: 'CVE-2024-3400' }] }) });
      return Promise.resolve({ ok: false });
    });

    const env = { SECURITY_HUB_KV: makeKV() };
    const req = new Request(`https://x/api/vulns/cve/${cveId}`);
    const res = await handleCVELookup(req, env, {}, cveId);
    const body = await res.json();

    expect(body.in_kev).toBe(false);
    expect(body.epss_score).toBeCloseTo(0.01, 4);
  });

  it('returns in_kev:null (not a false "not exploited" claim) when the live KEV feed is unreachable', async () => {
    const cveId = 'CVE-2024-3400';
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (NVD_URL_RE.test(u))  return Promise.resolve(nvdResponse(cveId));
      if (EPSS_URL_RE.test(u)) return Promise.resolve({ ok: true, json: async () => ({ data: [] }) });
      if (KEV_URL_RE.test(u))  return Promise.reject(new Error('CISA feed down'));
      return Promise.resolve({ ok: false });
    });

    const env = { SECURITY_HUB_KV: makeKV() };
    const req = new Request(`https://x/api/vulns/cve/${cveId}`);
    const res = await handleCVELookup(req, env, {}, cveId);
    const body = await res.json();

    expect(body.in_kev).toBeNull();
  });

  it('caches the KEV catalog in KV and does not re-fetch CISA on a second lookup within the TTL', async () => {
    const kv = makeKV();
    let kevFetchCount = 0;
    global.fetch.mockImplementation((url) => {
      const u = String(url);
      if (NVD_URL_RE.test(u))  return Promise.resolve(nvdResponse('CVE-2024-3400'));
      if (EPSS_URL_RE.test(u)) return Promise.resolve({ ok: true, json: async () => ({ data: [] }) });
      if (KEV_URL_RE.test(u))  { kevFetchCount++; return Promise.resolve({ ok: true, json: async () => ({ vulnerabilities: [{ cveID: 'CVE-2024-3400' }] }) }); }
      return Promise.resolve({ ok: false });
    });

    const env = { SECURITY_HUB_KV: kv };
    await handleCVELookup(new Request('https://x/api/vulns/cve/CVE-2024-3400'), env, {}, 'CVE-2024-3400');
    await handleCVELookup(new Request('https://x/api/vulns/cve/CVE-2024-3400'), env, {}, 'CVE-2024-3400');

    expect(kevFetchCount).toBe(1);
  });
});

describe('cyber-defense.html — IOC lookup reads the real nested /api/hunt/ioc response shape', () => {
  const root = resolve(import.meta.dirname, '..');
  const fe = readFileSync(resolve(root, '../frontend/cyber-defense.html'), 'utf8');

  function cdLookupBody() {
    const start = fe.indexOf('async function cdLookup()');
    expect(start, 'cdLookup must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('\n}', start);
    expect(end, "cdLookup's closing brace must be found").toBeGreaterThan(-1);
    return fe.slice(start, end);
  }

  it('unwraps d.results[0], not the top-level response, for the IOC branch', () => {
    const body = cdLookupBody();
    expect(body).toContain('d.results && d.results[0]');
    // The old buggy reads (as executable code, not this fix's explanatory
    // comment which necessarily mentions the old pattern by name).
    expect(body).not.toContain('= d.virustotal');
    expect(body).not.toContain('d.abuseipdb ?');
  });

  it('reads VirusTotal stats from the real nested raw_data.virustotal path', () => {
    const body = cdLookupBody();
    expect(body).toContain('res.raw_data && res.raw_data.virustotal');
  });

  it('reads the abuse score from the real top-level abuse_score field (a number), not a nested abuseipdb.abuse_confidence_score', () => {
    const body = cdLookupBody();
    expect(body).toContain('res.abuse_score');
    expect(body).not.toContain('abuse_confidence_score');
  });
});
