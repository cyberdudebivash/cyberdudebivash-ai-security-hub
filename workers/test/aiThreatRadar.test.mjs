/* Tests — AI Threat Radar (dedicated, targeted AI/LLM ecosystem fetches: OSV.dev
 * batched watchlist lookup, rotated NVD keyword search, GitHub Advisory REST API).
 * Mocks global fetch per-source so no real network calls happen; verifies entry
 * mapping/severity normalization, cross-source dedup, per-source failure isolation,
 * and the KV status snapshot written for the radar health endpoint. */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  fetchOSVRadarSignals, fetchNVDRadarKeyword, fetchGitHubAdvisoryRadar,
  runAIThreatRadar, RADAR_STATUS_KV_KEY, AI_RADAR_PACKAGES,
} from '../src/services/aiThreatRadar.js';

// ── In-memory D1 (same convention as aiThreatIngestion.test.mjs) ───────────
function memDB() {
  const rows = new Map();
  const mk = (sql) => ({
    _sql: sql, _b: [],
    bind(...a) { this._b = a; return this; },
    async run() {
      if (/^\s*INSERT INTO ai_threat_feed/i.test(sql)) {
        const [id, feed_type, title, description, severity, cve_id,
          affected_frameworks, iocs, mitigations, owasp_ref, attack_ref, atlas_ref,
          source_url, published_at, metadata] = this._b;
        rows.set(id, { id, feed_type, title, description, severity, cve_id,
          affected_frameworks, iocs, mitigations, owasp_ref, attack_ref, atlas_ref,
          source_url, published_at, metadata });
      }
      return { success: true };
    },
  });
  return {
    rows,
    prepare(sql) { return mk(sql); },
    async batch(stmts) { for (const s of stmts) await s.run(); return stmts.map(() => ({ success: true })); },
  };
}

function memKV() {
  const store = new Map();
  return {
    store,
    async put(key, value, opts) { store.set(key, value); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
  };
}

const jsonRes = (body, ok = true) => ({
  ok, status: ok ? 200 : 500,
  json: async () => body,
});

beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
afterEach(() => { vi.unstubAllGlobals(); });

describe('fetchOSVRadarSignals', () => {
  it('batches the watchlist, fetches details for matched vuln IDs, and maps fields', async () => {
    global.fetch.mockImplementation(async (url, opts) => {
      if (url.includes('querybatch')) {
        return jsonRes({
          results: AI_RADAR_PACKAGES.map((p, i) =>
            i === 0 ? { vulns: [{ id: 'OSV-2024-1000', modified: '2024-06-01T00:00:00Z' }] } : {}),
        });
      }
      if (url.includes('/v1/vulns/OSV-2024-1000')) {
        return jsonRes({
          id: 'OSV-2024-1000',
          summary: 'LangChain SSRF via tool loader',
          details: 'A long description of the LangChain SSRF issue.',
          aliases: ['CVE-2024-9999'],
          affected: [{ package: { name: 'langchain' } }],
          references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }],
          database_specific: { severity: 'CRITICAL' },
          published: '2024-06-01T00:00:00Z',
        });
      }
      return jsonRes({}, false);
    });

    const entries = await fetchOSVRadarSignals();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      id: 'CVE-2024-9999',
      cve_id: 'CVE-2024-9999',
      severity: 'CRITICAL',
      source: 'osv',
      source_url: 'https://example.com/advisory',
      matched_on: ['langchain'],
    });
  });

  it('returns an empty array when the batch endpoint fails', async () => {
    global.fetch.mockResolvedValue(jsonRes({}, false));
    expect(await fetchOSVRadarSignals()).toEqual([]);
  });

  it('falls back to the OSV id and a default severity when alias/severity are missing', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('querybatch')) {
        return jsonRes({ results: [{ vulns: [{ id: 'OSV-2024-2000', modified: '2024-01-01T00:00:00Z' }] }] });
      }
      if (url.includes('/v1/vulns/OSV-2024-2000')) {
        return jsonRes({ id: 'OSV-2024-2000', summary: 'Unscored issue', affected: [] });
      }
      return jsonRes({}, false);
    });
    const entries = await fetchOSVRadarSignals();
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe('OSV-2024-2000');
    expect(entries[0].cve_id).toBeNull();
    expect(entries[0].severity).toBe('MEDIUM');
  });
});

describe('fetchNVDRadarKeyword', () => {
  it('maps NVD CVE records to radar entries with normalized severity', async () => {
    global.fetch.mockResolvedValue(jsonRes({
      vulnerabilities: [{
        cve: {
          id: 'CVE-2024-1111',
          descriptions: [{ lang: 'en', value: 'Prompt injection in an LLM agent framework.' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] },
          published: '2024-05-01T00:00:00.000',
        },
      }],
    }));

    const entries = await fetchNVDRadarKeyword();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      id: 'CVE-2024-1111', cve_id: 'CVE-2024-1111', severity: 'HIGH', source: 'nvd_radar',
    });
    expect(entries[0].matched_on).toHaveLength(1);
  });

  it('returns an empty array when the NVD request fails or has no results', async () => {
    global.fetch.mockResolvedValue(jsonRes({}, false));
    expect(await fetchNVDRadarKeyword()).toEqual([]);
  });

  it('defaults to MEDIUM severity when CVSS data is absent', async () => {
    global.fetch.mockResolvedValue(jsonRes({
      vulnerabilities: [{ cve: { id: 'CVE-2024-2222', descriptions: [], metrics: {} } }],
    }));
    const entries = await fetchNVDRadarKeyword();
    expect(entries[0].severity).toBe('MEDIUM');
  });
});

describe('fetchGitHubAdvisoryRadar', () => {
  it('queries pip and npm ecosystems and maps advisories', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('ecosystem=pip')) {
        return jsonRes([{
          cve_id: 'CVE-2024-3333', ghsa_id: 'GHSA-aaaa-bbbb-cccc',
          summary: 'transformers RCE via unsafe deserialization', severity: 'critical',
          description: 'Full description here.',
          html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
          published_at: '2024-04-01T00:00:00Z',
          vulnerabilities: [{ package: { name: 'transformers' } }],
        }]);
      }
      if (url.includes('ecosystem=npm')) {
        return jsonRes([]);
      }
      return jsonRes({}, false);
    });

    const entries = await fetchGitHubAdvisoryRadar();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      id: 'CVE-2024-3333', cve_id: 'CVE-2024-3333', severity: 'CRITICAL',
      source: 'github_advisory_api', matched_on: ['transformers'],
    });
  });

  it('falls back to the GHSA id when no CVE is assigned', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('ecosystem=pip')) {
        return jsonRes([{ ghsa_id: 'GHSA-no-cve', summary: 'No CVE yet', vulnerabilities: [] }]);
      }
      return jsonRes([]);
    });
    const entries = await fetchGitHubAdvisoryRadar();
    expect(entries[0].id).toBe('GHSA-no-cve');
    expect(entries[0].cve_id).toBeNull();
  });

  it('returns an empty array when both ecosystem queries fail', async () => {
    global.fetch.mockResolvedValue(jsonRes({}, false));
    expect(await fetchGitHubAdvisoryRadar()).toEqual([]);
  });
});

describe('runAIThreatRadar', () => {
  function mockAllSources() {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('querybatch')) {
        return jsonRes({ results: [{ vulns: [{ id: 'OSV-9000', modified: '2024-06-01T00:00:00Z' }] }] });
      }
      if (url.includes('/v1/vulns/OSV-9000')) {
        return jsonRes({
          id: 'OSV-9000', summary: 'LangChain SSRF', details: 'desc',
          aliases: ['CVE-2024-5000'], affected: [{ package: { name: 'langchain' } }],
          database_specific: { severity: 'HIGH' }, published: '2024-06-01T00:00:00Z',
        });
      }
      if (url.includes('services.nvd.nist.gov')) {
        return jsonRes({
          vulnerabilities: [{
            cve: {
              id: 'CVE-2024-6000',
              descriptions: [{ lang: 'en', value: 'An excessive agency flaw in an mcp server implementation.' }],
              metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'MEDIUM' } }] },
              published: '2024-05-01T00:00:00.000',
            },
          }],
        });
      }
      if (url.includes('api.github.com/advisories') && url.includes('ecosystem=pip')) {
        return jsonRes([{
          cve_id: 'CVE-2024-7000', ghsa_id: 'GHSA-radar-test',
          summary: 'mlflow path traversal', severity: 'high',
          html_url: 'https://github.com/advisories/GHSA-radar-test',
          published_at: '2024-03-01T00:00:00Z',
          vulnerabilities: [{ package: { name: 'mlflow' } }],
        }]);
      }
      if (url.includes('api.github.com/advisories') && url.includes('ecosystem=npm')) {
        return jsonRes([]);
      }
      return jsonRes({}, false);
    });
  }

  it('fans out to all three sources, dedupes, upserts, and writes a KV status snapshot', async () => {
    mockAllSources();
    const db = memDB();
    const kv = memKV();
    const env = { DB: db, SECURITY_HUB_KV: kv };

    const result = await runAIThreatRadar(env);

    expect(result.sources).toEqual({ osv: 1, nvd_radar: 1, github_advisory_api: 1 });
    expect(result.matched).toBe(3);
    expect(result.inserted).toBe(3);
    expect(result.errors).toHaveLength(0);

    expect(db.rows.has('ai_CVE-2024-5000')).toBe(true);
    expect(db.rows.has('ai_CVE-2024-6000')).toBe(true);
    expect(db.rows.has('ai_CVE-2024-7000')).toBe(true);

    const stored = db.rows.get('ai_CVE-2024-6000');
    expect(stored.feed_type).toBe('agent_threat');

    const status = JSON.parse(await kv.get(RADAR_STATUS_KV_KEY));
    expect(status.signals_found).toBe(3);
    expect(status.signals_inserted).toBe(3);
    expect(status.packages_watched).toBe(AI_RADAR_PACKAGES.length);
    expect(status.source_breakdown).toEqual({ osv: 1, nvd_radar: 1, github_advisory_api: 1 });
  });

  it('isolates a single-source failure (network error swallowed by the per-source fetch wrapper) so the other sources still write through', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('querybatch')) throw new Error('OSV network failure');
      if (url.includes('services.nvd.nist.gov')) {
        return jsonRes({
          vulnerabilities: [{
            cve: {
              id: 'CVE-2024-8000',
              descriptions: [{ lang: 'en', value: 'A PyTorch deserialization vulnerability.' }],
              metrics: {},
              published: '2024-05-01T00:00:00.000',
            },
          }],
        });
      }
      return jsonRes([]);
    });

    const env = { DB: memDB(), SECURITY_HUB_KV: memKV() };
    const result = await runAIThreatRadar(env);

    expect(result.sources.osv).toBe(0);
    expect(result.sources.nvd_radar).toBe(1);
    expect(result.matched).toBe(1);
    expect(result.inserted).toBe(1);
  });

  it('records a source error and continues when a source runner itself throws (malformed upstream payload)', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('querybatch')) return jsonRes({});
      // `vulnerabilities` truthy but non-array makes fetchNVDRadarKeyword's
      // .map() throw past safeFetchJSON's network-level try/catch.
      if (url.includes('services.nvd.nist.gov')) return jsonRes({ vulnerabilities: 'not-an-array' });
      if (url.includes('api.github.com/advisories') && url.includes('ecosystem=pip')) {
        return jsonRes([{
          cve_id: 'CVE-2024-7777', ghsa_id: 'GHSA-still-fine',
          summary: 'gradio XSS', severity: 'medium',
          vulnerabilities: [{ package: { name: 'gradio' } }],
        }]);
      }
      return jsonRes([]);
    });

    const env = { DB: memDB(), SECURITY_HUB_KV: memKV() };
    const result = await runAIThreatRadar(env);

    expect(result.sources.nvd_radar).toBe(0);
    expect(result.errors.some(e => e.startsWith('nvd_radar:'))).toBe(true);
    expect(result.sources.github_advisory_api).toBe(1);
    expect(result.matched).toBe(1);
    expect(result.inserted).toBe(1);
    expect(env.DB.rows.has('ai_CVE-2024-7777')).toBe(true);
  });

  it('is a no-op with no DB binding', async () => {
    mockAllSources();
    const result = await runAIThreatRadar({});
    expect(result).toEqual({ matched: 0, inserted: 0, sources: {}, errors: [] });
  });

  it('dedupes the same underlying CVE reported by two sources, keeping one row', async () => {
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('querybatch')) {
        return jsonRes({ results: [{ vulns: [{ id: 'OSV-DUP', modified: '2024-06-01T00:00:00Z' }] }] });
      }
      if (url.includes('/v1/vulns/OSV-DUP')) {
        return jsonRes({
          id: 'OSV-DUP', summary: 'Duplicate-sourced issue', aliases: ['CVE-2024-9090'],
          affected: [{ package: { name: 'torch' } }], database_specific: { severity: 'LOW' },
          published: '2024-06-01T00:00:00Z',
        });
      }
      if (url.includes('api.github.com/advisories') && url.includes('ecosystem=pip')) {
        return jsonRes([{
          cve_id: 'CVE-2024-9090', ghsa_id: 'GHSA-dup-dup',
          summary: 'Duplicate-sourced issue (GHSA copy)', severity: 'critical',
          vulnerabilities: [{ package: { name: 'torch' } }],
        }]);
      }
      return jsonRes([]);
    });

    const db = memDB();
    const result = await runAIThreatRadar({ DB: db, SECURITY_HUB_KV: memKV() });

    expect(result.matched).toBe(1);
    expect(db.rows.size).toBe(1);
    expect(db.rows.has('ai_CVE-2024-9090')).toBe(true);
  });
});
