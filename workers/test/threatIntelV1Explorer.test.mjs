// CAP-TIH-002 — the last item in the owner-directed 3-item dashboard cluster
// (CAP-TIH-009, CAP-TIH-014, CAP-TIH-002). Five real, DB-backed, tier-gated
// backend routes had zero frontend caller: GET /api/v1/iocs (ENTERPRISE),
// GET /api/v1/correlations (PRO/ENTERPRISE), GET /api/v1/graph (PRO/ENTERPRISE),
// GET /api/v1/hunting (PRO/ENTERPRISE), POST /api/threat-intel/ingest
// (PRO/ENTERPRISE manual re-ingestion trigger).
//
// IMPORTANT DESIGN CONSTRAINT verified here, not assumed: every /api/v1/*
// route requires a real API key (x-api-key: cdb_*) — workers/src/index.js's
// own v1 block rejects any caller whose authCtx.method !== 'api_key' with
// ERR_API_KEY_REQUIRED, *before* the PRO/ENTERPRISE tier check even runs. A
// dashboard session (Bearer JWT via apiFetch(), the pattern used for
// CAP-TIH-009/CAP-TIH-014's tabs) can never satisfy this. So the new "API
// Explorer" tab in user-dashboard.html deliberately does NOT reuse apiFetch()
// — it collects the customer's own previously-issued API key and calls these
// endpoints directly with x-api-key, the only mechanism that actually works.
//
// Also verified here, not assumed: the shared ok()/fail() response helpers
// wrap all payloads in a {success, data, error, timestamp} envelope — the
// actual fields (iocs, correlation, graph, alerts, ingestion) live one level
// deeper, under .data. The dashboard's new functions unwrap accordingly.
//
// Naming note: this domain has multiple parallel, unreconciled implementations
// of "hunting"/"graph"/"correlation" (see the CAP-TIH-002 registry entry's
// notes). The new tab deliberately avoids the names "Threat Hunting" and
// "Threat Graph" (already used by CAP-TIH-001's page and the dashboard's own
// client-side tab) to avoid presenting two same-named, unrelated features.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import worker from '../src/index.js';

const {
  handleV1IOCs, handleV1Correlations, handleV1Graph, handleV1Hunting, handleManualIngest,
} = await import('../src/handlers/threatIntel.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function req(url, opts) { return new Request(url, opts); }

function statement(sql, table) {
  return {
    _args: [],
    bind(...a) { this._args = a; return this; },
    async all() { return table.all ? table.all(sql, this._args) : { results: [] }; },
    async first() { return table.first ? table.first(sql, this._args) : null; },
    async run() { return { success: true }; },
  };
}

describe('CAP-TIH-002 backend — real tier gates on all 5 previously-unwired handlers', () => {
  it('handleV1IOCs requires ENTERPRISE (PRO is not enough)', async () => {
    const res = await handleV1IOCs(req('https://x/api/v1/iocs'), {}, { tier: 'PRO' });
    expect(res.status).toBe(403);
  });
  it('handleV1Correlations requires PRO or ENTERPRISE', async () => {
    const res = await handleV1Correlations(req('https://x/api/v1/correlations'), {}, { tier: 'STARTER' });
    expect(res.status).toBe(403);
  });
  it('handleV1Graph requires PRO or ENTERPRISE', async () => {
    const res = await handleV1Graph(req('https://x/api/v1/graph'), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });
  it('handleV1Hunting requires PRO or ENTERPRISE', async () => {
    const res = await handleV1Hunting(req('https://x/api/v1/hunting'), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });
  it('handleManualIngest requires PRO or ENTERPRISE', async () => {
    const res = await handleManualIngest(req('https://x/api/threat-intel/ingest', { method: 'POST' }), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });
});

describe('CAP-TIH-002 backend — real, non-fabricated data for authorized callers', () => {
  it('handleV1IOCs returns real DB rows wrapped in the {success,data} envelope', async () => {
    const env = {
      SECURITY_HUB_DB: {
        prepare(sql) {
          return statement(sql, {
            all: () => ({ results: [{ id: 'ioc1', type: 'ip', value: '198.51.100.7', confidence: 0.9, severity: 'HIGH', intel_title: 'Test CVE' }] }),
            first: () => ({ n: 1 }),
          });
        },
      },
    };
    const res = await handleV1IOCs(req('https://x/api/v1/iocs'), env, { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.iocs).toHaveLength(1);
    expect(body.data.iocs[0].value).toBe('198.51.100.7');
    expect(body.data.total).toBe(1);
  });

  it('handleV1Correlations returns an honest empty summary when the feed has nothing correlatable (seed fallback, no fabrication)', async () => {
    const env = { SECURITY_HUB_DB: { prepare(sql) { return statement(sql, { all: () => ({ results: [] }) }); } } };
    const res = await handleV1Correlations(req('https://x/api/v1/correlations'), env, { tier: 'PRO' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data.correlations)).toBe(true);
    expect(body.data.summary).toBeTruthy();
  });

  it('handleV1Correlations 404s honestly for a CVE ID not present in the feed', async () => {
    const env = { SECURITY_HUB_DB: { prepare(sql) { return statement(sql, { all: () => ({ results: [] }) }); } } };
    const res = await handleV1Correlations(req('https://x/api/v1/correlations?cve=CVE-1999-0001'), env, { tier: 'PRO' });
    expect(res.status).toBe(404);
  });

  it('handleV1Graph returns an honest empty graph when env.DB is unavailable (no fabricated nodes)', async () => {
    const res = await handleV1Graph(req('https://x/api/v1/graph'), {}, { tier: 'PRO' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.graph.nodes).toEqual([]);
  });

  it('handleV1Graph builds real nodes from real D1 rows', async () => {
    const env = {
      DB: {
        prepare(sql) {
          return statement(sql, {
            all: () => /FROM threat_intel/.test(sql)
              ? { results: [{ id: 'CVE-2026-5555', title: 'Test', severity: 'CRITICAL', cvss: 9.8, exploit_status: 'confirmed', known_ransomware: 0, ioc_list: '[]', epss_score: 0.5 }] }
              : { results: [] },
          });
        },
      },
    };
    const res = await handleV1Graph(req('https://x/api/v1/graph'), env, { tier: 'PRO' });
    const body = await res.json();
    expect(body.data.graph.nodes.length).toBeGreaterThan(0);
    expect(body.data.graph.nodes.some(n => n.value === 'CVE-2026-5555')).toBe(true);
  });

  it('handleV1Hunting returns real risk_posture/hunting_summary structure (seed fallback when DB empty)', async () => {
    const env = { SECURITY_HUB_DB: { prepare(sql) { return statement(sql, { all: () => ({ results: [] }) }); } } };
    const res = await handleV1Hunting(req('https://x/api/v1/hunting'), env, { tier: 'PRO' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.hunting_summary).toBeTruthy();
    expect(Array.isArray(body.data.alerts)).toBe(true);
  });
});

describe('CAP-TIH-002 backend — manual ingest trigger (real pipeline, network stubbed)', () => {
  const realFetch = global.fetch;
  beforeEach(() => {
    global.fetch = vi.fn(async () => ({ ok: false, status: 503, headers: { get: () => '' } }));
  });
  afterEach(() => { global.fetch = realFetch; });

  it('runs the real ingestion pipeline and reports real source/error metadata (no live network reached)', async () => {
    const env = { SECURITY_HUB_KV: { get: async () => null, put: async () => {}, delete: async () => {} } };
    const res = await handleManualIngest(req('https://x/api/threat-intel/ingest', { method: 'POST' }), env, { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.ingestion.sources).toContain('seed');
    expect(global.fetch).toHaveBeenCalled();
  });
});

describe('CAP-TIH-002 router — /api/v1/* genuinely requires an API key, confirming the dashboard cannot use session auth', () => {
  function genericEnv() {
    return {
      DB: { prepare() { return { bind() { return this; }, async first() { return null; }, async all() { return { results: [] }; } }; } },
      SECURITY_HUB_DB: { prepare() { return { bind() { return this; }, async first() { return null; }, async all() { return { results: [] }; } }; } },
      KV: { get: async () => null, put: async () => {} },
      SECURITY_HUB_KV: { get: async () => null, put: async () => {} },
    };
  }
  function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }

  for (const path of ['/api/v1/iocs', '/api/v1/correlations', '/api/v1/graph', '/api/v1/hunting']) {
    it(`GET ${path} rejects a plain unauthenticated request with ERR_API_KEY_REQUIRED`, async () => {
      const res = await worker.fetch(req(`https://x${path}`), genericEnv(), ctxStub());
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.code).toBe('ERR_API_KEY_REQUIRED');
    });
  }
});

describe('user-dashboard.html — API Explorer tab (CAP-TIH-002)', () => {
  it('has a real nav-item, in the Developer section', () => {
    expect(dash).toContain(`data-page="v1-explorer" onclick="showPage('v1-explorer',this)"`);
  });

  it('does not reuse the "Threat Hunting" or "Threat Graph" names already used elsewhere on this platform', () => {
    const start = dash.indexOf('id="page-v1-explorer"');
    const section = dash.slice(start, start + 6000);
    expect(section).toContain('Automated Hunting Alerts');
    expect(section).toContain('Intel Graph Neighborhood');
    expect(section).not.toMatch(/>\s*Threat Hunting\s*</);
    expect(section).not.toMatch(/>\s*Threat Graph\s*</);
  });

  it('uses a dedicated x-api-key fetch helper, not the session-cookie apiFetch() used by other tabs', () => {
    const fn = dash.slice(dash.indexOf('async function v1ApiFetch'), dash.indexOf('function v1ErrorLine'));
    expect(fn).toContain("'x-api-key': key");
    expect(fn).not.toContain('Authorization');
  });

  it('every tool calls its real v1/ingest endpoint', () => {
    expect(dash).toContain('`/api/v1/iocs?${qs}`');
    expect(dash).toContain('`/api/v1/correlations${qs}`');
    expect(dash).toContain('`/api/v1/graph${qs}`');
    expect(dash).toContain('`/api/v1/hunting?min_severity=${encodeURIComponent(minSev)}`');
    expect(dash).toContain(`v1ApiFetch('/api/threat-intel/ingest', { method: 'POST' })`);
  });

  it('unwraps the real {success,data,error} envelope rather than reading flat fields (regression guard for the envelope-shape bug)', () => {
    for (const fnName of ['v1QueryIOCs', 'v1QueryCorrelations', 'v1QueryGraph', 'v1RunHunting']) {
      const start = dash.indexOf(`async function ${fnName}`);
      expect(start, `${fnName} not found`).toBeGreaterThan(-1);
      const fn = dash.slice(start, dash.indexOf('\n  }', start) + 4);
      expect(fn, `${fnName} should unwrap data.data`).toContain('data.data');
    }
    const refreshStart = dash.indexOf('async function v1RefreshFeed');
    const refreshFn = dash.slice(refreshStart, dash.indexOf('\n  }', refreshStart) + 4);
    expect(refreshFn).toContain('data.data?.ingestion');
  });

  it('the existing Threat Intel API and Intelligence Preview tabs are untouched', () => {
    expect(dash).toContain(`data-page="intel-api" onclick="showPage('intel-api',this);loadIntelAPIStatus()"`);
    expect(dash).toContain(`data-page="intel-preview" onclick="showPage('intel-preview',this);intelPreviewFeatured()"`);
  });
});
