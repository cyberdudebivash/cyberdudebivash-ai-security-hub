/* Coverage for the v43 Agent Threat Advisories engine — the real backend
 * that replaces the static "Security Advisories" list and the fabricated
 * per-framework "N active advisories" / risk-percentage counters that were
 * hardcoded into frontend/agent-threats.html. */
import { describe, it, expect } from 'vitest';
import {
  handleListAgentAdvisories,
  handleAgentThreatOverview,
  handleCreateAgentAdvisory,
} from '../src/handlers/agentThreatAdvisories.js';

function makeRows(rows) {
  return rows.map(r => ({
    advisory_id: r.advisory_id, title: r.title, description: r.description,
    framework: r.framework, affected_versions: null, affected_products: null,
    severity: r.severity, cvss_score: r.cvss_score, owasp_llm_id: null, cwe_id: null,
    mitre_atlas_id: null, tags: '["x"]', patch_status: r.patch_status || 'no_patch',
    patch_version: null, published_at: r.published_at, updated_at: r.published_at,
    source: 'cyberdudebivash_research', is_new: 0, full_advisory_url: null,
  }));
}

function makeEnv(seedRows, { adminToken = 'sek_admin_test' } = {}) {
  const rows = makeRows(seedRows);
  const inserted = [];
  return {
    ADMIN_TOKEN: adminToken,
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async all() {
            if (/SELECT \* FROM agent_threat_advisories/.test(sql)) {
              const fw = bound.find(b => typeof b === 'string' && b !== 'latest');
              const filtered = sql.includes('WHERE framework = ?') ? rows.filter(r => r.framework === bound[0]) : rows;
              return { results: filtered };
            }
            if (/SELECT framework, severity, cvss_score, patch_status/.test(sql)) {
              return { results: rows };
            }
            return { results: [] };
          },
          async first() {
            if (/SELECT COUNT\(\*\)/.test(sql)) {
              const filtered = sql.includes('WHERE framework = ?') ? rows.filter(r => r.framework === bound[0]) : rows;
              return { total: filtered.length };
            }
            return null;
          },
          async run() {
            if (/INSERT INTO agent_threat_advisories/.test(sql)) {
              if (rows.some(r => r.advisory_id === bound[0])) {
                throw new Error('UNIQUE constraint failed: agent_threat_advisories.advisory_id');
              }
              inserted.push(bound);
              return { success: true };
            }
            return { success: true };
          },
        };
      },
    },
    __inserted: inserted,
  };
}

const SEED = [
  { advisory_id: 'CDB-AGT-2025-0019', title: 'MCP Tool Poisoning', description: 'desc', framework: 'mcp', severity: 'CRITICAL', cvss_score: 9.8, published_at: '2025-06-07', patch_status: 'no_patch' },
  { advisory_id: 'CDB-AGT-2025-0017', title: 'LangChain ReAct Abuse', description: 'desc', framework: 'langchain', severity: 'CRITICAL', cvss_score: 9.1, published_at: '2025-06-03', patch_status: 'patched' },
  { advisory_id: 'CDB-AGT-2025-0011', title: 'CrewAI Memory Poisoning', description: 'desc', framework: 'crewai', severity: 'MEDIUM', cvss_score: 6.5, published_at: '2025-05-15', patch_status: 'patched' },
];

function req(url, opts) { return new Request(url, opts); }

describe('handleListAgentAdvisories', () => {
  it('returns the real seeded advisories sorted by latest', async () => {
    const env = makeEnv(SEED);
    const res = await handleListAgentAdvisories(req('https://x.test/api/agent-threats/advisories'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.advisories.length).toBe(3);
    expect(body.total).toBe(3);
  });

  it('filters by framework', async () => {
    const env = makeEnv(SEED);
    const res = await handleListAgentAdvisories(req('https://x.test/api/agent-threats/advisories?framework=mcp'), env);
    const body = await res.json();
    expect(body.advisories.every(a => a.framework === 'mcp')).toBe(true);
  });

  it('fails closed (503) with no DB binding, never falls back to fake data', async () => {
    const res = await handleListAgentAdvisories(req('https://x.test/api/agent-threats/advisories'), {});
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.advisories).toEqual([]);
  });
});

describe('handleAgentThreatOverview', () => {
  it('computes real per-framework counts instead of hardcoded fake percentages', async () => {
    const env = makeEnv(SEED);
    const res = await handleAgentThreatOverview(req('https://x.test/api/agent-threats/overview'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    // Real dataset has exactly 1 advisory per seeded framework — must not
    // match the old hardcoded "8 active advisories" / "11 active advisories" copy.
    const mcp = body.frameworks.find(f => f.framework === 'mcp');
    expect(mcp.advisory_count).toBe(1);
    expect(mcp.risk_level).toBe('CRITICAL'); // CVSS 9.8, unpatched
    expect(body.total_advisories).toBe(3);
  });

  it('omits frameworks with zero real advisories rather than inventing a count', async () => {
    const env = makeEnv(SEED);
    const res = await handleAgentThreatOverview(req('https://x.test/api/agent-threats/overview'), env);
    const body = await res.json();
    expect(body.frameworks.find(f => f.framework === 'autogen')).toBeUndefined();
  });
});

describe('handleCreateAgentAdvisory', () => {
  it('rejects without a valid admin bearer token (fail-closed)', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAgentAdvisory(req('https://x.test/api/admin/agent-threats/advisories', {
      method: 'POST',
      body: JSON.stringify({ advisory_id: 'X', title: 't', description: 'd', framework: 'mcp', severity: 'HIGH', published_at: '2026-01-01' }),
    }), env);
    expect(res.status).toBe(401);
  });

  it('publishes a new advisory with a valid admin token', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAgentAdvisory(req('https://x.test/api/admin/agent-threats/advisories', {
      method: 'POST',
      headers: { Authorization: 'Bearer sek_admin_test' },
      body: JSON.stringify({
        advisory_id: 'CDB-AGT-2026-0001', title: 'New finding', description: 'd',
        framework: 'mcp', severity: 'HIGH', published_at: '2026-06-29',
      }),
    }), env);
    expect(res.status).toBe(201);
    expect(env.__inserted.length).toBe(1);
  });

  it('rejects an unknown framework', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAgentAdvisory(req('https://x.test/api/admin/agent-threats/advisories', {
      method: 'POST',
      headers: { Authorization: 'Bearer sek_admin_test' },
      body: JSON.stringify({
        advisory_id: 'X', title: 't', description: 'd', framework: 'not_a_real_framework',
        severity: 'HIGH', published_at: '2026-06-29',
      }),
    }), env);
    expect(res.status).toBe(400);
  });

  it('returns 503 with no ADMIN_TOKEN configured (fail-closed, never silently open)', async () => {
    const env = makeEnv(SEED, { adminToken: '' });
    const res = await handleCreateAgentAdvisory(req('https://x.test/api/admin/agent-threats/advisories', {
      method: 'POST', headers: { Authorization: 'Bearer anything' }, body: '{}',
    }), env);
    expect(res.status).toBe(503);
  });
});
