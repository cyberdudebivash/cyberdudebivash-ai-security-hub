/* Tests — AI threat feed handler's `type` query-param normalization and merge of
 * live ai_threat_feed rows (written by services/aiThreatIngestion.js) into the
 * curated library response. Regression coverage for the type/feed_type vocabulary
 * mismatch: the public `type` param (prompt_attacks | agent_threats | ai_cves |
 * model_advisories) must map onto the real feed_type enum stored in D1
 * (prompt_attack | agent_threat | vulnerability | advisory), and matching rows
 * must actually appear in the response arrays the frontend reads from. */
import { describe, it, expect, vi } from 'vitest';
import { handleAIThreatFeed, handleAIThreatRadarScanNow } from '../src/handlers/aiThreatIntel.js';
import * as aiThreatRadar from '../src/services/aiThreatRadar.js';

function memDB(seedRows = []) {
  const rows = seedRows;
  return {
    prepare(sql) {
      return {
        _sql: sql, _b: [],
        bind(...a) { this._b = a; return this; },
        async all() {
          if (/WHERE feed_type=\?/i.test(this._sql)) {
            const [feedType] = this._b;
            return { results: rows.filter(r => r.feed_type === feedType) };
          }
          return { results: rows };
        },
      };
    },
  };
}

const LIVE_AGENT_ROW = {
  id: 'ai_GHSA-test-0001', feed_type: 'agent_threat', title: 'MCP server tool permission flaw',
  description: 'Excessive agency in an MCP server implementation.', severity: 'HIGH',
  cve_id: null, affected_models: '[]', affected_frameworks: '["mcp server"]',
  mitigations: '[]', owasp_ref: 'LLM06', source_url: 'https://github.com/advisories/GHSA-test-0001',
  published_at: 1700000000,
};

const LIVE_VULN_ROW = {
  id: 'ai_CVE-2024-5184', feed_type: 'vulnerability', title: 'Embedchain RAG Framework SSRF',
  description: 'SSRF via RAG pipeline.', severity: 'CRITICAL', cve_id: 'CVE-2024-5184',
  affected_models: '[]', affected_frameworks: '["embedchain"]', mitigations: '[]',
  owasp_ref: null, attack_ref: 'T1190', atlas_ref: 'AML.T0051',
  source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-5184', published_at: 1700000001,
};

const LIVE_ADVISORY_ROW = {
  id: 'ai_GHSA-test-0002', feed_type: 'advisory', title: 'Ollama model loading advisory',
  description: 'Advisory for ollama.', severity: 'MEDIUM', cve_id: null, affected_models: '[]',
  affected_frameworks: '["ollama"]', mitigations: '[]', owasp_ref: null,
  source_url: 'https://github.com/advisories/GHSA-test-0002', published_at: 1700000002,
};

function req(qs) { return { url: `https://x.test/api/ai-security/threat-feed${qs}` }; }

describe('handleAIThreatFeed type normalization', () => {
  it('maps type=agent_threats to feed_type=agent_threat and merges the live row into agent_threats', async () => {
    const env = { DB: memDB([LIVE_AGENT_ROW]) };
    const res = await handleAIThreatFeed(req('?type=agent_threats'), env);
    const body = await res.json();
    const live = body.agent_threats.find(t => t.id === 'ai_GHSA-test-0001');
    expect(live).toBeDefined();
    expect(live.live).toBe(true);
    expect(live.name).toBe('MCP server tool permission flaw');
    expect(body.prompt_attack_patterns).toHaveLength(0);
    expect(body.ai_vulnerabilities).toHaveLength(0);
  });

  it('maps type=ai_cves to feed_type=vulnerability and merges the live row into ai_vulnerabilities', async () => {
    const env = { DB: memDB([LIVE_VULN_ROW]) };
    const res = await handleAIThreatFeed(req('?type=ai_cves'), env);
    const body = await res.json();
    const live = body.ai_vulnerabilities.find(t => t.id === 'ai_CVE-2024-5184');
    expect(live).toBeDefined();
    expect(live.cve_id).toBe('CVE-2024-5184');
    expect(live.attack_ref).toBe('T1190');
    expect(live.atlas_ref).toBe('AML.T0051');
    expect(body.agent_threats).toHaveLength(0);
  });

  it('maps type=model_advisories to feed_type=advisory and merges into ai_vulnerabilities', async () => {
    const env = { DB: memDB([LIVE_ADVISORY_ROW]) };
    const res = await handleAIThreatFeed(req('?type=model_advisories'), env);
    const body = await res.json();
    expect(body.ai_vulnerabilities.find(t => t.id === 'ai_GHSA-test-0002')).toBeDefined();
  });

  it('does not leak an agent_threat row into a prompt_attacks-filtered response', async () => {
    const env = { DB: memDB([LIVE_AGENT_ROW]) };
    const res = await handleAIThreatFeed(req('?type=prompt_attacks'), env);
    const body = await res.json();
    expect(body.prompt_attack_patterns.find(t => t.id === 'ai_GHSA-test-0001')).toBeUndefined();
  });

  it('with no type param, returns curated + all live rows merged across buckets', async () => {
    const env = { DB: memDB([LIVE_AGENT_ROW, LIVE_VULN_ROW, LIVE_ADVISORY_ROW]) };
    const res = await handleAIThreatFeed(req(''), env);
    const body = await res.json();
    expect(body.agent_threats.some(t => t.id === 'ai_GHSA-test-0001')).toBe(true);
    expect(body.ai_vulnerabilities.some(t => t.id === 'ai_CVE-2024-5184')).toBe(true);
    expect(body.ai_vulnerabilities.some(t => t.id === 'ai_GHSA-test-0002')).toBe(true);
  });
});

describe('handleAIThreatRadarScanNow', () => {
  it('rejects a non-admin caller with 403 and does not run the radar', async () => {
    const spy = vi.spyOn(aiThreatRadar, 'runAIThreatRadar').mockResolvedValue({ matched: 0, inserted: 0, sources: {}, errors: [] });
    const env = { DB: {}, SECURITY_HUB_KV: {} };
    const res = await handleAIThreatRadarScanNow({}, env, { isAdmin: false });
    expect(res.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('rejects an anonymous caller (no authCtx) with 403', async () => {
    const spy = vi.spyOn(aiThreatRadar, 'runAIThreatRadar').mockResolvedValue({ matched: 0, inserted: 0, sources: {}, errors: [] });
    const res = await handleAIThreatRadarScanNow({}, {}, null);
    expect(res.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('runs the radar for an admin caller and returns its result merged with success/triggered_at', async () => {
    const fakeResult = { matched: 3, inserted: 3, sources: { osv: 1, nvd_radar: 1, github_advisory_api: 1 }, errors: [] };
    const spy = vi.spyOn(aiThreatRadar, 'runAIThreatRadar').mockResolvedValue(fakeResult);
    const env = { DB: {}, SECURITY_HUB_KV: {} };
    const res = await handleAIThreatRadarScanNow({}, env, { isAdmin: true });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(spy).toHaveBeenCalledWith(env);
    expect(body.success).toBe(true);
    expect(typeof body.triggered_at).toBe('string');
    expect(body.matched).toBe(3);
    expect(body.inserted).toBe(3);
    expect(body.sources).toEqual(fakeResult.sources);
    spy.mockRestore();
  });
});
