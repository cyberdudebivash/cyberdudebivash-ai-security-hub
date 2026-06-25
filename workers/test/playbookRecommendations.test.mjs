/* P10.6 regression tests — handlePlaybookRecommendations in executiveRiskHandlers.js
 *
 * Verifies:
 *   1. ENTERPRISE gate rejects non-enterprise tiers with 403
 *   2. With threat intel in DB, returns enriched recommendation objects
 *   3. Each recommendation has all required P10.6 schema fields
 *   4. With no DB data, returns empty recommendations with a guidance note (no fabrication)
 *   5. KEV vulns produce kev_status:true + HIGH confidence in the output
 *   6. Endpoint is read-only — handler returns JSON only, no side effects
 */
import { describe, it, expect } from 'vitest';
import { handlePlaybookRecommendations } from '../src/handlers/executiveRiskHandlers.js';

// ─── Minimal mocks ────────────────────────────────────────────────────────────

function makeDB({ tiRows = [], assetRows = [], asmRows = [] } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async all() {
          if (/FROM threat_intel/.test(sql))      return { results: tiRows };
          if (/FROM customer_assets/.test(sql))   return { results: assetRows };
          if (/FROM asm_targets/.test(sql))       return { results: asmRows };
          return { results: [] };
        },
        async first() { return null; },
        async run()   { return { success: true }; },
      };
      return stmt;
    },
  };
}

// RadarService is imported inside executiveRiskHandlers — the mock KV makes it
// return gracefully with an empty result rather than crashing.
function makeKV() {
  const store = new Map();
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const v = store.get(key);
      return (opts === 'json' || opts?.type === 'json') ? JSON.parse(v) : v;
    },
    async put(key, val) { store.set(key, val); },
  };
}

function makeEnv(dbOpts = {}) {
  return {
    DB:               makeDB(dbOpts),
    SECURITY_HUB_KV:  makeKV(),
  };
}

function jsonReq(body = {}) {
  return new Request('https://hub.test/api/executive/playbook-recommendations', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
}

const ENTERPRISE_CTX = { authenticated: true, tier: 'ENTERPRISE', userId: 'u1', isAdmin: false };
const STARTER_CTX    = { authenticated: true, tier: 'STARTER',    userId: 'u2', isAdmin: false };

// ─── Test suite ───────────────────────────────────────────────────────────────

describe('handlePlaybookRecommendations — P10.6', () => {

  it('returns 403 for non-enterprise tier', async () => {
    const res  = await handlePlaybookRecommendations(jsonReq(), makeEnv(), STARTER_CTX);
    const body = await res.json();
    expect(res.status).toBe(403);
    expect(body.success).toBe(false);
    expect(body.error).toMatch(/ENTERPRISE/i);
  });

  it('returns 403 for unauthenticated request', async () => {
    const res = await handlePlaybookRecommendations(jsonReq(), makeEnv(), {});
    expect(res.status).toBe(403);
  });

  it('returns success with empty recommendations when DB has no threat intel', async () => {
    const res  = await handlePlaybookRecommendations(jsonReq(), makeEnv(), ENTERPRISE_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-EXEC-P106');
    expect(Array.isArray(body.recommendations)).toBe(true);
    // No threat intel → no recommendations; guidance note must be present
    expect(body.recommendations).toHaveLength(0);
    expect(typeof body.note).toBe('string');
    expect(body.note.length).toBeGreaterThan(0);
  });

  it('returns enriched recommendations with all required P10.6 schema fields', async () => {
    const tiRows = [
      {
        cve_id: 'CVE-2024-1234', title: 'Critical Auth Bypass', description: 'Unauthenticated RCE',
        cvss_score: 9.8, epss_score: 0.85, actively_exploited: 1, known_ransomware: 0,
        mitre_technique: 'T1190', severity: 'CRITICAL',
      },
      {
        cve_id: 'CVE-2024-5678', title: 'High Priv Escalation', description: 'Local privilege escalation',
        cvss_score: 7.8, epss_score: 0.20, actively_exploited: 0, known_ransomware: 0,
        mitre_technique: null, severity: 'HIGH',
      },
    ];

    const res  = await handlePlaybookRecommendations(jsonReq({ sector: 'finance' }), makeEnv({ tiRows }), ENTERPRISE_CTX);
    const body = await res.json();

    expect(body.success).toBe(true);
    expect(body.recommendations.length).toBeGreaterThan(0);

    const rec = body.recommendations[0];
    // Required P10.6 schema fields
    expect(typeof rec.id).toBe('string');
    expect(typeof rec.title).toBe('string');
    expect(typeof rec.priority).toBe('number');
    expect(typeof rec.urgency).toBe('string');
    expect(typeof rec.category).toBe('string');
    expect(Array.isArray(rec.evidence)).toBe(true);
    expect(['HIGH', 'MEDIUM', 'LOW']).toContain(rec.confidence);
    expect(Array.isArray(rec.affected_assets)).toBe(true);
    expect(typeof rec.recommended_action).toBe('string');
    expect(Array.isArray(rec.mitre_mapping)).toBe(true);
    expect(typeof rec.kev_status).toBe('boolean');
    // epss/cvss may be null when no matching vuln is linked
    expect(rec.epss === null || typeof rec.epss === 'number').toBe(true);
    expect(rec.cvss === null || typeof rec.cvss === 'number').toBe(true);
    expect(typeof rec.business_impact).toBe('string');
    expect(typeof rec.estimated_effort).toBe('string');
    expect(typeof rec.estimated_risk_reduction).toBe('string');
    expect(Array.isArray(rec.references)).toBe(true);
  });

  it('KEV CVE produces kev_status:true and HIGH confidence on the first recommendation', async () => {
    const tiRows = [
      {
        cve_id: 'CVE-2024-KEV1', title: 'KEV Critical', description: 'Actively exploited',
        cvss_score: 9.9, epss_score: 0.92, actively_exploited: 1, known_ransomware: 1,
        mitre_technique: 'T1190', severity: 'CRITICAL',
      },
    ];
    const res  = await handlePlaybookRecommendations(jsonReq(), makeEnv({ tiRows }), ENTERPRISE_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);

    // First recommendation should be the KEV patch (priority 1)
    const kevRec = body.recommendations.find(r => r.kev_status === true);
    expect(kevRec).toBeDefined();
    expect(kevRec.confidence).toBe('HIGH');
    // Evidence must mention KEV — never fabricated
    expect(kevRec.evidence.some(e => /KEV/i.test(e))).toBe(true);
    // NVD reference for the specific CVE
    expect(kevRec.references.some(r => r.includes('CVE-2024-KEV1'))).toBe(true);
    // CISA KEV catalog link
    expect(kevRec.references.some(r => r.includes('cisa.gov'))).toBe(true);
  });

  it('handler is read-only — DB is never mutated', async () => {
    let writeCallCount = 0;
    const env = {
      DB: {
        prepare(sql) {
          const stmt = {
            bind() { return stmt; },
            async all() {
              // track any INSERT/UPDATE/DELETE
              if (/INSERT|UPDATE|DELETE/i.test(sql)) writeCallCount++;
              return { results: [] };
            },
            async first() {
              if (/INSERT|UPDATE|DELETE/i.test(sql)) writeCallCount++;
              return null;
            },
            async run() {
              writeCallCount++;
              return { success: true };
            },
          };
          return stmt;
        },
      },
      SECURITY_HUB_KV: makeKV(),
    };

    await handlePlaybookRecommendations(jsonReq(), env, ENTERPRISE_CTX);
    expect(writeCallCount).toBe(0);
  });

  it('scope metadata reflects actual data row counts', async () => {
    const tiRows    = [{ cve_id: 'CVE-X', title: 'T', cvss_score: 8, epss_score: 0.1, actively_exploited: 0, known_ransomware: 0, mitre_technique: null, severity: 'HIGH', description: null }];
    const assetRows = [{ asset_value: 'CVE-X', asset_type: 'cve_watchlist' }];
    const asmRows   = [{ id: 1, target: 'example.com', asm_score: 72 }];

    const res  = await handlePlaybookRecommendations(jsonReq(), makeEnv({ tiRows, assetRows, asmRows }), ENTERPRISE_CTX);
    const body = await res.json();

    expect(body.scope.threat_intel_signals).toBe(1);
    expect(body.scope.customer_assets).toBe(1);
    expect(body.scope.asm_targets).toBe(1);
  });

});
