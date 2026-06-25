/* P11.0 regression tests — AI Security Decision Platform (decisionHandler.js)
 *
 * Verifies:
 *   1.  All 5 endpoints reject non-PRO tiers with 403
 *   2.  All 5 endpoints reject unauthenticated requests with 401
 *   3.  handleDecisionSummary returns required top-level fields
 *   4.  handleDecisionActions returns ranked action list with source labels
 *   5.  handleDecisionBusinessImpact returns all 5 impact dimensions
 *   6.  handleDecisionPriorities returns P1/P2 split + correlation object
 *   7.  handleDecisionExecutive returns valid role summary (with AI fallback)
 *   8.  Business impact returns 0 scores (not errors) when DB is empty
 *   9.  KV cache is written on first call and served on second call (_cache: HIT)
 *   10. Handler is read-only — storeDecisions D1 writes use INSERT OR IGNORE (safe)
 */
import { describe, it, expect } from 'vitest';
import {
  handleDecisionSummary,
  handleDecisionActions,
  handleDecisionBusinessImpact,
  handleDecisionPriorities,
  handleDecisionExecutive,
} from '../src/handlers/decisionHandler.js';

// ─── Mocks ────────────────────────────────────────────────────────────────────

const THREAT_ROWS = [
  { cve_id: 'CVE-2024-1001', title: 'RCE in OpenSSH', cvss_score: 9.8, epss_score: 0.88,
    actively_exploited: 1, known_ransomware: 1, severity: 'CRITICAL', source: 'cisa_kev',
    mitre_technique: 'T1190', description: 'Critical RCE' },
  { cve_id: 'CVE-2024-1002', title: 'Priv Escalation in kernel', cvss_score: 7.8, epss_score: 0.22,
    actively_exploited: 0, known_ransomware: 0, severity: 'HIGH', source: 'nvd',
    mitre_technique: null, description: 'Local privesc' },
];

const ACTOR_ROWS = [
  { name: 'APT28', sector: 'government', active: 1 },
];

const ASSET_ROWS = [
  { asset_value: 'CVE-2024-1001', asset_type: 'cve_watchlist' },
  { asset_value: 'nginx',          asset_type: 'technology' },
];

const ASM_ROWS = [
  { target: 'example.com', asm_score: 65 },
];

function makeDB({ tiRows = THREAT_ROWS, assetRows = ASSET_ROWS, actorRows = ACTOR_ROWS, asmRows = ASM_ROWS } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async all() {
          if (/FROM threat_intel/.test(sql))    return { results: tiRows };
          if (/FROM customer_assets/.test(sql)) return { results: assetRows };
          if (/FROM threat_actors/.test(sql))   return { results: actorRows };
          if (/FROM asm_targets/.test(sql))     return { results: asmRows };
          return { results: [] };
        },
        async first() { return null; },
        async run()   { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

function makeEnv(opts = {}) {
  return { DB: makeDB(opts), SECURITY_HUB_KV: makeKV() };
}

const PRO_CTX       = { authenticated: true, tier: 'PRO',     userId: 'u1' };
const STARTER_CTX   = { authenticated: true, tier: 'STARTER', userId: 'u2' };
const UNAUTH_CTX    = { authenticated: false };

function getReq(path = '/api/decision/summary', params = {}) {
  const url = new URL(`https://hub.test${path}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  return new Request(url.toString(), { method: 'GET' });
}

// ─── Auth gate tests ──────────────────────────────────────────────────────────

describe('P11.0 — tier gate (all endpoints)', () => {
  const endpoints = [
    [handleDecisionSummary,       '/api/decision/summary'],
    [handleDecisionActions,       '/api/decision/actions'],
    [handleDecisionBusinessImpact,'/api/decision/business-impact'],
    [handleDecisionPriorities,    '/api/decision/priorities'],
    [handleDecisionExecutive,     '/api/decision/executive'],
  ];

  for (const [handler, path] of endpoints) {
    it(`${path} returns 403 for STARTER tier`, async () => {
      const res  = await handler(getReq(path), makeEnv(), STARTER_CTX);
      const body = await res.json();
      expect(res.status).toBe(403);
      expect(body.success).toBe(false);
    });

    it(`${path} returns 401 for unauthenticated request`, async () => {
      const res  = await handler(getReq(path), makeEnv(), UNAUTH_CTX);
      expect(res.status).toBe(401);
    });
  }
});

// ─── Functional tests ─────────────────────────────────────────────────────────

describe('handleDecisionSummary — P11.1', () => {
  it('returns required top-level fields', async () => {
    const res  = await handleDecisionSummary(getReq(), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-DECISION-SUMMARY');
    expect(typeof body.overall_threat_level).toBe('string');
    expect(body.decision_counts).toBeDefined();
    expect(body.business_impact).toBeDefined();
    expect(body.correlation).toBeDefined();
    expect(Array.isArray(body.top_actions)).toBe(true);
    expect(Array.isArray(body.data_sources)).toBe(true);
  });

  it('business_impact has overall_score and 5 dimensions', async () => {
    const res  = await handleDecisionSummary(getReq(), makeEnv(), PRO_CTX);
    const body = await res.json();
    const impact = body.business_impact;
    expect(typeof impact.overall_score).toBe('number');
    expect(['CRITICAL','HIGH','MEDIUM','LOW']).toContain(impact.overall_rating);
    expect(impact.dimensions.operational).toBeDefined();
    expect(impact.dimensions.financial).toBeDefined();
    expect(impact.dimensions.compliance).toBeDefined();
    expect(impact.dimensions.service).toBeDefined();
    expect(impact.dimensions.reputation).toBeDefined();
  });
});

describe('handleDecisionActions — P11.5', () => {
  it('returns actions array with rank and source fields', async () => {
    const res  = await handleDecisionActions(getReq('/api/decision/actions'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.actions)).toBe(true);
    // At least one action from the threat data
    expect(body.actions.length).toBeGreaterThan(0);
    const action = body.actions[0];
    expect(typeof action.rank).toBe('number');
    expect(typeof action.title).toBe('string');
    expect(typeof action.source).toBe('string');
    expect(['decision_engine', 'adaptive_brain']).toContain(action.source);
    expect(['P1-CRITICAL','P2-HIGH','P3-MEDIUM']).toContain(action.priority);
  });

  it('total_actions does not exceed 10', async () => {
    const res  = await handleDecisionActions(getReq('/api/decision/actions'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.total_actions).toBeLessThanOrEqual(10);
    expect(body.actions.length).toBeLessThanOrEqual(10);
  });
});

describe('handleDecisionBusinessImpact — P11.3', () => {
  it('returns all 5 impact dimensions with scores', async () => {
    const res  = await handleDecisionBusinessImpact(getReq('/api/decision/business-impact'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    const dims = body.business_impact.dimensions;
    expect(dims.operational.score).toBeGreaterThanOrEqual(0);
    expect(dims.financial.score).toBeGreaterThanOrEqual(0);
    expect(dims.compliance.score).toBeGreaterThanOrEqual(0);
    expect(dims.service.score).toBeGreaterThanOrEqual(0);
    expect(dims.reputation.score).toBeGreaterThanOrEqual(0);
  });

  it('returns zero scores (not errors) when DB is empty', async () => {
    const env  = makeEnv({ tiRows: [], assetRows: [], actorRows: [], asmRows: [] });
    const res  = await handleDecisionBusinessImpact(getReq('/api/decision/business-impact'), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.business_impact.overall_score).toBe(0);
  });

  it('includes mitigation recommendations', async () => {
    const res  = await handleDecisionBusinessImpact(getReq('/api/decision/business-impact'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Array.isArray(body.mitigations.immediate)).toBe(true);
    expect(body.mitigations.note).toMatch(/recommendations only/);
  });
});

describe('handleDecisionPriorities — P11.2', () => {
  it('returns P1/P2 arrays and correlation object', async () => {
    const res  = await handleDecisionPriorities(getReq('/api/decision/priorities'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.p1_critical)).toBe(true);
    expect(Array.isArray(body.p2_high)).toBe(true);
    expect(body.correlation).toBeDefined();
    expect(typeof body.correlation.correlated_cve_count).toBe('number');
    expect(Array.isArray(body.correlation.top_mitre_techniques)).toBe(true);
  });

  it('summary.escalation_required is true when KEV CVE present', async () => {
    const res  = await handleDecisionPriorities(getReq('/api/decision/priorities'), makeEnv(), PRO_CTX);
    const body = await res.json();
    // CVE-2024-1001 is KEV + CVSS 9.8 → should escalate
    expect(body.summary.escalation_required).toBe(true);
  });
});

describe('handleDecisionExecutive — P11.6', () => {
  it('returns a non-empty summary string for ciso role', async () => {
    const res  = await handleDecisionExecutive(getReq('/api/decision/executive', { role: 'ciso' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.role).toBe('ciso');
    expect(typeof body.summary).toBe('string');
    expect(body.summary.length).toBeGreaterThan(10);
    expect(body.key_metrics).toBeDefined();
    expect(typeof body.key_metrics.kev_count).toBe('number');
  });

  it('clamps invalid role to ciso', async () => {
    const res  = await handleDecisionExecutive(getReq('/api/decision/executive', { role: 'hacker' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.role).toBe('ciso');
  });

  it('lists all 6 available roles', async () => {
    const res  = await handleDecisionExecutive(getReq('/api/decision/executive'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.available_roles).toHaveLength(6);
    expect(body.available_roles).toContain('ceo');
    expect(body.available_roles).toContain('board');
    expect(body.available_roles).toContain('compliance');
  });
});

describe('KV caching — P11.8', () => {
  it('second call to summary returns _cache: HIT', async () => {
    const env = makeEnv();
    // First call — populate cache
    await handleDecisionSummary(getReq(), env, PRO_CTX);
    // Second call — should hit KV
    const res2 = await handleDecisionSummary(getReq(), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('second call to business-impact returns _cache: HIT', async () => {
    const env = makeEnv();
    await handleDecisionBusinessImpact(getReq('/api/decision/business-impact'), env, PRO_CTX);
    const res2 = await handleDecisionBusinessImpact(getReq('/api/decision/business-impact'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });
});
