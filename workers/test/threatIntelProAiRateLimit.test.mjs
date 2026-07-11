/* Regression test — threatIntelPro.js's AI-Analyst chat + AI-generated
 * CVE/sector brief routes (Tier 2 backlog item #1; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * POST /api/intel/analyst(/query), GET /api/intel/cve-brief/:id and
 * GET /api/intel/sector/:sector each trigger a real LLM call (analyzeQuery /
 * generateCVEBrief / generateSectorBrief in services/aiThreatAnalyst.js) but
 * had zero authentication requirement and zero rate limiting — any anonymous
 * visitor could script unlimited calls, an open cost-abuse vector paying for
 * real third-party LLM API usage on every single request.
 *
 * Verifies each route now calls the shared checkRateLimitCost() (the same
 * utility already used by handlers/threatHunting.js, vulnManagement.js and
 * auditLog.js for their own costly operations) with a distinct endpoint key
 * before doing any LLM/DB work, denies with the standard 429 shape when the
 * quota is exhausted (without ever invoking the LLM), and proceeds normally
 * when allowed.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

let RL_ALLOWED = true;
const rlCalls = [];
vi.mock('../src/middleware/rateLimit.js', () => ({
  checkRateLimitCost: async (env, authCtx, endpoint) => {
    rlCalls.push(endpoint);
    return RL_ALLOWED
      ? { allowed: true, tier: authCtx?.tier || 'FREE', remaining: 3 }
      : { allowed: false, reason: 'cost_budget_exceeded', tier: authCtx?.tier || 'FREE', remaining: 0, retry_after: 86400 };
  },
  rateLimitResponse: (r, module) => new Response(JSON.stringify({ error: 'Rate limit exceeded', reason: r.reason, module }), { status: 429 }),
}));

const { analyzeQuery, generateCVEBrief, generateSectorBrief } = vi.hoisted(() => ({
  analyzeQuery:        vi.fn(async () => ({ response: 'mock analysis',     model: 'mock', provider: 'mock', latency_ms: 1 })),
  generateCVEBrief:    vi.fn(async () => ({ response: 'mock brief',        model: 'mock', provider: 'mock', latency_ms: 1 })),
  generateSectorBrief: vi.fn(async () => ({ response: 'mock sector brief', model: 'mock', provider: 'mock', latency_ms: 1 })),
}));
vi.mock('../src/services/aiThreatAnalyst.js', () => ({ analyzeQuery, generateCVEBrief, generateSectorBrief }));

vi.mock('../src/services/compositeRiskScoring.js', () => ({
  scoreCVE: () => ({ score: 50 }), scoreBatch: () => [], fetchEPSS: async () => ({}), analyzeRiskDistribution: () => ({}),
}));
vi.mock('../src/services/mitreAttackService.js', () => ({
  mapToAttack: () => ([]), mapBatchToAttack: () => ([]), buildAttackHeatmap: () => ({}),
  TACTICS: {}, TECHNIQUES: {}, getTechnique: () => null, searchTechniques: () => [],
}));
vi.mock('../src/services/aptActorProfiles.js', () => ({
  getActor: () => null, getAllActors: () => [], getActorsBySector: () => [], getActorsByCVE: () => [],
  getActorsByTechnique: () => [], attributeCVE: () => [], getActorStats: () => ({}),
}));

import { handleThreatIntelPro } from '../src/handlers/threatIntelPro.js';

function makeEnv(withDB) {
  return {
    DB: withDB ? {
      prepare: () => ({
        bind: () => ({
          first: async () => ({ id: 'CVE-2026-0001', title: 'Test CVE', description: 'x', severity: 'HIGH', cvss: 8.8, tags: '[]' }),
        }),
      }),
    } : undefined,
  };
}

const authCtx = { tier: 'FREE', identity: 'ip:1.2.3.4' };

beforeEach(() => {
  RL_ALLOWED = true;
  rlCalls.length = 0;
  analyzeQuery.mockClear();
  generateCVEBrief.mockClear();
  generateSectorBrief.mockClear();
});

describe('POST /api/intel/analyst/query — AI analyst chat is rate-limited', () => {
  it('checks the intel/analyst quota before calling the LLM', async () => {
    const req = new Request('https://x/api/intel/analyst/query', { method: 'POST', body: JSON.stringify({ query: 'hi' }) });
    await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(rlCalls).toContain('intel/analyst');
  });

  it('returns 429 and never calls the LLM when the quota is exhausted', async () => {
    RL_ALLOWED = false;
    const req = new Request('https://x/api/intel/analyst/query', { method: 'POST', body: JSON.stringify({ query: 'hi' }) });
    const res = await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(res.status).toBe(429);
    expect(analyzeQuery).not.toHaveBeenCalled();
  });

  it('proceeds to call the LLM when the quota allows', async () => {
    const req = new Request('https://x/api/intel/analyst/query', { method: 'POST', body: JSON.stringify({ query: 'hi' }) });
    const res = await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(res.status).toBe(200);
    expect(analyzeQuery).toHaveBeenCalledTimes(1);
  });

  it('also gates the GET ?q= alias at /api/intel/analyst', async () => {
    RL_ALLOWED = false;
    const req = new Request('https://x/api/intel/analyst?q=hello');
    const res = await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(res.status).toBe(429);
    expect(analyzeQuery).not.toHaveBeenCalled();
  });
});

describe('GET /api/intel/cve-brief/:id — AI CVE brief is rate-limited', () => {
  it('checks the intel/cve-brief quota before calling the LLM', async () => {
    const req = new Request('https://x/api/intel/cve-brief/CVE-2026-0001');
    await handleThreatIntelPro(req, makeEnv(true), authCtx);
    expect(rlCalls).toContain('intel/cve-brief');
  });

  it('returns 429 and never calls the LLM when the quota is exhausted', async () => {
    RL_ALLOWED = false;
    const req = new Request('https://x/api/intel/cve-brief/CVE-2026-0001');
    const res = await handleThreatIntelPro(req, makeEnv(true), authCtx);
    expect(res.status).toBe(429);
    expect(generateCVEBrief).not.toHaveBeenCalled();
  });

  it('proceeds to call the LLM when the quota allows', async () => {
    const req = new Request('https://x/api/intel/cve-brief/CVE-2026-0001');
    const res = await handleThreatIntelPro(req, makeEnv(true), authCtx);
    expect(res.status).toBe(200);
    expect(generateCVEBrief).toHaveBeenCalledTimes(1);
  });
});

describe('GET /api/intel/sector/:sector — AI sector brief is rate-limited', () => {
  it('checks the intel/sector quota before calling the LLM', async () => {
    const req = new Request('https://x/api/intel/sector/healthcare');
    await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(rlCalls).toContain('intel/sector');
  });

  it('returns 429 and never calls the LLM when the quota is exhausted', async () => {
    RL_ALLOWED = false;
    const req = new Request('https://x/api/intel/sector/healthcare');
    const res = await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(res.status).toBe(429);
    expect(generateSectorBrief).not.toHaveBeenCalled();
  });

  it('proceeds to call the LLM when the quota allows', async () => {
    const req = new Request('https://x/api/intel/sector/healthcare');
    const res = await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(res.status).toBe(200);
    expect(generateSectorBrief).toHaveBeenCalledTimes(1);
  });
});

describe('unrelated /api/intel/actors route is not accidentally gated by the new check', () => {
  it('does not call checkRateLimitCost at all', async () => {
    const req = new Request('https://x/api/intel/actors');
    await handleThreatIntelPro(req, makeEnv(false), authCtx);
    expect(rlCalls).toEqual([]);
  });
});

describe('endpoint cost registry — static source check (avoids re-importing the mocked module)', () => {
  const root = resolve(import.meta.dirname, '..');
  const src  = readFileSync(resolve(root, 'src/middleware/rateLimit.js'), 'utf8');

  it('registers intel/analyst, intel/cve-brief and intel/sector each at cost 2', () => {
    expect(src).toMatch(/'intel\/analyst':\s*2,/);
    expect(src).toMatch(/'intel\/cve-brief':\s*2,/);
    expect(src).toMatch(/'intel\/sector':\s*2,/);
  });
});
