/* Subscription-gate contract for the AI Brain V2 endpoints.
 *
 * /api/ai/simulate and /api/ai/forecast are advertised PRO+ (pricing matrix) and
 * documented "(PRO+)" in the handler, but shipped with ZERO enforcement — an
 * anonymous FREE caller received full attack-simulation / risk-forecast results
 * (a subscription bypass, verified live returning HTTP 200). These tests lock the
 * gate: FREE/STARTER get a 402 ERR_PLAN_REQUIRED upsell; PRO/ENTERPRISE/MSSP pass;
 * analyze (STARTER+) is intentionally NOT gated at PRO.
 *
 * Drives the real exported worker.fetch() so it exercises the actual routing +
 * gate wiring, not a reimplementation.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { hasAccess } from '../src/auth/apiKeys.js';

function kvStub() {
  return { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) };
}
function dbStub() {
  const stmt = { bind: () => stmt, first: async () => null, all: async () => ({ results: [] }), run: async () => ({}) };
  return { prepare: () => stmt, batch: async () => [] };
}
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }
function baseEnv() {
  // No JWT_SECRET / ADMIN_KEY → resolveAuthV5 lands on the FREE ip_fallback tier.
  return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub() };
}

const BODY = JSON.stringify({ scan_result: { risk_score: 75, risk_level: 'HIGH' }, module: 'domain', target: 'x.com' });
function post(path) {
  return new Request(`https://cyberdudebivash.in${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: BODY,
  });
}

describe('plan matrix sanity (source of truth: auth/apiKeys.js PLAN_FEATURES)', () => {
  it('ai_simulate / ai_forecast are PRO+ only', () => {
    for (const t of ['FREE', 'STARTER']) {
      expect(hasAccess('ai_simulate', t), `${t} must NOT have ai_simulate`).toBe(false);
      expect(hasAccess('ai_forecast', t), `${t} must NOT have ai_forecast`).toBe(false);
    }
    for (const t of ['PRO', 'ENTERPRISE', 'MSSP']) {
      expect(hasAccess('ai_simulate', t), `${t} must have ai_simulate`).toBe(true);
      expect(hasAccess('ai_forecast', t), `${t} must have ai_forecast`).toBe(true);
    }
  });
});

describe('/api/ai/simulate — subscription gate (was: open bypass)', () => {
  it('anonymous FREE caller is blocked with 402 ERR_PLAN_REQUIRED (no simulation leaked)', async () => {
    const res = await worker.fetch(post('/api/ai/simulate'), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.code).toBe('ERR_PLAN_REQUIRED');
    expect(body.required_plan).toBe('PRO');
    // The paid artifact must NOT be present in a blocked response
    expect(body.kill_chain).toBeUndefined();
    expect(body.simulation_id).toBeUndefined();
    expect(body.data).toBeUndefined();
  });
});

describe('/api/ai/forecast — subscription gate (was: open bypass)', () => {
  it('anonymous FREE caller is blocked with 402 ERR_PLAN_REQUIRED', async () => {
    const res = await worker.fetch(post('/api/ai/forecast'), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.code).toBe('ERR_PLAN_REQUIRED');
    expect(body.required_plan).toBe('PRO');
  });
});

describe('/api/ai-security/redteam/* — subscription gate (was: zero enforcement)', () => {
  // handlers/aiRedTeam.js's four routes checked only `authCtx?.userId` — any
  // FREE signup got unlimited access to a capability priced/marketed as
  // premium (prompt-injection, jailbreak, agent-takeover engagements, MITRE
  // ATLAS campaigns). Gated the same way /api/ai/simulate already was.
  const engageBody = JSON.stringify({ target_model: 'gpt-4o' });
  function postRT(path, body) {
    return new Request(`https://cyberdudebivash.in${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
  }

  it('anonymous FREE caller is blocked from starting an engagement (402 ERR_PLAN_REQUIRED)', async () => {
    const res = await worker.fetch(postRT('/api/ai-security/redteam/engage', engageBody), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.code).toBe('ERR_PLAN_REQUIRED');
    expect(body.required_plan).toBe('PRO');
    expect(body.engagement_id).toBeUndefined();
  });

  it('anonymous FREE caller is blocked from submitting an attack transcript', async () => {
    const res = await worker.fetch(postRT('/api/ai-security/redteam/rt_test/attack', JSON.stringify({ attack_type: 'jailbreak', test_id: 'JB-001', target_response: 'x' })), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    expect((await res.json()).code).toBe('ERR_PLAN_REQUIRED');
  });

  it('anonymous FREE caller is blocked from reading a report', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/ai-security/redteam/rt_test/report'), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    expect((await res.json()).code).toBe('ERR_PLAN_REQUIRED');
  });

  it('anonymous FREE caller is blocked from reading engagement status', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/ai-security/redteam/rt_test'), baseEnv(), ctxStub());
    expect(res.status).toBe(402);
    expect((await res.json()).code).toBe('ERR_PLAN_REQUIRED');
  });
});

describe('/api/ai/analyze — intentionally NOT PRO-gated', () => {
  it('is not blocked by the PRO gate (analyze is STARTER-tier; must not 402 on plan)', async () => {
    const res = await worker.fetch(post('/api/ai/analyze'), baseEnv(), ctxStub());
    // Analyze must never return the PRO plan-gate. It may 200 (deterministic engine)
    // or fail for another reason, but never ERR_PLAN_REQUIRED.
    if (res.status === 402) {
      const body = await res.json();
      expect(body.code).not.toBe('ERR_PLAN_REQUIRED');
    } else {
      expect(res.status).not.toBe(402);
    }
  });
});
