// CAP-SEC-AUDIT (Enterprise Production Certification Program, 2026-07-12) —
// workers/src/handlers/aiRedTeamPro.js. Registry/prior sessions had zero test
// coverage for this module. A manual OWASP-style sweep found: the router
// (workers/src/index.js's /api/ai-redteam/* prefix) passed no authCtx at all,
// and every campaigns/reports route trusted a client-supplied org_id
// (body.org_id / ?org_id=, defaulting to the literal 'default') with no auth
// check whatsoever — any anonymous caller could create/list/read/run AI
// red-team campaigns (including target_model/target_endpoint) for ANY org.
//
// Fixed: campaigns/reports routes now require isRealUser(authCtx) and derive
// org_id exclusively from the authenticated session, mirroring the established,
// already-correct pattern in handlers/aiGovernancePro.js. techniques/prompts/
// probe/robustness-score routes are deliberately left public — they are
// stateless, non-tenant-specific reference data, and frontend/ai-security-
// assessment.html has an intentional unauthenticated "try before you pay" demo
// modal calling /api/ai-redteam/techniques and /api/ai-redteam/probe/jailbreak
// that must keep working without login.
import { describe, it, expect, beforeEach } from 'vitest';
import { handleAIRedTeamPro } from '../src/handlers/aiRedTeamPro.js';

function makeDB() {
  const campaigns = new Map();
  return {
    _campaigns: campaigns,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() {
              if (sql.startsWith('INSERT INTO ai_redteam_campaigns')) {
                const [id, org_id, name, description, target_model, target_endpoint, technique_ids, status, created_by, created_at, updated_at] = args;
                campaigns.set(id, { id, org_id, name, description, target_model, target_endpoint, technique_ids, status, created_by, created_at, updated_at });
              } else if (sql.startsWith('UPDATE ai_redteam_campaigns')) {
                const [status, updated_at, id, org_id] = args;
                const c = campaigns.get(id);
                if (c && c.org_id === org_id) { c.status = status; c.updated_at = updated_at; }
              }
              return { success: true };
            },
            async first() {
              if (sql.includes('WHERE id=? AND org_id=?')) {
                const [id, org_id] = args;
                const c = campaigns.get(id);
                return (c && c.org_id === org_id) ? c : null;
              }
              if (sql.includes('WHERE id=?')) {
                const [id] = args;
                return campaigns.get(id) || null;
              }
              return null;
            },
            async all() {
              const [org_id] = args;
              return { results: [...campaigns.values()].filter(c => c.org_id === org_id) };
            },
          };
        },
      };
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async get(key, type) { const v = store.get(key); return v === undefined ? null : (type === 'json' ? JSON.parse(v) : v); },
    async put(key, value) { store.set(key, value); },
  };
}

function req(url, { method = 'GET', body } = {}) {
  return { url, method, json: async () => body ?? {} };
}

const anon = { authenticated: false, tier: 'FREE', identity: 'ip:anon' };
const userA = { authenticated: true, userId: 'user-A', user_id: 'user-A', org_id: 'org-A', email: 'a@example.com', tier: 'ENTERPRISE' };
const userB = { authenticated: true, userId: 'user-B', user_id: 'user-B', org_id: 'org-B', email: 'b@example.com', tier: 'ENTERPRISE' };

describe('aiRedTeamPro — campaigns/reports require real auth, scoped by server-derived org_id', () => {
  let env;
  beforeEach(() => { env = { DB: makeDB(), KV: makeKV() }; });

  it('anonymous POST /api/ai-redteam/campaigns is rejected, not silently defaulted to org "default"', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', {
      method: 'POST', body: { name: 'x', org_id: 'org-A' },
    }), env, anon);
    expect(res.status).toBe(401);
  });

  it('anonymous GET /api/ai-redteam/campaigns is rejected', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns?org_id=org-A'), env, anon);
    expect(res.status).toBe(401);
  });

  it('a real user can create a campaign, and org_id is taken from their session, not the request body', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', {
      method: 'POST', body: { name: 'Q3 Assessment', org_id: 'org-SPOOFED', target_model: 'gpt-4o' },
    }), env, userA);
    expect(res.status).toBe(201);
    const stored = [...env.DB._campaigns.values()][0];
    expect(stored.org_id).toBe('org-A');
    expect(stored.org_id).not.toBe('org-SPOOFED');
    expect(stored.created_by).toBe('a@example.com');
  });

  it('user B cannot see user A\'s campaigns via GET /api/ai-redteam/campaigns, even by supplying org_id=org-A', async () => {
    await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', { method: 'POST', body: { name: 'A-camp' } }), env, userA);
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns?org_id=org-A'), env, userB);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.campaigns).toEqual([]);
  });

  it('user B cannot fetch user A\'s campaign by ID (IDOR closed)', async () => {
    const createRes = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', { method: 'POST', body: { name: 'A-camp' } }), env, userA);
    const { id } = await createRes.json();
    const res = await handleAIRedTeamPro(req(`https://x/api/ai-redteam/campaigns/${id}`), env, userB);
    expect(res.status).toBe(404);
  });

  it('user B cannot run user A\'s campaign by ID (IDOR closed on mutation, not just read)', async () => {
    const createRes = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', { method: 'POST', body: { name: 'A-camp', technique_ids: ['AML.T0000'] } }), env, userA);
    const { id } = await createRes.json();
    const res = await handleAIRedTeamPro(req(`https://x/api/ai-redteam/campaigns/${id}/run`, { method: 'POST' }), env, userB);
    expect(res.status).toBe(404);
  });

  it('the real owner can fetch and run their own campaign', async () => {
    const createRes = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', { method: 'POST', body: { name: 'A-camp', technique_ids: ['AML.T0000'] } }), env, userA);
    const { id } = await createRes.json();
    const getRes = await handleAIRedTeamPro(req(`https://x/api/ai-redteam/campaigns/${id}`), env, userA);
    expect(getRes.status).toBe(200);
    const runRes = await handleAIRedTeamPro(req(`https://x/api/ai-redteam/campaigns/${id}/run`, { method: 'POST' }), env, userA);
    expect(runRes.status).toBe(200);
    const runBody = await runRes.json();
    expect(runBody.status).toBe('SIMULATION_COMPLETE');
  });

  it('anonymous POST /api/ai-redteam/reports is rejected', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/reports', { method: 'POST', body: {} }), env, anon);
    expect(res.status).toBe(401);
  });

  it('user B cannot pull user A\'s campaign results into a report by guessing the campaign id', async () => {
    const createRes = await handleAIRedTeamPro(req('https://x/api/ai-redteam/campaigns', { method: 'POST', body: { name: 'A-camp', technique_ids: ['AML.T0000'] } }), env, userA);
    const { id } = await createRes.json();
    await handleAIRedTeamPro(req(`https://x/api/ai-redteam/campaigns/${id}/run`, { method: 'POST' }), env, userA);

    const reportRes = await handleAIRedTeamPro(req('https://x/api/ai-redteam/reports', {
      method: 'POST', body: { campaign_id: id },
    }), env, userB);
    expect(reportRes.status).toBe(200);
    const reportBody = await reportRes.json();
    // User B's report must not surface user A's real campaign results.
    expect(reportBody.campaignResults).toBeNull();
    expect(reportBody.executiveSummary.campaignResults).toBeNull();
  });
});

describe('aiRedTeamPro — public reference-data routes stay unauthenticated (frontend demo modal depends on this)', () => {
  let env;
  beforeEach(() => { env = { DB: makeDB(), KV: makeKV() }; });

  it('anonymous GET /api/ai-redteam/techniques still works', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/techniques'), env, anon);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBeGreaterThan(0);
  });

  it('anonymous POST /api/ai-redteam/probe/jailbreak still works (the free demo modal\'s core call)', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/probe/jailbreak', {
      method: 'POST', body: {},
    }), env, anon);
    expect(res.status).toBe(200);
  });

  it('anonymous GET /api/ai-redteam/prompts still works', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/prompts'), env, anon);
    expect(res.status).toBe(200);
  });

  it('even undefined authCtx (no third argument at all) does not throw on public routes', async () => {
    const res = await handleAIRedTeamPro(req('https://x/api/ai-redteam/techniques'), env, undefined);
    expect(res.status).toBe(200);
  });
});
