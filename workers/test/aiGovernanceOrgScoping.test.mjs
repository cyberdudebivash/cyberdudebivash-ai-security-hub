/* Regression tests for a confirmed cross-tenant data exposure:
 * `handleAIGovernancePro` (workers/src/handlers/aiGovernancePro.js) and the
 * AI Governance PDF export handler (workers/src/handlers/aiGovernancePdfHandler.js)
 * previously took `org_id` directly from client body/query params with ZERO
 * authentication anywhere in the domain — any anonymous visitor could read,
 * modify, or delete another organisation's AI model registry, policies, and
 * confidential governance/compliance reports (including owner_email) just by
 * supplying that org's id. Fixed by requiring isRealUser(authCtx) on every
 * route and deriving org scope exclusively from authCtx.org_id (the same
 * per-user tenant id withAuthAliases() already establishes for every other
 * scoped domain in this codebase), never from client input.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAIGovernancePro } from '../src/handlers/aiGovernancePro.js';
import { handlePdfGenerate, handlePdfList } from '../src/handlers/aiGovernancePdfHandler.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE ai_model_registry (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0', model_type TEXT, type TEXT, use_case TEXT,
    data_classification TEXT, deployment_context TEXT, autonomy_level TEXT, impact_domain TEXT,
    explainability TEXT, bias_tested INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'LOW', eu_ai_act_category TEXT NOT NULL DEFAULT 'MINIMAL',
    owner_email TEXT, status TEXT NOT NULL DEFAULT 'active', metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  )`);
  sqlite.exec(`CREATE TABLE ai_governance_policies (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL,
    description TEXT DEFAULT '', rules TEXT DEFAULT '[]', enforcement_level TEXT NOT NULL DEFAULT 'WARN',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  )`);
  sqlite.exec(`CREATE TABLE ai_governance_assessments (
    id TEXT PRIMARY KEY, org_id TEXT, status TEXT NOT NULL DEFAULT 'in_progress',
    completed_at INTEGER, answers TEXT DEFAULT '{}', gaps TEXT DEFAULT '[]', roadmap TEXT DEFAULT '[]'
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}
function makeKV() {
  const store = new Map();
  return {
    async get(k, type) { const v = store.has(k) ? store.get(k) : null; return type === 'json' && v != null ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, v); },
    _store: store,
  };
}

const userA = { authenticated: true, method: 'jwt', user_id: 'user-a', tier: 'ENTERPRISE' };
const userB = { authenticated: true, method: 'jwt', user_id: 'user-b', tier: 'ENTERPRISE' };
const anon  = { authenticated: true, method: 'ip_fallback', user_id: null, tier: 'FREE' };

describe('handleAIGovernancePro — auth + org scoping (previously unauthenticated, client-controlled org_id)', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1(), KV: makeKV() }; });

  it('anonymous caller gets 401 on every route, not a 200 with someone else\'s data', async () => {
    const req = new Request('https://x/api/ai-governance/models', { method: 'GET' });
    const res = await handleAIGovernancePro(req, env, anon);
    expect(res.status).toBe(401);
  });

  it('client-supplied org_id in the POST body is ignored — model is stored under the caller\'s own tenant', async () => {
    const req = new Request('https://x/api/ai-governance/models', {
      method: 'POST',
      body: JSON.stringify({ org_id: 'victim-org', name: 'Fraud Model', model_type: 'classification',
        data_classification: 'pii', deployment_context: 'production_customer_facing',
        autonomy_level: 'human_in_loop', impact_domain: 'financial', explainability: 'black_box',
        owner_email: 'ciso@victim.example' }),
    });
    const res = await handleAIGovernancePro(req, env, userA);
    expect(res.status).toBe(201);
    const row = env.DB._sqlite.prepare('SELECT org_id FROM ai_model_registry WHERE name = ?').get('Fraud Model');
    expect(row.org_id).toBe('u:user-a');
    expect(row.org_id).not.toBe('victim-org');
  });

  it('a second, unrelated user cannot list the first user\'s models via ?org_id= query override', async () => {
    await handleAIGovernancePro(new Request('https://x/api/ai-governance/models', {
      method: 'POST', body: JSON.stringify({ name: 'A-Only Model', model_type: 'nlp', data_classification: 'confidential',
        deployment_context: 'production_internal', autonomy_level: 'advisory_only', impact_domain: 'internal_tools',
        explainability: 'interpretable', owner_email: 'owner-a@a.example' }),
    }), env, userA);

    const res = await handleAIGovernancePro(
      new Request('https://x/api/ai-governance/models?org_id=u:user-a', { method: 'GET' }), env, userB,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.models.length).toBe(0);
    expect(body.total).toBe(0);
  });

  it('a second user cannot GET/UPDATE/DELETE the first user\'s model by guessing its id (IDOR)', async () => {
    const createRes = await handleAIGovernancePro(new Request('https://x/api/ai-governance/models', {
      method: 'POST', body: JSON.stringify({ name: 'Secret Model', model_type: 'nlp', data_classification: 'secret',
        deployment_context: 'production_internal', autonomy_level: 'advisory_only', impact_domain: 'internal_tools',
        explainability: 'interpretable', owner_email: 'owner-a@a.example' }),
    }), env, userA);
    const { id } = await createRes.json();

    const getRes = await handleAIGovernancePro(new Request(`https://x/api/ai-governance/models/${id}`, { method: 'GET' }), env, userB);
    expect(getRes.status).toBe(404);

    const delRes = await handleAIGovernancePro(new Request(`https://x/api/ai-governance/models/${id}`, { method: 'DELETE' }), env, userB);
    expect(delRes.status).toBe(404);
    const still = env.DB._sqlite.prepare('SELECT status FROM ai_model_registry WHERE id = ?').get(id);
    expect(still.status).toBe('active');

    const ownGetRes = await handleAIGovernancePro(new Request(`https://x/api/ai-governance/models/${id}`, { method: 'GET' }), env, userA);
    expect(ownGetRes.status).toBe(200);
  });

  it('shadow-AI inventory is isolated per tenant, not shared by client-supplied org_id', async () => {
    await handleAIGovernancePro(new Request('https://x/api/ai-governance/shadow-ai/detect', {
      method: 'POST', body: JSON.stringify({ org_id: 'victim-org', dns_logs: ['api.openai.com'] }),
    }), env, userA);

    const res = await handleAIGovernancePro(
      new Request('https://x/api/ai-governance/shadow-ai/inventory?org_id=u:user-a', { method: 'GET' }), env, userB,
    );
    const body = await res.json();
    expect(body.detected).toEqual([]);
  });
});

describe('handlePdfGenerate/handlePdfList — auth + org scoping (previously unauthenticated cross-tenant report exposure)', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1(), KV: makeKV() }; });

  it('anonymous caller cannot generate or list reports', async () => {
    const genRes = await handlePdfGenerate(new Request('https://x/api/ai-governance/pdf/generate', {
      method: 'POST', body: JSON.stringify({ org_id: 'victim-org' }),
    }), env, anon);
    expect(genRes.status).toBe(401);

    const listRes = await handlePdfList(new Request('https://x/api/ai-governance/pdf/list?org_id=victim-org'), env, anon);
    expect(listRes.status).toBe(401);
  });

  it('client-supplied org_id in the generate body is ignored — report is scoped to the caller\'s own tenant', async () => {
    const res = await handlePdfGenerate(new Request('https://x/api/ai-governance/pdf/generate', {
      method: 'POST', body: JSON.stringify({ org_id: 'victim-org', report_type: 'FULL_GOVERNANCE' }),
    }), env, userA);
    expect(res.status).toBe(200);
    expect(await env.KV.get('agpdf:list:victim-org', 'json')).toBeNull();
    expect(await env.KV.get('agpdf:list:u:user-a', 'json')).not.toBeNull();
  });

  it('a second user cannot list the first user\'s generated reports via ?org_id= override', async () => {
    await handlePdfGenerate(new Request('https://x/api/ai-governance/pdf/generate', {
      method: 'POST', body: JSON.stringify({ report_type: 'FULL_GOVERNANCE' }),
    }), env, userA);

    const res = await handlePdfList(new Request('https://x/api/ai-governance/pdf/list?org_id=u:user-a'), env, userB);
    const body = await res.json();
    expect(body.reports).toEqual([]);
    expect(body.count).toBe(0);

    const ownRes = await handlePdfList(new Request('https://x/api/ai-governance/pdf/list'), env, userA);
    const ownBody = await ownRes.json();
    expect(ownBody.count).toBe(1);
  });
});
