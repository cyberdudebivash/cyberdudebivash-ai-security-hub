/* AI Security Maturity Assessment — backend orchestration (ESSP Wave 1, PR 1).
 *
 * Orchestrates the existing AI Security Scorecard engine
 * (aiSecurityScorecardHandler.js's generateScorecard) under real org-scoped
 * RBAC and persistence. The scorecard engine itself is mocked here — it
 * performs real domain-security computation and has its own test coverage
 * elsewhere; these tests verify the new orchestration/persistence/RBAC/
 * isolation layer only, against a real SQL engine (node:sqlite), following
 * this repo's orgRbacIsolation.test.mjs / aiGovernanceOrgScoping.test.mjs
 * conventions.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/handlers/aiSecurityScorecardHandler.js', () => ({
  generateScorecard: vi.fn(async (domain) => ({
    domain,
    score: 82,
    max_score: 100,
    grade: 'B',
    grade_label: 'Good',
    risk_level: 'MEDIUM',
    grade_color: '#eab308',
    generated_at: new Date().toISOString(),
    dimensions: [],
    finding_summary: { critical: 0, high: 1, medium: 2, total: 3 },
    all_findings: [],
    cta: {},
    powered_by: 'CYBERDUDEBIVASH® AI Security Hub — Sentinel APEX',
  })),
}));

import { generateScorecard } from '../src/handlers/aiSecurityScorecardHandler.js';
import {
  handleRunAiMaturityAssessment,
  handleGetAiMaturityAssessment,
  handleListAiMaturityAssessments,
} from '../src/handlers/aiMaturityHandler.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
}

const U = (id) => ({ authenticated: true, userId: id, user_id: id });
const ownerA = U('owner-a'), analystA = U('analyst-a'), viewerA = U('viewer-a'), outsider = U('outsider');
const ownerB = U('owner-b');

const runReq = (body) => new Request('https://x/api/ai-maturity/assess', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});
const listReq = (qs) => new Request(`https://x/api/ai-maturity/assessments${qs}`, { method: 'GET' });
const getReq  = (id) => new Request(`https://x/api/ai-maturity/assessments/${id}`, { method: 'GET' });

describe('AI Maturity Assessment — orchestration, persistence, RBAC, isolation', () => {
  let env, db;

  beforeEach(() => {
    vi.clearAllMocks();
    env = { DB: makeRealD1() };
    db = env.DB._sqlite;
    db.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, plan TEXT, max_members INTEGER)`);
    db.exec(`CREATE TABLE org_members (id TEXT DEFAULT (lower(hex(randomblob(8)))), org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active')`);
    db.exec(`CREATE TABLE audit_log (user_id TEXT, action TEXT, resource TEXT, resource_id TEXT, status TEXT, metadata TEXT, created_at TEXT)`);
    db.exec(`CREATE TABLE ai_maturity_assessments (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, requested_by TEXT NOT NULL, target_scope TEXT NOT NULL,
      composite_score INTEGER NOT NULL, maturity_level TEXT NOT NULL, scorecard_json TEXT NOT NULL DEFAULT '{}',
      framework_scores_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'completed',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
    db.exec(`CREATE TABLE ai_maturity_score_history (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, assessment_id TEXT NOT NULL,
      composite_score INTEGER NOT NULL, maturity_level TEXT NOT NULL, recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);

    db.prepare(`INSERT INTO organizations (id, plan, max_members) VALUES ('org-a','ENTERPRISE',50)`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-a','owner-a','OWNER','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-a','analyst-a','ANALYST','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-a','viewer-a','VIEWER','active')`).run();

    db.prepare(`INSERT INTO organizations (id, plan, max_members) VALUES ('org-b','ENTERPRISE',50)`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-b','owner-b','OWNER','active')`).run();
  });

  it('unauthenticated caller gets 401, not a 200 with a real assessment', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, { authenticated: false });
    expect(res.status).toBe(401);
    expect(generateScorecard).not.toHaveBeenCalled();
  });

  it('ANALYST can run an assessment; it persists the engine\'s real score, not a hardcoded template', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, analystA);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.composite_score).toBe(82);
    expect(body.data.maturity_level).toBe('MANAGED');
    expect(body.data.framework_scores).toEqual({});

    const row = db.prepare(`SELECT * FROM ai_maturity_assessments WHERE id = ?`).get(body.data.id);
    expect(row.org_id).toBe('org-a');
    expect(row.composite_score).toBe(82);
    expect(row.maturity_level).toBe('MANAGED');

    const history = db.prepare(`SELECT * FROM ai_maturity_score_history WHERE assessment_id = ?`).get(body.data.id);
    expect(history.composite_score).toBe(82);
  });

  it('a different engine score bands into a different maturity level (proves the band is derived, not fixed)', async () => {
    generateScorecard.mockResolvedValueOnce({ domain: 'low.example.com', score: 20 });
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'low.example.com' }), env, analystA);
    const body = await res.json();
    expect(body.data.composite_score).toBe(20);
    expect(body.data.maturity_level).toBe('INCOMPLETE');
  });

  it('a VIEWER (below ANALYST) is rejected with 403, not allowed to run an assessment', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, viewerA);
    expect(res.status).toBe(403);
    expect(generateScorecard).not.toHaveBeenCalled();
  });

  it('a non-member of the org is rejected with 403', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, outsider);
    expect(res.status).toBe(403);
    expect(generateScorecard).not.toHaveBeenCalled();
  });

  it('missing target_scope is a 400, not a 500 from calling the engine with undefined', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a' }), env, analystA);
    expect(res.status).toBe(400);
    expect(generateScorecard).not.toHaveBeenCalled();
  });

  it('writes a real audit_log row on a successful run', async () => {
    const res = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, analystA);
    const { id } = (await res.json()).data;
    const audit = db.prepare(`SELECT * FROM audit_log WHERE resource_id = ?`).get('org-a');
    expect(audit).toBeTruthy();
    expect(audit.action).toBe('ai_maturity_assessment_run');
    expect(JSON.parse(audit.metadata).assessment_id).toBe(id);
  });

  it('GET by id: a same-org member can fetch it', async () => {
    const runRes = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, analystA);
    const { id } = (await runRes.json()).data;

    const res = await handleGetAiMaturityAssessment(getReq(id), env, ownerA, id);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.id).toBe(id);
  });

  it('GET by id: a member of a DIFFERENT org gets 404, not the other org\'s assessment (cross-org isolation)', async () => {
    const runRes = await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, analystA);
    const { id } = (await runRes.json()).data;

    const res = await handleGetAiMaturityAssessment(getReq(id), env, ownerB, id);
    expect(res.status).toBe(404);
  });

  it('GET by id: a nonexistent id is 404', async () => {
    const res = await handleGetAiMaturityAssessment(getReq('nope'), env, ownerA, 'nope');
    expect(res.status).toBe(404);
  });

  it('LIST: a non-member is rejected (403) when listing another org\'s assessments', async () => {
    await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'example.com' }), env, analystA);
    const res = await handleListAiMaturityAssessments(listReq('?org_id=org-a'), env, ownerB);
    expect(res.status).toBe(403);
  });

  it('LIST: org-B\'s own (empty) list never includes org-A\'s assessments — cross-org list isolation', async () => {
    await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'a1.example.com' }), env, analystA);
    await handleRunAiMaturityAssessment(runReq({ org_id: 'org-a', target_scope: 'a2.example.com' }), env, analystA);

    const resB = await handleListAiMaturityAssessments(listReq('?org_id=org-b'), env, ownerB);
    expect(resB.status).toBe(200);
    const bodyB = await resB.json();
    expect(bodyB.data).toEqual([]);
    expect(bodyB.meta.pagination.total).toBe(0);

    const resA = await handleListAiMaturityAssessments(listReq('?org_id=org-a'), env, ownerA);
    const bodyA = await resA.json();
    expect(bodyA.data.length).toBe(2);
    expect(bodyA.meta.pagination.total).toBe(2);
  });
});
