/* SOC case management must be tenant-isolated. Regression for a cross-tenant leak
 * found during the authenticated dashboard walkthrough: two different FREE accounts
 * (no explicit org_id) both collapsed into a shared 'default' org and saw — and
 * could mutate — each other's SOC cases. Now each org-less user is isolated by a
 * per-user tenant key (u:<user_id>), and update/comment/metrics are org-scoped.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  tenantKey, handleListCases, handleCreateCase, handleGetCase,
  handleUpdateCase, handleAddCaseComment, handleCaseMetrics,
} from '../src/handlers/socCases.js';

// ── Minimal in-memory D1 mock supporting the queries socCases.js issues ────────
function makeDB() {
  const cases = [];
  const comments = [];
  const run = (sql, binds) => {
    if (/INSERT INTO soc_cases/i.test(sql)) {
      const [id, case_number, title, severity, assignee_id, org_id] = binds;
      cases.push({ id, case_number, title, severity, status: 'OPEN', org_id, assignee_id,
        mitre_tactics: '[]', ioc_list: '[]', alert_ids: '[]', created_at: new Date().toISOString(),
        updated_at: new Date().toISOString() });
      return { meta: { changes: 1 } };
    }
    if (/INSERT INTO soc_case_comments/i.test(sql)) { comments.push({ binds }); return { meta: { changes: 1 } }; }
    if (/^UPDATE soc_cases/i.test(sql.trim())) {
      // last two binds are (caseId, caseId); optional org filter not modeled — we
      // rely on assertCaseOwnership having gated the call before it reaches here.
      const caseId = binds[binds.length - 1];
      const row = cases.find(c => c.id === caseId || c.case_number === caseId);
      if (row) { Object.assign(row, { updated_at: new Date().toISOString() }); return { meta: { changes: 1 } }; }
      return { meta: { changes: 0 } };
    }
    return { meta: { changes: 0 } };
  };
  const first = (sql, binds) => {
    if (/SELECT org_id FROM soc_cases/i.test(sql)) {
      const [id] = binds; return cases.find(c => c.id === id || c.case_number === id) || null;
    }
    if (/SELECT \* FROM soc_cases/i.test(sql)) {
      const [id] = binds; return cases.find(c => c.id === id || c.case_number === id) || null;
    }
    if (/SELECT COUNT\(\*\) as total/i.test(sql)) {
      const org = binds[0];
      return { total: cases.filter(c => org === undefined || c.org_id === org).length };
    }
    if (/COUNT\(\*\) as total,/i.test(sql)) { // metrics aggregate
      const org = binds && binds[0];
      const scope = cases.filter(c => org == null || c.org_id === org);
      return { total: scope.length, open_count: scope.filter(c=>c.status==='OPEN').length,
        in_progress:0, escalated:0, resolved:0, crit_open:0, high_open:0 };
    }
    if (/SELECT COUNT\(\*\) as total FROM soc_case_comments|SELECT \* FROM soc_case_comments/i.test(sql)) return null;
    return null;
  };
  const all = (sql, binds) => {
    if (/FROM soc_cases/i.test(sql)) {
      const org = binds[0];
      return { results: cases.filter(c => c.org_id === org) };
    }
    if (/FROM soc_case_comments/i.test(sql)) return { results: [] };
    return { results: [] };
  };
  const prepare = (sql) => {
    let _binds = [];
    const api = {
      bind: (...b) => { _binds = b; return api; },
      run:   () => Promise.resolve(run(sql, _binds)),
      first: () => Promise.resolve(first(sql, _binds)),
      all:   () => Promise.resolve(all(sql, _binds)),
    };
    return api;
  };
  return { SECURITY_HUB_DB: { prepare }, _cases: cases };
}

const userA = { authenticated: true, user_id: 'user-A', email: 'a@corp.io' };
const userB = { authenticated: true, user_id: 'user-B', email: 'b@corp.io' };
const req = (body) => new Request('https://x/api/soc/cases', body
  ? { method: 'POST', body: JSON.stringify(body) } : {});

describe('SOC tenant isolation', () => {
  let env;
  beforeEach(() => { env = makeDB(); });

  it('two org-less users get DIFFERENT tenant keys (not shared "default")', () => {
    expect(tenantKey(userA)).toBe('u:user-A');
    expect(tenantKey(userB)).toBe('u:user-B');
    expect(tenantKey(userA)).not.toBe(tenantKey(userB));
    expect(tenantKey({})).toBe('default');
  });

  it('user B cannot LIST user A\'s cases', async () => {
    await handleCreateCase(req({ title: 'A secret case', severity: 'CRITICAL' }), env, userA);
    const listB = await (await handleListCases(req(), env, userB)).json();
    expect(listB.total).toBe(0);
    expect(listB.cases).toHaveLength(0);
    const listA = await (await handleListCases(req(), env, userA)).json();
    expect(listA.total).toBe(1);
  });

  it('user B cannot GET user A\'s case by id (403)', async () => {
    await handleCreateCase(req({ title: 'A case', severity: 'HIGH' }), env, userA);
    const id = env._cases[0].id;
    const resp = await handleGetCase(req(), env, userB, id);
    expect(resp.status).toBe(403);
    const ok = await handleGetCase(req(), env, userA, id);
    expect(ok.status).toBe(200);
  });

  it('user B cannot UPDATE user A\'s case (403) — no cross-tenant writes', async () => {
    await handleCreateCase(req({ title: 'A case', severity: 'HIGH' }), env, userA);
    const id = env._cases[0].id;
    const resp = await handleUpdateCase(
      new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'CLOSED' }) }),
      env, userB, id);
    expect(resp.status).toBe(403);
    expect(env._cases[0].status).toBe('OPEN'); // unchanged
  });

  it('user B cannot COMMENT on user A\'s case (403)', async () => {
    await handleCreateCase(req({ title: 'A case', severity: 'HIGH' }), env, userA);
    const id = env._cases[0].id;
    const resp = await handleAddCaseComment(
      new Request('https://x', { method: 'POST', body: JSON.stringify({ text: 'pwned' }) }),
      env, userB, id);
    expect(resp.status).toBe(403);
  });

  it('metrics are scoped to the caller\'s tenant', async () => {
    await handleCreateCase(req({ title: 'A1', severity: 'HIGH' }), env, userA);
    await handleCreateCase(req({ title: 'A2', severity: 'LOW' }), env, userA);
    const mB = await (await handleCaseMetrics(req(), env, userB)).json();
    expect(mB.total).toBe(0);
    const mA = await (await handleCaseMetrics(req(), env, userA)).json();
    expect(mA.total).toBe(2);
  });
});
