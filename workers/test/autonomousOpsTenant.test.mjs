/* The Autonomous Ops brief/plan (PRO+) must only see the caller's own SOC cases.
 * Regression for a residual cross-tenant leak: loadOpsContext listed soc_cases with
 * no org filter, so a PRO tenant's executive brief was built from EVERY tenant's cases.
 */
import { describe, it, expect } from 'vitest';
import { loadOpsContext, handleAutonomousWorkflowStatus } from '../src/handlers/autonomousOpsHandler.js';

// Mock D1: records the soc_cases SQL + binds, returns only rows matching the org bind.
function makeEnv(allCases) {
  const prepare = (sql) => {
    let binds = [];
    const api = {
      bind: (...b) => { binds = b; return api; },
      all: () => {
        if (/FROM soc_cases/i.test(sql)) {
          const scoped = /WHERE org_id = \?/i.test(sql);
          const rows = scoped ? allCases.filter(c => c.org_id === binds[0]) : allCases;
          return Promise.resolve({ results: rows });
        }
        return Promise.resolve({ results: [] });
      },
      first: () => Promise.resolve(null),
    };
    return api;
  };
  return { DB: { prepare } };
}

const ALL = [
  { id: 'c1', org_id: 'u:user-A', case_number: 'A-1', severity: 'CRITICAL', status: 'OPEN' },
  { id: 'c2', org_id: 'u:user-B', case_number: 'B-1', severity: 'HIGH', status: 'OPEN' },
  { id: 'c3', org_id: 'u:user-A', case_number: 'A-2', severity: 'LOW', status: 'OPEN' },
];

describe('Autonomous Ops — tenant-scoped SOC context', () => {
  it('a non-privileged tenant sees ONLY its own cases', async () => {
    const env = makeEnv(ALL);
    const ctx = await loadOpsContext(env, { authenticated: true, user_id: 'user-A', org_id: 'u:user-A' });
    expect(ctx.caseRows.map(c => c.case_number).sort()).toEqual(['A-1', 'A-2']);
    expect(ctx.caseRows.some(c => c.org_id === 'u:user-B')).toBe(false);
  });

  it('a different tenant sees only ITS cases (no cross-tenant bleed)', async () => {
    const env = makeEnv(ALL);
    const ctx = await loadOpsContext(env, { authenticated: true, user_id: 'user-B', org_id: 'u:user-B' });
    expect(ctx.caseRows.map(c => c.case_number)).toEqual(['B-1']);
  });

  it('an admin/privileged principal sees platform-wide cases', async () => {
    const env = makeEnv(ALL);
    const ctx = await loadOpsContext(env, { authenticated: true, user_id: 'admin', role: 'admin', isAdmin: true });
    expect(ctx.caseRows).toHaveLength(3);
  });
});

// ── Workflow Status view — must not leak other tenants' SOC case content ──────
// Regression: handleAutonomousWorkflowStatus returned case_number + title + timeline
// from soc_cases/soc_timeline with no org filter, exposing every tenant's case
// content (titles, numbers, actors) to any PRO+ caller.

const TITLED = [
  { id: 'c1', org_id: 'u:user-A', case_number: 'A-1', title: 'Acme phishing incident',  severity: 'CRITICAL', status: 'OPEN', assignee_id: null, sla_due_at: null, created_at: '2026-07-01' },
  { id: 'c2', org_id: 'u:user-B', case_number: 'B-1', title: 'Globex ransomware breach', severity: 'CRITICAL', status: 'OPEN', assignee_id: null, sla_due_at: null, created_at: '2026-07-02' },
];
const TIMELINE = [
  { case_id: 'c1', org_id: 'u:user-A', event_type: 'note', actor: 'analyst-A', occurred_at: '2026-07-01' },
  { case_id: 'c2', org_id: 'u:user-B', event_type: 'note', actor: 'analyst-B', occurred_at: '2026-07-02' },
];

function makeStatusEnv() {
  const prepare = (sql) => {
    let binds = [];
    const api = {
      bind: (...b) => { binds = b; return api; },
      all: () => {
        if (/FROM soc_cases/i.test(sql)) {
          const rows = /WHERE org_id = \?/i.test(sql) ? TITLED.filter(c => c.org_id === binds[0]) : TITLED;
          return Promise.resolve({ results: rows });
        }
        if (/FROM soc_timeline/i.test(sql)) {
          const rows = /WHERE org_id = \?/i.test(sql) ? TIMELINE.filter(t => t.org_id === binds[0]) : TIMELINE;
          return Promise.resolve({ results: rows });
        }
        return Promise.resolve({ results: [] }); // workflow_executions etc.
      },
      first: () => Promise.resolve(null),
    };
    return api;
  };
  return { DB: { prepare }, SECURITY_HUB_KV: { get: async () => null, put: async () => {} } };
}

describe('Autonomous Ops — workflow status is tenant-isolated', () => {
  it('a PRO tenant never sees another tenant\'s case title/number or timeline actor', async () => {
    const res  = await handleAutonomousWorkflowStatus({}, makeStatusEnv(),
      { authenticated: true, user_id: 'user-A', org_id: 'u:user-A', tier: 'PRO' });
    const body = await res.json();
    const blob = JSON.stringify(body);
    expect(blob).toContain('A-1');
    expect(blob).not.toContain('Globex ransomware breach');
    expect(blob).not.toContain('B-1');
    expect(blob).not.toContain('analyst-B');
  });

  it('an admin sees platform-wide case content', async () => {
    const res  = await handleAutonomousWorkflowStatus({}, makeStatusEnv(),
      { authenticated: true, user_id: 'admin', role: 'admin', isAdmin: true, tier: 'ENTERPRISE' });
    const blob = JSON.stringify(await res.json());
    expect(blob).toContain('A-1');
    expect(blob).toContain('B-1');
  });
});
