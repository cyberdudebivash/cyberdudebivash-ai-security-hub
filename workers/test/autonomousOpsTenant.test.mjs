/* The Autonomous Ops brief/plan (PRO+) must only see the caller's own SOC cases.
 * Regression for a residual cross-tenant leak: loadOpsContext listed soc_cases with
 * no org filter, so a PRO tenant's executive brief was built from EVERY tenant's cases.
 */
import { describe, it, expect } from 'vitest';
import { loadOpsContext } from '../src/handlers/autonomousOpsHandler.js';

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
