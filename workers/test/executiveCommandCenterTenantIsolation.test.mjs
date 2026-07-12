// CAP-SEC-AUDIT (Enterprise Production Certification Program, 2026-07-12) —
// workers/src/handlers/executiveCommandCenter.js. The router-level tier gate
// (workers/src/index.js's /api/executive/* catch-all, covered by the existing
// executiveCommandCenterGate.test.mjs) correctly rejects anonymous/FREE-tier
// callers. But that gate resolved a real authCtx purely to make its own
// allow/deny decision, then called this handler with none of it — so every
// route below independently trusted a client-supplied org_id (body.org_id /
// ?org_id=, defaulting to the literal 'default'). Net effect: ANY caller who
// legitimately cleared the tier gate — even the cheapest PRO-tier paying
// customer — could read or write ANY OTHER org's FAIR risk models, KRI
// dashboards, and board/CISO reports just by supplying a different org_id.
//
// Fixed: org_id is now derived exclusively from the authenticated session
// inside handleExecutiveCommandCenter and passed down explicitly to every
// sub-route, mirroring the established pattern in handlers/aiGovernancePro.js.
import { describe, it, expect, beforeEach } from 'vitest';
import { handleExecutiveCommandCenter } from '../src/handlers/executiveCommandCenter.js';

function makeDB() {
  const fair = new Map();
  const kri = new Map();
  const reports = new Map();
  return {
    _fair: fair, _kri: kri, _reports: reports,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() {
              if (sql.startsWith('INSERT INTO fair_risk_assessments')) {
                const [id, org_id, scenario_name] = args;
                fair.set(id, { id, org_id, scenario_name });
              } else if (sql.startsWith('INSERT OR REPLACE INTO executive_kri_values')) {
                const [org_id, period, kri_values] = args;
                kri.set(`${org_id}:${period}`, { kri_values });
              } else if (sql.startsWith('INSERT INTO executive_reports')) {
                const [id, org_id, report_type] = args;
                reports.set(id, { id, org_id, report_type });
              }
              return { success: true };
            },
            async first() {
              if (sql.includes('FROM executive_kri_values')) {
                const [org_id, period] = args;
                return kri.get(`${org_id}:${period}`) || null;
              }
              return null;
            },
            async all() {
              if (sql.includes('FROM fair_risk_assessments')) {
                const [org_id] = args;
                return { results: [...fair.values()].filter(r => r.org_id === org_id) };
              }
              return { results: [] };
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
    _store: store,
    async get(key, type) { const v = store.get(key); return v === undefined ? null : (type === 'json' ? JSON.parse(v) : v); },
    async put(key, value) { store.set(key, value); },
  };
}

function req(url, { method = 'GET', body } = {}) {
  return { url, method, json: async () => body ?? {} };
}

const userA = { authenticated: true, userId: 'user-A', org_id: 'org-A' };
const userB = { authenticated: true, userId: 'user-B', org_id: 'org-B' };
const anon = { authenticated: false };

describe('handleExecutiveCommandCenter — requires real auth, org_id server-derived', () => {
  let env;
  beforeEach(() => { env = { DB: makeDB(), KV: makeKV() }; });

  it('rejects an anonymous caller reaching the handler directly', async () => {
    const res = await handleExecutiveCommandCenter(req('https://x/api/executive/risk/fair', { method: 'POST', body: {} }), env, anon);
    expect(res.status).toBe(401);
  });

  it('POST /api/executive/risk/fair stores the assessment under the caller\'s real org_id, ignoring a spoofed one', async () => {
    const res = await handleExecutiveCommandCenter(req('https://x/api/executive/risk/fair', {
      method: 'POST', body: { org_id: 'org-SPOOFED', scenario_name: 'Ransomware', threat_event_frequency: 5, vulnerability: 0.3, asset_value: 1000000, loss_magnitude_factor: 0.5 },
    }), env, userA);
    expect(res.status).toBe(200);
    const stored = [...env.DB._fair.values()][0];
    expect(stored.org_id).toBe('org-A');
  });

  it('user B cannot see user A\'s risk portfolio by supplying org_id=org-A', async () => {
    await handleExecutiveCommandCenter(req('https://x/api/executive/risk/fair', {
      method: 'POST', body: { scenario_name: 'A-scenario', threat_event_frequency: 1, vulnerability: 0.1, asset_value: 100, loss_magnitude_factor: 0.1 },
    }), env, userA);
    const res = await handleExecutiveCommandCenter(req('https://x/api/executive/risk/portfolio?org_id=org-A'), env, userB);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.orgId).toBe('org-B');
    expect(body.totalScenarios).toBe(0);
  });

  it('user B cannot read user A\'s KRI dashboard by supplying org_id=org-A', async () => {
    await handleExecutiveCommandCenter(req('https://x/api/executive/kri/submit', {
      method: 'POST', body: { org_id: 'org-A', period: '2026-07', values: { 'KRI-001': 5 } },
    }), env, userA);
    const res = await handleExecutiveCommandCenter(req('https://x/api/executive/kri/dashboard', {
      method: 'POST', body: { org_id: 'org-A', period: '2026-07' },
    }), env, userB);
    expect(res.status).toBe(200);
    const body = await res.json();
    // user B's own submission never happened, so every KRI should be NOT_REPORTED,
    // not user A's real submitted values.
    expect(body.kris.every(k => k.status === 'NOT_REPORTED')).toBe(true);
  });

  it('user B cannot fetch user A\'s board report by report id + org_id=org-A', async () => {
    const boardRes = await handleExecutiveCommandCenter(req('https://x/api/executive/reports/board', {
      method: 'POST', body: {},
    }), env, userA);
    const board = await boardRes.json();
    const res = await handleExecutiveCommandCenter(req(`https://x/api/executive/reports/${board.reportId}?org_id=org-A`), env, userB);
    expect(res.status).toBe(404);
  });

  it('the real owner can fetch their own board report', async () => {
    const boardRes = await handleExecutiveCommandCenter(req('https://x/api/executive/reports/board', {
      method: 'POST', body: {},
    }), env, userA);
    const board = await boardRes.json();
    const res = await handleExecutiveCommandCenter(req(`https://x/api/executive/reports/${board.reportId}`), env, userA);
    expect(res.status).toBe(200);
  });

  it('board report recommendations no longer cite the fabricated "340% YoY" statistic (AI-integrity sweep)', async () => {
    const boardRes = await handleExecutiveCommandCenter(req('https://x/api/executive/reports/board', {
      method: 'POST', body: {},
    }), env, userA);
    const board = await boardRes.json();
    const rationales = JSON.stringify(board.boardRecommendations);
    expect(rationales).not.toContain('340%');
  });
});
