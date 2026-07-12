/* Regression tests — automation-dashboard.html's dead/wrong endpoints
 * (full-frontend-audit follow-up, Tier 1 item #5; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * - Connector Health hit /api/integrations/connectors (owner-only internal
 *   domain, index.js:1550) instead of the real customer-facing
 *   /api/auto/integrations/connectors (handleAutoRoute).
 * - SIEM Test hit /api/integrations/test (same wrong domain) instead of
 *   /api/auto/integrations/test, and never checked the response body's
 *   `success` field — handleIntegrationTest always returns HTTP 200 even
 *   for a failed connection, so the UI unconditionally showed "Connection
 *   successful" as long as the request itself didn't throw.
 * - Usage tab read d.summary/d.quota/d.by_endpoint; handleUsageDashboard
 *   never computed summary/quota at all (permanently 0/∞) and called the
 *   endpoint breakdown top_endpoints, not by_endpoint.
 * - Governance tab read d.released/d.user_tier/d.quota_warning/
 *   d.throttle_limits; handleGovernance just returned the static
 *   API_MANIFEST (version/endpoints/deprecations only) with none of those
 *   per-caller fields.
 * - Webhooks list called JSON.parse() on w.events, which handleWebhookList
 *   already parses into a real array server-side — parsing an array throws,
 *   silently caught, leaving the list permanently empty.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { handleAutoRoute } from '../src/handlers/enterpriseAutomation.js';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/automation-dashboard.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

// ── Backend: real in-memory SQLite, same pattern as
// enterpriseAutomationTeamManagement.test.mjs — needed because these fixes
// rely on real SQLite date arithmetic (datetime('now','start of month')).
function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
}

const USER = { authenticated: true, userId: 'u1', tier: 'STARTER' }; // monthly_limit 600, daily_limit 20, burst_per_min 5

describe('handleUsageDashboard (GET /api/auto/usage) — summary/quota now populated', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE ops_usage_events (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL,
      ts TEXT DEFAULT (datetime('now')), endpoint TEXT NOT NULL,
      latency_ms INTEGER, cached INTEGER DEFAULT 0
    )`);
  });

  function insertEvent(id, ts, endpoint, cached) {
    env.SECURITY_HUB_DB._sqlite.prepare(
      `INSERT INTO ops_usage_events (id, org_id, user_id, ts, endpoint, latency_ms, cached) VALUES (?, 'o1', 'u1', ?, ?, 50, ?)`
    ).run(id, ts, endpoint, cached ? 1 : 0);
  }

  it('computes summary.total_calls/cache_hit_ratio and quota.month_calls/radar_limit/quota_pct from real rows', async () => {
    insertEvent('e1', new Date().toISOString(), '/api/radar/latest', 1);
    insertEvent('e2', new Date().toISOString(), '/api/radar/latest', 0);
    insertEvent('e3', new Date().toISOString(), '/api/scan/run', 0);

    const req = new Request('https://x/api/auto/usage?days=7');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/usage', 'GET');
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.summary.total_calls).toBe(3);
    expect(body.summary.cache_hit_ratio).toBeCloseTo(1 / 3, 5);
    expect(body.quota.month_calls).toBe(3);
    expect(body.quota.radar_limit).toBe(600); // STARTER monthly_limit
    expect(body.quota.quota_pct).toBeCloseTo((3 / 600) * 100, 1);
    expect(body.top_endpoints.length).toBeGreaterThan(0);
  });

  it('radar_limit is null (not -1) for an unlimited tier, matching the truthiness check the frontend already uses', async () => {
    const req = new Request('https://x/api/auto/usage?days=7');
    const res = await handleAutoRoute(req, env, { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' }, '/api/auto/usage', 'GET');
    const body = await res.json();
    expect(body.quota.radar_limit).toBeNull();
    expect(body.quota.quota_pct).toBe(0);
  });

  it('a row older than the `days` window is excluded from summary but a row from this calendar month still counts toward quota', async () => {
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    insertEvent('e_old', tenDaysAgo, '/api/radar/latest', 0);
    const req = new Request('https://x/api/auto/usage?days=7');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/usage', 'GET');
    const body = await res.json();
    expect(body.summary.total_calls).toBe(0); // outside the 7-day window
    // quota is calendar-month-to-date, independent of `days` — only excluded if the fixture is also outside the calendar month, which isn't asserted here to avoid month-boundary flakiness.
  });
});

describe('handleGovernance (GET /api/auto/governance) — user_tier/throttle_limits/released/quota_warning now populated', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE ops_usage_events (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL,
      ts TEXT DEFAULT (datetime('now')), endpoint TEXT NOT NULL,
      latency_ms INTEGER, cached INTEGER DEFAULT 0
    )`);
  });

  it('reports the real caller tier and its throttle limits, and released aliases last_updated', async () => {
    const req = new Request('https://x/api/auto/governance');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/governance', 'GET');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user_tier).toBe('STARTER');
    expect(body.throttle_limits).toEqual({ requests_per_minute: 5, requests_per_day: 20 });
    expect(body.released).toBe(body.last_updated);
    expect(Array.isArray(body.endpoints)).toBe(true); // static manifest data still present
  });

  it('requests_per_day is -1 (unlimited) for ENTERPRISE, matching the frontend\'s existing ===-1 check', async () => {
    const req = new Request('https://x/api/auto/governance');
    const res = await handleAutoRoute(req, env, { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' }, '/api/auto/governance', 'GET');
    const body = await res.json();
    expect(body.throttle_limits.requests_per_day).toBe(-1);
  });

  it('quota_warning is null when usage is well under the monthly limit', async () => {
    const req = new Request('https://x/api/auto/governance');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/governance', 'GET');
    const body = await res.json();
    expect(body.quota_warning).toBeNull();
  });

  it('quota_warning appears once usage crosses 80% of the monthly limit', async () => {
    // STARTER monthly_limit is 600 — insert 500 events this month (83%).
    const stmt = env.SECURITY_HUB_DB._sqlite.prepare(
      `INSERT INTO ops_usage_events (id, org_id, user_id, ts, endpoint) VALUES (?, 'o1', 'u1', datetime('now'), '/x')`
    );
    for (let i = 0; i < 500; i++) stmt.run(`e${i}`);
    const req = new Request('https://x/api/auto/governance');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/governance', 'GET');
    const body = await res.json();
    expect(body.quota_warning).not.toBeNull();
    expect(body.quota_warning.used).toBe(500);
    expect(body.quota_warning.limit).toBe(600);
  });
});

// ── Frontend ─────────────────────────────────────────────────────────────
describe('loadConnectors / testConnector — real /api/auto/integrations/* paths, real success check', () => {
  it('loadConnectors calls /api/auto/integrations/connectors, not the owner-only /api/integrations/connectors', () => {
    const body = fnBody('loadConnectors');
    expect(body).toContain("apiFetch('/api/auto/integrations/connectors')");
  });

  it('testConnector calls /api/auto/integrations/test and checks d.success before claiming success', () => {
    const body = fnBody('testConnector');
    expect(body).toContain("apiPost('/api/auto/integrations/test'");
    expect(body).toMatch(/if\s*\(\s*d\.success\s*\)/);
  });
});

describe('loadWebhooks — no longer double-parses an already-parsed array', () => {
  it('renders w.events directly instead of JSON.parse(w.events)', () => {
    const body = fnBody('loadWebhooks');
    expect(body).not.toContain('JSON.parse(w.events');
    expect(body).toContain('(w.events||[])');
  });
});

describe('loadUsage — reads the real top_endpoints field name', () => {
  it('no longer reads the nonexistent d.by_endpoint', () => {
    const body = fnBody('loadUsage');
    expect(body).not.toContain('d.by_endpoint');
    expect(body).toContain('d.top_endpoints');
  });
});
