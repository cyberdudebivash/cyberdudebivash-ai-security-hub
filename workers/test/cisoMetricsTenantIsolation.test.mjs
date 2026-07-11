/* Regression tests for a confirmed cross-tenant data leak in the CISO Command
 * Center (workers/src/handlers/cisoMetrics.js): every PRO/ENTERPRISE/MSSP
 * customer viewing "CISO Executive Metrics" — explicitly subtitled "derived
 * from your scan data" — actually saw the platform-wide aggregate across
 * EVERY other customer's scan history and incidents, because:
 *   1. fetchRealMetricsFromD1() queried scan_history with no WHERE clause,
 *   2. loadIncidents()/saveIncidents() used one single shared KV key for
 *      every caller (ciso:incidents), and
 *   3. handleGetCISOMetrics() cached the fully-computed response under one
 *      single shared KV key (ciso:metrics_cache) — so even correctly-scoped
 *      data would have leaked across users via the cache alone.
 * The board-report PDF export (handleExportCisoPdf) inherits the same bug
 * via handleGetCISOReport, so it's covered implicitly by the same fix.
 *
 * Fixed by deriving every KV/D1 scope from authCtx's own user_id — the same
 * per-tenant pattern already used correctly elsewhere in this codebase (e.g.
 * workers/src/handlers/orgManagement.js) — never a shared/global key.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleGetCISOMetrics, handleGetIncidents, handleCreateIncident,
  handleGetRiskRegister, handleGetCISOPosture, handleGetComplianceStatus,
} from '../src/handlers/cisoMetrics.js';
import { isRealUser } from '../src/auth/middleware.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE scan_history (
    id TEXT PRIMARY KEY, user_id TEXT, job_id TEXT, scan_id TEXT, target TEXT,
    module TEXT, risk_score REAL DEFAULT 0, risk_level TEXT, grade TEXT,
    data_source TEXT, status TEXT DEFAULT 'completed',
    scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')), findings TEXT
  )`);
  sqlite.exec(`CREATE TABLE mythos_runs (
    id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'completed',
    tools_generated INTEGER DEFAULT 0, tools_published INTEGER DEFAULT 0,
    tools_failed INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0,
    intel_count INTEGER DEFAULT 0, run_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE threat_intel (
    id TEXT PRIMARY KEY, severity TEXT DEFAULT 'MEDIUM', epss_score REAL,
    source TEXT DEFAULT 'NVD', created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    async get(k, opts) { const v = store.has(k) ? store.get(k) : null; const wantsJson = opts === 'json' || opts?.type === 'json'; return wantsJson && v != null ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, v); },
    _store: store,
  };
}

const userA = { authenticated: true, method: 'jwt', user_id: 'user-a', tier: 'ENTERPRISE' };
const userB = { authenticated: true, method: 'jwt', user_id: 'user-b', tier: 'ENTERPRISE' };
const anon  = { authenticated: true, method: 'ip_fallback', user_id: null, tier: 'FREE' };

describe('CISO Command Center — tenant isolation (previously a shared platform-wide aggregate)', () => {
  let env;
  beforeEach(() => {
    const D = makeRealD1();
    D._sqlite.prepare(`INSERT INTO scan_history (id, user_id, module, risk_score, risk_level, created_at) VALUES (?,?,?,?,?,datetime('now'))`)
      .run('s1', 'user-a', 'domain', 92, 'CRITICAL');
    D._sqlite.prepare(`INSERT INTO scan_history (id, user_id, module, risk_score, risk_level, created_at) VALUES (?,?,?,?,?,datetime('now'))`)
      .run('s2', 'user-b', 'domain', 10, 'LOW');
    env = { SECURITY_HUB_DB: D, SECURITY_HUB_KV: makeKV() };
  });

  it('anonymous callers cannot reach posture/compliance-status (both previously had zero auth check)', async () => {
    expect((await handleGetCISOPosture(new Request('https://x/api/ciso/posture'), env, anon)).status).toBe(401);
    expect((await handleGetComplianceStatus(new Request('https://x/api/ciso/compliance-status'), env, anon)).status).toBe(401);
  });

  it('handleGetCISOMetrics: user A only sees their own scan_history rows, not user B\'s', async () => {
    const resA = await handleGetCISOMetrics(new Request('https://x/api/ciso/metrics'), env, userA);
    const bodyA = (await resA.json()).data;
    expect(bodyA.platform.total_scans).toBe(1);
    expect(bodyA.platform.critical_findings).toBe(1);

    const resB = await handleGetCISOMetrics(new Request('https://x/api/ciso/metrics'), env, userB);
    const bodyB = (await resB.json()).data;
    expect(bodyB.platform.total_scans).toBe(1);
    expect(bodyB.platform.critical_findings).toBe(0);
  });

  it('the 5-minute response cache is namespaced per user, not a single shared key', async () => {
    await handleGetCISOMetrics(new Request('https://x/api/ciso/metrics'), env, userA);
    const keys = [...env.SECURITY_HUB_KV._store.keys()];
    expect(keys).toContain('ciso:metrics_cache:user-a');
    expect(keys).not.toContain('ciso:metrics_cache');

    // Calling as user B must NOT be served user A's cached payload.
    const resB = await handleGetCISOMetrics(new Request('https://x/api/ciso/metrics'), env, userB);
    const bodyB = (await resB.json()).data;
    expect(bodyB.platform.critical_findings).toBe(0);
  });

  it('incidents created by user A are invisible to user B (previously one shared KV list)', async () => {
    const createRes = await handleCreateIncident(new Request('https://x/api/ciso/incidents', {
      method: 'POST', body: JSON.stringify({ title: 'Confidential breach at Org A' }),
    }), env, userA);
    expect(createRes.status).toBe(200);

    const bIncidents = await handleGetIncidents(new Request('https://x/api/ciso/incidents'), env, userB);
    const bBody = (await bIncidents.json()).data;
    expect(bBody.total).toBe(0);
    expect(bBody.incidents).toEqual([]);

    const aIncidents = await handleGetIncidents(new Request('https://x/api/ciso/incidents'), env, userA);
    const aBody = (await aIncidents.json()).data;
    expect(aBody.total).toBe(1);
    expect(aBody.incidents[0].title).toBe('Confidential breach at Org A');
  });

  it('risk register incident-derived entries are also tenant-isolated', async () => {
    await handleCreateIncident(new Request('https://x/api/ciso/incidents', {
      method: 'POST', body: JSON.stringify({ title: 'Org A active incident', severity: 'CRITICAL' }),
    }), env, userA);

    const regB = (await (await handleGetRiskRegister(new Request('https://x/api/ciso/risk-register'), env, userB)).json()).data;
    expect(regB.risk_register.some(r => r.title?.includes('Org A active incident'))).toBe(false);

    const regA = (await (await handleGetRiskRegister(new Request('https://x/api/ciso/risk-register'), env, userA)).json()).data;
    expect(regA.risk_register.some(r => r.title?.includes('Org A active incident'))).toBe(true);
  });
});

describe('isRealUser contract sanity (used throughout this fix)', () => {
  it('rejects anonymous IP-fallback, accepts JWT principal', () => {
    expect(isRealUser(anon)).toBe(false);
    expect(isRealUser(userA)).toBe(true);
  });
});
