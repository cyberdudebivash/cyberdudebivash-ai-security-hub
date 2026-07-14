/* /api/scan/stats was verified live in production returning total_scans=72/today=3
 * while /api/health and /api/platform/metrics reported 219/5 for the exact same
 * platform on the exact same request — a customer-visible contradiction on the
 * homepage dashboard (risk-block "Scans today" tile and the Command Centers).
 *
 * Root cause: this endpoint only ever maxed the KV 7-day counter against
 * scan_history, and never folded in scan_jobs — the fullest lifetime ledger that
 * /api/health and metricsHydration.js's fetchLiveMetricsFromD1 already fold in (see
 * metricsHydration.test.mjs's "agrees with /api/health (118), no understatement").
 * Same class of contradiction that test already covers for /api/platform/metrics —
 * this endpoint just never got the matching fix. This test proves it now does. */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

function makeD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('CREATE TABLE scan_history (id TEXT PRIMARY KEY, scanned_at TEXT, risk_score INTEGER)');
  sqlite.exec('CREATE TABLE scan_jobs (id TEXT PRIMARY KEY, created_at TEXT)');
  sqlite.exec('CREATE TABLE threat_intel (id TEXT PRIMARY KEY, severity TEXT)');

  // scan_history: 11 lifetime, 0 today — mirrors metricsHydration.test.mjs's mockDB.
  for (let i = 0; i < 11; i++) {
    sqlite.exec(`INSERT INTO scan_history (id, scanned_at, risk_score) VALUES ('sh${i}', '2020-01-01', 10)`);
  }
  // scan_jobs: 118 lifetime / 5 today — the fuller ledger /api/health reports.
  const now = new Date().toISOString();
  for (let i = 0; i < 118; i++) {
    const ts = i < 5 ? now : '2020-01-01T00:00:00.000Z';
    sqlite.exec(`INSERT INTO scan_jobs (id, created_at) VALUES ('sj${i}', '${ts}')`);
  }

  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { prepare: wrap };
}

function makeEmptyKV() {
  // Empty on purpose — isolates the test to the D1 ledgers (scan_history vs scan_jobs).
  return { async get() { return null; }, async put() {} };
}

const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

describe('GET /api/scan/stats — agrees with /api/health and /api/platform/metrics', () => {
  it('folds scan_jobs into total_scans/today instead of under-reporting against KV+scan_history alone', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeEmptyKV() };
    const res = await worker.fetch(new Request('https://x/api/scan/stats'), env, ctxStub);
    const body = await res.json();

    expect(body.success).toBe(true);
    // Before the fix this was max(KV 0, scan_history 11) = 11 — contradicting
    // /api/health's 118 for the exact same underlying data.
    expect(body.total_scans).toBe(118);
    expect(body.today).toBe(5);
    expect(body.scan_jobs).toBe(118);
    expect(body.d1_scans).toBe(11); // scan_history alone, retained for transparency
  });
});
