/* A transient D1 "requests queued for too long" overload (verified live in
 * production — self-resolves within ~90s with zero intervention) was flipping
 * /api/platform/health's status to DEGRADED and eop/health.js's probes to
 * degraded/major_outage on a SINGLE failed query, painting a sitewide
 * "Database, Threat Intel, Payments degraded" banner across the live homepage
 * for every visitor even though the database was not actually down.
 *
 * Fix: each D1 probe query now goes through lib/resilience.js's withRetry()
 * (2 attempts, 150ms backoff) before the probe reports the component
 * unhealthy. These tests prove both halves: a single transient blip is now
 * absorbed silently, AND a genuinely sustained failure still correctly
 * reports unhealthy — the fix masks blips, not real outages.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';
import { probeD1, probeIntel, probePayments, probeAuth, handleHealthV2 } from '../src/handlers/eop/health.js';

const D1_OVERLOAD_ERROR = 'D1_ERROR: D1 DB is overloaded. Requests queued for too long.';

// A real in-memory SQLite D1 stub whose queries matching `failPattern` can be
// made to throw a real D1-shaped overload error for the first N calls before
// succeeding — simulating exactly the transient blip observed live. Queries
// not matching failPattern always run for real against the in-memory schema.
function makeFlakyD1({ failPattern = /SELECT 1 AS alive/, failFirstNCalls = 0, alwaysFail = false } = {}) {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('CREATE TABLE threat_intel (id TEXT PRIMARY KEY, ingested_at TEXT)');
  sqlite.exec('CREATE TABLE payments (id TEXT PRIMARY KEY, status TEXT)');
  sqlite.exec('CREATE TABLE orders (id TEXT PRIMARY KEY)');
  sqlite.exec('CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT)');
  sqlite.exec("CREATE TABLE operational_history (id TEXT PRIMARY KEY, component TEXT, status TEXT, latency_ms INTEGER, version TEXT, error_detail TEXT, checked_at TEXT)");
  let matchedCalls = 0;
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async first() {
      if (failPattern.test(sql)) {
        matchedCalls++;
        if (alwaysFail || matchedCalls <= failFirstNCalls) throw new Error(D1_OVERLOAD_ERROR);
      }
      return sqlite.prepare(sql).get(...b) ?? null;
    },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { prepare: wrap, _matchedCalls: () => matchedCalls };
}

function makeKV() {
  const store = new Map();
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
    async delete(k) { store.delete(k); },
  };
}
const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

describe('eop/health.js probes — absorb a single transient D1 blip', () => {
  it('probeD1 succeeds on the retry and reports operational, not major_outage', async () => {
    const env = { DB: makeFlakyD1({ failFirstNCalls: 1 }) };
    const result = await probeD1(env);
    expect(result.status).toBe('operational');
    expect(result.error).toBeUndefined();
    expect(env.DB._matchedCalls()).toBe(2); // 1 failure + 1 successful retry
  });

  it('probeIntel retries its own COUNT query and recovers from a single transient failure', async () => {
    const env = { DB: makeFlakyD1({ failPattern: /FROM threat_intel/, failFirstNCalls: 1 }) };
    const result = await probeIntel(env);
    expect(result.error).toBeUndefined();
    expect(result.detail).toBe('0 entries last 7d'); // real query ran (empty fixture table), not a probe failure
    expect(env.DB._matchedCalls()).toBe(2);
  });

  it('probeIntel still correctly reports degraded when its COUNT query is sustainedly failing', async () => {
    const env = { DB: makeFlakyD1({ failPattern: /FROM threat_intel/, alwaysFail: true }) };
    const result = await probeIntel(env);
    expect(result.status).toBe('degraded');
    expect(result.error).toContain('overloaded');
  });

  it('probeD1 still correctly reports major_outage when D1 is genuinely, sustainedly down (fix does not mask real outages)', async () => {
    const env = { DB: makeFlakyD1({ alwaysFail: true }) };
    const result = await probeD1(env);
    expect(result.status).toBe('major_outage');
    expect(result.error).toContain('overloaded');
    expect(env.DB._matchedCalls()).toBe(2); // exactly 2 attempts (D1_PROBE_RETRIES), not unbounded
  });

  it('probePayments and probeAuth also retry their own D1 query before failing', async () => {
    const envOk = { DB: makeFlakyD1({}), RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's' };
    const payments = await probePayments(envOk);
    expect(payments.status).toBe('operational');

    const envDown = { DB: { prepare: () => ({ bind() { return this; }, first: async () => { throw new Error(D1_OVERLOAD_ERROR); } }) }, JWT_SECRET: 'x' };
    const auth = await probeAuth(envDown);
    expect(auth.status).toBe('degraded');
    expect(auth.error).toContain('overloaded');
  });

  it('handleHealthV2 end-to-end: a single transient D1 blip no longer trips the platform into partial_outage/critical', async () => {
    const env = { DB: makeFlakyD1({ failFirstNCalls: 1 }), KV: makeKV(), RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's', JWT_SECRET: 'x' };
    const res = await handleHealthV2(new Request('https://x/api/platform/health/v2'), env);
    const body = await res.json();
    const db = body.components.find(c => c.name === 'D1 Database');
    expect(db.status).toBe('operational');
    expect(body.status).not.toBe('critical');
    expect(body.status).not.toBe('partial_outage');
  });

  it('handleHealthV2 end-to-end: a sustained D1 outage still correctly reports partial_outage/critical (real outages are not hidden)', async () => {
    const env = { DB: makeFlakyD1({ alwaysFail: true }), KV: makeKV(), RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's', JWT_SECRET: 'x' };
    const res = await handleHealthV2(new Request('https://x/api/platform/health/v2'), env);
    const body = await res.json();
    const db = body.components.find(c => c.name === 'D1 Database');
    expect(db.status).toBe('major_outage');
    expect(['partial_outage', 'critical']).toContain(body.status);
  });
});

describe('GET /api/platform/health (index.js) — full router, same fix', () => {
  it('a single transient D1 blip on the SELECT-1 probe no longer flips the banner to DEGRADED', async () => {
    const env = { DB: makeFlakyD1({ failFirstNCalls: 1 }), SECURITY_HUB_KV: makeKV(), RAZORPAY_KEY_ID: 'k' };
    const res = await worker.fetch(new Request('https://x/api/platform/health'), env, ctxStub);
    const body = await res.json();
    expect(body.status).toBe('OK');
    expect(body.db).toBe(true);
    expect(body.details.db.error).toBeUndefined();
  });

  it('a sustained D1 outage still correctly reports DEGRADED with the real error message (not silently hidden)', async () => {
    const env = { DB: makeFlakyD1({ alwaysFail: true }), SECURITY_HUB_KV: makeKV(), RAZORPAY_KEY_ID: 'k' };
    const res = await worker.fetch(new Request('https://x/api/platform/health'), env, ctxStub);
    const body = await res.json();
    expect(body.status).toBe('DEGRADED');
    expect(body.db).toBe(false);
    expect(body.details.db.error).toContain('overloaded');
  });
});
