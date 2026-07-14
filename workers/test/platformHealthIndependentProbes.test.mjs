/* GET /api/platform/health was verified live in production showing "Database,
 * Threat Intel, Payments" all degraded together in a single banner. Root cause:
 * the intel and revenue probes were gated behind `checks.db` (step 2's own
 * result) instead of running their own independent query — `if (env.DB &&
 * checks.db) { ...query... } else { checks.X = false }`. Any time the DB
 * self-check's own 2-attempt/150ms retry didn't recover within THIS request,
 * intel and revenue were force-failed without ever attempting their own
 * queries, so a single D1 blip always painted all three components degraded
 * together, even when intel/revenue's own queries would have succeeded.
 *
 * Fix: intel and revenue now only require `env.DB` (the binding) to attempt
 * their own independently-retried query, exactly like the standalone
 * probeIntel/probePayments in eop/health.js already did. This test proves that
 * when the DB self-check is sustainedly failing but threat_intel/payments are
 * fine, intel and revenue now correctly report healthy instead of cascading. */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

// A real in-memory SQLite D1 stub whose `SELECT 1 AS alive` probe always fails
// (simulating a DB self-check that never recovers within its own retry budget),
// while threat_intel and payments queries run for real against fixture data.
function makeDbCheckAlwaysFailsD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('CREATE TABLE threat_intel (id TEXT PRIMARY KEY, ingested_at TEXT)');
  sqlite.exec('CREATE TABLE payments (id TEXT PRIMARY KEY, status TEXT)');
  sqlite.exec("INSERT INTO threat_intel (id, ingested_at) VALUES ('t1', datetime('now'))");
  sqlite.exec("INSERT INTO payments (id, status) VALUES ('p1', 'completed')");

  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async first() {
      if (/SELECT 1 AS alive/.test(sql)) throw new Error('D1_ERROR: D1 DB is overloaded. Requests queued for too long.');
      return sqlite.prepare(sql).get(...b) ?? null;
    },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { prepare: wrap };
}

function makeKV() {
  const store = new Map();
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
    async delete(k) { store.delete(k); },
  };
}

describe('GET /api/platform/health — intel/revenue no longer cascade off a DB probe failure', () => {
  it('reports intel and revenue healthy even while the DB self-check is sustainedly failing', async () => {
    const env = {
      DB: makeDbCheckAlwaysFailsD1(),
      SECURITY_HUB_KV: makeKV(),
      RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's',
    };
    const res = await worker.fetch(new Request('https://x/api/platform/health'), env, ctxStub);
    const body = await res.json();

    expect(body.db).toBe(false); // correctly reflects the real, sustained DB probe failure
    // Before the fix these were force-failed alongside db with no query ever attempted.
    expect(body.intel).toBe(true);
    expect(body.revenue).toBe(true);
    expect(body.status).toBe('DEGRADED'); // not DOWN — 3 of 4 checks genuinely pass

    const intelComponent = body.eop.components.find(c => c.name === 'Threat Intelligence');
    const paymentsComponent = body.eop.components.find(c => c.name === 'Payment System');
    const dbComponent = body.eop.components.find(c => c.name === 'D1 Database');
    expect(intelComponent.status).toBe('operational');
    expect(paymentsComponent.status).toBe('operational');
    expect(dbComponent.status).toBe('major_outage');
  });
});
