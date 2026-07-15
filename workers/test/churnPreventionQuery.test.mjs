/* Phase 6 (Customer Lifecycle Completion Program) — Churn Prevention Engine.
 *
 * runChurnPrevention() (workers/src/services/automationEngine.js) is what's
 * supposed to find paying customers who have gone quiet for 7+ days and
 * queue a retention/win-back email for them. It runs unconditionally on
 * every cron tick (workers/src/index.js:9134-9148).
 *
 * The bug: the query filtered on `l.status = 'active'`, a column that has
 * never existed on the `leads` table (schema_master.sql:1730-1760 defines
 * `funnel_stage` and `stage`, not `status`). D1's `.all().catch(() => ({
 * results: [] }))` swallowed the resulting "no such column" error on every
 * single cron run, so `at_risk` has always silently been 0 in production —
 * zero retention emails have ever been queued for an inactive paying
 * customer since this code existed. No test file referenced
 * runChurnPrevention before this one, so nothing caught it. Same bug class
 * and same silent-catch shape as renewalQueueSeeding.test.mjs's
 * seedRenewalQueue35d fix (PR #264) — proven here against a real
 * node:sqlite D1 rather than a permissive always-succeeds mock, which would
 * hide exactly this class of bug.
 *
 * `funnel_stage = 'customer'` is the established "currently paying,
 * converted" signal used identically elsewhere (lifecycleEngine.js:136 sets
 * it on conversion; revenueKPI.js:53 reads it as the MRR "converted"
 * count; leads.js:211 and index.js:9247 both exclude 'customer' and
 * 'churned' together to mean "still a pre-conversion lead").
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { runChurnPrevention } from '../src/services/automationEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE leads (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, domain TEXT,
    source TEXT DEFAULT 'scan', is_enterprise INTEGER DEFAULT 0,
    plan TEXT DEFAULT 'free', lead_score INTEGER DEFAULT 0,
    funnel_stage TEXT DEFAULT 'visitor', scan_count INTEGER DEFAULT 0,
    converted_at TEXT, created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE scan_history (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))), user_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    _store: store,
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  };
}

function daysAgo(n) {
  return new Date(Date.now() - n * 86400000).toISOString().replace('T', ' ').slice(0, 19);
}

describe('runChurnPrevention — at-risk paying-customer query (previously always found 0)', () => {
  it('flags a paying customer inactive 7+ days and queues a retention email', async () => {
    const db = makeRealD1();
    const kv = makeKV();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, plan, lead_score, funnel_stage) VALUES ('l_1','quiet@acme.test','PRO',80,'customer')`
    ).run();
    db._sqlite.prepare(
      `INSERT INTO scan_history (user_id, created_at) VALUES ('l_1', ?)`
    ).run(daysAgo(10));

    const result = await runChurnPrevention({ DB: db, SECURITY_HUB_KV: kv });
    expect(result.success).toBe(true);
    expect(result.at_risk).toBe(1);
    expect(result.emails_queued).toBe(1);

    const queued = [...kv._store.keys()].find(k => k.startsWith('email:queue:retention:'));
    expect(queued).toBeTruthy();
    const payload = JSON.parse(kv._store.get(queued));
    expect(payload.email).toBe('quiet@acme.test');
    expect(payload.plan).toBe('PRO');
  });

  it('does not flag a free-plan lead', async () => {
    const db = makeRealD1();
    const kv = makeKV();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, plan, funnel_stage) VALUES ('l_2','free@acme.test','free','customer')`
    ).run();
    db._sqlite.prepare(`INSERT INTO scan_history (user_id, created_at) VALUES ('l_2', ?)`).run(daysAgo(30));

    const result = await runChurnPrevention({ DB: db, SECURITY_HUB_KV: kv });
    expect(result.at_risk).toBe(0);
  });

  it('does not flag a lead that never converted (funnel_stage still visitor/lead)', async () => {
    const db = makeRealD1();
    const kv = makeKV();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, plan, funnel_stage) VALUES ('l_3','prospect@acme.test','PRO','visitor')`
    ).run();

    const result = await runChurnPrevention({ DB: db, SECURITY_HUB_KV: kv });
    expect(result.at_risk).toBe(0);
  });

  it('does not flag a paying customer who scanned within the last 7 days', async () => {
    const db = makeRealD1();
    const kv = makeKV();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, plan, funnel_stage) VALUES ('l_4','active@acme.test','ENTERPRISE','customer')`
    ).run();
    db._sqlite.prepare(`INSERT INTO scan_history (user_id, created_at) VALUES ('l_4', ?)`).run(daysAgo(2));

    const result = await runChurnPrevention({ DB: db, SECURITY_HUB_KV: kv });
    expect(result.at_risk).toBe(0);
  });

  it('does not re-queue a customer who already has a pending retention email', async () => {
    const db = makeRealD1();
    const kv = makeKV();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, plan, funnel_stage) VALUES ('l_5','dup@acme.test','PRO','customer')`
    ).run();
    db._sqlite.prepare(`INSERT INTO scan_history (user_id, created_at) VALUES ('l_5', ?)`).run(daysAgo(15));
    await kv.put('churn:risk:dup@acme.test', '1');

    const result = await runChurnPrevention({ DB: db, SECURITY_HUB_KV: kv });
    expect(result.at_risk).toBe(1); // still identified as at-risk...
    expect(result.emails_queued).toBe(0); // ...but not re-queued
  });
});
