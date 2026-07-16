/* Customer Lifecycle Audit (2026-07-16) — Subscription Expiry Enforcement.
 *
 * enforceSubscriptionExpiry() (workers/src/handlers/renewalEngine.js) is what
 * makes the platform's billing model actually work: since no auto-recharge
 * exists (billingEngine.runPaymentRecovery is reminder-only — see its own
 * TODO), every paid subscription is a one-time charge that must eventually
 * lapse back to FREE once current_period_end passes, whether the customer
 * explicitly cancelled (cancel_at_period_end=1, left 'active' until period
 * end by handleCancelSubscription) or simply never renewed.
 *
 * The bug (in the inline cron block this function replaces, workers/src/index.js):
 *   1. The query selected/filtered on `s.expires_at`, a column that has never
 *      existed on the `subscriptions` table (schema_master.sql:3131-3160
 *      defines `current_period_end`, not `expires_at` — same defect class as
 *      seedRenewalQueue35d, fixed in PR #264, renewalQueueSeeding.test.mjs).
 *   2. Even past that, the UPDATE set `status = 'expired'`, a value absent
 *      from the table's own CHECK(status IN ('trialing','active','past_due',
 *      'cancelled','paused')) constraint — D1 batches are transactional, so
 *      this would have rolled back the paired `users.tier` downgrade too.
 * Both errors were silently swallowed by `.catch(() => ({ results: [] }))` /
 * `.catch(...)`, so this enforcement has never downgraded a single subscriber
 * since it was added — paying customers who complete one charge retain
 * paid-tier access indefinitely. This file proves the fix against a real
 * node:sqlite D1 with the actual CHECK constraint in place (a permissive
 * always-succeeds mock would hide exactly this class of bug).
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { enforceSubscriptionExpiry } from '../src/handlers/renewalEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'FREE'
      CHECK(plan IN ('FREE','STARTER','PRO','ENTERPRISE','MSSP')),
    status TEXT NOT NULL DEFAULT 'active'
      CHECK(status IN ('trialing','active','past_due','cancelled','paused')),
    price_inr INTEGER NOT NULL DEFAULT 0,
    current_period_end TEXT NOT NULL DEFAULT (datetime('now')),
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'FREE' CHECK(tier IN ('FREE','STARTER','PRO','ENTERPRISE','MSSP'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) {
      sqlite.exec('BEGIN');
      try {
        for (const s of stmts) await s.run();
        sqlite.exec('COMMIT');
      } catch (e) {
        sqlite.exec('ROLLBACK');
        throw e;
      }
    },
  };
}

function daysFromNow(n) {
  return new Date(Date.now() + n * 86400000).toISOString().replace('T', ' ').slice(0, 19);
}

describe('enforceSubscriptionExpiry — downgrade lapsed subscribers to FREE (previously always downgraded 0)', () => {
  it('downgrades a subscriber whose current_period_end has passed, and marks the subscription cancelled', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('u_1','lapsed@acme.test','PRO')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_1','u_1','lapsed@acme.test','PRO','active',149900,?,0)`
    ).run(daysFromNow(-2));

    const result = await enforceSubscriptionExpiry({ DB: db });
    expect(result.error).toBeUndefined();
    expect(result.downgraded).toBe(1);

    const user = db._sqlite.prepare(`SELECT tier FROM users WHERE id='u_1'`).get();
    expect(user.tier).toBe('FREE');
    const sub = db._sqlite.prepare(`SELECT status FROM subscriptions WHERE id='sub_1'`).get();
    expect(sub.status).toBe('cancelled');
  });

  it('downgrades a subscriber who explicitly cancelled once their grace period elapses', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('u_2','cancelled@acme.test','STARTER')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_2','u_2','cancelled@acme.test','STARTER','active',99900,?,1)`
    ).run(daysFromNow(-1));

    const result = await enforceSubscriptionExpiry({ DB: db });
    expect(result.downgraded).toBe(1);
    const user = db._sqlite.prepare(`SELECT tier FROM users WHERE id='u_2'`).get();
    expect(user.tier).toBe('FREE');
  });

  it('does not touch a subscription still within its current period', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('u_3','active@acme.test','PRO')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_3','u_3','active@acme.test','PRO','active',149900,?,0)`
    ).run(daysFromNow(20));

    const result = await enforceSubscriptionExpiry({ DB: db });
    expect(result.downgraded).toBe(0);
    const user = db._sqlite.prepare(`SELECT tier FROM users WHERE id='u_3'`).get();
    expect(user.tier).toBe('PRO');
  });

  it('never downgrades ENTERPRISE or MSSP tier even if a stray subscriptions row expires', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('u_4','enterprise@acme.test','ENTERPRISE')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_4','u_4','enterprise@acme.test','ENTERPRISE','active',149900,?,0)`
    ).run(daysFromNow(-5));

    await enforceSubscriptionExpiry({ DB: db });
    const user = db._sqlite.prepare(`SELECT tier FROM users WHERE id='u_4'`).get();
    expect(user.tier).toBe('ENTERPRISE');
  });

  it('regression guard: the old buggy column/status-value combination would have failed against this real schema', async () => {
    const db = makeRealD1();
    expect(() => db._sqlite.prepare(
      `SELECT expires_at FROM subscriptions LIMIT 1`
    ).all()).toThrow();

    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end)
       VALUES ('sub_check','u_check','check@acme.test','PRO','active',149900,datetime('now'))`
    ).run();
    expect(() => db._sqlite.prepare(
      `UPDATE subscriptions SET status = 'expired' WHERE id = 'sub_check'`
    ).run()).toThrow();
  });
});
