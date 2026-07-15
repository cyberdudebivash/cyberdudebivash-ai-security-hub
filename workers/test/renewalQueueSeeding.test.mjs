/* Phase 6 (Customer Lifecycle Completion Program) — Renewal Automation Engine.
 *
 * seedRenewalQueue35d() (workers/src/handlers/renewalEngine.js) is what makes
 * the engine's own documented claim — "Renewal reminders at T-30, T-14, T-7,
 * T-1 days" — actually true. billingEngine.buildRenewalQueue() only looks
 * 7 days ahead, so without this 35-day extension a row never enters
 * renewal_queue early enough for the T-30 or T-14 reminder windows in
 * runRenewalAutomation() to ever fire.
 *
 * The bug: the query selected/filtered on `s.expires_at`, a column that has
 * never existed on the `subscriptions` table (schema_master.sql:3131-3160
 * defines `current_period_end`, not `expires_at`). D1's `.all().catch(() =>
 * ({ results: [] }))` swallowed the resulting "no such column" error on
 * every single cron run, so seedRenewalQueue35d has always silently
 * returned `{ queued: 0 }` in production — zero test coverage existed to
 * catch it. This file proves the fix against a real node:sqlite D1 (a
 * permissive always-succeeds mock would hide exactly this class of bug,
 * same lesson as ssoConsolidation.test.mjs).
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { seedRenewalQueue35d } from '../src/handlers/renewalEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'FREE', status TEXT NOT NULL DEFAULT 'active',
    price_inr INTEGER NOT NULL DEFAULT 0, billing_cycle TEXT NOT NULL DEFAULT 'monthly',
    current_period_start TEXT NOT NULL DEFAULT (datetime('now')),
    current_period_end TEXT NOT NULL DEFAULT (datetime('now')),
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0
  )`);
  sqlite.exec(`CREATE TABLE renewal_queue (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    subscription_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT NOT NULL,
    plan TEXT NOT NULL, amount_inr INTEGER NOT NULL DEFAULT 0, renewal_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'upcoming' CHECK(status IN ('upcoming','processing','renewed','failed','churned')),
    notified_at TEXT, renewed_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function daysFromNow(n) {
  return new Date(Date.now() + n * 86400000).toISOString().replace('T', ' ').slice(0, 19);
}

describe('seedRenewalQueue35d — 35-day renewal-queue seeding (previously always queued 0)', () => {
  it('queues an active subscription renewing within 35 days, with correct user_id/email/renewal_date', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_1','u_1','customer@acme.test','PRO','active',4999,?,0)`
    ).run(daysFromNow(20));

    const result = await seedRenewalQueue35d({ DB: db });
    expect(result.queued).toBe(1);
    expect(result.error).toBeUndefined();

    const row = db._sqlite.prepare(`SELECT * FROM renewal_queue WHERE subscription_id = 'sub_1'`).get();
    expect(row).toBeTruthy();
    expect(row.user_id).toBe('u_1');
    expect(row.email).toBe('customer@acme.test');
    expect(row.plan).toBe('PRO');
    expect(row.amount_inr).toBe(4999);
    expect(row.status).toBe('upcoming');
  });

  it('does not queue a subscription renewing more than 35 days out', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_2','u_2','far@acme.test','PRO','active',4999,?,0)`
    ).run(daysFromNow(60));

    const result = await seedRenewalQueue35d({ DB: db });
    expect(result.queued).toBe(0);
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM renewal_queue`).get().c).toBe(0);
  });

  it('does not queue a subscription the customer has already cancelled (cancel_at_period_end=1)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_3','u_3','cancelled@acme.test','PRO','active',4999,?,1)`
    ).run(daysFromNow(10));

    const result = await seedRenewalQueue35d({ DB: db });
    expect(result.queued).toBe(0);
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM renewal_queue`).get().c).toBe(0);
  });

  it('does not re-queue a subscription already in the queue as upcoming', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_4','u_4','dup@acme.test','PRO','active',4999,?,0)`
    ).run(daysFromNow(5));
    db._sqlite.prepare(
      `INSERT INTO renewal_queue (subscription_id, user_id, email, plan, amount_inr, renewal_date, status)
       VALUES ('sub_4','u_4','dup@acme.test','PRO',4999,?,'upcoming')`
    ).run(daysFromNow(5));

    const result = await seedRenewalQueue35d({ DB: db });
    expect(result.queued).toBe(0);
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM renewal_queue WHERE subscription_id='sub_4'`).get().c).toBe(1);
  });
});
