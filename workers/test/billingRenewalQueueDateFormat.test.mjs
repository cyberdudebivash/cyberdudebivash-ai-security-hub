/* Follow-up (2026-07-16 continuation session, PHASE7 §6) — billingEngine.js
 * buildRenewalQueue() sibling of the date-format mismatch already fixed in
 * enforceSubscriptionExpiry/seedRenewalQueue35d (renewalEngine.js).
 *
 * The bug: `s.current_period_end BETWEEN datetime('now') AND
 * datetime('now','+7 days')` string-compares current_period_end against
 * SQLite's space-separated datetime('now') format. payments.js writes
 * current_period_end as ISO ("...T...Z"); because 'T' (0x54) sorts after
 * ' ' (0x20), an ISO value on the lower boundary's calendar day can sort
 * as "not yet in range" until the date itself rolls over — a subscription
 * renewing later today could be silently skipped from the 7-day renewal
 * queue on the very day it should first be queued. Fixed by normalizing
 * all three operands through unixepoch(), same pattern as the two sibling
 * fixes in this same follow-up.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { buildRenewalQueue } from '../src/services/v24/billingEngine.js';

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
  sqlite.exec(`CREATE TABLE users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL
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

function hoursFromNowISO(n) {
  return new Date(Date.now() + n * 3600000).toISOString();
}

describe('billingEngine.buildRenewalQueue — 7-day renewal-queue seeding date-format fix', () => {
  it('queues a subscription renewing later today, written in real ISO-8601 format (payments.js\'s actual write format)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email) VALUES ('u_1','customer@acme.test')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_1','u_1','customer@acme.test','PRO','active',4999,?,0)`
    ).run(hoursFromNowISO(3)); // renews later today, same calendar day

    const result = await buildRenewalQueue(db);
    expect(result.error).toBeUndefined();
    expect(result.queued).toBe(1);

    const row = db._sqlite.prepare(`SELECT * FROM renewal_queue WHERE subscription_id = 'sub_1'`).get();
    expect(row).toBeTruthy();
    expect(row.user_id).toBe('u_1');
  });

  it('does not queue a subscription renewing more than 7 days out', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email) VALUES ('u_2','far@acme.test')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_2','u_2','far@acme.test','PRO','active',4999,?,0)`
    ).run(hoursFromNowISO(24 * 20));

    const result = await buildRenewalQueue(db);
    expect(result.queued).toBe(0);
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM renewal_queue`).get().c).toBe(0);
  });

  it('does not queue a cancelled (cancel_at_period_end=1) subscription', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO users (id, email) VALUES ('u_3','cancelled@acme.test')`).run();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_3','u_3','cancelled@acme.test','PRO','active',4999,?,1)`
    ).run(hoursFromNowISO(3));

    const result = await buildRenewalQueue(db);
    expect(result.queued).toBe(0);
  });
});
