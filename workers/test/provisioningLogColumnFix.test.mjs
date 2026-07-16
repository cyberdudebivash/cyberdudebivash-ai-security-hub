/* Follow-up (2026-07-16, PHASE7 §7 finding #5) — provisioning_log column
 * mismatch. enterpriseTransformHandler.js's handleCancelSubscription,
 * handleUpgradeInitiate, and handleOverageCharge each wrote
 * `INSERT INTO provisioning_log (user_id, event, metadata, created_at)` —
 * neither `event` nor `metadata` exists on this table in any of its three
 * schema definitions (schema_v39_marketplace.sql, schema_bootstrap.sql,
 * schema_migration_prod_missing_tables_2026_07.sql — all agree). The real
 * schema requires `trigger_type` (NOT NULL, CHECK-constrained) and
 * `actions_taken` (NOT NULL DEFAULT '[]') instead. Every one of these three
 * inserts therefore failed on every call (constraint violation) and was
 * silently swallowed by `.catch(() => {})` — the actual customer-facing
 * actions (cancel, upgrade-initiate, overage-charge) all still worked;
 * only the audit-trail logging line silently no-op'd. This file proves the
 * fix against a real node:sqlite D1 with the live CHECK constraint in
 * place — a permissive always-succeeds mock (as used elsewhere in this
 * repo's billingPortal.test.mjs) would hide exactly this class of bug,
 * same lesson as every other real-schema test file in this repo.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleCancelSubscription,
  handleUpgradeInitiate,
  handleOverageCharge,
} from '../src/handlers/enterpriseTransformHandler.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'FREE', status TEXT NOT NULL DEFAULT 'active',
    price_inr INTEGER NOT NULL DEFAULT 0,
    current_period_end TEXT NOT NULL DEFAULT (datetime('now')),
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
    cancel_reason TEXT, updated_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE invoices (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, amount_usd TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD', status TEXT NOT NULL DEFAULT 'pending',
    description TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  // Exact live schema (schema_v39_marketplace.sql:119-131 /
  // schema_bootstrap.sql / schema_migration_prod_missing_tables_2026_07.sql)
  sqlite.exec(`CREATE TABLE provisioning_log (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id          TEXT,
    tenant_id        TEXT,
    trigger_type     TEXT NOT NULL
                       CHECK(trigger_type IN ('purchase','subscription','trial','manual','upgrade','downgrade','cancel','renewal')),
    trigger_ref      TEXT,
    actions_taken    TEXT NOT NULL DEFAULT '[]',
    entitlements_granted TEXT DEFAULT '[]',
    api_keys_created INTEGER NOT NULL DEFAULT 0,
    tenant_created   INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'success'
                       CHECK(status IN ('success','partial','failed')),
    error_detail     TEXT,
    duration_ms      INTEGER,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function jsonReq(url, body) {
  return new Request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

const REAL_SUB_ROW = (overrides = {}) => ({
  id: 'sub_1', user_id: 'u_1', email: 'ciso@fortune500.com', plan: 'PRO',
  status: 'active', price_inr: 149900, current_period_end: '2026-08-01T00:00:00.000Z',
  cancel_at_period_end: 0, ...overrides,
});

describe('provisioning_log column fix — audit-trail inserts now match the live schema', () => {
  it('handleCancelSubscription writes a valid trigger_type=\'cancel\' row (previously failed the trigger_type NOT NULL CHECK every time)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (id, user_id, email, plan, status, price_inr, current_period_end, cancel_at_period_end)
       VALUES ('sub_1','u_1','ciso@fortune500.com','PRO','active',149900,'2026-08-01T00:00:00.000Z',0)`
    ).run();

    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_1', email: 'ciso@fortune500.com' };
    const res = await handleCancelSubscription(jsonReq('https://x/api/customer/billing/cancel', {}), { DB: db }, authCtx);
    expect(res.status).toBe(200);

    const row = db._sqlite.prepare(`SELECT * FROM provisioning_log WHERE user_id = 'u_1'`).get();
    expect(row).toBeTruthy();
    expect(row.trigger_type).toBe('cancel');
    expect(row.trigger_ref).toBe('sub_1');
    expect(() => JSON.parse(row.actions_taken)).not.toThrow();
  });

  it('handleUpgradeInitiate writes a valid trigger_type=\'upgrade\' row', async () => {
    const db = makeRealD1();
    const authCtx = { authenticated: true, tier: 'STARTER', userId: 'u_2' };
    const res = await handleUpgradeInitiate(jsonReq('https://x/api/customer/billing/upgrade', { target_plan: 'PRO' }), { DB: db }, authCtx);
    expect(res.status).toBe(200);

    const row = db._sqlite.prepare(`SELECT * FROM provisioning_log WHERE user_id = 'u_2'`).get();
    expect(row).toBeTruthy();
    expect(row.trigger_type).toBe('upgrade');
    expect(row.trigger_ref).toBeTruthy();
    const actions = JSON.parse(row.actions_taken);
    expect(actions[0].to).toBe('PRO');
  });

  it('handleOverageCharge writes a valid trigger_type=\'manual\' row', async () => {
    const db = makeRealD1();
    const authCtx = { authenticated: true, userId: 'admin_1', isAdmin: true };
    const res = await handleOverageCharge(
      jsonReq('https://x/api/platform/overage/charge', { user_id: 'u_3', amount_usd: 12.5 }),
      { DB: db }, authCtx,
    );
    expect(res.status).toBe(200);

    const row = db._sqlite.prepare(`SELECT * FROM provisioning_log WHERE user_id = 'u_3'`).get();
    expect(row).toBeTruthy();
    expect(row.trigger_type).toBe('manual');
    const actions = JSON.parse(row.actions_taken);
    expect(actions[0].amount_usd).toBe(12.5);
  });

  it('regression guard: the old event/metadata column combination would fail against this real schema', async () => {
    const db = makeRealD1();
    expect(() => db._sqlite.prepare(
      `INSERT INTO provisioning_log (user_id, event, metadata, created_at) VALUES ('u_x', 'CANCEL_REQUESTED', '{}', datetime('now'))`
    ).run()).toThrow();
  });
});
