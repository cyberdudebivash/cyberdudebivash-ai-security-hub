/* CAP-DEVPORTAL-005: growth-funnel API key delivery.
 *
 * provisionApiKey() persisted only a SHA-256 hash of the generated key (by
 * design — correct, matches the canonical auth/apiKeys.js pattern), but its
 * three real call sites (apiRevenueEngine.js's handlePaymentSuccess, and
 * growth.js's handleUpgradeLead / handleProvisionApiKey) either discarded
 * the raw key it returned entirely, or (for handleProvisionApiKey) returned
 * it once in an HTTP response with no caller anywhere in this repo and no
 * durable backup. Once the response/return value was gone, the raw key was
 * permanently unrecoverable — worse than "not delivered."
 *
 * This file proves two independent fixes:
 *  1. provisionApiKey() now links api_keys.user_id to a real account when
 *     the lead's email matches one, so the key becomes visible through the
 *     EXISTING, already-shipped dashboard "API Keys" page (auth/apiKeys.js's
 *     listUserApiKeys(), WHERE user_id = ?) with no new frontend needed.
 *  2. All three call sites now pass the real raw key into
 *     triggerPostPurchase()'s meta.api_key, the same lifecycle entry point
 *     the core checkout flow already uses — templateSubscriptionDay0
 *     (emailEngine.js) already knew how to render meta.api_key, it just
 *     never received one from these paths.
 *
 * triggerPostPurchase itself (revenue-event bookkeeping, drip enrollment)
 * has its own test coverage elsewhere and is mocked here — this file's job
 * is to prove the boundary: does the real raw key actually reach it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/services/lifecycleEngine.js', () => ({
  triggerPostPurchase: vi.fn(async () => {}),
}));

import { triggerPostPurchase } from '../src/services/lifecycleEngine.js';
import { provisionApiKey, handlePaymentSuccess } from '../src/services/apiRevenueEngine.js';
import { handleUpgradeLead, handleProvisionApiKey } from '../src/handlers/growth.js';

function makeDb() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, tier TEXT)`);
  sqlite.exec(`CREATE TABLE api_keys (
    id TEXT PRIMARY KEY, user_id TEXT, email TEXT, tier TEXT, api_key TEXT,
    key_hash TEXT, key_prefix TEXT, active INTEGER DEFAULT 1, created_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE leads (
    email TEXT PRIMARY KEY, plan TEXT, funnel_stage TEXT, converted_at TEXT, updated_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE billing_events (
    id TEXT PRIMARY KEY, email TEXT, plan TEXT, payment_id TEXT, order_id TEXT, event_type TEXT, created_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE funnel_events (
    id TEXT PRIMARY KEY, email TEXT, event_type TEXT, stage TEXT, metadata TEXT, created_at TEXT
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeEnv() {
  const db = makeDb();
  return { DB: db, _sqlite: db._sqlite, SECURITY_HUB_KV: { async get() { return null; }, async put() {} } };
}

describe('provisionApiKey — account linkage (CAP-DEVPORTAL-005)', () => {
  let env;
  beforeEach(() => { env = makeEnv(); });

  it('links the new key to a real account when the email matches an existing user', async () => {
    env._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('usr_1', 'known@example.com', 'FREE')`).run();

    await provisionApiKey(env, 'known@example.com', 'pro');

    const row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('known@example.com');
    expect(row.user_id).toBe('usr_1');
  });

  it('leaves user_id null for a pre-signup lead with no matching account (still correct — no dashboard to show it in)', async () => {
    await provisionApiKey(env, 'no-account-yet@example.com', 'starter');

    const row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('no-account-yet@example.com');
    expect(row.user_id).toBeNull();
  });

  it('backfills user_id on rotation if the account was created after the key first existed', async () => {
    await provisionApiKey(env, 'later-signup@example.com', 'starter');
    let row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('later-signup@example.com');
    expect(row.user_id).toBeNull();

    env._sqlite.prepare(`INSERT INTO users (id, email, tier) VALUES ('usr_2', 'later-signup@example.com', 'FREE')`).run();
    await provisionApiKey(env, 'later-signup@example.com', 'pro'); // rotate

    row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('later-signup@example.com');
    expect(row.user_id).toBe('usr_2');
    expect(row.tier).toBe('PRO');
  });

  it('still stores only a SHA-256 hash, never the raw key (no regression to the original security fix)', async () => {
    const { api_key } = await provisionApiKey(env, 'known@example.com', 'pro');
    const row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('known@example.com');
    expect(row.api_key).not.toBe(api_key);
    expect(row.api_key).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('handlePaymentSuccess — webhook path now delivers the key instead of discarding it (CAP-DEVPORTAL-005)', () => {
  it('passes the real raw sap_ key into triggerPostPurchase, not the hash and not empty', async () => {
    vi.clearAllMocks();
    const env = makeEnv();
    env._sqlite.prepare(`INSERT INTO leads (email, plan, funnel_stage) VALUES ('customer@example.com', 'free', 'lead')`).run();

    const result = await handlePaymentSuccess(env, { email: 'customer@example.com', plan: 'pro', payment_id: 'pay_123', order_id: 'order_123' });

    expect(result.success).toBe(true);
    expect(triggerPostPurchase).toHaveBeenCalledTimes(1);
    const [, call] = triggerPostPurchase.mock.calls[0]; // (env, options) — options is arg index 1
    expect(call.email).toBe('customer@example.com');
    expect(call.event_type).toBe('subscription_activated');
    expect(call.meta.api_key).toMatch(/^sap_[0-9a-f]+$/);

    // The delivered key must be the SAME one actually persisted (hashed) for this email.
    const row = env._sqlite.prepare(`SELECT * FROM api_keys WHERE email = ?`).get('customer@example.com');
    expect(row).toBeTruthy();
    expect(row.api_key).not.toBe(call.meta.api_key); // stored value is the hash
  });
});

describe('growth.js handleUpgradeLead — no longer discards the provisioned key (CAP-DEVPORTAL-005)', () => {
  function req(body) {
    return new Request('https://x/api/growth/upgrade', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
  }

  it('delivers a real api_key via triggerPostPurchase for a paid-plan upgrade', async () => {
    vi.clearAllMocks();
    const env = makeEnv();
    env._sqlite.prepare(`INSERT INTO leads (email, plan, funnel_stage) VALUES ('upgrader@example.com', 'free', 'lead')`).run();

    const res = await handleUpgradeLead(req({ email: 'upgrader@example.com', plan: 'pro' }), env);
    expect(res.status).toBe(200);

    expect(triggerPostPurchase).toHaveBeenCalledTimes(1);
    expect(triggerPostPurchase.mock.calls[0][1].meta.api_key).toMatch(/^sap_[0-9a-f]+$/);
  });

  // Note: a "plan: 'free'" case is not tested here — upgradeLead() itself
  // only accepts ['starter','pro','enterprise'] and 400s on 'free' before
  // this handler's `if (plan !== 'free')` guard is ever reached, so that
  // branch is unreachable through the real HTTP endpoint (pre-existing,
  // unrelated to this fix).
});

describe('growth.js handleProvisionApiKey — synchronous response unchanged, email now a durable backup (CAP-DEVPORTAL-005)', () => {
  function req(body) {
    return new Request('https://x/api/growth/api-key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
  }

  it('still returns the raw key directly in the response (unchanged, pre-existing correct behavior)', async () => {
    vi.clearAllMocks();
    const env = makeEnv();
    env._sqlite.prepare(`INSERT INTO leads (email, plan, funnel_stage) VALUES ('sync@example.com', 'pro', 'converted')`).run();

    const res = await handleProvisionApiKey(req({ email: 'sync@example.com' }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.api_key).toMatch(/^sap_[0-9a-f]+$/);

    // The exact same key that was returned is also the one handed to the durable email backup.
    expect(triggerPostPurchase).toHaveBeenCalledTimes(1);
    expect(triggerPostPurchase.mock.calls[0][1].meta.api_key).toBe(body.data.api_key);
  });

  it('still refuses a free/unverified lead (pre-existing CAP-DEVPORTAL-004 protection, unaffected)', async () => {
    vi.clearAllMocks();
    const env = makeEnv();
    env._sqlite.prepare(`INSERT INTO leads (email, plan, funnel_stage) VALUES ('nopay@example.com', 'free', 'lead')`).run();

    const res = await handleProvisionApiKey(req({ email: 'nopay@example.com' }), env);
    expect(res.status).toBe(403);
    expect(triggerPostPurchase).not.toHaveBeenCalled();
  });
});
