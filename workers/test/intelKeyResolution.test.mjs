/* Regression tests — self-serve API keys on the intel API.
 * The intel monetization API resolves x-api-key via middleware/auth.js. It must
 * accept BOTH KV-provisioned keys (legacy/Stripe paid flow) AND D1 self-serve
 * keys generated via POST /api/keys (cdb_*), so a key created in the developer
 * portal authenticates on the paid feeds exactly as the docs promise. */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { resolveAuth } from '../src/middleware/auth.js';
import { entitlementsFor } from '../src/handlers/intelMonetization.js';
import { handleProvisionApiKey } from '../src/handlers/growth.js';

function makeReq(headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { headers: { get(k) { return lower[k.toLowerCase()] ?? null; } } };
}

// Real (in-memory) D1, matching the live api_keys/leads schema — see
// devPortalApiKeyFixes.test.mjs, the established pattern for this table.
function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT,
    key_hash      TEXT NOT NULL,
    key_prefix    TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT 'Default Key',
    tier          TEXT NOT NULL DEFAULT 'FREE',
    daily_limit   INTEGER NOT NULL DEFAULT 5,
    monthly_limit INTEGER NOT NULL DEFAULT 50,
    active        INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at  TEXT,
    expires_at    TEXT,
    email         TEXT,
    api_key       TEXT,
    revoked       INTEGER NOT NULL DEFAULT 0,
    org_id        TEXT NOT NULL DEFAULT 'default',
    status        TEXT NOT NULL DEFAULT 'ACTIVE'
  )`);
  sqlite.exec(`CREATE TABLE leads (email TEXT PRIMARY KEY, plan TEXT)`);
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
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
    async delete(k) { store.delete(k); },
  };
}

describe('intel API key resolution (KV + D1 self-serve)', () => {
  it('resolves a KV-provisioned key to its tier (legacy/paid path)', async () => {
    const env = {
      SECURITY_HUB_KV: { async get(k) { return k === 'apikey:cdb_kvkey' ? JSON.stringify({ tier: 'PRO', active: true, owner_email: 'kv@x.com' }) : null; } },
      DB: null,
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_kvkey' }), env);
    expect(auth.authenticated).toBe(true);
    expect(auth.tier).toBe('PRO');
  });

  it('falls back to D1 for a self-serve cdb_ key and uses the CURRENT account tier', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } }, // not in KV
      DB: { prepare() { return { bind() { return this; }, async first() {
        return { id: 7, user_id: 'u1', key_prefix: 'cdb_abc...', label: 'CI', tier: 'STARTER', user_tier: 'ENTERPRISE', user_status: 'active', active: 1 };
      } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_selfserve_key_value' }), env);
    expect(auth.authenticated).toBe(true);
    expect(auth.method).toBe('api_key');
    expect(auth.tier).toBe('ENTERPRISE'); // account upgrade applies immediately
  });

  it('rejects an inactive user even with a valid D1 key row', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } },
      DB: { prepare() { return { bind() { return this; }, async first() {
        return { id: 8, user_id: 'u2', tier: 'PRO', user_tier: 'PRO', user_status: 'suspended', active: 1 };
      } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_suspended_user_key' }), env);
    expect(auth.authenticated).toBe(false);
  });

  it('returns invalid for an unknown cdb_ key (absent from KV and D1)', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } },
      DB: { prepare() { return { bind() { return this; }, async first() { return null; } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_does_not_exist' }), env);
    expect(auth.authenticated).toBe(false);
  });

  it('IP fallback to FREE when no key is supplied', async () => {
    const env = { SECURITY_HUB_KV: { async get() { return null; } }, DB: null };
    const auth = await resolveAuth(makeReq({ 'CF-Connecting-IP': '1.2.3.4' }), env);
    expect(auth.tier).toBe('FREE');
    expect(auth.method).toBe('ip_fallback');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CAP-DEVPORTAL-004 follow-up: sap_ growth/plan keys previously provisioned
// successfully (POST /api/growth/api-key) but could never authenticate here —
// this file's KV lookup only ever checked the RAW key name (apiRevenueEngine
// caches under a HASHED name) and its D1 branch only recognized cdb_. A minted
// sap_ key was therefore a dead credential end-to-end. Fixed by delegating to
// apiRevenueEngine's own resolver (hash-then-match against its D1 rows) in a
// new, additive branch — cdb_/KV/IP-fallback paths above are untouched.
describe('intel API key resolution — sap_ growth/plan keys (CAP-DEVPORTAL-004)', () => {
  async function freshEnv() {
    const D1 = makeRealD1();
    return { env: { DB: D1, SECURITY_HUB_KV: makeKV() }, D: D1 };
  }

  it('a freshly provisioned sap_ key authenticates end-to-end at the correct tier (the actual customer journey: mint → use)', async () => {
    const { env: e, D: d } = await freshEnv();
    d._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('paid@customer.example', 'pro');

    const provisionRes = await handleProvisionApiKey(
      new Request('https://x/api/growth/api-key', { method: 'POST', body: JSON.stringify({ email: 'paid@customer.example' }) }),
      e,
    );
    const { data } = await provisionRes.json();
    expect(data.api_key).toMatch(/^sap_/);

    // This is the exact request path a real API caller takes: the raw key in
    // an x-api-key header, resolved through the same resolveAuth() the intel
    // API's resolveFeedTier() calls — previously always 'invalid_key' here.
    const auth = await resolveAuth(makeReq({ 'x-api-key': data.api_key }), e);
    expect(auth.authenticated).toBe(true);
    expect(auth.method).toBe('api_key');
    expect(auth.tier).toBe('PRO');
    expect(auth.owner_email).toBe('paid@customer.example');

    // Closing the loop into the actual consumer: intelMonetization.js's own
    // tier table (not this file's TIERS) is what gates feed access.
    const ent = entitlementsFor(auth.tier);
    expect(ent.tier).toBe('PRO');
    expect(ent.full_detail).toBe(true);
  });

  it('a STARTER-plan sap_ key resolves to STARTER, not a silent FREE downgrade', async () => {
    const { env: e, D: d } = await freshEnv();
    d._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('starter@customer.example', 'starter');
    const { data } = await (await handleProvisionApiKey(
      new Request('https://x/api/growth/api-key', { method: 'POST', body: JSON.stringify({ email: 'starter@customer.example' }) }),
      e,
    )).json();

    const auth = await resolveAuth(makeReq({ 'x-api-key': data.api_key }), e);
    expect(auth.tier).toBe('STARTER');
    expect(entitlementsFor(auth.tier).tier).toBe('STARTER');
  });

  it('rotating the key invalidates the old one (no year-long stale credential)', async () => {
    const { env: e, D: d } = await freshEnv();
    d._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('rotate@customer.example', 'pro');
    const mk = () => handleProvisionApiKey(
      new Request('https://x/api/growth/api-key', { method: 'POST', body: JSON.stringify({ email: 'rotate@customer.example' }) }),
      e,
    );
    const { data: first }  = await (await mk()).json();
    const { data: second } = await (await mk()).json();
    expect(second.api_key).not.toBe(first.api_key);

    const oldAuth = await resolveAuth(makeReq({ 'x-api-key': first.api_key }), e);
    expect(oldAuth.authenticated).toBe(false);

    const newAuth = await resolveAuth(makeReq({ 'x-api-key': second.api_key }), e);
    expect(newAuth.authenticated).toBe(true);
  });

  it('an sap_-shaped key that was never provisioned is rejected, not mistaken for a valid one', async () => {
    const { env: e } = await freshEnv();
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'sap_' + 'a'.repeat(32) }), e);
    expect(auth.authenticated).toBe(false);
    expect(auth.error).toBe('invalid_key');
  });

  it('does not regress the cdb_ D1 branch (checked directly above) when DB also contains sap_-shaped rows', async () => {
    const { env: e, D: d } = await freshEnv();
    d._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('coexist@customer.example', 'enterprise');
    await (await handleProvisionApiKey(
      new Request('https://x/api/growth/api-key', { method: 'POST', body: JSON.stringify({ email: 'coexist@customer.example' }) }),
      e,
    )).json();

    // A cdb_ key against the very same env/DB the sap_ branch just used —
    // proves the new branch is purely additive, not a fallthrough that
    // accidentally swallows other prefixes.
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_unrelated_key' }), e);
    expect(auth.authenticated).toBe(false); // no cdb_ row exists — correctly falls through, not misattributed to the sap_ lead
  });
});
