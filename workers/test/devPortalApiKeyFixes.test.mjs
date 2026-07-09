/* Regression tests for CAP-DEVPORTAL-002/003/004
 * (docs/capability-registry/domains/developer-portal-apikeys.json) — three
 * independent, confirmed-broken API-key issuance paths, documented in a
 * Wave 2 registry-population pass and fixed here as their own dedicated,
 * bounded change.
 *
 * All three now delegate to (or match the exact schema of) the canonical
 * createApiKey()/api_keys table in src/auth/apiKeys.js, rather than
 * reimplementing key issuance with their own drifted column lists.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAutoRoute } from '../src/handlers/enterpriseAutomation.js';
import { handleDeveloperPortal } from '../src/handlers/developerPortal.js';
import { handleProvisionApiKey } from '../src/handlers/growth.js';
import { resolveApiKey } from '../src/services/apiRevenueEngine.js';

// ─── Real (in-memory) D1, matching the live api_keys schema exactly — a
// hand-rolled mock could (and previously did) hide every one of these bugs.
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
  sqlite.exec(`CREATE TABLE api_usage_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    api_key_id  TEXT,
    endpoint    TEXT NOT NULL,
    method      TEXT NOT NULL DEFAULT 'GET',
    status_code INTEGER,
    latency_ms  INTEGER,
    ip_address  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    email       TEXT,
    logged_at   TEXT
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
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, v); } };
}

// ─────────────────────────────────────────────────────────────────────────────
// CAP-DEVPORTAL-002 — Self-Service Automation API Keys (enterpriseAutomation.js)
// ─────────────────────────────────────────────────────────────────────────────
describe('POST /api/self/keys — CAP-DEVPORTAL-002', () => {
  let env, D;
  beforeEach(() => {
    D = makeRealD1();
    env = { SECURITY_HUB_DB: D };
  });

  it('stores the CALLER\'S TIER, not their org id, as the key tier (the confirmed parameter-ordering bug)', async () => {
    const authCtx = { userId: 'u1', orgId: 'org-acme-corp', tier: 'ENTERPRISE' };
    const req = new Request('https://x/api/self/keys', { method: 'POST', body: JSON.stringify({ label: 'CI key' }) });
    const res = await handleAutoRoute(req, env, authCtx, '/api/self/keys', 'POST');
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tier).toBe('ENTERPRISE');
    expect(body.tier).not.toBe('org-acme-corp');
    expect(body.key).toMatch(/^cdb_/);

    const row = D._sqlite.prepare('SELECT tier FROM api_keys WHERE user_id = ?').get('u1');
    expect(row.tier).toBe('ENTERPRISE');
  });

  it('enforces the tier\'s key limit (unbounded creation was the un-caught secondary bug)', async () => {
    const authCtx = { userId: 'u2', orgId: 'org-x', tier: 'FREE' }; // FREE = 1 key
    const mk = () => handleAutoRoute(
      new Request('https://x/api/self/keys', { method: 'POST', body: '{}' }),
      env, authCtx, '/api/self/keys', 'POST',
    );
    const first  = await mk();
    expect(first.status).toBe(201);
    const second = await mk();
    expect(second.status).toBe(409);
    const body = await second.json();
    expect(body.error).toMatch(/limit reached/i);
  });

  it('list returns count/max_keys (previously undefined — frontend showed "undefined of undefined allowed")', async () => {
    const authCtx = { userId: 'u3', orgId: 'org-x', tier: 'PRO' }; // PRO = 5 keys
    await handleAutoRoute(new Request('https://x/api/self/keys', { method: 'POST', body: '{}' }), env, authCtx, '/api/self/keys', 'POST');
    const res  = await handleAutoRoute(new Request('https://x/api/self/keys'), env, authCtx, '/api/self/keys', 'GET');
    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.max_keys).toBe(5);
  });

  it('rotate works and is no longer a 404 (the confirmed missing route)', async () => {
    const authCtx = { userId: 'u4', orgId: 'org-x', tier: 'STARTER' };
    const created = await (await handleAutoRoute(new Request('https://x/api/self/keys', { method: 'POST', body: '{}' }), env, authCtx, '/api/self/keys', 'POST')).json();

    const res = await handleAutoRoute(
      new Request(`https://x/api/self/keys/${created.id}/rotate`, { method: 'POST', body: '{}' }),
      env, authCtx, `/api/self/keys/${created.id}/rotate`, 'POST',
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.key).toMatch(/^cdb_/);
    expect(body.key).not.toBe(created.key);

    const oldRow = D._sqlite.prepare('SELECT active FROM api_keys WHERE id = ?').get(created.id);
    expect(oldRow.active).toBe(0);
  });

  it('rejects an anonymous caller (no userId/user_id)', async () => {
    const res = await handleAutoRoute(new Request('https://x/api/self/keys', { method: 'POST', body: '{}' }), env, {}, '/api/self/keys', 'POST');
    expect(res.status).toBe(401);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CAP-DEVPORTAL-003 — Developer Portal key endpoints (developerPortal.js)
// ─────────────────────────────────────────────────────────────────────────────
describe('POST/GET/DELETE /api/developer/keys* — CAP-DEVPORTAL-003', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  it('rejects an unauthenticated caller instead of attempting the (previously columnless-broken) insert', async () => {
    const req = new Request('https://x/api/developer/keys', { method: 'POST', body: JSON.stringify({ name: 'x' }) });
    const res = await handleDeveloperPortal(req, env, { authenticated: false });
    expect(res.status).toBe(401);
  });

  it('an authenticated caller successfully creates a real key (previously a guaranteed 500 — no such column: name)', async () => {
    const authCtx = { authenticated: true, user_id: 'dev1', tier: 'PRO' };
    const req = new Request('https://x/api/developer/keys', { method: 'POST', body: JSON.stringify({ name: 'My App' }) });
    const res = await handleDeveloperPortal(req, env, authCtx);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.key).toMatch(/^cdb_/);
  });

  it('list/delete are ownership-scoped through the same canonical handlers (no more org_id=default free-for-all)', async () => {
    const owner    = { authenticated: true, user_id: 'dev2', tier: 'FREE' };
    const stranger = { authenticated: true, user_id: 'dev3', tier: 'FREE' };
    const created = await (await handleDeveloperPortal(
      new Request('https://x/api/developer/keys', { method: 'POST', body: '{}' }), env, owner,
    )).json();

    const strangerDelete = await handleDeveloperPortal(
      new Request(`https://x/api/developer/keys/${created.id}`, { method: 'DELETE' }), env, stranger,
    );
    expect(strangerDelete.status).toBe(404); // not the owner's key — no existence leak

    const ownerList = await (await handleDeveloperPortal(new Request('https://x/api/developer/keys'), env, owner)).json();
    expect(ownerList.keys.length).toBe(1);
  });

  it('quickstart/SDK templates no longer point at the literal unfilled placeholder domain', async () => {
    const res  = await handleDeveloperPortal(new Request('https://x/api/developer/quickstart'), env, {});
    const body = await res.json();
    expect(body.baseUrl).toBe('https://cyberdudebivash.in');
    expect(JSON.stringify(body)).not.toMatch(/your-worker\.workers\.dev/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CAP-DEVPORTAL-004 — Growth/Plan API Key Provisioning (apiRevenueEngine.js)
// ─────────────────────────────────────────────────────────────────────────────
describe('POST /api/growth/api-key — CAP-DEVPORTAL-004', () => {
  let env, D;
  beforeEach(() => {
    D = makeRealD1();
    env = { DB: D, SECURITY_HUB_KV: makeKV() };
  });

  it('rejects provisioning when no verified paid lead is on file, even if the caller supplies a plan', async () => {
    // The confirmed bug: an unverified caller could mint an arbitrary-tier
    // key for any email by just passing {email, plan:"enterprise"} — no
    // lead, no payment, no ownership check.
    const req = new Request('https://x/api/growth/api-key', {
      method: 'POST', body: JSON.stringify({ email: 'nobody@evil.example', plan: 'enterprise' }),
    });
    const res = await handleProvisionApiKey(req, env);
    expect(res.status).toBe(403);
    const row = D._sqlite.prepare('SELECT * FROM api_keys WHERE email = ?').get('nobody@evil.example');
    expect(row).toBeUndefined();
  });

  it('provisions successfully for a real, server-recorded paid lead (the actual, now-fixed INSERT)', async () => {
    D._sqlite.exec(`CREATE TABLE leads (email TEXT PRIMARY KEY, plan TEXT)`);
    D._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('paid@customer.example', 'pro');

    const req = new Request('https://x/api/growth/api-key', {
      method: 'POST', body: JSON.stringify({ email: 'paid@customer.example' }),
    });
    const res = await handleProvisionApiKey(req, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.api_key).toMatch(/^sap_/);

    // Resolve it straight back out (the previously-broken `SELECT email, plan`
    // — plan is not a real column — is now `SELECT email, tier`).
    const resolved = await resolveApiKey(env, body.data.api_key);
    expect(resolved).toEqual({ email: 'paid@customer.example', plan: 'pro' });
  });

  it('re-provisioning the same email updates the existing row instead of throwing on the invalid ON CONFLICT(email)', async () => {
    D._sqlite.exec(`CREATE TABLE leads (email TEXT PRIMARY KEY, plan TEXT)`);
    D._sqlite.prepare(`INSERT INTO leads (email, plan) VALUES (?, ?)`).run('repeat@customer.example', 'starter');

    const mk = () => handleProvisionApiKey(new Request('https://x/api/growth/api-key', {
      method: 'POST', body: JSON.stringify({ email: 'repeat@customer.example' }),
    }), env);

    await mk();
    await mk();

    const rows = D._sqlite.prepare('SELECT * FROM api_keys WHERE email = ?').all('repeat@customer.example');
    expect(rows.length).toBe(1); // upsert, not a duplicate row or a thrown SQLite error
  });
});
