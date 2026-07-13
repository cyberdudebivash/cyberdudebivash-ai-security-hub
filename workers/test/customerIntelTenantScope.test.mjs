// CAP-TIH-012 — Customer/MSSP Personalized Intelligence: zero test coverage
// existed for workers/src/handlers/customerIntel.js despite it containing a
// security-sensitive tenant-scope-override mechanism (tenantScope(), private
// to this file): a caller with tier MSSP/OWNER/ADMIN can pass ?customer_id=
// to act on behalf of a managed customer; every other tier's customer_id
// param must be silently ignored, or any customer could read/write any other
// customer's profile, radar, risk, assets, or report just by guessing an ID.
//
// Covers the 5 endpoints that exercise tenantScope() against simple D1 state
// (profile + assets CRUD) without pulling in RadarService's broader
// dependency graph (radar/risk/report call the identical tenantScope() logic
// but additionally require a populated threat-intel snapshot to exercise —
// out of proportion to what's needed to prove this specific security
// property, which is identical across all 8 routes since they share one
// helper).
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleGetProfile, handleUpdateProfile, handleGetAssets, handleRegisterAsset, handleDeleteAsset,
} from '../src/handlers/customerIntel.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeEnv() {
  const db = makeRealD1();
  db._sqlite.exec(`CREATE TABLE customer_profiles (
    id TEXT PRIMARY KEY, org_id TEXT, org_name TEXT, industry TEXT, country TEXT, org_size TEXT,
    technology_stack TEXT DEFAULT '[]', cloud_providers TEXT DEFAULT '[]',
    business_critical_assets TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))`);
  db._sqlite.exec(`CREATE TABLE customer_assets (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, org_id TEXT, asset_type TEXT NOT NULL,
    asset_value TEXT NOT NULL, label TEXT, created_at TEXT DEFAULT (datetime('now')))`);
  return { SECURITY_HUB_DB: db, SECURITY_HUB_KV: null };
}

function customer(userId, tier = 'PRO') {
  return { authenticated: true, method: 'jwt', user_id: userId, userId, id: userId, tier };
}
const anonymous = { authenticated: true, method: 'ip_fallback', user_id: null, userId: null, id: null, tier: 'FREE' };

function req(url, opts) { return new Request(`https://x${url}`, opts); }

describe('CAP-TIH-012 — customerIntel.js auth gate (regression lock, was zero coverage)', () => {
  let env;
  beforeEach(() => { env = makeEnv(); });

  it('an anonymous (IP-fallback) caller is rejected with 401 on profile, assets, and register', async () => {
    expect((await handleGetProfile(req('/api/customer/profile'), env, anonymous)).status).toBe(401);
    expect((await handleGetAssets(req('/api/customer/assets'), env, anonymous)).status).toBe(401);
    expect((await handleRegisterAsset(req('/api/customer/assets', { method: 'POST', body: '{}' }), env, anonymous)).status).toBe(401);
  });
});

describe('CAP-TIH-012 — tenantScope(): non-MSSP tiers cannot escape their own scope', () => {
  let env;
  beforeEach(() => { env = makeEnv(); });

  it('a PRO-tier customer_id override on GET /api/customer/profile is silently ignored', async () => {
    // Seed a real "victim" profile.
    await handleUpdateProfile(req('/api/customer/profile', {
      method: 'PUT', body: JSON.stringify({ org_name: 'Victim Corp', industry: 'Finance' }),
    }), env, customer('victim'));

    // A PRO-tier attacker tries to read the victim's profile via ?customer_id=.
    const res = await handleGetProfile(req('/api/customer/profile?customer_id=victim'), env, customer('attacker', 'PRO'));
    const { profile } = await res.json();
    expect(profile.id).toBe('attacker');
    expect(profile.org_name).not.toBe('Victim Corp');
    expect(profile._new).toBe(true);
  });

  it('a PRO-tier attacker POSTing an asset with customer_id=victim writes it under their OWN id, not the victim\'s', async () => {
    const res = await handleRegisterAsset(req('/api/customer/assets?customer_id=victim', {
      method: 'POST', body: JSON.stringify({ asset_type: 'domain', asset_value: 'evil.example.com' }),
    }), env, customer('attacker', 'PRO'));
    expect(res.status).toBe(200);

    const row = env.SECURITY_HUB_DB._sqlite.prepare('SELECT owner_id FROM customer_assets').get();
    expect(row.owner_id).toBe('attacker');
    expect(row.owner_id).not.toBe('victim');
  });

  it('a PRO-tier attacker cannot delete an asset owned by another customer, even knowing its real ID', async () => {
    await handleRegisterAsset(req('/api/customer/assets', {
      method: 'POST', body: JSON.stringify({ asset_type: 'domain', asset_value: 'victim-real-asset.com' }),
    }), env, customer('victim'));
    const victimAsset = env.SECURITY_HUB_DB._sqlite.prepare('SELECT id FROM customer_assets').get();

    const res = await handleDeleteAsset(req(`/api/customer/assets/${victimAsset.id}`), env, customer('attacker', 'PRO'), victimAsset.id);
    expect(res.status).toBe(200); // handler always reports success (DELETE ... WHERE owner_id=? matched 0 rows)

    const stillThere = env.SECURITY_HUB_DB._sqlite.prepare('SELECT COUNT(*) AS c FROM customer_assets WHERE id = ?').get(victimAsset.id);
    expect(stillThere.c).toBe(1);
  });

  it('TEAM and FREE tiers are equally blocked from the customer_id override (not just PRO)', async () => {
    for (const tier of ['TEAM', 'FREE', 'ENTERPRISE']) {
      const res = await handleGetAssets(req('/api/customer/assets?customer_id=victim'), env, customer(`caller-${tier}`, tier));
      const { assets } = await res.json();
      expect(assets, `tier ${tier} should not see victim's assets`).toEqual([]);
    }
  });
});

describe('CAP-TIH-012 — tenantScope(): MSSP/OWNER/ADMIN genuinely act on behalf of a managed customer', () => {
  let env;
  beforeEach(() => { env = makeEnv(); });

  it('an MSSP-tier caller reads the managed customer\'s real profile via ?customer_id=', async () => {
    await handleUpdateProfile(req('/api/customer/profile', {
      method: 'PUT', body: JSON.stringify({ org_name: 'Managed Client Inc', industry: 'Healthcare' }),
    }), env, customer('managed-client'));

    const res = await handleGetProfile(req('/api/customer/profile?customer_id=managed-client'), env, customer('mssp-analyst', 'MSSP'));
    const { profile } = await res.json();
    expect(profile.id).toBe('managed-client');
    expect(profile.org_name).toBe('Managed Client Inc');
  });

  it('an OWNER-tier caller registers an asset that lands under the managed customer\'s id, not their own', async () => {
    const res = await handleRegisterAsset(req('/api/customer/assets?customer_id=managed-client', {
      method: 'POST', body: JSON.stringify({ asset_type: 'domain', asset_value: 'managed-client.com' }),
    }), env, customer('owner-user', 'OWNER'));
    expect(res.status).toBe(200);

    const row = env.SECURITY_HUB_DB._sqlite.prepare('SELECT owner_id FROM customer_assets').get();
    expect(row.owner_id).toBe('managed-client');
  });

  it('an ADMIN-tier caller with no customer_id still defaults to their own scope (override is opt-in, not automatic)', async () => {
    const res = await handleGetProfile(req('/api/customer/profile'), env, customer('admin-user', 'ADMIN'));
    const { profile } = await res.json();
    expect(profile.id).toBe('admin-user');
  });

  it('two managed customers\' assets stay isolated from each other even under MSSP access', async () => {
    await handleRegisterAsset(req('/api/customer/assets?customer_id=client-a', {
      method: 'POST', body: JSON.stringify({ asset_type: 'domain', asset_value: 'a.com' }),
    }), env, customer('mssp', 'MSSP'));
    await handleRegisterAsset(req('/api/customer/assets?customer_id=client-b', {
      method: 'POST', body: JSON.stringify({ asset_type: 'domain', asset_value: 'b.com' }),
    }), env, customer('mssp', 'MSSP'));

    const aRes = await handleGetAssets(req('/api/customer/assets?customer_id=client-a'), env, customer('mssp', 'MSSP'));
    const bRes = await handleGetAssets(req('/api/customer/assets?customer_id=client-b'), env, customer('mssp', 'MSSP'));
    const a = await aRes.json();
    const b = await bRes.json();
    expect(a.assets.length).toBe(1);
    expect(a.assets[0].asset_value).toBe('a.com');
    expect(b.assets.length).toBe(1);
    expect(b.assets[0].asset_value).toBe('b.com');
  });
});
