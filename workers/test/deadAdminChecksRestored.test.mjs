/* Regression test — three handlers gated staff-only (or MSSP-tier) operations
 * on `authCtx.role === 'admin'` / `'mssp_admin'` or `authCtx.plan === 'ENTERPRISE'`.
 * None of those fields is ever actually set anywhere in the auth layer
 * (verified directly: no auth/*.js file assigns `role` or `plan` on any
 * authCtx it returns) — every one of these gates was unreachable by anyone,
 * including the platform owner via the ADMIN_KEY bypass, which sets
 * `isAdmin: true`, not `role` or `plan`. This locks the fix: the real field
 * (`isAdmin`) now grants access, and for msspTenantPlatform.js, a real
 * paying MSSP-tier customer (`tier: 'MSSP'`) can reach their own tenant
 * platform — while tenant isolation (partnerScope() → authCtx.userId) still
 * holds, verified with a real SQLite engine matching the existing
 * msspTenantIsolation.test.mjs pattern for the sibling msspWorkspace.js file. */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleCustomerDashboard,
  handleCreateSubTenant,
  handleGenerateCustomerAPIKey,
  handleListCustomerAPIKeys,
} from '../src/handlers/msspTenantPlatform.js';
import { handleV24 } from '../src/handlers/v24Handler.js';
import { handleRefreshMetrics } from '../src/handlers/platformMetricsAuthority.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
}

const ANON      = { authenticated: false };
const FREE_USER = { authenticated: true, userId: 'u1', tier: 'FREE' };
const MSSP_A    = { authenticated: true, userId: 'pA', tier: 'MSSP' };
const MSSP_B    = { authenticated: true, userId: 'pB', tier: 'MSSP' };
const OWNER     = { authenticated: true, userId: 'admin', isAdmin: true };

describe('msspTenantPlatform.js — requireMSSPAdmin() gate restored + isolation intact', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE mssp_customers (
      id TEXT PRIMARY KEY, org_name TEXT, org_slug TEXT, contact_name TEXT, contact_email TEXT,
      tier TEXT, status TEXT DEFAULT 'active', risk_score INTEGER, compliance_score INTEGER,
      mrr_cents INTEGER, parent_customer_id TEXT, created_at TEXT, updated_at TEXT, partner_id TEXT
    )`);
    env.SECURITY_HUB_DB._sqlite.prepare(
      `INSERT INTO mssp_customers (id, org_name, org_slug, tier, status, partner_id) VALUES (?,?,?,?,?,?)`
    ).run('cust1', 'Acme Corp', 'acme', 'PRO', 'active', 'pA');
    // Pre-create what ensureTenantTables() would create — its ready-flag is
    // module-level state that persists across tests, but each test here gets
    // a fresh in-memory DB, so relying on that caching would silently skip
    // table creation on a fresh DB after the first test bootstraps it.
    // CREATE TABLE IF NOT EXISTS makes this safe either way.
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE IF NOT EXISTS mssp_customer_api_keys (
      id TEXT PRIMARY KEY, partner_id TEXT NOT NULL, customer_id TEXT NOT NULL,
      key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL, name TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT '["read"]', status TEXT NOT NULL DEFAULT 'active',
      last_used_at TEXT, expires_at TEXT, created_at TEXT NOT NULL, revoked_at TEXT
    )`);
  });

  it('anonymous caller is rejected (403), not silently scoped to nothing', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, ANON, 'cust1');
    expect(res.status).toBe(403);
  });

  it('a FREE-tier authenticated user is rejected (403) — not every logged-in user is MSSP', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, FREE_USER, 'cust1');
    expect(res.status).toBe(403);
  });

  it('a real MSSP-tier customer can reach their own customer dashboard (200)', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, MSSP_A, 'cust1');
    expect(res.status).toBe(200);
  });

  it('a different MSSP-tier customer cannot read another tenant\'s dashboard (404, not leaked)', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, MSSP_B, 'cust1');
    expect(res.status).toBe(404);
  });

  it('the platform owner (isAdmin) passes the gate', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, OWNER, 'cust1');
    // isAdmin's own partnerScope is 'admin', distinct from 'pA' — owner sees
    // "Customer not found" (404) for pA's customer, same fail-closed
    // behavior as any other scope that doesn't own the row. The assertion
    // that matters here is it's not 403 (blocked at the auth gate) like the
    // anonymous/FREE-tier cases above.
    expect(res.status).not.toBe(403);
  });

  it('MSSP-tier customer can create a sub-tenant under their own customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ org_name: 'Sub Co' }) });
    const res = await handleCreateSubTenant(req, env, MSSP_A, 'cust1');
    expect(res.status).toBe(201);
  });

  it('a different MSSP-tier customer cannot create a sub-tenant under someone else\'s customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ org_name: 'Sub Co' }) });
    const res = await handleCreateSubTenant(req, env, MSSP_B, 'cust1');
    expect(res.status).toBe(404);
  });

  it('MSSP-tier customer can generate an API key scoped to their own customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ name: 'ci-key' }) });
    const res = await handleGenerateCustomerAPIKey(req, env, MSSP_A, 'cust1');
    expect(res.status).toBe(201);
  });

  it('a different MSSP-tier customer cannot list API keys for someone else\'s customer', async () => {
    // Seed a key under pA's customer first.
    const genReq = new Request('https://x', { method: 'POST', body: JSON.stringify({ name: 'ci-key' }) });
    await handleGenerateCustomerAPIKey(genReq, env, MSSP_A, 'cust1');

    const res  = await handleListCustomerAPIKeys(new Request('https://x'), env, MSSP_B, 'cust1');
    const body = await res.json();
    expect(body.keys).toEqual([]); // scoped query returns nothing for a non-owning partner_id
  });
});

function fakeD1() {
  const noop = { async all(){ return { results: [] }; }, async first(){ return null; }, async run(){ return { meta: { changes: 0 } }; } };
  return { prepare: () => ({ bind: () => noop, ...noop }) };
}

describe('v24Handler.js — isAdmin() gate restored for staff-only revenue operations', () => {
  it('a non-admin caller is rejected (403) from the payment-recovery trigger', async () => {
    const req = new Request('https://x/api/v24/billing/recovery/run', { method: 'POST' });
    const res = await handleV24(req, { DB: fakeD1() }, { authenticated: true, userId: 'u1', tier: 'ENTERPRISE' }, '/api/v24/billing/recovery/run', 'POST');
    expect(res.status).toBe(403);
  });

  it('the platform owner (isAdmin) is admitted to the payment-recovery trigger', async () => {
    const req = new Request('https://x/api/v24/billing/recovery/run', { method: 'POST' });
    const res = await handleV24(req, { DB: fakeD1() }, { authenticated: true, isAdmin: true }, '/api/v24/billing/recovery/run', 'POST');
    expect(res.status).not.toBe(403);
  });

  it('a non-admin caller is rejected (403) from trust-incident posting', async () => {
    const req = new Request('https://x/api/v24/trust/incident', { method: 'POST', body: JSON.stringify({ title: 't', severity: 'high' }) });
    const res = await handleV24(req, { DB: fakeD1() }, { authenticated: true, userId: 'u1' }, '/api/v24/trust/incident', 'POST');
    expect(res.status).toBe(403);
  });
});

describe('platformMetricsAuthority.js — requireAdmin() gate restored', () => {
  it('a non-admin caller is rejected (403) from the metrics cache refresh', async () => {
    const req = new Request('https://x/api/authority/refresh', { method: 'POST' });
    req.user = { authenticated: true, userId: 'u1' };
    const res = await handleRefreshMetrics(req, {});
    expect(res.status).toBe(403);
  });

  it('the platform owner (isAdmin) is admitted to the metrics cache refresh', async () => {
    const req = new Request('https://x/api/authority/refresh?all=true', { method: 'POST' });
    req.user = { authenticated: true, isAdmin: true };
    const res = await handleRefreshMetrics(req, { SECURITY_HUB_KV: undefined });
    expect(res.status).not.toBe(403);
  });
});
