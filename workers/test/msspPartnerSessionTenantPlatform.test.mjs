/* CAP-MSSP-003 — msspTenantPlatform.js's requireMSSPAdmin()/partnerScope()
 * never recognized a real MSSP partner session (workers/src/handlers/
 * partnerAuth.js magic-link login), only a JWT/API-key user whose own
 * subscription tier happens to be the literal string 'MSSP'.
 *
 * A real partner session (resolvePartnerSession() in workers/src/auth/
 * middleware.js) resolves to { partnerId: 'p_xxx', userId: null,
 * user_id: null, tier: 'RESELLER'|'SILVER'|'GOLD'|'PLATINUM', role: 'partner' }
 * — requireMSSPAdmin() only checked authCtx.isAdmin and tier==='MSSP', so
 * this identity 403'd on every one of the 18 handlers in this file. Separately,
 * partnerScope() only read authCtx.userId/user_id — always null for a partner
 * session — so even if the admin gate were bypassed, every query would have
 * been scoped to a null partner_id, returning nothing.
 *
 * This is why the 2 already-wired handlers in the sibling msspWorkspace.js
 * worked for real partners (that file's requireMSSPAdmin/partnerScope were
 * already fixed for role==='partner'/partnerId — 2026-07-06 revenue-mechanisms
 * audit) while every other handler in msspTenantPlatform.js did not: a
 * frontend built against this file's contract, exactly as documented, would
 * have appeared correct in code review and then 403'd for every real partner
 * in production.
 *
 * Mirrors workers/test/deadAdminChecksRestored.test.mjs's coverage (same
 * handlers, same real-SQLite pattern) but for the partner-session identity
 * specifically, since that file only exercises the legacy tier:'MSSP'
 * JWT-user identity. Both identities must now work, and must not cross.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleCustomerDashboard,
  handleCreateSubTenant,
  handleListSubTenants,
  handleGenerateCustomerAPIKey,
  handleListCustomerAPIKeys,
  handleAddCustomerLabel,
  handleListCustomerLabels,
} from '../src/handlers/msspTenantPlatform.js';

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

// Shaped exactly like resolvePartnerSession() + withAuthAliases()'s real
// output (workers/src/auth/middleware.js) — not a simplified stand-in.
function partnerSession(partnerId) {
  return {
    authenticated: true,
    method: 'partner_session',
    identity: `partner:${partnerId}`,
    userId: null,
    user_id: null,
    partnerId,
    partner_id: partnerId,
    tier: 'RESELLER',
    role: 'partner',
    email: `${partnerId}@partner.example.com`,
  };
}

const ANON      = { authenticated: false };
const FREE_USER = { authenticated: true, userId: 'u1', user_id: 'u1', tier: 'FREE' };
const PARTNER_A = partnerSession('pA');
const PARTNER_B = partnerSession('pB');

describe('msspTenantPlatform.js — real partner-session identity (CAP-MSSP-003)', () => {
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
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE IF NOT EXISTS mssp_customer_api_keys (
      id TEXT PRIMARY KEY, partner_id TEXT NOT NULL, customer_id TEXT NOT NULL,
      key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL, name TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT '["read"]', status TEXT NOT NULL DEFAULT 'active',
      last_used_at TEXT, expires_at TEXT, created_at TEXT NOT NULL, revoked_at TEXT
    )`);
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE IF NOT EXISTS mssp_customer_labels (
      id TEXT PRIMARY KEY, partner_id TEXT NOT NULL, customer_id TEXT NOT NULL,
      label TEXT NOT NULL, created_at TEXT
    )`);
  });

  it('anonymous caller is still rejected (403) — the fix did not weaken the gate', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, ANON, 'cust1');
    expect(res.status).toBe(403);
  });

  it('a plain FREE-tier authenticated user (not a partner) is still rejected (403)', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, FREE_USER, 'cust1');
    expect(res.status).toBe(403);
  });

  it('a real partner session can now reach their own customer dashboard (was: 403 for every real partner)', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, PARTNER_A, 'cust1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.customer.org_name).toBe('Acme Corp');
  });

  it('a different partner session cannot read partner A\'s customer dashboard (404, not leaked)', async () => {
    const res = await handleCustomerDashboard(new Request('https://x'), env, PARTNER_B, 'cust1');
    expect(res.status).toBe(404);
  });

  it('a real partner session can create a sub-tenant under their own customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ org_name: 'Sub Co' }) });
    const res = await handleCreateSubTenant(req, env, PARTNER_A, 'cust1');
    expect(res.status).toBe(201);
  });

  it('a different partner session cannot create a sub-tenant under someone else\'s customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ org_name: 'Sub Co' }) });
    const res = await handleCreateSubTenant(req, env, PARTNER_B, 'cust1');
    expect(res.status).toBe(404);
  });

  it('a real partner session sees their own newly-created sub-tenant via handleListSubTenants', async () => {
    const createReq = new Request('https://x', { method: 'POST', body: JSON.stringify({ org_name: 'Sub Co' }) });
    await handleCreateSubTenant(createReq, env, PARTNER_A, 'cust1');
    const res = await handleListSubTenants(new Request('https://x'), env, PARTNER_A, 'cust1');
    const body = await res.json();
    expect(body.sub_tenants.length).toBe(1);
    expect(body.sub_tenants[0].org_name).toBe('Sub Co');
  });

  it('a real partner session can generate an API key scoped to their own customer', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ name: 'ci-key' }) });
    const res = await handleGenerateCustomerAPIKey(req, env, PARTNER_A, 'cust1');
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.key).toMatch(/^cak_/);
  });

  it('a different partner session cannot list API keys for someone else\'s customer (empty, not error, not leaked)', async () => {
    const genReq = new Request('https://x', { method: 'POST', body: JSON.stringify({ name: 'ci-key' }) });
    await handleGenerateCustomerAPIKey(genReq, env, PARTNER_A, 'cust1');

    const res  = await handleListCustomerAPIKeys(new Request('https://x'), env, PARTNER_B, 'cust1');
    const body = await res.json();
    expect(body.keys).toEqual([]);
  });

  it('a real partner session can add and list a label on their own customer', async () => {
    const addReq = new Request('https://x', { method: 'POST', body: JSON.stringify({ label: 'high-value' }) });
    const addRes = await handleAddCustomerLabel(addReq, env, PARTNER_A, 'cust1');
    expect(addRes.status).toBe(200);

    const res  = await handleListCustomerLabels(new Request('https://x'), env, PARTNER_A, 'cust1');
    const body = await res.json();
    expect(body.labels).toContain('high-value');
  });

  it('the legacy tier:\'MSSP\' JWT-user identity still works unchanged (no regression from this fix)', async () => {
    const legacyUser = { authenticated: true, userId: 'pA', user_id: 'pA', tier: 'MSSP' };
    const res = await handleCustomerDashboard(new Request('https://x'), env, legacyUser, 'cust1');
    expect(res.status).toBe(200);
  });

  it('a partner session can never be scoped by a client-supplied userId — only server-derived partnerId is trusted', async () => {
    // If a partner session ever carried a stray/forged userId matching
    // another tenant's customer's owning id, partnerScope() must still
    // prefer partnerId (checked first) — proven by using partner A's real
    // partnerId with a userId that collides with nothing in mssp_customers.
    const spoofed = { ...PARTNER_A, userId: 'pB', user_id: 'pB' };
    const res = await handleCustomerDashboard(new Request('https://x'), env, spoofed, 'cust1');
    // partnerId ('pA', the real owner) wins over the spoofed userId ('pB').
    expect(res.status).toBe(200);
  });
});
