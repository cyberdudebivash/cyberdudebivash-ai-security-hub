/* Regression tests — a real MSSP partner session (handlers/partnerAuth.js,
 * authCtx.partnerId + role:'partner', no user_id — mssp_partners is a
 * separate identity from `users`) must be able to reach the same "own-org"
 * MSSP workspace views a legacy MSSP-tier user account already could, and
 * must be scoped by their real mssp_partners.id — not silently locked out
 * (requireMSSPAdmin only ever checked tier==='MSSP'/isAdmin) and not
 * collapsed onto another tenant's rows (partnerScope only ever read
 * userId/user_id, which a partner session never has). */
import { describe, it, expect, beforeEach } from 'vitest';
import { handleListCustomers, handleCreateCustomer, handleMSSPOverview } from '../src/handlers/msspWorkspace.js';

function makeDB() {
  const customers = [];
  const db = {
    prepare(sql) {
      let b = [];
      const stmt = {
        bind(...a) { b = a; return stmt; },
        async run() {
          if (/INSERT INTO mssp_customers/.test(sql)) {
            customers.push({ id: b[0], org_name: b[1], org_slug: b[2], tier: b[5], partner_id: b[7], status: 'active' });
          }
          return { success: true };
        },
        async first() {
          if (/total_customers/.test(sql)) {
            const [scope] = b;
            const mine = customers.filter(c => c.partner_id === scope);
            return { total_customers: mine.length, active: mine.length, onboarding: 0, high_risk: 0, total_mrr_cents: 0, avg_risk: 0, avg_compliance: 0 };
          }
          if (/COUNT\(\*\) as total/.test(sql)) {
            const [status, scope] = b;
            return { total: customers.filter(c => c.status === status && c.partner_id === scope).length };
          }
          return null;
        },
        async all() {
          if (/LIMIT 5/.test(sql)) {
            const [scope] = b;
            return { results: customers.filter(c => c.partner_id === scope) };
          }
          const [status, scope] = b;
          return { results: customers.filter(c => c.status === status && c.partner_id === scope) };
        },
      };
      return stmt;
    },
  };
  return { db, customers };
}

function jsonReq(url, method = 'GET', body) {
  return new Request(url, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
}

const partnerSession = { authenticated: true, role: 'partner', partnerId: 'mp_real_partner_1', tier: 'GOLD' };

describe('MSSP workspace — a real partner session is admitted and correctly scoped', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_DB: makeDB().db }; });

  it('requireMSSPAdmin admits a partner session (was tier===MSSP/isAdmin only)', async () => {
    const res = await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, partnerSession);
    expect(res.status).not.toBe(403);
  });

  it('a customer created by a partner session is stamped with the real mssp_partners.id, not a user id', async () => {
    const res = await handleCreateCustomer(jsonReq('https://x/api/mssp/customers', 'POST', { org_name: 'Acme Corp' }), env, partnerSession);
    expect(res.status).toBe(201);
    const created = (await res.json()).customer;
    const list = await (await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, partnerSession)).json();
    expect(list.customers.map(c => c.id)).toContain(created.id);
  });

  it('a second partner session cannot see the first partner\'s customers', async () => {
    await handleCreateCustomer(jsonReq('https://x/api/mssp/customers', 'POST', { org_name: 'Acme Corp' }), env, partnerSession);
    const otherPartner = { authenticated: true, role: 'partner', partnerId: 'mp_other_partner_2', tier: 'SILVER' };
    const otherList = await (await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, otherPartner)).json();
    expect(otherList.customers.length).toBe(0);
  });

  it('overview counts only the logged-in partner\'s own customers', async () => {
    await handleCreateCustomer(jsonReq('https://x/api/mssp/customers', 'POST', { org_name: 'Acme Corp' }), env, partnerSession);
    const ov = await (await handleMSSPOverview(jsonReq('https://x/api/mssp/overview'), env, partnerSession)).json();
    expect(ov.total_customers).toBe(1);
  });

  it('a legacy MSSP-tier user account (no partnerId) still works via the old userId scope', async () => {
    const legacyUser = { authenticated: true, tier: 'MSSP', userId: 'legacy-user-1' };
    const res = await handleCreateCustomer(jsonReq('https://x/api/mssp/customers', 'POST', { org_name: 'Legacy Co' }), env, legacyUser);
    expect(res.status).toBe(201);
    const list = await (await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, legacyUser)).json();
    expect(list.customers.length).toBe(1);
  });
});
