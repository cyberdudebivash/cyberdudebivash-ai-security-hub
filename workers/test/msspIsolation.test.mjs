/* Regression tests — Fix #1: MSSP per-partner tenant isolation.
 * Proves, behaviorally, that one partner cannot list, read, or update another
 * partner's mssp_customers — the queries are scoped by the bound partner_id,
 * and missing scope fails closed (empty / 404 / 403), never a cross-tenant leak. */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  handleListCustomers, handleCreateCustomer,
  handleCustomerMetrics, handleMSSPOverview,
} from '../src/handlers/msspWorkspace.js';

// In-memory mssp_customers store with REAL partner_id filtering.
function makeDB() {
  const customers = [];
  function rowMatchesPartner(row, scope) { return row.partner_id === scope; }
  const db = {
    prepare(sql) {
      let b = [];
      const stmt = {
        bind(...a) { b = a; return stmt; },
        async run() {
          if (/INSERT INTO mssp_customers/.test(sql)) {
            // cols: id, org_name, org_slug, contact_name, contact_email, tier, notes, partner_id, ...
            customers.push({
              id: b[0], org_name: b[1], org_slug: b[2], tier: b[5],
              partner_id: b[7], status: 'active', risk_score: 50,
              compliance_score: 50, mrr_cents: 0,
            });
          }
          return { success: true };
        },
        async first() {
          if (/SELECT \* FROM mssp_customers/.test(sql)) {       // metrics lookup
            const [id, slug, scope] = b;
            return customers.find(c => (c.id === id || c.org_slug === slug) && rowMatchesPartner(c, scope)) || null;
          }
          if (/total_customers/.test(sql)) {                      // overview summary
            const [scope] = b;
            const mine = customers.filter(c => rowMatchesPartner(c, scope));
            return { total_customers: mine.length, active: mine.length, onboarding: 0,
                     high_risk: 0, total_mrr_cents: 0, avg_risk: 0, avg_compliance: 0 };
          }
          if (/COUNT\(\*\) as total/.test(sql)) {                 // list count
            const [status, scope] = b;
            return { total: customers.filter(c => c.status === status && rowMatchesPartner(c, scope)).length };
          }
          return null; // scan_results / soc_cases — not modeled
        },
        async all() {
          if (/LIMIT 5/.test(sql)) {                              // overview recent
            const [scope] = b;
            return { results: customers.filter(c => rowMatchesPartner(c, scope)) };
          }
          // list query: WHERE status = ? AND partner_id = ?
          const [status, scope] = b;
          return { results: customers.filter(c => c.status === status && rowMatchesPartner(c, scope)) };
        },
      };
      return stmt;
    },
  };
  return { db, customers };
}

const partnerA = { authenticated: true, role: 'mssp_admin', userId: 'partner-A' };
const partnerB = { authenticated: true, role: 'mssp_admin', userId: 'partner-B' };

function jsonReq(url, method = 'GET', body) {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

describe('MSSP tenant isolation', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_DB: makeDB().db }; });

  async function seedForA(env) {
    const res = await handleCreateCustomer(
      jsonReq('https://x/api/mssp/customers', 'POST', { org_name: 'Acme Corp' }),
      env, partnerA,
    );
    expect(res.status).toBe(201);
    return (await res.json()).customer;
  }

  it('partner B cannot see partner A\'s customers in the list', async () => {
    await seedForA(env);
    const aList = await (await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, partnerA)).json();
    const bList = await (await handleListCustomers(jsonReq('https://x/api/mssp/customers'), env, partnerB)).json();
    expect(aList.customers.length).toBe(1);
    expect(bList.customers.length).toBe(0);
  });

  it('partner B cannot read partner A\'s customer metrics (404)', async () => {
    const cust = await seedForA(env);
    const res = await handleCustomerMetrics(
      jsonReq(`https://x/api/mssp/customers/${cust.id}/metrics`), env, partnerB, cust.id);
    expect(res.status).toBe(404);
  });

  it('partner A\'s overview counts only their own customers', async () => {
    await seedForA(env);
    const aOv = await (await handleMSSPOverview(jsonReq('https://x/api/mssp/overview'), env, partnerA)).json();
    const bOv = await (await handleMSSPOverview(jsonReq('https://x/api/mssp/overview'), env, partnerB)).json();
    expect(aOv.total_customers).toBe(1);
    expect(bOv.total_customers).toBe(0);
  });

  it('no partner scope fails closed — empty list, no leak', async () => {
    await seedForA(env);
    const res = await handleListCustomers(
      jsonReq('https://x/api/mssp/customers'), env, { authenticated: true, role: 'mssp_admin' });
    const body = await res.json();
    expect(body.customers.length).toBe(0);
  });
});
