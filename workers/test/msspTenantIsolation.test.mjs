/* MSSP multi-tenant (per-partner) isolation (Journey 6).
 *
 * Verdict: MSSP customer management is correctly isolated — the partner scope is
 * derived from the authenticated JWT identity (not client input), and every
 * read/write is scoped `WHERE partner_id = ?`. This suite locks that: partner B
 * can neither read nor mutate partner A's customer. It also covers the one
 * correctness fix — handleUpdateCustomer now returns 404 (not a misleading
 * success) when no row matches the caller's scope.
 *
 * Run against a real SQL engine (node:sqlite) with the real query shapes.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleGetCustomer, handleUpdateCustomer, handleDeleteCustomer, handleSuspendCustomer,
} from '../src/handlers/msspWorkspace.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}
const partnerA = { authenticated: true, userId: 'pA', role: 'mssp_admin' };
const partnerB = { authenticated: true, userId: 'pB', role: 'mssp_admin' };
const req = (method = 'GET', bodyObj) => new Request('https://x/api/mssp/customers/cust1', {
  method, headers: { 'Content-Type': 'application/json' }, body: bodyObj ? JSON.stringify(bodyObj) : undefined,
});

describe('MSSP customers are isolated per partner', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE mssp_customers (
      id TEXT PRIMARY KEY, org_name TEXT, org_slug TEXT, contact_name TEXT, contact_email TEXT,
      tier TEXT, status TEXT DEFAULT 'active', risk_score INTEGER, compliance_score INTEGER,
      mrr_cents INTEGER, notes TEXT, parent_customer_id TEXT, suspended_at TEXT, archived_at TEXT,
      deleted_at TEXT, suspension_reason TEXT, created_at TEXT, updated_at TEXT, last_activity_at TEXT,
      partner_id TEXT
    )`);
    // A customer owned by partner A.
    env.SECURITY_HUB_DB._sqlite.prepare(
      `INSERT INTO mssp_customers (id, org_name, org_slug, tier, status, partner_id) VALUES (?,?,?,?,?,?)`
    ).run('cust1', 'Acme Corp', 'acme', 'PRO', 'active', 'pA');
  });

  it('owner (A) can read their customer', async () => {
    const res = await handleGetCustomer(req('GET'), env, partnerA, 'cust1');
    expect(res.status).toBe(200);
  });
  it('partner B cannot READ partner A\'s customer (404)', async () => {
    const res = await handleGetCustomer(req('GET'), env, partnerB, 'cust1');
    expect(res.status).toBe(404);
  });
  it('partner B cannot UPDATE partner A\'s customer (404, no change)', async () => {
    const res = await handleUpdateCustomer(req('PATCH', { org_name: 'Hacked' }), env, partnerB, 'cust1');
    expect(res.status).toBe(404);
    const row = env.SECURITY_HUB_DB._sqlite.prepare(`SELECT org_name FROM mssp_customers WHERE id='cust1'`).get();
    expect(row.org_name).toBe('Acme Corp'); // unchanged
  });
  it('partner B cannot DELETE partner A\'s customer (404, still active)', async () => {
    const res = await handleDeleteCustomer(req('DELETE'), env, partnerB, 'cust1');
    expect(res.status).toBe(404);
    const row = env.SECURITY_HUB_DB._sqlite.prepare(`SELECT status FROM mssp_customers WHERE id='cust1'`).get();
    expect(row.status).toBe('active');
  });
  it('partner B cannot SUSPEND partner A\'s customer (404)', async () => {
    const res = await handleSuspendCustomer(req('POST', { reason: 'x' }), env, partnerB, 'cust1');
    expect(res.status).toBe(404);
  });
  it('owner (A) CAN update their customer (200)', async () => {
    const res = await handleUpdateCustomer(req('PATCH', { org_name: 'Acme Renamed' }), env, partnerA, 'cust1');
    expect(res.status).toBe(200);
  });
});
