/* GST / Invoice engine consolidation.
 *
 * Two invoice engines existed. The customer-facing billing portal
 * (billing-portal.html → GET /api/billing/invoices → gstInvoice.js) minted
 * invoice numbers on the fly from the `payments` table with three distinct
 * defects:
 *   1. handleListInvoices derived the number from pagination position
 *      (offset + i + 1) — non-persistent, and every existing invoice's
 *      number shifted whenever a new payment arrived.
 *   2. handleGetInvoice hardcoded seq=1 — every invoice ever fetched by id
 *      got the identical number.
 *   3. handleGenerateInvoice derived seq from COUNT(*) — a plain TOCTOU race
 *      with no uniqueness constraint backing it (report_jobs has no
 *      invoice_number column at all).
 * Meanwhile the real, already-wired engine (v24/billingEngine.js createInvoice()
 * → the `invoices` table, UNIQUE(invoice_number), already populated by the
 * live Razorpay payment-success path and every marketplace purchase) sat
 * unused by the customer-facing routes.
 *
 * This suite verifies gstInvoice.js is now a thin façade over that single
 * authority — stable/unique/immutable numbers, no pagination-based or
 * hardcoded numbering, idempotent generation, and safe concurrent creation —
 * using a real in-memory SQLite engine (node:sqlite) so UNIQUE-constraint and
 * race behavior is exercised for real, not approximated by a hand-rolled mock.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleListInvoices, handleGetInvoice, handleGenerateInvoice } from '../src/handlers/gstInvoice.js';
import { createInvoice } from '../src/services/v24/billingEngine.js';

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

let env, db;

beforeEach(() => {
  env = { DB: makeRealD1(), PLATFORM_GSTIN: '29ABCDE1234F1Z5' };
  db = env.DB._sqlite;

  db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT)`);
  db.exec(`
    CREATE TABLE payments (
      id TEXT PRIMARY KEY, user_id TEXT, module TEXT, target TEXT,
      amount INTEGER NOT NULL, currency TEXT DEFAULT 'INR',
      razorpay_order_id TEXT UNIQUE, razorpay_payment_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending', email TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), paid_at TEXT
    )
  `);
  db.exec(`
    CREATE TABLE invoices (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
      invoice_number TEXT NOT NULL UNIQUE,
      customer_id TEXT NOT NULL, user_id TEXT, email TEXT NOT NULL,
      company TEXT, gstin TEXT, billing_address TEXT DEFAULT '{}',
      line_items TEXT NOT NULL DEFAULT '[]',
      subtotal_inr INTEGER NOT NULL DEFAULT 0, gst_rate REAL NOT NULL DEFAULT 18.0,
      gst_amount_inr INTEGER NOT NULL DEFAULT 0, total_inr INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'INR', status TEXT NOT NULL DEFAULT 'draft',
      payment_id TEXT, payment_method TEXT, due_date TEXT, paid_at TEXT, sent_at TEXT,
      pdf_key TEXT, notes TEXT, period_start TEXT, period_end TEXT, subscription_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    CREATE TABLE revenue_streams (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
      period TEXT NOT NULL, stream TEXT NOT NULL,
      revenue_inr INTEGER NOT NULL DEFAULT 0, transaction_count INTEGER NOT NULL DEFAULT 0,
      customer_count INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.exec(`CREATE UNIQUE INDEX idx_revstream_period ON revenue_streams(period, stream)`);
  // schema_v49_invoice_payment_id_unique.sql — the DB-level guarantee that
  // actually makes concurrent same-payment invoice creation safe.
  db.exec(`CREATE UNIQUE INDEX idx_invoices_payment_id_unique ON invoices(payment_id) WHERE payment_id IS NOT NULL AND payment_id != ''`);
});

function payReq(url) { return new Request(url); }

function insertPaidPayment(overrides = {}) {
  const p = {
    id: 'pay_row_1', user_id: 'u_1', module: 'domain_scan', target: 'example.com',
    amount: 118000, razorpay_order_id: 'order_ABC123', razorpay_payment_id: 'pay_ABC123',
    status: 'paid', email: 'customer@example.com',
    ...overrides,
  };
  db.prepare(
    `INSERT INTO payments (id, user_id, module, target, amount, razorpay_order_id, razorpay_payment_id, status, email)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(p.id, p.user_id, p.module, p.target, p.amount, p.razorpay_order_id, p.razorpay_payment_id, p.status, p.email);
  return p;
}

describe('handleListInvoices — reads the persisted ledger, never fabricates numbers', () => {
  it('returns the stable stored invoice_number, not a pagination-derived one', async () => {
    insertPaidPayment();
    const created = await createInvoice(env.DB, {
      userId: 'u_1', email: 'customer@example.com',
      lineItems: [{ description: 'Domain Scan', amount_inr: 1000, quantity: 1 }],
      paymentId: 'pay_ABC123', paymentMethod: 'razorpay',
    }, env);
    expect(created.ok).toBe(true);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const res = await handleListInvoices(payReq('https://x/api/billing/invoices'), env, authCtx);
    const body = await res.json();
    expect(body.data.invoices).toHaveLength(1);
    expect(body.data.invoices[0].invoice_number).toBe(created.invoice_number);
  });

  it('the same invoice keeps the same number across repeated list calls and new unrelated invoices arriving', async () => {
    insertPaidPayment();
    const first = await createInvoice(env.DB, {
      userId: 'u_1', email: 'customer@example.com',
      lineItems: [{ description: 'Domain Scan', amount_inr: 1000, quantity: 1 }],
      paymentId: 'pay_ABC123',
    }, env);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const before = await (await handleListInvoices(payReq('https://x/api/billing/invoices'), env, authCtx)).json();

    // A second, unrelated customer's invoice arrives — under the old
    // pagination-based numbering this would have shifted every previously
    // shown number for this customer.
    await createInvoice(env.DB, {
      userId: 'u_2', email: 'other@example.com',
      lineItems: [{ description: 'Other', amount_inr: 500, quantity: 1 }],
      paymentId: 'pay_other',
    }, env);

    const after = await (await handleListInvoices(payReq('https://x/api/billing/invoices'), env, authCtx)).json();
    expect(after.data.invoices[0].invoice_number).toBe(before.data.invoices[0].invoice_number);
    expect(after.data.invoices[0].invoice_number).toBe(first.invoice_number);
  });

  it('requires authentication', async () => {
    const res = await handleListInvoices(payReq('https://x/api/billing/invoices'), env, {});
    expect(res.status).toBe(401);
  });
});

describe('handleGetInvoice — no more hardcoded seq=1 for every invoice', () => {
  it('two different invoices for the same customer get two different numbers', async () => {
    insertPaidPayment({ id: 'pay_row_1', razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1' });
    insertPaidPayment({ id: 'pay_row_2', razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2' });
    await createInvoice(env.DB, { userId: 'u_1', email: 'customer@example.com', lineItems: [{ description: 'A', amount_inr: 100, quantity: 1 }], paymentId: 'pay_1' }, env);
    await createInvoice(env.DB, { userId: 'u_1', email: 'customer@example.com', lineItems: [{ description: 'B', amount_inr: 200, quantity: 1 }], paymentId: 'pay_2' }, env);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const inv1 = await (await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_1')).json();
    const inv2 = await (await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_2')).json();

    expect(inv1.data.invoice_number).not.toBe(inv2.data.invoice_number);
  });

  it('resolves legacy download_url links keyed by Razorpay order_id', async () => {
    insertPaidPayment();
    const created = await createInvoice(env.DB, {
      userId: 'u_1', email: 'customer@example.com',
      lineItems: [{ description: 'Domain Scan', amount_inr: 1000, quantity: 1 }],
      paymentId: 'pay_ABC123',
    }, env);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const res = await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_ABC123');
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.data.invoice_number).toBe(created.invoice_number);
  });

  it('materializes exactly once for a paid payment that has no invoice yet, then stays stable', async () => {
    insertPaidPayment();
    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };

    const first = await (await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_ABC123')).json();
    const second = await (await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_ABC123')).json();
    expect(first.data.invoice_number).toBe(second.data.invoice_number);

    const rows = db.prepare(`SELECT COUNT(*) c FROM invoices WHERE payment_id = 'pay_ABC123'`).get();
    expect(rows.c).toBe(1);
  });

  it('refuses to materialize an invoice for a payment that never completed', async () => {
    insertPaidPayment({ status: 'pending' });
    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const res = await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_ABC123');
    expect(res.status).toBe(404);
  });

  it('denies access to another customer\'s invoice', async () => {
    insertPaidPayment();
    await createInvoice(env.DB, { userId: 'u_1', email: 'customer@example.com', lineItems: [{ description: 'A', amount_inr: 100, quantity: 1 }], paymentId: 'pay_ABC123' }, env);

    const attacker = { user_id: 'u_evil', email: 'evil@example.com' };
    const res = await handleGetInvoice(payReq('https://x'), env, attacker, 'order_ABC123');
    expect(res.status).toBe(404);
  });

  it('fixes the buildInvoiceObject env ReferenceError when no GSTIN secret is configured', async () => {
    delete env.PLATFORM_GSTIN;
    insertPaidPayment();
    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const res = await handleGetInvoice(payReq('https://x'), env, authCtx, 'order_ABC123');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.supplier.gstin).toBe('PENDING_REGISTRATION');
  });
});

describe('handleGenerateInvoice — idempotent, no duplicate invoice assignment', () => {
  it('a duplicate generate request for the same order returns the SAME invoice, not a new one', async () => {
    insertPaidPayment();
    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const body = JSON.stringify({ order_id: 'order_ABC123', customer_gstin: '29ABCDE1234F1Z5', customer_state: 'Karnataka' });
    const req = () => new Request('https://x', { method: 'POST', body });

    const first = await (await handleGenerateInvoice(req(), env, authCtx)).json();
    const second = await (await handleGenerateInvoice(req(), env, authCtx)).json();

    expect(first.data.invoice_number).toBe(second.data.invoice_number);
    const rows = db.prepare(`SELECT COUNT(*) c FROM invoices WHERE payment_id = 'pay_ABC123'`).get();
    expect(rows.c).toBe(1);
  });

  it('rejects generation for a payment that has not completed', async () => {
    insertPaidPayment({ status: 'failed' });
    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ order_id: 'order_ABC123' }) });
    const res = await handleGenerateInvoice(req, env, authCtx);
    expect(res.status).toBe(409);
  });

  it('enriches a pre-existing GSTIN-less invoice with a later-supplied GSTIN instead of minting a new number', async () => {
    insertPaidPayment();
    // Simulates the automatic fire-and-forget invoice created at payment
    // time by payments.js, which never collects GSTIN/company.
    const auto = await createInvoice(env.DB, {
      userId: 'u_1', email: 'customer@example.com',
      lineItems: [{ description: 'Domain Scan', amount_inr: 1000, quantity: 1 }],
      paymentId: 'pay_ABC123',
    }, env);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({
      order_id: 'order_ABC123', customer_gstin: '29ABCDE1234F1Z5', customer_company: 'Acme Pvt Ltd', customer_state: 'Maharashtra',
    }) });
    const res = await handleGenerateInvoice(req, env, authCtx);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.data.invoice_number).toBe(auto.invoice_number);
    expect(body.data.customer.gstin).toBe('29ABCDE1234F1Z5');
    expect(body.data.itc_eligible).toBe(true);

    const rows = db.prepare(`SELECT COUNT(*) c FROM invoices WHERE payment_id = 'pay_ABC123'`).get();
    expect(rows.c).toBe(1);
  });

  it('does not overwrite an existing GSTIN with a different one from a later request', async () => {
    insertPaidPayment();
    await createInvoice(env.DB, {
      userId: 'u_1', email: 'customer@example.com', gstin: '29ORIGINAL1234Z5',
      lineItems: [{ description: 'Domain Scan', amount_inr: 1000, quantity: 1 }],
      paymentId: 'pay_ABC123',
    }, env);

    const authCtx = { user_id: 'u_1', email: 'customer@example.com' };
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ order_id: 'order_ABC123', customer_gstin: '27DIFFERENT567Z1' }) });
    const body = await (await handleGenerateInvoice(req, env, authCtx)).json();
    expect(body.data.customer.gstin).toBe('29ORIGINAL1234Z5');
  });
});

describe('createInvoice() — concurrency safety (real UNIQUE constraint + retry)', () => {
  it('N concurrent invoice creations for N different payments all get distinct sequential numbers', async () => {
    const n = 8;
    const results = await Promise.all(
      Array.from({ length: n }, (_, i) => createInvoice(env.DB, {
        userId: `u_${i}`, email: `u${i}@example.com`,
        lineItems: [{ description: 'Concurrent', amount_inr: 100, quantity: 1 }],
        paymentId: `pay_concurrent_${i}`,
      }, env))
    );
    expect(results.every(r => r.ok)).toBe(true);
    const numbers = results.map(r => r.invoice_number);
    expect(new Set(numbers).size).toBe(n); // all unique — no collisions survived
  });

  it('N concurrent requests for the SAME payment converge on exactly one invoice number', async () => {
    const n = 6;
    const results = await Promise.all(
      Array.from({ length: n }, () => createInvoice(env.DB, {
        userId: 'u_race', email: 'race@example.com',
        lineItems: [{ description: 'Same payment race', amount_inr: 500, quantity: 1 }],
        paymentId: 'pay_same_race',
      }, env))
    );
    expect(results.every(r => r.ok)).toBe(true);
    const numbers = new Set(results.map(r => r.invoice_number));
    expect(numbers.size).toBe(1);

    const rows = db.prepare(`SELECT COUNT(*) c FROM invoices WHERE payment_id = 'pay_same_race'`).get();
    expect(rows.c).toBe(1);
  });
});
