/* Regression tests — real MSSP revenue-share implementation (replaces the
 * "Revenue Share 60/40" marketing claim that previously had zero backend
 * support). Proves: correct split math, per-partner configurable percentage,
 * idempotency on duplicate webhook/verify delivery, and partner attribution
 * lookup by customer email. */
import { describe, it, expect, beforeEach } from 'vitest';
import { resolvePartnerIdForEmail, recordRevenueShare } from '../src/handlers/msspRevenue.js';

function makeDB({ partners = [], customers = [] } = {}) {
  const ledger = [];
  const alteredCols = new Set();
  const db = {
    prepare(sql) {
      let b = [];
      const stmt = {
        bind(...a) { b = a; return stmt; },
        async run() {
          if (/ALTER TABLE/.test(sql)) {
            // Simulate "duplicate column" on second call for the same column —
            // mirrors real SQLite behavior the production code depends on.
            const col = sql.match(/ADD COLUMN (\w+)/)?.[1];
            if (col && alteredCols.has(col)) throw new Error(`duplicate column name: ${col}`);
            if (col) alteredCols.add(col);
            return { success: true };
          }
          if (/CREATE TABLE|CREATE INDEX/.test(sql)) return { success: true };
          if (/INSERT INTO mssp_revenue_ledger/.test(sql)) {
            const [partner_id, payment_id, customer_email, module, gross, pct, partnerShare, platformShare] = b;
            if (ledger.some(l => l.payment_id === payment_id)) {
              throw new Error('UNIQUE constraint failed: mssp_revenue_ledger.payment_id');
            }
            ledger.push({
              partner_id, payment_id, customer_email, module,
              gross_amount_paise: gross, partner_share_pct: pct,
              partner_share_paise: partnerShare, platform_share_paise: platformShare,
              status: 'accrued',
            });
            return { success: true };
          }
          return { success: true };
        },
        async first() {
          if (/SELECT partner_id FROM mssp_customers/.test(sql)) {
            const [email] = b;
            const c = customers.find(c => c.contact_email === email && c.partner_id);
            return c ? { partner_id: c.partner_id } : null;
          }
          if (/SELECT partner_share_pct FROM mssp_partners/.test(sql)) {
            const [id] = b;
            const p = partners.find(p => p.id === id);
            return p ? { partner_share_pct: p.partner_share_pct } : null;
          }
          return null;
        },
        async all() { return { results: [] }; },
      };
      return stmt;
    },
  };
  return { db, ledger };
}

describe('MSSP revenue share — real implementation', () => {
  beforeEach(() => {
    // Each test gets a fresh DB mock; the module-level _revenueTablesReady
    // flag persists across tests in the same process, which is fine — it
    // mirrors a warm Worker isolate and the ALTER/CREATE calls are no-ops
    // either way once already applied.
  });

  it('computes a 60/40 split by default, matching the marketed claim', async () => {
    const { db, ledger } = makeDB({
      partners: [{ id: 'p1', partner_share_pct: 60.0 }],
    });
    const result = await recordRevenueShare({ DB: db }, {
      paymentId: 'pay_1', partnerId: 'p1', grossAmountPaise: 100000,
      customerEmail: 'customer@example.com', module: 'domain',
    });
    expect(result.recorded).toBe(true);
    expect(result.partnerSharePaise).toBe(60000);
    expect(result.platformSharePaise).toBe(40000);
    expect(ledger).toHaveLength(1);
    expect(ledger[0].partner_share_paise + ledger[0].platform_share_paise).toBe(100000);
  });

  it('respects a per-partner configured split percentage', async () => {
    const { db } = makeDB({
      partners: [{ id: 'p2', partner_share_pct: 70.0 }],
    });
    const result = await recordRevenueShare({ DB: db }, {
      paymentId: 'pay_2', partnerId: 'p2', grossAmountPaise: 200000,
      customerEmail: 'big@example.com', module: 'subscription',
    });
    expect(result.partnerSharePaise).toBe(140000);
    expect(result.platformSharePaise).toBe(60000);
  });

  it('defaults to 60% if the partner row has no explicit share configured', async () => {
    const { db } = makeDB({ partners: [] }); // partner lookup returns null
    const result = await recordRevenueShare({ DB: db }, {
      paymentId: 'pay_3', partnerId: 'p_unknown', grossAmountPaise: 100000,
      customerEmail: 'x@example.com', module: 'domain',
    });
    expect(result.sharePct).toBe(60.0);
    expect(result.partnerSharePaise).toBe(60000);
  });

  it('is idempotent — a duplicate payment_id does not double-record revenue', async () => {
    const { db, ledger } = makeDB({ partners: [{ id: 'p1', partner_share_pct: 60.0 }] });
    const args = { paymentId: 'pay_dup', partnerId: 'p1', grossAmountPaise: 50000, customerEmail: 'e@x.com', module: 'domain' };
    const first  = await recordRevenueShare({ DB: db }, args);
    const second = await recordRevenueShare({ DB: db }, args); // simulates webhook + client-verify both firing
    expect(first.recorded).toBe(true);
    expect(second.recorded).toBe(false);
    expect(second.reason).toBe('duplicate');
    expect(ledger).toHaveLength(1); // not double-counted
  });

  it('never throws — missing fields produce a no-op result, not an exception', async () => {
    const { db } = makeDB();
    const result = await recordRevenueShare({ DB: db }, { paymentId: null, partnerId: 'p1', grossAmountPaise: 100 });
    expect(result.recorded).toBe(false);
    expect(result.reason).toBe('missing_fields');
  });

  it('resolvePartnerIdForEmail finds the owning partner via mssp_customers.contact_email', async () => {
    const { db } = makeDB({
      customers: [{ contact_email: 'client@cisco.com', partner_id: 'p_cisco' }],
    });
    const partnerId = await resolvePartnerIdForEmail({ DB: db }, 'client@cisco.com');
    expect(partnerId).toBe('p_cisco');
  });

  it('resolvePartnerIdForEmail returns null for ordinary direct customers (no partner)', async () => {
    const { db } = makeDB({ customers: [] });
    const partnerId = await resolvePartnerIdForEmail({ DB: db }, 'direct.customer@example.com');
    expect(partnerId).toBeNull();
  });

  it('resolvePartnerIdForEmail fails open to null when DB is unavailable', async () => {
    const partnerId = await resolvePartnerIdForEmail({}, 'x@example.com');
    expect(partnerId).toBeNull();
  });
});
