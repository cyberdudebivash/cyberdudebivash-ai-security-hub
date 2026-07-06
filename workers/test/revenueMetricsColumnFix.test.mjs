/* Regression tests — the two revenue dashboards silently reported ₹0 MRR
 * even with real paying customers (2026-07-06 revenue-mechanisms audit).
 *
 * handlers/revenueMetrics.js queried a `users.plan` column that has never
 * existed (the live schema's column is `users.tier`, uppercase values) — the
 * query threw on every call, was swallowed by its own catch block, and left
 * pro/enterprise counts at 0 forever. STARTER and MSSP tiers were also never
 * counted at all, even before that.
 *
 * services/analyticsEngine.js's computeMRR() queried `leads.plan`, a column
 * that does exist but is never written by the real checkout path
 * (handlers/payments.js handleVerifyPayment updates users.tier, not
 * leads.plan) — same symptom, different root cause.
 *
 * Both now read users.tier, the column the real payment-verify handler
 * actually writes on a purchase.
 */
import { describe, it, expect } from 'vitest';
import { computeMRR } from '../src/services/analyticsEngine.js';
import { handleRevenueMetrics } from '../src/handlers/revenueMetrics.js';

// ── computeMRR (services/analyticsEngine.js) ────────────────────────────────
function makeLeadsStyleDb(userRows) {
  return {
    prepare(sql) {
      return {
        async all() {
          if (!/FROM users/.test(sql)) return { results: [] };
          const counts = {};
          for (const r of userRows) {
            if (!r.tier || r.tier === 'FREE') continue;
            counts[r.tier] = (counts[r.tier] || 0) + 1;
          }
          return { results: Object.entries(counts).map(([tier, count]) => ({ tier, count })) };
        },
      };
    },
  };
}

describe('computeMRR — reads users.tier (real column), not leads.plan (never written by checkout)', () => {
  it('is non-zero when real paying users exist across STARTER/PRO/ENTERPRISE/MSSP', async () => {
    const env = {
      DB: makeLeadsStyleDb([
        { tier: 'FREE' }, { tier: 'FREE' },
        { tier: 'STARTER' },
        { tier: 'PRO' }, { tier: 'PRO' },
        { tier: 'ENTERPRISE' },
        { tier: 'MSSP' },
      ]),
    };
    const result = await computeMRR(env);
    // 1*499 + 2*1499 + 1*4999 + 1*9999 = 17995
    expect(result.mrr).toBe(499 + 2 * 1499 + 4999 + 9999);
    expect(result.arr).toBe(result.mrr * 12);
    expect(result.by_plan.pro.customers).toBe(2);
    expect(result.by_plan.mssp.customers).toBe(1);
    expect(result.by_plan.free).toBeUndefined(); // free excluded, matching prior behavior
  });

  it('is exactly 0 with no paying users — not silently 0 due to a broken query', async () => {
    const env = { DB: makeLeadsStyleDb([{ tier: 'FREE' }, { tier: 'FREE' }]) };
    const result = await computeMRR(env);
    expect(result.mrr).toBe(0);
    expect(result.error).toBeUndefined();
  });
});

// ── handleRevenueMetrics (handlers/revenueMetrics.js) ───────────────────────
function makeRevenueDb(tierRows) {
  function router(sql) {
    if (/SUM\(CASE WHEN tier = 'FREE'/.test(sql)) {
      const counts = { total: 0, free_count: 0, starter_count: 0, pro_count: 0, ent_count: 0, mssp_count: 0 };
      const field = { FREE: 'free_count', STARTER: 'starter_count', PRO: 'pro_count', ENTERPRISE: 'ent_count', MSSP: 'mssp_count' };
      for (const r of tierRows) {
        counts.total++;
        if (field[r.tier]) counts[field[r.tier]]++;
      }
      return { first: async () => counts, all: async () => ({ results: [] }), run: async () => ({}) };
    }
    // Everything else (new-this-month, assessments, revenue_snapshots, the
    // fallback plain COUNT) — throw so the real function's own try/catch
    // defaults it safely, exactly as it does in production against tables
    // this test isn't exercising.
    const fail = async () => { throw new Error('unmocked query: ' + sql.trim().slice(0, 50)); };
    return { first: fail, all: fail, run: fail };
  }
  return { prepare: (sql) => ({ ...router(sql), bind: () => router(sql) }) };
}

function makeKV() {
  return { async get() { return null; }, async put() {} };
}

describe('handleRevenueMetrics — dashboard reports real MRR instead of always ₹0', () => {
  it('reports non-zero MRR for an admin caller when real PRO/ENTERPRISE users exist', async () => {
    const env = {
      SECURITY_HUB_KV: makeKV(),
      SECURITY_HUB_DB: makeRevenueDb([
        { tier: 'FREE' }, { tier: 'PRO' }, { tier: 'PRO' }, { tier: 'ENTERPRISE' },
      ]),
    };
    const res = await handleRevenueMetrics(new Request('https://x/api/revenue/metrics'), env, { isAdmin: true });
    expect(res.status).toBe(200);
    const body = await res.json();
    // 2*1499 + 1*4999 = 7997
    expect(body.mrr).toBe(2 * 1499 + 4999);
    expect(body.pro_users).toBe(2);
    expect(body.enterprise_users).toBe(1);
    expect(body.paying_subscribers).toBe(3);
  });

  it('403s a non-admin, non-enterprise caller (unchanged access control)', async () => {
    const env = { SECURITY_HUB_KV: makeKV(), SECURITY_HUB_DB: makeRevenueDb([]) };
    const res = await handleRevenueMetrics(new Request('https://x/api/revenue/metrics'), env, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });
});
