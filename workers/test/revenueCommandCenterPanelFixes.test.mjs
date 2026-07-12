/* Regression tests — revenue-command-center.html's 6-of-8-broken-panels
 * finding from the full-frontend audit (Tier 1 backlog item #3; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * Backend: handlers/revenueMetrics.js's KPI response never had today/week/
 * month fields at all (only mrr/arr, no daily-cash-collected concept), and
 * called its pipeline field pipeline_value while the frontend read pipeline.
 *
 * Frontend: 6 of revenue-command-center.html's 8 panels read fields that
 * don't exist on their real backend response (flat vs nested, array vs
 * object-wrapped array, or a taxonomy that never matched real values) — see
 * each describe block below for the specific shape. Static source-parse
 * only, same established pattern as homepageSignInPath.test.mjs.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { handleRevenueMetrics } from '../src/handlers/revenueMetrics.js';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/revenue-command-center.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

// ── Backend: handleRevenueMetrics ───────────────────────────────────────────
function makeMetricsDb({ tierRows = [], payments = [] } = {}) {
  function router(sql, args) {
    if (/SUM\(CASE WHEN tier = 'FREE'/.test(sql)) {
      const counts = { total: 0, free_count: 0, starter_count: 0, pro_count: 0, ent_count: 0, mssp_count: 0 };
      const field = { FREE: 'free_count', STARTER: 'starter_count', PRO: 'pro_count', ENTERPRISE: 'ent_count', MSSP: 'mssp_count' };
      for (const r of tierRows) {
        counts.total++;
        if (field[r.tier]) counts[field[r.tier]]++;
      }
      return { first: async () => counts, all: async () => ({ results: [] }), run: async () => ({}) };
    }
    if (/FROM payments WHERE status='success' AND created_at >= \?/.test(sql)) {
      return {
        first: async () => {
          const threshold = args[0];
          const total = payments
            .filter(p => p.status === 'success' && p.created_at >= threshold)
            .reduce((s, p) => s + p.amount_inr, 0);
          return { total };
        },
      };
    }
    const fail = async () => { throw new Error('unmocked query: ' + sql.trim().slice(0, 60)); };
    return { first: fail, all: fail, run: fail };
  }
  return { prepare: (sql) => ({ ...router(sql, []), bind: (...args) => router(sql, args) }) };
}
function makeKV() {
  return { async get() { return null; }, async put() {} };
}

describe('handleRevenueMetrics — today/week/month/pipeline (previously missing, KPI tiles always showed ₹0)', () => {
  it('sums real payments into today/week/month, excludes non-success and out-of-window rows, and aliases pipeline_value as pipeline', async () => {
    const now = new Date();
    const recentlyPaid = new Date(now.getTime() - 5 * 60 * 1000).toISOString(); // 5 min ago — always within today/week/month
    const wellOutside = new Date(now.getTime() - 35 * 24 * 60 * 60 * 1000).toISOString(); // 35 days ago — always outside every window (max month length is 31 days)

    const env = {
      SECURITY_HUB_KV: makeKV(),
      SECURITY_HUB_DB: makeMetricsDb({
        tierRows: [],
        payments: [
          { status: 'success', amount_inr: 1000, created_at: recentlyPaid },
          { status: 'success', amount_inr: 5000, created_at: wellOutside },
          { status: 'failed',  amount_inr: 9999, created_at: recentlyPaid },
        ],
      }),
    };
    const res = await handleRevenueMetrics(new Request('https://x/api/revenue/metrics'), env, { isAdmin: true });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.today).toBe(1000);
    expect(body.week).toBe(1000);
    expect(body.month).toBe(1000);
    expect(body.pipeline).toBe(body.pipeline_value);
  });
});

// ── Frontend: revenue-command-center.html ───────────────────────────────────
describe('loadLeads — reads the real {breakdown:[{source,count,pct}]} shape', () => {
  it('no longer references the hardcoded LEAD_SOURCES taxonomy that never matched real source values', () => {
    expect(fe).not.toContain("const LEAD_SOURCES = ['Organic Search'");
  });
  it('reads d.breakdown as an array and renders each entry\'s own source/count/pct', () => {
    const body = fnBody('loadLeads');
    expect(body).toContain('d.breakdown');
    expect(body).toContain('b.source');
    expect(body).toContain('b.pct');
  });
});

describe('loadFunnel — reads the real {stages:[{stage,label,count,conversion_from_prev}]} shape', () => {
  it('no longer references the hardcoded FUNNEL_STEPS keys that never matched real stage ids', () => {
    expect(fe).not.toContain("key: 'visitors'");
    expect(fe).not.toContain("key: 'free_scan'");
  });
  it('reads d.stages as an array and renders each entry\'s own label/count/conversion_from_prev', () => {
    const body = fnBody('loadFunnel');
    expect(body).toContain('d.stages');
    expect(body).toContain('step.conversion_from_prev');
  });
});

describe('loadTransactions — reads the real {transactions:[...]} wrapper and paid_at/created_at', () => {
  it('unwraps data.transactions instead of assuming the top-level response is an array', () => {
    const body = fnBody('loadTransactions');
    expect(body).toContain('Array.isArray(data.transactions)');
  });
  it('formats tx.paid_at/created_at instead of a nonexistent tx.date field', () => {
    expect(fe).toContain('tx.paid_at || tx.created_at');
  });
});

describe('loadForecast — reads the real nested current_month/next_month/quarterly objects', () => {
  it('no longer reads the flat, nonexistent current_month_actual/next_month_projection/quarterly_forecast fields', () => {
    expect(fe).not.toContain('d.current_month_actual');
    expect(fe).not.toContain('d.next_month_projection');
    expect(fe).not.toContain('d.quarterly_forecast');
  });
  it('reads current_month.actual/target, next_month.projected, quarterly.projected', () => {
    const body = fnBody('loadForecast');
    expect(body).toMatch(/current_month\?\.actual/);
    expect(body).toMatch(/current_month\?\.target/);
    expect(body).toMatch(/next_month\?\.projected/);
    expect(body).toMatch(/quarterly\?\.projected/);
  });
});

describe('Pipeline Kanban — reads the real {stages:{lead:{count,value,deals}, ...}} object, real stage keys', () => {
  it('STAGES uses the real backend keys (lead/qualified/demo/proposal/negotiation/closed_won/closed_lost), not the old made-up Title-Case set', () => {
    expect(fe).toContain("key: 'lead'");
    expect(fe).toContain("key: 'closed_won'");
    expect(fe).not.toContain("const STAGES = ['Lead','Qualified','Discovery'");
  });
  it('loadPipeline reads d.stages (an object), not the top-level response as a raw deals array', () => {
    const body = fnBody('loadPipeline');
    expect(body).toContain('d.stages');
  });
  it('renderKanban reads each stage\'s own count/value/deals and the real deal field names', () => {
    const body = fnBody('renderKanban');
    expect(body).toContain('stageData.count');
    expect(body).toContain('stageData.value');
    expect(body).toContain('d.deal_value_inr');
    expect(body).toMatch(/d\.contact_name\s*\|\|\s*d\.contact_email/);
  });
});

describe('Add Deal — submits the real required fields (company, contact_email, deal_value_inr)', () => {
  it('the modal has a Contact Email input (the backend requires contact_email specifically)', () => {
    expect(fe).toContain('id="dContactEmail"');
  });
  it('submitDeal posts contact_email and deal_value_inr, not the old contact/value names', () => {
    const body = fnBody('submitDeal');
    expect(body).toContain('contact_email: contactEmail');
    expect(body).toContain('deal_value_inr: Number(value)');
  });
  it('requires a contact email before submitting (was previously never collected at all)', () => {
    const body = fnBody('submitDeal');
    expect(body).toContain('!contactEmail');
  });
});
