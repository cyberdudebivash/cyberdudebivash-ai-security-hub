/* Regression tests — GET /api/mssp/revenue used to be owner-gated ONLY,
 * with a code comment admitting there was no partner self-serve login to
 * check against. Now that one exists (handlers/partnerAuth.js), a real
 * partner session must be able to see their OWN revenue-share ledger
 * without needing owner access — but never anyone else's, even if they
 * pass a different ?partner_id= themselves. */
import { describe, it, expect } from 'vitest';
import { handleGetPartnerRevenue } from '../src/handlers/msspRevenue.js';
import { isOwner } from '../src/auth/middleware.js';

function makeDB({ partners = {} } = {}) {
  const ledger = [];
  const db = {
    prepare(sql) {
      let b = [];
      const stmt = {
        bind(...a) { b = a; return stmt; },
        async run() { return { success: true }; },
        async first() {
          if (/SELECT partner_share_pct FROM mssp_partners WHERE id/.test(sql)) {
            const [id] = b;
            return partners[id] ? { partner_share_pct: partners[id].partner_share_pct } : null;
          }
          if (/COUNT\(\*\) AS total_entries/.test(sql)) {
            const [partnerId] = b;
            const mine = ledger.filter(l => l.partner_id === partnerId);
            return { total_entries: mine.length, total_gross_paise: mine.reduce((s, l) => s + l.gross_amount_paise, 0), total_partner_earnings_paise: 0, pending_payout_paise: 0, paid_out_paise: 0 };
          }
          return null;
        },
        async all() {
          if (/FROM mssp_revenue_ledger WHERE partner_id/.test(sql)) {
            const [partnerId] = b;
            return { results: ledger.filter(l => l.partner_id === partnerId) };
          }
          return { results: [] };
        },
      };
      return stmt;
    },
  };
  return { db, ledger };
}

const OWNER_EMAIL = 'bivash@cyberdudebivash.com';

describe('GET /api/mssp/revenue — owner vs. real partner self-service', () => {
  it('the owner can view any partner\'s ledger via ?partner_id=', async () => {
    const { db } = makeDB({ partners: { p_1: { partner_share_pct: 60 } } });
    const res = await handleGetPartnerRevenue(
      new Request('https://x/api/mssp/revenue?partner_id=p_1'),
      { DB: db },
      { isAdmin: true },
      isOwner,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.partner_id).toBe('p_1');
  });

  it('the owner gets a 400 without ?partner_id= (no implicit "my own" for the owner)', async () => {
    const { db } = makeDB();
    const res = await handleGetPartnerRevenue(new Request('https://x/api/mssp/revenue'), { DB: db }, { isAdmin: true }, isOwner);
    expect(res.status).toBe(400);
  });

  it('a real partner session sees their OWN ledger with no ?partner_id= needed', async () => {
    const { db } = makeDB({ partners: { mp_self: { partner_share_pct: 40 } } });
    const authCtx = { authenticated: true, role: 'partner', partnerId: 'mp_self', email: 'partner@acme.com' };
    const res = await handleGetPartnerRevenue(new Request('https://x/api/mssp/revenue'), { DB: db }, authCtx, isOwner);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.partner_id).toBe('mp_self');
  });

  it('a partner session cannot view another partner\'s ledger by passing a different ?partner_id=', async () => {
    const { db } = makeDB({ partners: { mp_self: { partner_share_pct: 40 }, mp_other: { partner_share_pct: 60 } } });
    const authCtx = { authenticated: true, role: 'partner', partnerId: 'mp_self', email: 'partner@acme.com' };
    const res = await handleGetPartnerRevenue(new Request('https://x/api/mssp/revenue?partner_id=mp_other'), { DB: db }, authCtx, isOwner);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.partner_id).toBe('mp_self'); // ignores the query param entirely for non-owners
  });

  it('neither owner nor a partner session — 403', async () => {
    const { db } = makeDB();
    const res = await handleGetPartnerRevenue(new Request('https://x/api/mssp/revenue'), { DB: db }, { authenticated: true, tier: 'FREE' }, isOwner);
    expect(res.status).toBe(403);
  });
});
