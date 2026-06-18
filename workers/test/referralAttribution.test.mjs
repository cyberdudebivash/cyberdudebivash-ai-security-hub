/* Regression tests — real referral/affiliate attribution wired into the lead
 * pipeline and post-purchase lifecycle. Proves, behaviorally:
 *   - commission math + tier upgrades are computed from real conversions
 *   - an unknown ref_code is a safe no-op, never a fabricated credit
 *   - lead attribution is first-touch: a later ref_code never overwrites the first
 *   - the public leaderboard reports a real, incrementally-maintained aggregate
 *     (honest zeros until a conversion happens) instead of hardcoded numbers
 *   - triggerPostPurchase actually credits the referring affiliate, exactly once
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  handleJoin, handleTrackReferral, handleGetLeaderboard,
  recordReferralConversion, attributeReferral,
} from '../src/handlers/affiliateSystem.js';
import { triggerPostPurchase } from '../src/services/lifecycleEngine.js';

// ── In-memory KV ─────────────────────────────────────────────────────────────
function makeKV() {
  const store = new Map();
  return {
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
    _store: store,
  };
}

// ── In-memory D1 — models referral_attribution only. Every other table write
//    is a non-blocking no-op, matching how triggerPostPurchase already
//    tolerates partial DB failures (each step is independently try/catch-wrapped).
function makeDB() {
  const referralAttribution = new Map(); // email -> row
  const db = {
    prepare(sql) {
      let b = [];
      const stmt = {
        bind(...a) { b = a; return stmt; },
        async run() {
          if (/INSERT OR IGNORE INTO referral_attribution/.test(sql)) {
            const [email, ref_code, source, attributed_at] = b;
            if (!referralAttribution.has(email)) {
              referralAttribution.set(email, { email, ref_code, source, attributed_at, converted: 0, converted_at: null });
            }
            return { success: true };
          }
          if (/UPDATE referral_attribution SET converted/.test(sql)) {
            const [converted_at, email] = b;
            const row = referralAttribution.get(email);
            if (row) { row.converted = 1; row.converted_at = converted_at; }
            return { success: true };
          }
          return { success: true };
        },
        async first() {
          if (/FROM referral_attribution/.test(sql)) {
            const [email] = b;
            return referralAttribution.get(email) || null;
          }
          return null;
        },
        async all() { return { results: [] }; },
      };
      return stmt;
    },
  };
  return { db, referralAttribution };
}

function jsonReq(url, method = 'GET', body) {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function joinAffiliate(env, name, email) {
  const res  = await handleJoin(jsonReq('https://x/api/affiliate/join', 'POST', { name, email }), env, {});
  const body = await res.json();
  return body.data.ref_code;
}

describe('Referral attribution — commission math + tier upgrades', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_KV: makeKV(), DB: makeDB().db }; });

  it('credits the AFFILIATE-tier commission (10%) on a real conversion', async () => {
    const ref_code = await joinAffiliate(env, 'Asha Rao', 'asha@example.com');
    const result = await recordReferralConversion(env, { ref_code, amount_inr: 10000, referred_email: 'buyer@x.com' });
    expect(result.tracked).toBe(true);
    expect(result.commission_inr).toBe(1000);
    expect(result.new_tier).toBe('AFFILIATE');
  });

  it('upgrades tier once revenue + referral thresholds are crossed', async () => {
    const ref_code = await joinAffiliate(env, 'Beena Shah', 'beena@example.com');
    // PARTNER requires >= 3 referrals AND >= 150000 revenue.
    await recordReferralConversion(env, { ref_code, amount_inr: 60000, referred_email: 'b1@x.com' });
    await recordReferralConversion(env, { ref_code, amount_inr: 60000, referred_email: 'b2@x.com' });
    const third = await recordReferralConversion(env, { ref_code, amount_inr: 60000, referred_email: 'b3@x.com' });
    // The 3rd conversion's own commission is still computed at the pre-upgrade
    // tier (10%) — the upgrade applies to tier going forward, not retroactively.
    expect(third.commission_inr).toBe(6000);
    expect(third.new_tier).toBe('PARTNER');

    const fourth = await recordReferralConversion(env, { ref_code, amount_inr: 60000, referred_email: 'b4@x.com' });
    expect(fourth.commission_inr).toBe(9000); // 15% — now credited at the upgraded PARTNER tier
  });

  it('is a safe no-op for an unknown ref_code — never fabricates a credit', async () => {
    const result = await recordReferralConversion(env, { ref_code: 'does_not_exist', amount_inr: 5000 });
    expect(result).toEqual({ tracked: false, reason: 'invalid_ref_code' });
  });

  it('requires an amount to record a conversion', async () => {
    const ref_code = await joinAffiliate(env, 'Chetan Verma', 'chetan@example.com');
    const result = await recordReferralConversion(env, { ref_code });
    expect(result).toEqual({ tracked: false, reason: 'missing_fields' });
  });
});

describe('Referral attribution — first-touch lead capture', () => {
  let env, db, referralAttribution;
  beforeEach(() => {
    const made = makeDB();
    db = made.db; referralAttribution = made.referralAttribution;
    env = { SECURITY_HUB_KV: makeKV(), DB: db };
  });

  it('attributes a lead to a valid ref_code', async () => {
    const ref_code = await joinAffiliate(env, 'Deepa Iyer', 'deepa@example.com');
    const result = await attributeReferral(env, { email: 'lead@x.com', ref_code });
    expect(result.attributed).toBe(true);
  });

  it('rejects attribution to a ref_code that does not belong to any affiliate', async () => {
    const result = await attributeReferral(env, { email: 'lead@x.com', ref_code: 'fake_code' });
    expect(result).toEqual({ attributed: false, reason: 'invalid_ref_code' });
  });

  it('first touch wins — a later, different ref_code never overwrites the first', async () => {
    const refA = await joinAffiliate(env, 'Esha Kapoor', 'esha@example.com');
    const refB = await joinAffiliate(env, 'Farah Khan', 'farah@example.com');
    await attributeReferral(env, { email: 'lead2@x.com', ref_code: refA });
    await attributeReferral(env, { email: 'lead2@x.com', ref_code: refB });

    expect(referralAttribution.get('lead2@x.com').ref_code).toBe(refA);
  });
});

describe('Referral attribution — leaderboard reports real numbers, not placeholders', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_KV: makeKV(), DB: makeDB().db }; });

  it('reports honest zeros when no conversions have happened', async () => {
    const res  = await handleGetLeaderboard(jsonReq('https://x/api/affiliate/leaderboard'), env);
    const body = (await res.json()).data;
    expect(body.program_stats).toEqual({ avg_commission_inr: 0, top_earner_inr: 0, total_commission_inr: 0 });
  });

  it('reflects the real aggregate after a conversion — no hardcoded figures', async () => {
    const ref_code = await joinAffiliate(env, 'Gita Nair', 'gita@example.com');
    await recordReferralConversion(env, { ref_code, amount_inr: 20000, referred_email: 'h@x.com' });

    const res  = await handleGetLeaderboard(jsonReq('https://x/api/affiliate/leaderboard'), env);
    const body = (await res.json()).data;
    expect(body.program_stats.total_commission_inr).toBe(2000); // 10% of 20000
    expect(body.program_stats.avg_commission_inr).toBe(2000);
    expect(body.program_stats.top_earner_inr).toBe(2000);
  });
});

describe('POST /api/affiliate/track stays backward compatible after the refactor', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_KV: makeKV(), DB: makeDB().db }; });

  it('tracks a click', async () => {
    const ref_code = await joinAffiliate(env, 'Hari Om', 'hari@example.com');
    const res  = await handleTrackReferral(jsonReq('https://x/api/affiliate/track', 'POST', { ref_code, event_type: 'click' }), env);
    const body = await res.json();
    expect(body.data).toEqual({ tracked: true, type: 'click' });
  });

  it('tracks a conversion end-to-end through the HTTP layer', async () => {
    const ref_code = await joinAffiliate(env, 'Ira Mehta', 'ira@example.com');
    const res  = await handleTrackReferral(jsonReq('https://x/api/affiliate/track', 'POST', {
      ref_code, event_type: 'conversion', amount_inr: 5000, referred_email: 'buyer2@x.com',
    }), env);
    const body = await res.json();
    expect(body.data.tracked).toBe(true);
    expect(body.data.commission_inr).toBe(500);
  });

  it('returns 404 INVALID_REF for an unknown ref_code on conversion', async () => {
    const res = await handleTrackReferral(jsonReq('https://x/api/affiliate/track', 'POST', {
      ref_code: 'nope', event_type: 'conversion', amount_inr: 5000,
    }), env);
    expect(res.status).toBe(404);
  });
});

describe('triggerPostPurchase credits the referring affiliate exactly once', () => {
  let env, kv, db, referralAttribution;
  beforeEach(() => {
    kv = makeKV();
    const made = makeDB();
    db = made.db; referralAttribution = made.referralAttribution;
    env = { SECURITY_HUB_KV: kv, DB: db };
  });

  it('credits the affiliate on confirmed payment and marks attribution converted', async () => {
    const ref_code = await joinAffiliate(env, 'Jas Sandhu', 'jas@example.com');
    await attributeReferral(env, { email: 'customer@x.com', ref_code });

    await triggerPostPurchase(env, {
      email: 'customer@x.com', product: 'SECURITY_ASSESSMENT', amount_inr: 50000,
      event_type: 'delivery_activated', payment_id: 'pay_test_1',
    });

    const affRaw = await kv.get('affiliate:profile:jas@example.com', { type: 'json' });
    expect(affRaw.stats.total_commission_earned_inr).toBe(5000); // 10% of 50000
    expect(affRaw.stats.conversions).toBe(1);
    expect(referralAttribution.get('customer@x.com').converted).toBe(1);
  });

  it('never credits twice for the same attributed customer', async () => {
    const ref_code = await joinAffiliate(env, 'Kabir Singh', 'kabir@example.com');
    await attributeReferral(env, { email: 'repeat@x.com', ref_code });

    await triggerPostPurchase(env, { email: 'repeat@x.com', product: 'SECURITY_ASSESSMENT', amount_inr: 30000, payment_id: 'p1' });
    await triggerPostPurchase(env, { email: 'repeat@x.com', product: 'SECURITY_ASSESSMENT', amount_inr: 30000, payment_id: 'p2' });

    const affRaw = await kv.get('affiliate:profile:kabir@example.com', { type: 'json' });
    expect(affRaw.stats.conversions).toBe(1); // second purchase does not re-credit
  });

  it('does nothing when the customer has no referral attribution', async () => {
    await triggerPostPurchase(env, { email: 'organic@x.com', product: 'SECURITY_ASSESSMENT', amount_inr: 30000, payment_id: 'p1' });
    const affiliateKeys = [...kv._store.keys()].filter(k => k.startsWith('affiliate:profile:'));
    expect(affiliateKeys.length).toBe(0);
  });
});
