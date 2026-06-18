/**
 * CYBERDUDEBIVASH AI Security Hub — Lifecycle Engine
 * Phase 4 Revenue Validation: Post-Purchase Customer Lifecycle
 *
 * Called after any CONFIRMED payment to:
 *   1. Write revenue_events with correct attribution timing (AFTER success, not before)
 *   2. Write funnel_events for 'purchase' stage (for funnel analytics)
 *   3. Enroll customer in post-purchase email sequence
 *   4. Log CAC event for channel attribution
 *
 * Never called at checkout initiation — only at payment confirmation.
 */

import { enrollInSequence } from './emailEngine.js';

// Map product/event type → post-purchase email sequence
const SEQUENCE_MAP = {
  SUBSCRIPTION_STARTER:    'subscription_activated',
  SUBSCRIPTION_PRO:        'subscription_activated',
  SUBSCRIPTION_ENTERPRISE: 'subscription_activated',
  SECURITY_ASSESSMENT:     'assessment_delivered',
  AI_SECURITY_ASSESSMENT:  'assessment_delivered',
  THREAT_INTEL_REPORT:     'assessment_delivered',
  DOMAIN_REPORT:           'assessment_delivered',
  enterprise_inquiry:      'enterprise_nurture',
  mssp_partner:            'mssp_onboarded',
};

function seqForProduct(product = '') {
  const upper = product.toUpperCase();
  if (upper.startsWith('SUBSCRIPTION_')) return 'subscription_activated';
  if (upper.includes('ASSESSMENT'))     return 'assessment_delivered';
  if (upper.includes('REPORT'))        return 'assessment_delivered';
  if (upper.includes('MSSP'))          return 'mssp_onboarded';
  return SEQUENCE_MAP[product] || null;
}

// Map raw utm_source/source to valid revenue_events.source CHECK constraint values
function normalizeRevenueSource(raw) {
  const VALID = new Set(['razorpay', 'gumroad', 'affiliate', 'subscription', 'api_credits', 'expansion']);
  if (VALID.has(raw)) return raw;
  if ((raw || '').startsWith('subscription')) return 'subscription';
  return 'razorpay'; // payment-gateway default for all verified purchases
}

// Map raw utm_source to valid cac_events.channel CHECK constraint values
function normalizeChannel(utmSource) {
  const s = (utmSource || '').toLowerCase();
  if (['google', 'bing', 'duckduckgo', 'yahoo', 'adwords', 'ppc'].includes(s)) return 'paid_search';
  if (['facebook', 'instagram', 'linkedin', 'twitter', 'x', 'youtube', 'social'].includes(s)) return 'social';
  if (s === 'telegram') return 'telegram';
  if (s === 'affiliate') return 'affiliate';
  if (s === 'partner') return 'partner';
  if (['referral', 'ref'].includes(s)) return 'referral';
  if (s === 'organic') return 'organic';
  if (s === 'cold_outreach') return 'cold_outreach';
  return 'direct';
}

/**
 * Trigger post-purchase lifecycle events.
 * Call fire-and-forget from payment confirmation handlers.
 *
 * @param {object} env
 * @param {object} opts
 * @param {string}  opts.email         - customer email
 * @param {string}  opts.product       - product ID (e.g. 'SECURITY_ASSESSMENT', 'SUBSCRIPTION_PRO')
 * @param {string}  opts.product_name  - human-readable product name
 * @param {number}  opts.amount_inr    - confirmed payment amount in INR
 * @param {string}  opts.event_type    - 'delivery_activated' | 'subscription_activated' | etc.
 * @param {string}  [opts.source]      - traffic source for attribution
 * @param {string}  [opts.payment_id]  - payment gateway ID
 * @param {string}  [opts.plan]        - subscription tier if applicable
 * @param {object}  [opts.meta]        - extra data for email templates
 */
export async function triggerPostPurchase(env, {
  email, product = '', product_name = '', amount_inr = 0,
  event_type = 'purchase', source = 'direct', payment_id = '',
  plan = '', meta = {},
}) {
  if (!email || !env) return;

  const db = env.DB;
  const now = new Date().toISOString();
  const evId = 'rev_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);

  const revSource = normalizeRevenueSource(source);

  // 1 — Write confirmed revenue event (correct attribution timing)
  if (db) {
    try {
      await db.prepare(`
        INSERT INTO revenue_events
          (id, source, amount_inr, amount_usd, user_id, email, product, reference, metadata, created_at)
        VALUES (?, ?, ?, 0, NULL, ?, ?, ?, '{}', ?)
      `).bind(evId, revSource, amount_inr, email, product || event_type, payment_id, now).run();
    } catch { /* non-blocking */ }

    // 1b — Expansion revenue detection: if email already has a subscription at a lower plan,
    //      write an additional expansion event for the revenue delta (upgrade attribution).
    if ((product || '').toUpperCase().startsWith('SUBSCRIPTION_')) {
      try {
        const PLAN_RANK = { STARTER: 1, PRO: 2, ENTERPRISE: 3 };
        const newPlanKey = (product || '').toUpperCase().replace('SUBSCRIPTION_', '');
        const newRank    = PLAN_RANK[newPlanKey] || 0;
        const existing   = await db.prepare(
          `SELECT plan, price_inr FROM subscriptions WHERE email = ? AND status = 'active' ORDER BY activated_at DESC LIMIT 1`
        ).bind(email).first().catch(() => null);
        const existRank = existing ? (PLAN_RANK[existing.plan?.toUpperCase()] || 0) : 0;
        if (existRank > 0 && newRank > existRank) {
          const delta = Math.max(0, amount_inr - (existing?.price_inr || 0));
          if (delta > 0) {
            await db.prepare(`
              INSERT INTO revenue_events
                (id, source, amount_inr, amount_usd, user_id, email, product, reference, metadata, created_at)
              VALUES (?, 'expansion', ?, 0, NULL, ?, ?, ?, '{}', ?)
            `).bind('exp_' + evId, delta, email, product || event_type, payment_id, now).run().catch(() => {});
          }
        }
      } catch { /* non-blocking */ }
    }

    // 2 — Write funnel 'purchase' stage event for conversion analytics
    try {
      await db.prepare(`
        INSERT INTO funnel_events
          (id, email, stage, meta, created_at)
        VALUES (?, ?, 'purchase', ?, ?)
      `).bind('fe_' + evId, email, JSON.stringify({ source: revSource }), now).run();
    } catch { /* non-blocking */ }

    // 3 — Upsert lead record: mark as converted (INSERT if first purchase with no prior lead)
    try {
      const updated = await db.prepare(`
        UPDATE leads SET
          funnel_stage = 'customer',
          converted_at = ?,
          updated_at   = ?
        WHERE email = ?
      `).bind(now, now, email).run();
      if ((updated?.meta?.changes ?? updated?.changes ?? 0) === 0) {
        await db.prepare(`
          INSERT OR IGNORE INTO leads
            (id, email, funnel_stage, converted_at, source, created_at, updated_at)
          VALUES (?, ?, 'customer', ?, 'payment', ?, ?)
        `).bind('lead_' + evId, email, now, now, now).run();
      }
    } catch { /* non-blocking */ }

    // 4 — CAC event for channel attribution analytics
    if (amount_inr > 0) {
      try {
        const cacChannel = normalizeChannel(source);
        await db.prepare(`
          INSERT INTO cac_events
            (id, channel, campaign, email, cost_inr, converted, plan_converted, mrr_generated, event_date)
          VALUES (?, ?, ?, ?, 0, 1, ?, ?, date('now'))
        `).bind('cac_' + evId, cacChannel, meta?.utm_campaign || '', email, plan || product, amount_inr).run();
      } catch { /* non-blocking */ }
    }

    // 5 — Credit the referring affiliate, if this email was first-touch attributed
    //     to a ref_code at lead capture and hasn't already converted.
    //     Claim-then-credit: the UPDATE...WHERE converted=0 atomically claims the
    //     conversion before any commission is credited, so two concurrent or
    //     retried payment-confirmation calls for the same email can't both observe
    //     "not yet converted" and double-credit the affiliate. If crediting then
    //     fails, the claim is released so a later retry can still earn the
    //     commission instead of being stuck permanently "converted" with nothing
    //     ever recorded. Email is normalized to match the lowercase form lead
    //     capture always writes (gateways/order metadata don't reliably preserve it).
    if (amount_inr > 0) {
      try {
        const refEmail = String(email).trim().toLowerCase();
        const attribution = await db.prepare(
          `SELECT ref_code FROM referral_attribution WHERE email = ? AND converted = 0 LIMIT 1`
        ).bind(refEmail).first().catch(() => null);
        if (attribution?.ref_code) {
          const claim = await db.prepare(
            `UPDATE referral_attribution SET converted = 1, converted_at = ? WHERE email = ? AND converted = 0`
          ).bind(now, refEmail).run().catch(() => null);
          const claimed = (claim?.meta?.changes ?? claim?.changes ?? 0) > 0;
          if (claimed) {
            const { recordReferralConversion } = await import('../handlers/affiliateSystem.js');
            const result = await recordReferralConversion(env, {
              ref_code: attribution.ref_code, amount_inr, referred_email: refEmail, plan_id: product,
            });
            if (!result?.tracked) {
              await db.prepare(
                `UPDATE referral_attribution SET converted = 0, converted_at = NULL WHERE email = ?`
              ).bind(refEmail).run().catch(() => {});
            }
          }
        }
      } catch { /* non-blocking */ }
    }
  }

  // 6 — Enroll in post-purchase email sequence
  const sequenceId = seqForProduct(product) || seqForProduct(event_type);
  if (sequenceId && env.DB) {
    try {
      await enrollInSequence(env, email, sequenceId, {
        product, product_name, amount_inr, plan,
        payment_id, source, ...meta,
      });
    } catch { /* non-blocking */ }
  }
}

/**
 * Trigger enterprise inquiry lifecycle (lead, not yet a customer).
 * Writes funnel entry and enrolls in nurture sequence.
 */
export async function triggerEnterpriseInquiry(env, {
  email, company = '', interest = '', source = 'website',
}) {
  if (!email || !env?.DB) return;

  const now = new Date().toISOString();

  try {
    await env.DB.prepare(`
      INSERT INTO funnel_events
        (id, email, stage, meta, created_at)
      VALUES (?, ?, 'email_capture', ?, ?)
    `).bind('fe_ent_' + Date.now().toString(36), email, JSON.stringify({ source }), now).run();
  } catch { /* non-blocking */ }

  try {
    await enrollInSequence(env, email, 'enterprise_nurture', {
      company, interest, source,
    });
  } catch { /* non-blocking */ }
}

/**
 * Trigger MSSP partner onboarding lifecycle.
 * Writes revenue_events, funnel_events, cac_events, lead upsert, and enrolls in mssp_onboarded sequence.
 * Delegates to triggerPostPurchase which handles all attribution writes — seqForProduct('MSSP_PARTNER')
 * correctly resolves to 'mssp_onboarded' via the MSSP branch in seqForProduct.
 */
export async function triggerMsspOnboarding(env, {
  email, company = '', tier = 'RESELLER', partner_id = '',
  amount_inr = 0, source = 'partner',
}) {
  if (!email || !env?.DB) return;

  await triggerPostPurchase(env, {
    email,
    product:      'MSSP_PARTNER',
    product_name: `MSSP Partner — ${tier}`,
    amount_inr,
    event_type:   'mssp_activated',
    source:       source || 'partner',
    plan:         tier,
    meta:         { company, partner_id },
  });
}
