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

  // 1 — Write confirmed revenue event (correct attribution timing)
  if (db) {
    try {
      await db.prepare(`
        INSERT INTO revenue_events
          (id, source, amount_inr, email, event_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(evId, source, amount_inr, email, product || event_type, now).run();
    } catch { /* non-blocking — table schema variations across deploys */ }

    // 2 — Write funnel 'purchase' stage event for conversion analytics
    try {
      await db.prepare(`
        INSERT INTO funnel_events
          (id, email, stage, meta, created_at)
        VALUES (?, ?, 'purchase', ?, ?)
      `).bind('fe_' + evId, email, JSON.stringify({ source }), now).run();
    } catch { /* non-blocking */ }

    // 3 — Update lead record: mark as converted
    try {
      await db.prepare(`
        UPDATE leads SET
          funnel_stage = 'customer',
          converted_at = ?,
          updated_at   = ?
        WHERE email = ?
      `).bind(now, now, email).run();
    } catch { /* non-blocking — lead may not exist */ }

    // 4 — CAC event for channel attribution analytics
    if (amount_inr > 0) {
      try {
        await db.prepare(`
          INSERT INTO cac_events
            (id, channel, campaign, email, cost_inr, converted, plan_converted, mrr_generated, event_date)
          VALUES (?, ?, '', ?, 0, 1, ?, ?, date('now'))
        `).bind('cac_' + evId, source, email, plan || product, amount_inr).run();
      } catch { /* non-blocking */ }
    }
  }

  // 5 — Enroll in post-purchase email sequence
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
 * Enrolls partner in mssp_onboarded sequence.
 */
export async function triggerMsspOnboarding(env, {
  email, company = '', tier = 'RESELLER', partner_id = '',
}) {
  if (!email || !env?.DB) return;

  try {
    await enrollInSequence(env, email, 'mssp_onboarded', {
      company, tier, partner_id,
    });
  } catch { /* non-blocking */ }
}
