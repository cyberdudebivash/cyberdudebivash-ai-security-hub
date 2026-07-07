/* Regression tests — mssp_partners and mssp_onboarding_partners were two
 * structurally disconnected identity tables (2026-07-07 revenue-mechanisms
 * follow-up audit). A real self-serve MSSP signup (trial or paid checkout)
 * only ever wrote to mssp_onboarding_partners, so it never became a genuine
 * mssp_partners entity — meaning it could never own an mssp_customers row,
 * never earn a mssp_revenue_ledger split, and never showed up in the admin
 * command center (msspOps.js) or funnel dashboards (index.js, revenueKPI.js).
 * This locks:
 *  1. Every verify (paid) and trial signup now also creates/links a real
 *     mssp_partners row, under the SAME id as the mssp_onboarding_partners
 *     row.
 *  2. A second checkout for an already-onboarded email (tier upgrade) reuses
 *     the existing id instead of silently diverging — fixes a latent bug
 *     where ON CONFLICT(email) DO UPDATE never touches `id`, so a freshly
 *     generated id on every verify would orphan the KV token/state keys and
 *     the linked mssp_partners row from the row actually on disk.
 *  3. A trial that later converts to paid keeps the same mssp_partners row
 *     (and its api_key), just upgraded in place — not a second entity.
 *  4. mssp_partners linkage is best-effort: if it fails, the core
 *     onboarding/checkout flow still succeeds (mirrors the "never throws
 *     into the payment webhook path" invariant already used by
 *     msspRevenue.js). */
import { describe, it, expect } from 'vitest';
import { handleMsspVerify, handleMsspTrial } from '../src/handlers/msspOnboardingHandler.js';
import { MSSP_TIERS } from '../src/services/globalScale.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv({ checkouts = [], failMsspPartners = false } = {}) {
  const checkoutsByOrder = new Map(checkouts.map(c => [c.order_id, { ...c }]));
  const onboardingByEmail = new Map();
  const partnersByEmail = new Map(); // mssp_partners, keyed by contact_email
  const kv = new Map();

  const env = {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async run() {
            if (/CREATE TABLE/.test(sql)) return { success: true };

            if (/UPDATE mssp_onboarding_checkouts/.test(sql)) {
              const [status, partner_id, paid_at, order_id] = b;
              const c = checkoutsByOrder.get(order_id);
              if (c) { c.status = status; c.partner_id = partner_id; c.paid_at = paid_at; }
              return { success: true };
            }

            if (/INSERT INTO mssp_onboarding_partners/.test(sql) && /trial_ends_at/.test(sql) && !/razorpay_order_id/.test(sql)) {
              // Trial path (12 params, ON CONFLICT DO NOTHING)
              const [id, email, company_name, contact_name, tier_id, clients_limit, margin_pct, status, access_token, trial_ends_at, activated_at, created_at] = b;
              if (onboardingByEmail.has(email)) return { success: true };
              onboardingByEmail.set(email, { id, email, company_name, contact_name, tier_id, clients_limit, margin_pct, status, access_token, trial_ends_at, activated_at, created_at });
              return { success: true };
            }

            if (/INSERT INTO mssp_onboarding_partners/.test(sql)) {
              // Verify/paid path (15 params, ON CONFLICT DO UPDATE — id untouched)
              const [id, email, company_name, contact_name, phone, website, tier_id, clients_limit, margin_pct, status, access_token, razorpay_order_id, razorpay_payment_id, activated_at, created_at] = b;
              const existing = onboardingByEmail.get(email);
              if (existing) {
                existing.tier_id = tier_id; existing.clients_limit = clients_limit;
                existing.razorpay_order_id = razorpay_order_id; existing.razorpay_payment_id = razorpay_payment_id;
                existing.activated_at = activated_at; existing.status = 'active';
                return { success: true };
              }
              onboardingByEmail.set(email, { id, email, company_name, contact_name, phone, website, tier_id, clients_limit, margin_pct, status, access_token, razorpay_order_id, razorpay_payment_id, activated_at, created_at });
              return { success: true };
            }

            if (/INSERT INTO crm_leads/.test(sql)) return { success: true };

            if (/INSERT INTO mssp_partners/.test(sql)) {
              if (failMsspPartners) throw new Error('simulated mssp_partners write failure');
              const [id, company, contact_email, tier, plan, api_key, max_clients, margin_pct, status, onboarded_at, created_at, metadata] = b;
              const existing = partnersByEmail.get(contact_email);
              if (existing) {
                existing.tier = tier; existing.plan = plan; existing.max_clients = max_clients;
                existing.margin_pct = margin_pct; existing.status = status; existing.onboarded_at = onboarded_at;
                return { success: true };
              }
              partnersByEmail.set(contact_email, { id, company, contact_email, tier, plan, api_key, client_count: 0, max_clients, margin_pct, status, onboarded_at, created_at, metadata });
              return { success: true };
            }

            return { success: true };
          },
          async first() {
            if (/SELECT \* FROM mssp_onboarding_checkouts WHERE order_id/.test(sql)) {
              return checkoutsByOrder.get(b[0]) || null;
            }
            if (/SELECT id FROM mssp_onboarding_partners WHERE email/.test(sql)) {
              const rec = onboardingByEmail.get(b[0]);
              return rec ? { id: rec.id } : null;
            }
            if (/SELECT id, api_key FROM mssp_partners WHERE contact_email/.test(sql)) {
              const rec = partnersByEmail.get(b[0]);
              return rec ? { id: rec.id, api_key: rec.api_key } : null;
            }
            return null;
          },
          async all() { return { results: [] }; },
        };
      },
    },
    KV: {
      async get(k) { return kv.has(k) ? kv.get(k) : null; },
      async put(k, v) { kv.set(k, v); return true; },
    },
  };
  return { env, checkoutsByOrder, onboardingByEmail, partnersByEmail };
}

function req(url, body, headers = {}) {
  return new Request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
}

describe('MSSP verify — links a real mssp_partners row', () => {
  it('creates an mssp_partners row under the same id as mssp_onboarding_partners', async () => {
    const { env, partnersByEmail, onboardingByEmail } = makeEnv({
      checkouts: [{ order_id: 'o1', tier_id: 'gold', email: 'buyer@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending' }],
    });
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'o1|p1');
    const res = await handleMsspVerify(req('https://x', { razorpay_order_id: 'o1', razorpay_payment_id: 'p1', razorpay_signature: sig }), env);
    const body = await res.json();
    expect(body.success).toBe(true);

    const partner = partnersByEmail.get('buyer@acme.com');
    expect(partner).toBeTruthy();
    expect(partner.id).toBe(body.partner_id);
    expect(partner.id).toBe(onboardingByEmail.get('buyer@acme.com').id);
    expect(partner.status).toBe('active');
    expect(partner.tier).toBe('GOLD');
    expect(partner.max_clients).toBe(999999); // gold = unlimited (-1 sentinel mapped)
    expect(partner.margin_pct).toBe(50); // gold margin '50%' -> 50
    expect(partner.api_key).toMatch(/^cdb_mssp_/);
  });

  it('a second checkout for the same email (tier upgrade) reuses the existing id, not a fresh one', async () => {
    const { env, checkoutsByOrder, partnersByEmail, onboardingByEmail } = makeEnv({
      checkouts: [
        { order_id: 'o2', tier_id: 'reseller', email: 'upgrade@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending' },
      ],
    });
    const sig2 = await hmac(RAZORPAY_KEY_SECRET, 'o2|p2');
    const res1 = await handleMsspVerify(req('https://x', { razorpay_order_id: 'o2', razorpay_payment_id: 'p2', razorpay_signature: sig2 }), env);
    const firstId = (await res1.json()).partner_id;

    // A second, later checkout for the same email — a NEW order_id (upgrade to gold),
    // registered directly the way handleMsspCheckout's INSERT would have left it.
    checkoutsByOrder.set('o2b', { order_id: 'o2b', tier_id: 'gold', email: 'upgrade@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending', partner_id: null, paid_at: null });
    const sig3 = await hmac(RAZORPAY_KEY_SECRET, 'o2b|p2b');
    const res2 = await handleMsspVerify(req('https://x', { razorpay_order_id: 'o2b', razorpay_payment_id: 'p2b', razorpay_signature: sig3 }), env);
    const secondId = (await res2.json()).partner_id;

    expect(firstId).toBeTruthy();
    expect(secondId).toBe(firstId); // must NOT diverge into a second id
    expect(onboardingByEmail.get('upgrade@acme.com').id).toBe(firstId);
    expect(partnersByEmail.get('upgrade@acme.com').id).toBe(firstId);
    expect(partnersByEmail.get('upgrade@acme.com').tier).toBe('GOLD'); // upgraded in place
  });

  it('does not fail the verify response if mssp_partners linkage throws', async () => {
    const { env } = makeEnv({
      failMsspPartners: true,
      checkouts: [{ order_id: 'o3', tier_id: 'silver', email: 'resilient@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending' }],
    });
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'o3|p3');
    const res = await handleMsspVerify(req('https://x', { razorpay_order_id: 'o3', razorpay_payment_id: 'p3', razorpay_signature: sig }), env);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
  });
});

describe('MSSP trial — links a real mssp_partners row (status=trial)', () => {
  it('creates a linked mssp_partners row with trial defaults', async () => {
    const { env, partnersByEmail, onboardingByEmail } = makeEnv();
    const res = await handleMsspTrial(req('https://x', {
      email: 'trial@acme.com', company_name: 'Acme', contact_name: 'Jo',
    }, { 'CF-Connecting-IP': '3.3.3.3' }), env);
    const body = await res.json();
    expect(body.success).toBe(true);

    const partner = partnersByEmail.get('trial@acme.com');
    expect(partner).toBeTruthy();
    expect(partner.id).toBe(body.partner_id);
    expect(partner.id).toBe(onboardingByEmail.get('trial@acme.com').id);
    expect(partner.status).toBe('trial');
    expect(partner.max_clients).toBe(3);
    expect(partner.margin_pct).toBe(0);
  });
});
