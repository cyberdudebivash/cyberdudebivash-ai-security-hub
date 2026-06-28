/* Regression tests — P23.0 MSSP Public Onboarding had zero test coverage.
 * This is the self-serve activation flow new partner/enterprise customers
 * hit first, so it gets the same bar as the marketplace checkout: pricing
 * can't be client-controlled, payment verification is signature-gated and
 * idempotent, trial abuse is rate-limited, and checkout doesn't double-charge
 * on retry. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import {
  handleMsspTiers,
  handleMsspCheckout,
  handleMsspVerify,
  handleMsspTrial,
  handleMsspOnboardingStatus,
} from '../src/handlers/msspOnboardingHandler.js';
import { MSSP_TIERS } from '../src/services/globalScale.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv({ checkouts = [], partners = [] } = {}) {
  const checkoutsByOrder = new Map(checkouts.map(c => [c.order_id, { ...c }]));
  const partnersByEmail  = new Map(partners.map(p => [p.email, { ...p }]));
  const partnersById     = new Map(partners.map(p => [p.id, { ...p }]));
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

            if (/INSERT INTO mssp_onboarding_checkouts/.test(sql)) {
              const [id, order_id, tier_id, email, company_name, contact_name, phone, website, clients_estimate, amount_paise, currency, status, created_at] = b;
              checkoutsByOrder.set(order_id, { id, order_id, tier_id, email, company_name, contact_name, phone, website, clients_estimate, amount_paise, currency, status, created_at, partner_id: null, paid_at: null });
              return { success: true };
            }

            if (/UPDATE mssp_onboarding_checkouts/.test(sql)) {
              const [status, partner_id, paid_at, order_id] = b;
              const c = checkoutsByOrder.get(order_id);
              if (c) { c.status = status; c.partner_id = partner_id; c.paid_at = paid_at; }
              return { success: true };
            }

            if (/INSERT INTO mssp_partners/.test(sql) && /trial_ends_at/.test(sql)) {
              // Trial provisioning path (12 params)
              const [id, email, company_name, contact_name, tier_id, clients_limit, margin_pct, status, access_token, trial_ends_at, activated_at, created_at] = b;
              if (partnersByEmail.has(email)) return { success: true }; // ON CONFLICT DO NOTHING
              const rec = { id, email, company_name, contact_name, tier_id, clients_limit, margin_pct, status, access_token, trial_ends_at, activated_at, created_at };
              partnersByEmail.set(email, rec); partnersById.set(id, rec);
              return { success: true };
            }

            if (/INSERT INTO mssp_partners/.test(sql)) {
              // Verify/paid provisioning path (15 params)
              const [id, email, company_name, contact_name, phone, website, tier_id, clients_limit, margin_pct, status, access_token, razorpay_order_id, razorpay_payment_id, activated_at, created_at] = b;
              const rec = { id, email, company_name, contact_name, phone, website, tier_id, clients_limit, margin_pct, status, access_token, razorpay_order_id, razorpay_payment_id, activated_at, created_at, trial_ends_at: null };
              partnersByEmail.set(email, rec); partnersById.set(id, rec);
              return { success: true };
            }

            if (/INSERT INTO crm_leads/.test(sql)) return { success: true };

            return { success: true };
          },
          async first() {
            if (/SELECT \* FROM mssp_onboarding_checkouts WHERE order_id/.test(sql)) {
              return checkoutsByOrder.get(b[0]) || null;
            }
            if (/SELECT COUNT\(\*\) AS cnt FROM mssp_partners WHERE status/.test(sql)) {
              const status = b[0];
              const cnt = [...partnersByEmail.values()].filter(p => p.status === status).length;
              return { cnt };
            }
            if (/SELECT COUNT\(\*\) AS cnt FROM mssp_clients/.test(sql)) {
              return { cnt: 0 };
            }
            if (/FROM mssp_partners WHERE id=/.test(sql)) {
              return partnersById.get(b[0]) || null;
            }
            if (/FROM mssp_partners WHERE email=/.test(sql)) {
              return partnersByEmail.get(b[0]) || null;
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
  return { env, checkoutsByOrder, partnersByEmail, kv };
}

function req(url, body, headers = {}) {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

const realFetch = globalThis.fetch;
let fetchCalls = 0;
function stubRazorpayOrderCreate(orderId = 'order_stub') {
  fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls++;
    return new Response(JSON.stringify({ id: orderId, entity: 'order', amount: 0, currency: 'INR', status: 'created' }), { status: 200 });
  };
}
afterAll(() => { globalThis.fetch = realFetch; });

describe('MSSP onboarding tiers — public catalog', () => {
  it('returns all three canonical tiers with server-side pricing', async () => {
    const { env } = makeEnv();
    const res = await handleMsspTiers(new Request('https://x/api/mssp/onboarding/tiers'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.tiers.length).toBe(Object.keys(MSSP_TIERS).length);
    const silver = body.tiers.find(t => t.id === 'silver');
    expect(silver.amount_paise).toBe(MSSP_TIERS.silver.price_inr * 100);
  });
});

describe('MSSP checkout — validation + price integrity + dedup', () => {
  beforeEach(() => stubRazorpayOrderCreate('order_checkout_1'));

  it('rejects an invalid tier_id', async () => {
    const { env } = makeEnv();
    const res = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', {
      tier_id: 'platinum-fake', email: 'a@b.com', company_name: 'Acme', contact_name: 'Jo',
    }), env);
    expect(res.status).toBe(400);
  });

  it('rejects an invalid email', async () => {
    const { env } = makeEnv();
    const res = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', {
      tier_id: 'silver', email: 'not-an-email', company_name: 'Acme', contact_name: 'Jo',
    }), env);
    expect(res.status).toBe(400);
  });

  it('rejects missing company/contact name', async () => {
    const { env } = makeEnv();
    const res = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', {
      tier_id: 'silver', email: 'a@b.com', company_name: '', contact_name: '',
    }), env);
    expect(res.status).toBe(400);
  });

  it('charges the canonical MSSP_TIERS amount regardless of any client-supplied price field', async () => {
    const { env } = makeEnv();
    const res = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', {
      tier_id: 'gold', email: 'buyer@acme.com', company_name: 'Acme Corp', contact_name: 'Jo Smith',
      amount_paise: 1, // tamper attempt
    }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.amount_paise).toBe(MSSP_TIERS.gold.price_inr * 100);
    expect(body.amount_paise).not.toBe(1);
  });

  it('returns the existing pending order on retry instead of creating a duplicate Razorpay order', async () => {
    const { env } = makeEnv();
    const body = { tier_id: 'silver', email: 'dup@acme.com', company_name: 'Acme', contact_name: 'Jo' };
    const res1 = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', body), env);
    expect(res1.status).toBe(200);
    expect(fetchCalls).toBe(1);

    const res2 = await handleMsspCheckout(req('https://x/api/mssp/onboarding/checkout', body), env);
    const body2 = await res2.json();
    expect(body2.already_pending).toBe(true);
    expect(fetchCalls).toBe(1); // no second Razorpay order created
  });
});

describe('MSSP verify — signature gate, provisioning, idempotency', () => {
  it('rejects verification with an invalid signature and provisions nothing', async () => {
    const { env, partnersByEmail } = makeEnv({
      checkouts: [{ order_id: 'order_1', tier_id: 'silver', email: 'a@b.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending' }],
    });
    const res = await handleMsspVerify(req('https://x/api/mssp/onboarding/verify', {
      razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: 'bad-signature',
    }), env);
    expect(res.status).toBe(400);
    expect(partnersByEmail.size).toBe(0);
  });

  it('404s when no checkout record matches the order', async () => {
    const { env } = makeEnv();
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_missing|pay_x');
    const res = await handleMsspVerify(req('https://x/api/mssp/onboarding/verify', {
      razorpay_order_id: 'order_missing', razorpay_payment_id: 'pay_x', razorpay_signature: signature,
    }), env);
    expect(res.status).toBe(404);
  });

  it('provisions an active MSSP partner on valid signature', async () => {
    const { env, checkoutsByOrder, partnersByEmail } = makeEnv({
      checkouts: [{ order_id: 'order_2', tier_id: 'gold', email: 'new@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'pending' }],
    });
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_2|pay_2');
    const res = await handleMsspVerify(req('https://x/api/mssp/onboarding/verify', {
      razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2', razorpay_signature: signature,
    }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.tier_id).toBe('gold');
    expect(checkoutsByOrder.get('order_2').status).toBe('paid');
    expect(partnersByEmail.get('new@acme.com').status).toBe('active');
  });

  it('is idempotent — re-verifying an already-paid checkout does not re-provision', async () => {
    const { env } = makeEnv({
      checkouts: [{ order_id: 'order_3', tier_id: 'silver', email: 'x@acme.com', company_name: 'Acme', contact_name: 'Jo', status: 'paid', partner_id: 'mssp-existing-123' }],
    });
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_3|pay_3');
    const res = await handleMsspVerify(req('https://x/api/mssp/onboarding/verify', {
      razorpay_order_id: 'order_3', razorpay_payment_id: 'pay_3', razorpay_signature: signature,
    }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.already_verified).toBe(true);
    expect(body.partner_id).toBe('mssp-existing-123');
  });
});

describe('MSSP free trial — abuse limits', () => {
  it('rejects missing required fields', async () => {
    const { env } = makeEnv();
    const res = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', { email: 'a@b.com' }), env);
    expect(res.status).toBe(400);
  });

  it('rate-limits trial signups per IP after the max is reached', async () => {
    const { env } = makeEnv();
    const ipHeaders = { 'CF-Connecting-IP': '1.2.3.4' };
    for (let i = 0; i < 2; i++) {
      const res = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', {
        email: `trial${i}@acme.com`, company_name: 'Acme', contact_name: 'Jo',
      }, ipHeaders), env);
      expect(res.status).toBe(200);
    }
    const res3 = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', {
      email: 'trial3@acme.com', company_name: 'Acme', contact_name: 'Jo',
    }, ipHeaders), env);
    expect(res3.status).toBe(429);
  });

  it('rejects a second trial for the same email', async () => {
    const { env } = makeEnv();
    const body = { email: 'dupe@acme.com', company_name: 'Acme', contact_name: 'Jo' };
    const res1 = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', body, { 'CF-Connecting-IP': '9.9.9.9' }), env);
    expect(res1.status).toBe(200);
    const res2 = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', body, { 'CF-Connecting-IP': '9.9.9.8' }), env);
    expect(res2.status).toBe(409);
  });

  it('provisions a 14-day trial partner with no payment required', async () => {
    const { env, partnersByEmail } = makeEnv();
    const res = await handleMsspTrial(req('https://x/api/mssp/onboarding/trial', {
      email: 'fresh@acme.com', company_name: 'Acme', contact_name: 'Jo',
    }, { 'CF-Connecting-IP': '5.5.5.5' }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.trial_days).toBe(14);
    expect(partnersByEmail.get('fresh@acme.com').status).toBe('trial');
  });
});

describe('MSSP onboarding status', () => {
  it('requires partner_id or email', async () => {
    const { env } = makeEnv();
    const res = await handleMsspOnboardingStatus(new Request('https://x/api/mssp/onboarding/status'), env);
    expect(res.status).toBe(400);
  });

  it('404s for an unknown partner', async () => {
    const { env } = makeEnv();
    const res = await handleMsspOnboardingStatus(new Request('https://x/api/mssp/onboarding/status?email=ghost@acme.com'), env);
    expect(res.status).toBe(404);
  });

  it('returns onboarding checklist for a known partner', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mssp-1', email: 'known@acme.com', company_name: 'Acme', contact_name: 'Jo', tier_id: 'silver', clients_limit: 50, margin_pct: '40%', status: 'active', trial_ends_at: null, activated_at: new Date().toISOString() }],
    });
    const res = await handleMsspOnboardingStatus(new Request('https://x/api/mssp/onboarding/status?partner_id=mssp-1'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exists).toBe(true);
    expect(body.tier_id).toBe('silver');
    expect(Array.isArray(body.checklist)).toBe(true);
  });
});
