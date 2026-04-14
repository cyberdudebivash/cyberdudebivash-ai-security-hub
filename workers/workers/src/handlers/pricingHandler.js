// ═══════════════════════════════════════════════════════════════
// PRICING HANDLER — /api/pricing
// Serves canonical pricing from pricingConfig — never hardcoded
// ═══════════════════════════════════════════════════════════════
import { PRICING_CONFIG, getPlansArray } from '../config/pricingConfig.js';
import { PAYMENT_CONFIG } from '../config/paymentConfig.js';

export async function handlePricing(request, env) {
  const url    = new URL(request.url);
  const planId = url.searchParams.get('plan');
  const type   = url.searchParams.get('type') || 'all';

  const headers = {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control':               'public, max-age=300',
  };

  // ── Single plan lookup ──────────────────────────────────────
  if (planId) {
    const plan = PRICING_CONFIG.plans[planId.toUpperCase()]
              || PRICING_CONFIG.packages[planId.toUpperCase()];
    if (!plan) {
      return new Response(JSON.stringify({ error: 'Plan not found', planId }), { status: 404, headers });
    }
    return new Response(JSON.stringify({ plan }), { status: 200, headers });
  }

  // ── Type-specific responses ──────────────────────────────────
  if (type === 'plans') {
    return new Response(JSON.stringify({
      plans:    Object.values(PRICING_CONFIG.plans),
      currency: PRICING_CONFIG.currency,
      gst_rate: PRICING_CONFIG.gst_rate,
    }), { status: 200, headers });
  }

  if (type === 'packages') {
    return new Response(JSON.stringify({
      packages: Object.values(PRICING_CONFIG.packages),
      currency: PRICING_CONFIG.currency,
      gst_rate: PRICING_CONFIG.gst_rate,
    }), { status: 200, headers });
  }

  if (type === 'reports') {
    return new Response(JSON.stringify({
      reports:  PRICING_CONFIG.reports,
      currency: PRICING_CONFIG.currency,
    }), { status: 200, headers });
  }

  // ── Full pricing manifest ────────────────────────────────────
  return new Response(JSON.stringify({
    plans:    Object.values(PRICING_CONFIG.plans),
    packages: Object.values(PRICING_CONFIG.packages),
    reports:  PRICING_CONFIG.reports,
    currency: PRICING_CONFIG.currency,
    gst_rate: PRICING_CONFIG.gst_rate,
    business: {
      name: PAYMENT_CONFIG.business.name,
      gst:  PAYMENT_CONFIG.business.gst,
    },
  }), { status: 200, headers });
}

// ── Payment config endpoint /api/payment-config ──────────────
export async function handlePaymentConfig(request, env) {
  const headers = {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control':               'public, max-age=3600',
  };

  // Return safe subset — no sensitive account data in public API
  return new Response(JSON.stringify({
    upi: {
      primary:   PAYMENT_CONFIG.upi.primary,
      secondary: PAYMENT_CONFIG.upi.secondary,
      qr_path:   PAYMENT_CONFIG.upi.qr_path,
      name:      PAYMENT_CONFIG.upi.name,
    },
    bank: {
      account_name:   PAYMENT_CONFIG.bank.account_name,
      account_number: PAYMENT_CONFIG.bank.account_number,
      ifsc:           PAYMENT_CONFIG.bank.ifsc,
      bank_name:      PAYMENT_CONFIG.bank.bank_name,
    },
    crypto: {
      bnb_smart_chain: PAYMENT_CONFIG.crypto.bnb_smart_chain,
      network:         PAYMENT_CONFIG.crypto.network,
      token:           PAYMENT_CONFIG.crypto.token,
    },
    paypal: {
      email: PAYMENT_CONFIG.paypal.email,
      link:  PAYMENT_CONFIG.paypal.link,
    },
    business: {
      name:    PAYMENT_CONFIG.business.name,
      gst:     PAYMENT_CONFIG.business.gst,
      support: PAYMENT_CONFIG.business.support,
    },
    sla: PAYMENT_CONFIG.sla,
  }), { status: 200, headers });
}

// ── Guard: reject any request attempting to mutate payment data
export async function handlePaymentMutationGuard(request, env) {
  return new Response(JSON.stringify({
    error:   'PAYMENT_DATA_IMMUTABLE',
    message: 'Payment configuration is immutable and cannot be modified via API.',
    code:    403,
  }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  });
}
