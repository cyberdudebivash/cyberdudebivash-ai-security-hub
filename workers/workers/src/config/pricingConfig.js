// ═══════════════════════════════════════════════════════════════
// PRICING CONFIG — IMMUTABLE SOURCE OF TRUTH
// CYBERDUDEBIVASH PRIVATE LIMITED | GST: 21ARKPN8270G1ZP
// ALL prices in INR (paise for Razorpay: multiply by 100)
// ═══════════════════════════════════════════════════════════════
'use strict';

const PRICING_CONFIG = Object.freeze({

  // ── Subscription Plans ───────────────────────────────────────
  plans: Object.freeze({
    FREE: Object.freeze({
      id:           'FREE',
      name:         'Free',
      price_inr:    0,
      price_paise:  0,
      billing:      'forever',
      daily_scans:  5,
      api_keys:     1,
      label:        'Free Forever',
      cta:          'Get Started Free',
    }),
    STARTER: Object.freeze({
      id:           'STARTER',
      name:         'Starter',
      price_inr:    499,
      price_paise:  49900,
      billing:      'monthly',
      daily_scans:  50,
      api_keys:     2,
      label:        'Starter — ₹499/month',
      cta:          '⚡ Get Starter',
    }),
    PRO: Object.freeze({
      id:           'PRO',
      name:         'Pro',
      price_inr:    1499,
      price_paise:  149900,
      billing:      'monthly',
      daily_scans:  500,
      api_keys:     5,
      label:        'Pro Plan — ₹1,499/month',
      cta:          '🚀 Get Pro',
    }),
    ENTERPRISE: Object.freeze({
      id:           'ENTERPRISE',
      name:         'Enterprise',
      price_inr:    4999,
      price_paise:  499900,
      billing:      'monthly',
      daily_scans:  -1,
      api_keys:     20,
      label:        'Enterprise Plan — ₹4,999/month',
      cta:          '🏢 Get Enterprise',
    }),
    MSSP: Object.freeze({
      id:           'MSSP',
      name:         'MSSP Command',
      price_inr:    9999,
      price_paise:  999900,
      billing:      'monthly',
      daily_scans:  -1,
      api_keys:     -1,
      label:        'MSSP Command — ₹9,999/month',
      cta:          '🏷️ Get MSSP',
    }),
  }),

  // ── Enterprise Packages (one-time / annual) ──────────────────
  packages: Object.freeze({
    SECURITY_ASSESSMENT: Object.freeze({
      id:          'SECURITY_ASSESSMENT',
      name:        'Security Assessment',
      price_inr:   9999,
      price_paise: 999900,
      billing:     'one-time',
      label:       'Security Assessment — ₹9,999',
      description: 'Full domain + AI + compliance assessment with PDF report',
    }),
    THREAT_INTEL_REPORT: Object.freeze({
      id:          'THREAT_INTEL_REPORT',
      name:        'Threat Intel Report',
      price_inr:   14999,
      price_paise: 1499900,
      billing:     'one-time',
      label:       'Threat Intel Report — ₹14,999',
      description: 'Deep CVE intelligence report with IOC mapping and remediation plan',
    }),
    MSSP_WHITE_LABEL: Object.freeze({
      id:          'MSSP_WHITE_LABEL',
      name:        'MSSP White Label',
      price_inr:   49999,
      price_paise: 4999900,
      billing:     'monthly',
      label:       'MSSP White Label — ₹49,999/month',
      description: 'Full white-label platform with unlimited client management',
    }),
    ANNUAL_RETAINER: Object.freeze({
      id:          'ANNUAL_RETAINER',
      name:        'Annual Retainer',
      price_inr:   99999,
      price_paise: 9999900,
      billing:     'annual',
      label:       'Annual Retainer — ₹99,999/year',
      description: 'Full-year enterprise security retainer with SLA and dedicated support',
    }),
    // Legacy aliases — kept for backward compat, map to correct prices
    STARTER_PLUS_ANNUAL: Object.freeze({
      id:          'STARTER_PLUS_ANNUAL',
      name:        'Starter Plus Annual',
      price_inr:   49900,
      price_paise: 4990000,
      billing:     'annual',
      label:       'Starter Plus — ₹49,900/year',
    }),
    ENTERPRISE_SHIELD: Object.freeze({
      id:          'ENTERPRISE_SHIELD',
      name:        'Enterprise Shield',
      price_inr:   499900,
      price_paise: 49990000,
      billing:     'annual',
      label:       'Enterprise Shield — ₹4,99,900/year',
    }),
    MSSP_COMMAND: Object.freeze({
      id:          'MSSP_COMMAND',
      name:        'MSSP Command Suite',
      price_inr:   1499900,
      price_paise: 149990000,
      billing:     'annual',
      label:       'MSSP Command Suite — ₹14,99,900/year',
    }),
  }),

  // ── Pay-per-report ───────────────────────────────────────────
  reports: Object.freeze({
    domain:     Object.freeze({ price_inr: 199,  label: 'Domain Report — ₹199'  }),
    ai:         Object.freeze({ price_inr: 499,  label: 'AI Security Report — ₹499' }),
    redteam:    Object.freeze({ price_inr: 999,  label: 'Red Team Report — ₹999' }),
    compliance: Object.freeze({ price_inr: 799,  label: 'Compliance Report — ₹799' }),
    identity:   Object.freeze({ price_inr: 699,  label: 'Identity Report — ₹699' }),
    cloudsec:   Object.freeze({ price_inr: 599,  label: 'Cloud Security Report — ₹599' }),
    darkscan:   Object.freeze({ price_inr: 499,  label: 'Dark Web Report — ₹499' }),
    appsec:     Object.freeze({ price_inr: 899,  label: 'AppSec Report — ₹899' }),
    full:       Object.freeze({ price_inr: 1999, label: 'Full Platform Report — ₹1,999' }),
  }),

  // ── GST Rate ─────────────────────────────────────────────────
  gst_rate: 0.18,
  currency: 'INR',
  currency_symbol: '₹',
});

/**
 * Get plan price in INR — always use this, never hardcode
 */
export function getPlanPrice(planId) {
  const plan = PRICING_CONFIG.plans[planId] || PRICING_CONFIG.packages[planId];
  return plan ? plan.price_inr : null;
}

/**
 * Get price with GST
 */
export function getPriceWithGST(priceInr) {
  return Math.round(priceInr * (1 + PRICING_CONFIG.gst_rate));
}

/**
 * Get all plans as array for frontend rendering
 */
export function getPlansArray() {
  return Object.values(PRICING_CONFIG.plans);
}

export default PRICING_CONFIG;
export { PRICING_CONFIG };
