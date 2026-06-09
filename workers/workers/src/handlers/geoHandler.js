/**
 * ═══════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI SECURITY HUB
 * GEO HANDLER — Cloudflare Worker Route: GET /api/geo
 * ═══════════════════════════════════════════════════════════════════════
 * Reads CF-IPCountry from request headers (Cloudflare injects this
 * automatically on all requests to Workers). Returns JSON country code.
 * Also injects window.__CDB_COUNTRY__ into HTML responses server-side.
 * ═══════════════════════════════════════════════════════════════════════
 */
'use strict';

/**
 * GET /api/geo
 * Returns: { country: "IN" | "US" | ... , currency: "INR" | "USD" }
 */
export async function handleGeo(request, env, ctx) {
  const cf       = request.cf || {};
  const country  = (cf.country || request.headers.get('CF-IPCountry') || 'IN').toUpperCase();
  const currency = country === 'IN' ? 'INR' : 'USD';

  return new Response(JSON.stringify({
    country,
    currency,
    symbol:   currency === 'INR' ? '₹' : '$',
    ts:       Date.now(),
  }), {
    status: 200,
    headers: {
      'Content-Type':                'application/json',
      'Cache-Control':               'public, max-age=3600, s-maxage=3600',
      'CDN-Cache-Control':           'max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'X-Country':                   country,
      'X-Currency':                  currency,
    },
  });
}

/**
 * Server-side HTML injection middleware.
 * Wraps an HTML Response to inject <script>window.__CDB_COUNTRY__='XX'</script>
 * immediately after <head> — executes before any other JS, zero flicker.
 *
 * @param {Response} htmlResponse  The original HTML response
 * @param {Request}  request       The incoming request (to read CF headers)
 * @returns {Response}
 */
export function injectCountryIntoHTML(htmlResponse, request) {
  const cf      = (request && request.cf) || {};
  const country = (cf.country || (request && request.headers.get('CF-IPCountry')) || 'IN').toUpperCase();

  // Cloudflare HTMLRewriter — streams, zero buffering penalty
  return new HTMLRewriter()
    .on('head', {
      element(el) {
        // Inline script injected as very first child of <head>
        el.prepend(
          `<script>window.__CDB_COUNTRY__='${country}';</script>`,
          { html: true }
        );
      },
    })
    .transform(htmlResponse);
}

/**
 * Country → plan pricing map for server-side rendering / API responses.
 * Mirrors geo-currency-router.js client constants — keep in sync.
 */
export const PLAN_PRICING = Object.freeze({
  INR: Object.freeze({
    STARTER:    { monthly: 499,  annual: 4990  },
    PRO:        { monthly: 1499, annual: 14990 },
    ENTERPRISE: { monthly: 4999, annual: 49990 },
    MSSP:       { monthly: 9999, annual: 99990 },
  }),
  USD: Object.freeze({
    STARTER:    { monthly: 6,   annual: 60   },
    PRO:        { monthly: 19,  annual: 190  },
    ENTERPRISE: { monthly: 59,  annual: 590  },
    MSSP:       { monthly: 119, annual: 1190 },
  }),
});

export const REPORT_PRICING = Object.freeze({
  INR: 999,
  USD: 12,
});

/**
 * Returns the correct plan price for payment processing (INR paise or USD cents).
 */
export function getPlanAmountForPayment(planId, currency, billing = 'monthly') {
  const matrix = PLAN_PRICING[currency] || PLAN_PRICING.INR;
  const plan   = matrix[planId];
  if (!plan) return null;
  const amount = plan[billing];
  // Razorpay needs paise (multiply by 100 for INR)
  return currency === 'INR' ? amount * 100 : amount;
}
