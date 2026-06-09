/**
 * ═══════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI SECURITY HUB
 * GEO-CURRENCY ROUTER v1.0 — EDGE-FIRST MULTI-CURRENCY ENGINE
 * ═══════════════════════════════════════════════════════════════════════
 * Detects user country via Cloudflare CF-IPCountry header (edge-injected).
 * IN → INR pricing matrix (₹)
 * !IN → USD pricing matrix ($)
 * Zero flicker: runs synchronously before first paint via inline script.
 * ═══════════════════════════════════════════════════════════════════════
 */
(function GEOCURRENCY_ROUTER() {
  'use strict';

  /* ── PRICING MATRICES ─────────────────────────────────────────────── */
  const PRICING = Object.freeze({
    INR: Object.freeze({
      currency:       'INR',
      symbol:         '₹',
      locale:         'en-IN',
      plans: Object.freeze({
        FREE:       Object.freeze({ monthly: 0,    annual: 0,      label: 'Free Forever' }),
        STARTER:    Object.freeze({ monthly: 499,  annual: 4990,   label: 'Starter' }),
        PRO:        Object.freeze({ monthly: 1499, annual: 14990,  label: 'Pro' }),
        ENTERPRISE: Object.freeze({ monthly: 4999, annual: 49990,  label: 'Enterprise' }),
        MSSP:       Object.freeze({ monthly: 9999, annual: 99990,  label: 'MSSP Command' }),
      }),
      reports: Object.freeze({
        domain:     999,
        ai:         999,
        redteam:    999,
        compliance: 999,
        identity:   999,
        cloudsec:   999,
        darkscan:   999,
        appsec:     999,
        full:       1999,
      }),
      upgradeCTA: 'Upgrade to STARTER — ₹499/mo',
    }),
    USD: Object.freeze({
      currency:       'USD',
      symbol:         '$',
      locale:         'en-US',
      plans: Object.freeze({
        FREE:       Object.freeze({ monthly: 0,   annual: 0,    label: 'Free Forever' }),
        STARTER:    Object.freeze({ monthly: 6,   annual: 60,   label: 'Starter' }),
        PRO:        Object.freeze({ monthly: 19,  annual: 190,  label: 'Pro' }),
        ENTERPRISE: Object.freeze({ monthly: 59,  annual: 590,  label: 'Enterprise' }),
        MSSP:       Object.freeze({ monthly: 119, annual: 1190, label: 'MSSP Command' }),
      }),
      reports: Object.freeze({
        domain:     12,
        ai:         12,
        redteam:    12,
        compliance: 12,
        identity:   12,
        cloudsec:   12,
        darkscan:   12,
        appsec:     12,
        full:       24,
      }),
      upgradeCTA: 'Upgrade to STARTER — $6/mo',
    }),
  });

  /* ── COUNTRY DETECTION ────────────────────────────────────────────── */
  /**
   * Reads country from:
   * 1. window.__CDB_COUNTRY__ — injected by Cloudflare Worker server-side (highest trust)
   * 2. localStorage cache (ttl 24h) — avoid repeated API hits on navigation
   * 3. /api/geo endpoint — Worker-side CF-IPCountry reflection
   * 4. Falls back to INR (India default)
   */
  function detectCountry() {
    // Priority 1: server-injected (Cloudflare Worker sets this on HTML response)
    if (typeof window.__CDB_COUNTRY__ === 'string' && window.__CDB_COUNTRY__.length === 2) {
      return window.__CDB_COUNTRY__.toUpperCase();
    }
    // Priority 2: localStorage cache (24h TTL)
    try {
      const cached = JSON.parse(localStorage.getItem('cdb_geo_v1') || 'null');
      if (cached && cached.cc && cached.ts && (Date.now() - cached.ts < 86400000)) {
        return cached.cc.toUpperCase();
      }
    } catch (_) {}
    // Priority 3: async fetch — will update DOM after load
    fetchAndCacheCountry();
    // Fallback: INR (India default — majority traffic)
    return 'IN';
  }

  function fetchAndCacheCountry() {
    const api = (window.CONFIG && window.CONFIG.API_BASE)
      || 'https://cyberdudebivash-security-hub.workers.dev';
    fetch(api + '/api/geo', { credentials: 'omit' })
      .then(r => r.json())
      .then(d => {
        const cc = (d && d.country) ? d.country.toUpperCase() : 'IN';
        try {
          localStorage.setItem('cdb_geo_v1', JSON.stringify({ cc, ts: Date.now() }));
        } catch (_) {}
        // Re-apply if country changed from default
        if (cc !== window.__CDB_GEO.countryCode) {
          window.__CDB_GEO.countryCode = cc;
          window.__CDB_GEO.matrix = cc === 'IN' ? PRICING.INR : PRICING.USD;
          applyPricingToDOM();
        }
      })
      .catch(() => {}); // silent fail — keep default
  }

  /* ── CURRENCY RESOLUTION ──────────────────────────────────────────── */
  const countryCode = detectCountry();
  const matrix      = countryCode === 'IN' ? PRICING.INR : PRICING.USD;

  /* ── GLOBAL EXPORT ────────────────────────────────────────────────── */
  window.__CDB_GEO = {
    countryCode,
    matrix,
    PRICING,

    /**
     * Format a price value for display
     * @param {number} amount
     * @param {string} [currencyOverride] - 'INR' | 'USD'
     */
    format(amount, currencyOverride) {
      const m = currencyOverride ? PRICING[currencyOverride] : matrix;
      if (!m) return String(amount);
      try {
        return new Intl.NumberFormat(m.locale, {
          style: 'currency',
          currency: m.currency,
          minimumFractionDigits: 0,
          maximumFractionDigits: 0,
        }).format(amount);
      } catch (_) {
        return m.symbol + amount;
      }
    },

    /**
     * Get plan price for display
     * @param {'FREE'|'STARTER'|'PRO'|'ENTERPRISE'|'MSSP'} planId
     * @param {'monthly'|'annual'} [billing]
     */
    planPrice(planId, billing = 'monthly') {
      const plan = matrix.plans[planId];
      if (!plan) return null;
      return this.format(plan[billing]);
    },

    /**
     * Get report price for display
     * @param {string} reportType
     */
    reportPrice(reportType) {
      const amt = matrix.reports[reportType] || matrix.reports.domain;
      return this.format(amt);
    },

    /**
     * Get raw numeric price for payment processing
     * @param {string} reportType
     */
    reportAmount(reportType) {
      return matrix.reports[reportType] || matrix.reports.domain;
    },
  };

  /* ── DOM HYDRATION ────────────────────────────────────────────────── */
  /**
   * Updates all [data-cdb-price] elements with correct localized price.
   * Usage in HTML: <span data-cdb-price="plan:STARTER:monthly">₹499</span>
   *                <span data-cdb-price="report:domain">₹999</span>
   *                <span data-cdb-price="symbol">₹</span>
   */
  function applyPricingToDOM() {
    const m = window.__CDB_GEO.matrix;
    const geo = window.__CDB_GEO;

    // Update data-cdb-price elements
    document.querySelectorAll('[data-cdb-price]').forEach(el => {
      const spec = el.getAttribute('data-cdb-price');
      if (!spec) return;
      const parts = spec.split(':');
      try {
        if (parts[0] === 'plan' && parts[1] && parts[2]) {
          el.textContent = geo.planPrice(parts[1], parts[2]);
        } else if (parts[0] === 'report' && parts[1]) {
          el.textContent = geo.reportPrice(parts[1]);
        } else if (parts[0] === 'symbol') {
          el.textContent = m.symbol;
        } else if (parts[0] === 'upgrade-cta') {
          el.textContent = m.upgradeCTA;
        }
      } catch (_) {}
    });

    // Update pricing card elements with data-cdb-plan attribute
    document.querySelectorAll('[data-cdb-plan]').forEach(card => {
      const planId = card.getAttribute('data-cdb-plan');
      const plan = m.plans[planId];
      if (!plan) return;
      const priceEl = card.querySelector('[data-cdb-plan-price]');
      const periodEl = card.querySelector('[data-cdb-plan-period]');
      if (priceEl) {
        const billing = priceEl.getAttribute('data-cdb-plan-price') || 'monthly';
        priceEl.textContent = geo.format(plan[billing]);
      }
      if (periodEl) {
        periodEl.textContent = m.currency === 'USD' ? '/month' : '/mo';
      }
    });

    // Update upgrade banner CTA text
    document.querySelectorAll('[data-cdb-upgrade-cta]').forEach(el => {
      el.textContent = m.upgradeCTA;
    });

    // Update report unlock buttons
    document.querySelectorAll('[data-cdb-report-btn]').forEach(btn => {
      const rtype = btn.getAttribute('data-cdb-report-btn') || 'domain';
      const price = geo.reportPrice(rtype);
      btn.textContent = btn.getAttribute('data-cdb-btn-prefix') || '';
      btn.textContent += `💰 Unlock Full Report ${price}`;
    });

    // Emit event for other scripts to react
    document.dispatchEvent(new CustomEvent('cdb:currency:applied', {
      detail: { countryCode: window.__CDB_GEO.countryCode, currency: m.currency }
    }));
  }

  /* ── INIT ─────────────────────────────────────────────────────────── */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyPricingToDOM);
  } else {
    applyPricingToDOM();
  }

  // Re-apply on any client-side navigation (SPA compatibility)
  window.addEventListener('popstate', applyPricingToDOM);
  document.addEventListener('cdb:page:rendered', applyPricingToDOM);

})();
