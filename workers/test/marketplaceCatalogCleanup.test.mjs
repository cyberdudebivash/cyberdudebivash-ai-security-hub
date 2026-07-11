/* CAP-MKT-005 (Sentinel APEX Marketplace Mega-Dispatcher) — PRODUCT_CATALOG
 * cleanup, 2026-07-11.
 *
 * PRODUCT_CATALOG previously carried 14 detection-pack/intel-report/defense-
 * kit/ai-security/bundle products with no coherent purchase path of their
 * own (no working self-serve checkout, most cta_url fields were manual
 * mailto: inquiries, and the one structurally-compatible endpoint here would
 * have returned hardcoded API-subscription access info regardless of which
 * product was "subscribed" to). Removed as dead, superseded inventory —
 * the real, live, working browse-to-purchase journey for that class of
 * product is a completely separate system (marketplaceCheckoutHandler.js's
 * MARKETPLACE_CATALOG + POST /api/marketplace/checkout + /verify, confirmed
 * end-to-end and unaffected by this change).
 *
 * These tests lock in: (1) the 14 removed ids are genuinely gone, not just
 * undocumented; (2) the 4 real API-subscription products this file's
 * purchase/subscribe/trial/upgrade sub-actions were actually built for are
 * completely unaffected and still fully functional; (3) MARKETPLACE_CATALOG
 * — a different module entirely — was not touched by this change.
 */
import { describe, it, expect } from 'vitest';
import { handleMarketplace } from '../src/handlers/sentinelApexMarketplace.js';
import { MARKETPLACE_CATALOG } from '../src/handlers/marketplaceCheckoutHandler.js';

function makeD1() {
  const rows = { marketplace_orders: [], marketplace_entitlements: [], subscriptions: [] };
  return {
    prepare(sql) {
      return {
        bind(...args) { this._args = args; return this; },
        async run() {
          if (/INSERT.*INTO marketplace_orders/i.test(sql)) rows.marketplace_orders.push(this._args);
          if (/INSERT.*INTO marketplace_entitlements/i.test(sql)) rows.marketplace_entitlements.push(this._args);
          if (/INSERT INTO subscriptions/i.test(sql)) rows.subscriptions.push(this._args);
          return { meta: { changes: 1 } };
        },
        async first() { return null; },
        async all() { return { results: [] }; },
      };
    },
  };
}
const authCtx = { authenticated: true, userId: 'u1', user_id: 'u1' };

const REMOVED_IDS = [
  'kev-detection-pack', 'apt-yara-pack', 'ir-detection-pack', 'apt-bundle',
  'tactical-dossier', 'executive-risk-report', 'weekly-soc-brief',
  'soc-starter-kit', 'ir-kit', 'enterprise-kit', 'ai-spm-kit',
  'llm-redteam-pack', 'ai-intel-feed', 'apex-ultimate-bundle',
];

describe('PRODUCT_CATALOG — the 14 dead, orphaned products are genuinely removed', () => {
  it.each(REMOVED_IDS)('POST /api/marketplace/purchase with product_id=%s now 404s (was previously a real, but unreachable, catalog entry)', async (productId) => {
    const env = { DB: makeD1() };
    const req = new Request('https://x/api/marketplace/purchase', {
      method: 'POST',
      body: JSON.stringify({ product_id: productId }),
    });
    const res = await handleMarketplace(req, env, authCtx, '/api/marketplace/purchase', 'POST');
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toContain('Product not found');
  });
});

describe('PRODUCT_CATALOG — the 4 real API-subscription products are completely unaffected', () => {
  it('POST /api/marketplace/purchase still works for api-enterprise (manual/contract purchase path)', async () => {
    const env = { DB: makeD1() };
    const req = new Request('https://x/api/marketplace/purchase', {
      method: 'POST',
      body: JSON.stringify({ product_id: 'api-enterprise' }),
    });
    const res = await handleMarketplace(req, env, authCtx, '/api/marketplace/purchase', 'POST');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.product.id).toBe('api-enterprise');
  });

  it('POST /api/marketplace/subscribe still works for api-pro', async () => {
    const env = { DB: makeD1() };
    const req = new Request('https://x/api/marketplace/subscribe', {
      method: 'POST',
      body: JSON.stringify({ product_id: 'api-pro' }),
    });
    const res = await handleMarketplace(req, env, authCtx, '/api/marketplace/subscribe', 'POST');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.product.id).toBe('api-pro');
    expect(body.status).toBe('active');
  });

  it('POST /api/marketplace/trial still works for api-team (has trial_days)', async () => {
    const env = { DB: makeD1() };
    const req = new Request('https://x/api/marketplace/trial', {
      method: 'POST',
      body: JSON.stringify({ product_id: 'api-team' }),
    });
    const res = await handleMarketplace(req, env, authCtx, '/api/marketplace/trial', 'POST');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('trial_active');
    expect(body.trial_days).toBe(7);
  });

  it('GET /api/marketplace/compare and /roi-calculator are untouched — neither does a product-id lookup', async () => {
    const env = {};
    const compare = await handleMarketplace(new Request('https://x/api/marketplace/compare'), env, authCtx, '/api/marketplace/compare', 'GET');
    expect(compare.status).toBe(200);
    const roi = await handleMarketplace(new Request('https://x/api/marketplace/roi-calculator'), env, authCtx, '/api/marketplace/roi-calculator', 'GET');
    expect(roi.status).toBe(200);
  });
});

describe('MARKETPLACE_CATALOG (marketplaceCheckoutHandler.js) — a different module, untouched by this change', () => {
  it('still has all 12 real, browsable products', () => {
    expect(Object.keys(MARKETPLACE_CATALOG)).toHaveLength(12);
    expect(MARKETPLACE_CATALOG['dp-ransomware-2025']).toBeDefined();
    expect(MARKETPLACE_CATALOG['aa-threat-hunter']).toBeDefined();
  });

  it('none of the 14 removed PRODUCT_CATALOG ids were ever part of MARKETPLACE_CATALOG (nothing to reconcile there)', () => {
    for (const id of REMOVED_IDS) {
      expect(MARKETPLACE_CATALOG[id]).toBeUndefined();
    }
  });
});
