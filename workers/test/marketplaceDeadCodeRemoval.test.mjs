/* CAP-MKT-005 (Sentinel APEX Marketplace Mega-Dispatcher) — removed 3
 * permanently-unreachable functions.
 *
 * Diagnosed 2026-07-08 (docs/capability-registry/domains/
 * sentinel-apex-marketplace.json): workers/src/index.js registers
 * exact-match routes for GET /api/marketplace/catalog, GET
 * /api/marketplace/catalog/:productId, and POST /api/marketplace/checkout
 * BEFORE the generic `/api/marketplace/*` prefix dispatch that reaches
 * handleMarketplace() — those exact-match routes go to
 * marketplaceCheckoutHandler.js (the real, live, well-tested
 * implementation, confirmed by frontend/marketplace-checkout.html). Since
 * the router returns on first match, handleMarketplace()'s own internal
 * handleGetCatalog/handleGetProduct/handleCheckout were dead code —
 * reachable only by a direct unit-test import of handleMarketplace()
 * itself (bypassing the real router), never by an actual HTTP request.
 * Removed 2026-07-11 rather than left as silently-diverging duplicate
 * implementations of a payment-adjacent path.
 *
 * These tests exercise the REAL ROUTER (worker.fetch()), not
 * handleMarketplace() directly — a direct-import test would not have
 * caught the original shadowing bug (confirmed in the registry's own
 * evidence) and would not catch a regression of it either.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

function makeD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE marketplace_orders (
    id TEXT PRIMARY KEY, user_id TEXT, product_id TEXT, product_name TEXT,
    amount INTEGER, currency TEXT, discount INTEGER, coupon_code TEXT,
    status TEXT, payment_method TEXT, checkout_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { prepare: wrap };
}
function makeKV() {
  const store = new Map();
  return {
    async get(k, opts) { const v = store.get(k); if (v === undefined) return null; return opts?.type === 'json' ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, String(v)); },
  };
}
const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

describe('GET /api/marketplace/catalog — real router now hits the live handler end-to-end, not dead code', () => {
  it('returns marketplaceCheckoutHandler.js\'s real catalog shape (INR pricing, total_products) via the actual router', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/marketplace/catalog'), env, ctxStub);
    expect(res.status).toBe(200);
    const body = await res.json();
    // Real shape from marketplaceCheckoutHandler.js's handleMarketplaceCatalog
    // (currency: INR) — the removed dead code returned currency: USD, so this
    // also positively confirms which implementation actually answered.
    expect(body).toHaveProperty('total_products');
    expect(body.currency).toBe('INR');
  });

  it('GET /api/marketplace/catalog/:productId also hits the live handler', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/marketplace/catalog/dp-ransomware-2025'), env, ctxStub);
    const body = await res.json();
    // Real shape: handleMarketplaceProduct spreads the product fields at the
    // top level ({...product, price_display, ...}), not nested under "product"
    // (that nested shape was the removed dead code's response, not this one's).
    expect(res.status).toBe(200);
    expect(body.id).toBe('dp-ransomware-2025');
  });
});

describe('handleMarketplace() dispatcher — catalog/product/checkout are no longer dead code inside it', () => {
  it('a direct call (bypassing the router) for these 3 paths now correctly falls through to "route not found", not a shadowed handler', async () => {
    const { handleMarketplace } = await import('../src/handlers/sentinelApexMarketplace.js');
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    for (const [path, method] of [
      ['/api/marketplace/catalog', 'GET'],
      ['/api/marketplace/catalog/api-pro', 'GET'],
      ['/api/marketplace/checkout', 'POST'],
    ]) {
      const req = new Request(`https://x${path}`, { method, body: method === 'POST' ? '{}' : undefined });
      const res = await handleMarketplace(req, env, {}, path, method);
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error).toBe('Marketplace route not found');
      // The 404 hint list no longer claims this dispatcher serves them.
      expect(body.available).not.toContain('GET /api/marketplace/catalog');
      expect(body.available).not.toContain('POST /api/marketplace/checkout');
    }
  });

  it('the other 12 real sub-actions inside handleMarketplace() are untouched — spot-check a few', async () => {
    const { handleMarketplace } = await import('../src/handlers/sentinelApexMarketplace.js');
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const authCtx = { authenticated: true, userId: 'u1', user_id: 'u1' };

    const roi = await handleMarketplace(new Request('https://x/api/marketplace/roi-calculator'), env, authCtx, '/api/marketplace/roi-calculator', 'GET');
    expect(roi.status).toBe(200);

    const compare = await handleMarketplace(new Request('https://x/api/marketplace/compare'), env, authCtx, '/api/marketplace/compare', 'GET');
    expect(compare.status).toBe(200);

    const orders = await handleMarketplace(new Request('https://x/api/marketplace/orders'), env, authCtx, '/api/marketplace/orders', 'GET');
    expect(orders.status).toBe(200);
  });
});
