/* Regression test — handleCreateOrder no longer trusts a client-supplied
 * price_inr for module:'defense' (2026-07-06 revenue-mechanisms audit).
 * That branch was dead code (no frontend caller, and handleVerifyPayment
 * always rejected 'defense' since it's in neither SCAN_HANDLERS nor
 * NON_SCAN_MODULES — so nothing could ever complete this purchase anyway)
 * but still accepted an arbitrary client-controlled amount. Locks that a
 * defense-module create-order request is now rejected outright, regardless
 * of what price_inr the caller sends.
 */
import { describe, it, expect } from 'vitest';
import { handleCreateOrder } from '../src/handlers/payments.js';

function req(body) {
  return new Request('https://x/api/payment/create-order', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('handleCreateOrder — module:"defense" no longer accepts a client-controlled price', () => {
  it('rejects a defense-module order even with a plausible price_inr', async () => {
    const env = {};
    const res = await handleCreateOrder(req({ module: 'defense', target: 'Acme Corp', price_inr: 50000, solution_title: 'WAF Bundle' }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/marketplace\/checkout/);
  });

  it('rejects it even with an obviously manipulated price_inr (e.g. ₹1 for a real solution)', async () => {
    const env = {};
    const res = await handleCreateOrder(req({ module: 'defense', target: 'Acme Corp', price_inr: 1 }), env, {});
    expect(res.status).toBe(400);
  });
});
