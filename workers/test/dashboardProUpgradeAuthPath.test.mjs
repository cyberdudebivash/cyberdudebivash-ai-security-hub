/* 2026-07-10: the dashboard's "Upgrade to Pro" button (selectPlan('pro') in
 * frontend/user-dashboard.html) called POST /api/subscription/create then
 * POST /api/subscription/activate (workers/src/handlers/subscription.js).
 * Both handleActivateSubscription's D1 writes use column names that do not
 * exist in the live schema (workers/schema_master.sql):
 *   - payments INSERT used order_id/payment_id (real: razorpay_order_id/
 *     razorpay_payment_id) and never supplied the required NOT NULL `target`
 *     column; status value 'captured' isn't in the CHECK constraint
 *     ('pending'|'paid'|'failed'|'refunded').
 *   - subscriptions INSERT used processor/external_id/activated_at/
 *     expires_at (none of which exist) and never supplied the required NOT
 *     NULL `user_id` column.
 * Both writes are wrapped in .catch(), so every failure was swallowed
 * silently. handleActivateSubscription never touches users.tier at all, and
 * the frontend discarded the response's session_token entirely (grep for
 * session_token across frontend/user-dashboard.html: 0 matches) — so every
 * customer using this specific button was charged, shown "plan activated",
 * and left on their old tier with zero error anywhere.
 *
 * Separately found while verifying the fix live in a browser: the button
 * also never loaded the real Razorpay Checkout SDK. assets/payment-modal.js
 * installs a compat shim (`if (!window.Razorpay) window.Razorpay = ...`)
 * that always wins a `!window.Razorpay` guard, silently rerouting checkout
 * to the old manual-payment modal instead — confirmed via a real headless-
 * Chromium Playwright session, not assumed.
 *
 * FIX: route both the order-creation and verify calls onto the same
 * canonical, already-tested subscription path the pricing page's automated
 * checkout uses (workers/src/handlers/payments.js handleCreateOrder /
 * handleVerifyPayment) instead of patching the broken parallel
 * implementation — consistent with how CAP-DEVPORTAL-003 consolidated a
 * comparable duplicate system onto its canonical equivalent. Also loads the
 * real Razorpay SDK unconditionally (once per page load) rather than
 * gating on window.Razorpay, and stores the resulting JWT/refresh token so
 * the rest of the platform actually recognizes the upgraded tier. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(name, window = 3000) {
  const start = fe.indexOf(`function ${name}`);
  if (start === -1) return '';
  return fe.slice(start, start + window);
}

describe('Dashboard "Upgrade to Pro" uses the canonical subscription path (post 2026-07-10 incident)', () => {
  it('never calls the broken /api/subscription/create or /api/subscription/activate endpoints', () => {
    expect(fe).not.toContain("apiFetch('/api/subscription/create'");
    expect(fe).not.toContain("'/api/subscription/activate'");
  });

  it('selectPlan() creates the order via the canonical payments.js endpoint with the right body', () => {
    const body = fnBody('selectPlan', 4000);
    expect(body).not.toBe('');
    expect(body).toContain("apiFetch('/api/payments/create-order'");
    expect(body).toMatch(/module:\s*['"]subscription['"]/);
    expect(body).toMatch(/plan:\s*['"]PRO['"]/);
    expect(body).toMatch(/target:\s*['"]pro['"]/);
  });

  it('selectPlan() unconditionally (re)loads the real Razorpay SDK rather than trusting window.Razorpay', () => {
    const body = fnBody('selectPlan', 4000);
    // The SDK-load guard must not key off window.Razorpay — assets/payment-
    // modal.js's compat shim always satisfies that check first (own regression
    // lock, not a comment match: the code, not prose, must use a dedicated flag).
    const loadIdx = body.indexOf('checkout.razorpay.com/v1/checkout.js');
    expect(loadIdx).toBeGreaterThan(-1);
    const guardWindow = body.slice(Math.max(0, loadIdx - 400), loadIdx);
    expect(guardWindow).toContain('__cdbRealRzpLoaded');
    expect(guardWindow).not.toMatch(/if\s*\(\s*!window\.Razorpay\s*\)\s*\{/);
  });

  it('handlePaymentSuccess() verifies subscriptions via the canonical payments.js endpoint with the right body', () => {
    const body = fnBody('handlePaymentSuccess', 3000);
    expect(body).not.toBe('');
    const idx = body.indexOf("type === 'subscription'");
    expect(idx).toBeGreaterThan(-1);
    const subBranch = body.slice(idx, idx + 1400);
    // verifyEndpoint must stay '/api/payments/verify' (the try block's
    // default, set before this branch) — the historical broken value is only
    // ever mentioned in this branch's own explanatory comment now, so assert
    // the endpoint variable is never reassigned here rather than searching
    // for the string (which the comment legitimately still contains).
    expect(subBranch).not.toMatch(/verifyEndpoint\s*=\s*['"]/);
    expect(subBranch).toMatch(/module:\s*['"]subscription['"]/);
  });

  it('handlePaymentSuccess() stores the returned JWT and refresh token after a successful subscription verify', () => {
    // Regression (2026-07-11 full-frontend audit): this test previously
    // asserted localStorage.setItem('cdb_token', d.token) — the exact bug
    // it should have been guarding against. apiFetch() and every other read
    // site on this page only ever look at sessionStorage['cdb_access'] (via
    // _token/saveTokens(), the same path doLogin()'s own success handler
    // uses) — the old assertion locked in a storage key/type nothing reads,
    // so the customer's UI kept enforcing their pre-upgrade tier.
    const body = fnBody('handlePaymentSuccess', 3000);
    expect(body).toContain('_token = d.token');
    expect(body).toContain('saveTokens(_token, d.refresh_token)');
    expect(body).not.toContain("localStorage.setItem('cdb_token'");
  });
});
