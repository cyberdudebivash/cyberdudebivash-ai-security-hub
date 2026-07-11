/* Customer-reported production gap, 2026-07-11 — investigating why homepage
 * dashboard/hub links "aren't properly built" found that window.openMSSPApplication
 * and window.openEnterpriseBooking were each defined TWICE in frontend/index.html:
 * once near the real Enterprise/MSSP section (a genuine, dedicated
 * #mssp-modal application form with company/email/website capture that POSTs
 * to /api/global/mssp/apply, and a #enterprise-booking-modal that collects
 * business details before handing off to a real payment flow), and again,
 * much later, inside a "MANUAL PAYMENT SYSTEM" block whose own comment says
 * it exists to "intercept existing startSubscription / openEnterpriseBooking
 * calls." Because both are plain `window.X = function(){}` assignments
 * evaluated top-to-bottom, the second (later) definition silently won at
 * runtime for BOTH functions — not just the one the comment named.
 *
 * Concretely, this meant:
 *   - "🚀 Apply as MSSP Partner" (two buttons) never opened the real
 *     application form at all — it opened a generic manual bank-transfer/UPI
 *     instructions modal for a fixed "MSSP Management Platform — ₹49,999/month"
 *     description, with no company/email capture and no path to the real,
 *     tested POST /api/global/mssp/apply a partner application actually needs.
 *   - The second definition's own package-pricing map had drifted from the
 *     first's: both map the SAME key `starter_enterprise` to two DIFFERENT
 *     products at two DIFFERENT prices (first: "Security Assessment Report"
 *     ₹9,999; second: "Starter Plus — ₹49,900/year") — a real, silent
 *     pricing-mismatch risk for any future caller of that key, even though no
 *     current caller uses it (the Security Assessment card itself was already
 *     rewired to CDB_CHECKOUT_MODAL directly on 2026-07-10, per
 *     enterprisePackageCheckout.test.mjs — this second, wrong map entry was
 *     simply never exercised, not evidence the mismatch didn't exist).
 *
 * FIX: deleted the second (shadowing) redefinitions entirely, so the first,
 * dedicated, real implementations are what actually run. startSubscription
 * (a genuinely separate, unrelated flow — plan subscriptions, not enterprise
 * package bookings or MSSP partner applications) is untouched. Confirmed via
 * grep that all 3 real call sites in the file (openMSSPApplication() x2, no
 * args; openEnterpriseBooking('annual_retainer') x1) are fully satisfied by
 * the first definitions with no behavior the second uniquely provided that
 * anything still calls.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const indexHtml = readFileSync(
  fileURLToPath(new URL('../../frontend/index.html', import.meta.url)), 'utf8'
);

function occurrences(haystack, needle) {
  let count = 0, idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) { count++; idx += needle.length; }
  return count;
}

describe('openMSSPApplication / openEnterpriseBooking are each defined exactly once now', () => {
  it('window.openMSSPApplication is assigned exactly once', () => {
    expect(occurrences(indexHtml, 'window.openMSSPApplication = function')).toBe(1);
  });

  it('window.openEnterpriseBooking is assigned exactly once', () => {
    expect(occurrences(indexHtml, 'window.openEnterpriseBooking = function')).toBe(1);
  });

  it('the surviving openMSSPApplication opens the real application modal, not a manual-payment shortcut', () => {
    const idx = indexHtml.indexOf('window.openMSSPApplication = function');
    const block = indexHtml.slice(idx, idx + 200);
    expect(block).toContain("document.getElementById('mssp-modal').style.display = 'flex';");
    expect(block).not.toContain('openManualPayment');
  });

  it('the surviving openEnterpriseBooking opens the real booking modal with per-package pricing, not a flat manual-payment redirect', () => {
    const idx = indexHtml.indexOf('window.openEnterpriseBooking = function');
    const block = indexHtml.slice(idx, idx + 1000);
    expect(block).toContain("document.getElementById('enterprise-booking-modal').style.display = 'flex';");
    expect(block).not.toContain('openManualPayment');
  });

  it('submitMSSPApplication still does a real POST to /api/global/mssp/apply with company/email capture', () => {
    expect(indexHtml).toContain('window.submitMSSPApplication = async function()');
    const idx = indexHtml.indexOf('window.submitMSSPApplication = async function()');
    const block = indexHtml.slice(idx, idx + 1200);
    expect(block).toContain("fetch('/api/global/mssp/apply'");
    expect(block).toContain('company_name: company, email');
  });

  it('that route really exists server-side (regression guard, not just a frontend assumption)', () => {
    const workerSrc = readFileSync(
      fileURLToPath(new URL('../src/index.js', import.meta.url)), 'utf8'
    );
    expect(workerSrc).toContain("path === '/api/global/mssp/apply' && method === 'POST'");
  });

  it('startSubscription (a genuinely separate flow) is untouched and still uses openManualPayment for its own non-self-serve fallback', () => {
    expect(indexHtml).toContain('window.startSubscription = function(plan)');
    const idx = indexHtml.indexOf('window.startSubscription = function(plan)');
    const block = indexHtml.slice(idx, idx + 1200);
    expect(block).toContain('window.openManualPayment(p.id, p.inr, p.label);');
  });

  it('all 3 real call sites in the file are satisfied by the surviving definitions (no argument shape the removed ones uniquely handled)', () => {
    expect(occurrences(indexHtml, 'onclick="openMSSPApplication()"')).toBe(2);
    expect(occurrences(indexHtml, "onclick=\"openEnterpriseBooking('annual_retainer')\"")).toBe(1);
  });
});
