/* 2026-07-10: the homepage's "🏢 Enterprise & MSSP Solutions" section had two
 * separate problems, found while investigating why it "still shows the
 * manual payment system":
 *
 * 1. A real correctness bug, not a manual-vs-automated design choice: the
 *    card visibly labeled "Security Assessment ₹9,999" had its button wired
 *    to openEnterpriseBooking('starter_enterprise') — a *different* package
 *    (STARTER_PLUS_ANNUAL, ₹49,900/year). A customer who paid what the card
 *    showed would have been charged for the wrong product at ~5x the price.
 *    (Likely a copy-paste artifact from an earlier card layout.)
 *
 * 2. Both this card and the "Threat Intel Report" card only ever opened the
 *    old manual-only MPM modal (openManualPayment) — no Razorpay option at
 *    all, always human-verified. checkout-modal.js's CDB_CHECKOUT_MODAL
 *    already has a complete, previously-audited (2026-06-29, 2026-07-06)
 *    multi-rail flow — including a real Razorpay tab that goes through the
 *    canonical create-order → Razorpay → verify path — and was already
 *    loaded on this page but not used by these two buttons.
 *
 * FIX: both buttons now open CDB_CHECKOUT_MODAL with the correct
 * product_id, matching PACKAGE_PRICES (workers/src/lib/razorpay.js). Threat
 * Intel Report needed a new PACKAGE_PRICES entry (price already existed in
 * config/pricingConfig.js's display-only table, just never wired into the
 * table that actually determines what gets charged). MSSP White-Label and
 * Annual Retainer deliberately stay manual/sales-assisted — see PR
 * description for reasoning — this file does not change or test those. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PACKAGE_PRICES } from '../src/lib/razorpay.js';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

function enterpriseSectionHTML() {
  const start = fe.indexOf('ENTERPRISE &amp; MSSP SOLUTIONS');
  expect(start).toBeGreaterThan(-1);
  return fe.slice(start, start + 9000);
}

describe('Enterprise/MSSP Solutions — Security Assessment & Threat Intel Report checkout', () => {
  it('PACKAGE_PRICES has both SKUs at the price shown on the card', () => {
    expect(PACKAGE_PRICES.SECURITY_ASSESSMENT.amount).toBe(999900); // ₹9,999
    expect(PACKAGE_PRICES.THREAT_INTEL_REPORT).toBeDefined();
    expect(PACKAGE_PRICES.THREAT_INTEL_REPORT.amount).toBe(1499900); // ₹14,999
  });

  it('the Security Assessment card no longer points at the wrong package (starter_enterprise / ₹49,900)', () => {
    const section = enterpriseSectionHTML();
    expect(section).not.toContain("openEnterpriseBooking('starter_enterprise')");
  });

  it('the Security Assessment card opens CDB_CHECKOUT_MODAL with productId SECURITY_ASSESSMENT', () => {
    const section = enterpriseSectionHTML();
    const idx = section.indexOf('Security Assessment</div>');
    expect(idx).toBeGreaterThan(-1);
    const cardHtml = section.slice(idx, idx + 1200);
    expect(cardHtml).toContain('CDB_CHECKOUT_MODAL.open(');
    expect(cardHtml).toContain("module:'package'");
    expect(cardHtml).toContain("productId:'SECURITY_ASSESSMENT'");
  });

  it('the Threat Intel Report card opens CDB_CHECKOUT_MODAL with productId THREAT_INTEL_REPORT', () => {
    const section = enterpriseSectionHTML();
    const idx = section.indexOf('Threat Intel Report</div>');
    expect(idx).toBeGreaterThan(-1);
    const cardHtml = section.slice(idx, idx + 1200);
    expect(cardHtml).toContain('CDB_CHECKOUT_MODAL.open(');
    expect(cardHtml).toContain("module:'package'");
    expect(cardHtml).toContain("productId:'THREAT_INTEL_REPORT'");
  });

  it('MSSP White-Label and Annual Retainer are untouched (deliberately still manual/sales-assisted)', () => {
    const section = enterpriseSectionHTML();
    expect(section).toContain('openMSSPApplication()');
    expect(section).toContain("openEnterpriseBooking('annual_retainer')");
  });
});
