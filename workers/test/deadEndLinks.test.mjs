/* Regression tests — six confirmed-live-404 "next step" URLs returned by
 * onboarding/checkout success responses and error hints across the platform
 * (2026-07-06 revenue-mechanisms audit, P2-7). Each was verified live against
 * production (cyberdudebivash.in) before fixing. Pure static parse. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(resolve(__dirname, p), 'utf8');

const MSSP_ONBOARDING   = read('../src/handlers/msspOnboardingHandler.js');
const AFFILIATE_SYSTEM  = read('../src/handlers/affiliateSystem.js');
const PROPOSAL_GEN      = read('../src/handlers/proposalGenerator.js');
const ENTERPRISE_ONBOARD = read('../src/handlers/enterpriseOnboarding.js');
const AUTH_HANDLER      = read('../src/handlers/auth.js');
const ONBOARDING        = read('../src/handlers/onboarding.js');
const REPORT_HANDLER    = read('../src/handlers/report.js');
const AUTH_MIDDLEWARE   = read('../src/auth/middleware.js');
const MW_AUTH           = read('../src/middleware/auth.js');
const MSSP_ONBOARDING_PAGE = read('../../frontend/mssp-onboarding.html');
const CISO_HUB           = read('../../frontend/ciso-hub.html');
const DECISION_DASHBOARD = read('../../frontend/decision-dashboard.html');
const SITEMAP_PAGE       = read('../../frontend/sitemap.html');
const USER_DASHBOARD     = read('../../frontend/user-dashboard.html');
const INDEX_HTML         = read('../../frontend/index.html');

describe('dead-end links removed from onboarding/checkout responses', () => {
  it('MSSP onboarding no longer promises a /mssp-dashboard.html that does not exist', () => {
    expect(MSSP_ONBOARDING).not.toContain("'/mssp-dashboard.html'");
    expect(MSSP_ONBOARDING).toContain("dashboard_url: null");
  });

  it('affiliate join points at the real #affiliate-hub section, not the dead /affiliate-hub page', () => {
    expect(AFFILIATE_SYSTEM).not.toContain("'https://cyberdudebivash.in/affiliate-hub'");
    expect(AFFILIATE_SYSTEM).toContain('https://cyberdudebivash.in/#affiliate-hub');
  });

  it('proposal documents no longer claim an online /proposal/accept flow that was never built', () => {
    expect(PROPOSAL_GEN).not.toMatch(/accept_url:/);
    expect(PROPOSAL_GEN).toContain('contact_url');
  });

  it('enterprise capability listing no longer links a nonexistent enterprise-onboarding.html', () => {
    expect(ENTERPRISE_ONBOARD).not.toContain('enterprise-onboarding.html');
  });

  it('signup welcome email no longer links a nonexistent enterprise-onboarding.html', () => {
    expect(AUTH_HANDLER).not.toContain('enterprise-onboarding.html');
  });

  it('onboarding dashboard_url points at the real cyberdudebivash.in domain, not the intel subdomain (which has no /user-dashboard.html)', () => {
    expect(ONBOARDING).not.toContain('intel.cyberdudebivash.com/user-dashboard.html');
    expect(ONBOARDING).toContain('https://cyberdudebivash.in/user-dashboard');
  });

  it('report-not-found hint points at the real /api-docs page, not the dead /docs', () => {
    expect(REPORT_HANDLER).not.toMatch(/docs:\s*'https:\/\/cyberdudebivash\.in\/docs'/);
  });

  it('the two 401 responses fired on every unauthenticated request point at the real /api-docs page', () => {
    expect(AUTH_MIDDLEWARE).not.toMatch(/docs:\s*'https:\/\/cyberdudebivash\.in\/docs'/);
    expect(MW_AUTH).not.toMatch(/docs:\s*'https:\/\/cyberdudebivash\.in\/docs'/);
    expect(AUTH_MIDDLEWARE).toContain('https://cyberdudebivash.in/api-docs');
    expect(MW_AUTH).toContain('https://cyberdudebivash.in/api-docs');
  });

  it('MSSP onboarding "Go to MSSP Dashboard" buttons (post-payment and post-trial) point at the real partner self-service portal, not the staff-only command center', () => {
    // frontend/mssp-command-center.html is gated by CDB_STAFF_AUTH.guard(),
    // which only accepts the platform-owner email or an internal user_roles
    // row (see workers/src/handlers/staffAuth.js) — a brand-new external
    // MSSP partner can never pass it. Commit 67f6b924 fixed this exact
    // pattern in the onboarding welcome email; this page's own post-checkout
    // and post-trial buttons pointed at the same dead end and were missed.
    expect(MSSP_ONBOARDING_PAGE).not.toContain('/mssp-command-center.html');
    expect(MSSP_ONBOARDING_PAGE.match(/href="\/partner-portal\.html"/g) || []).toHaveLength(2);
  });

  it('ciso-hub\'s Enterprise Checkout fallback no longer points at upgrade.html#enterprise (upgrade.html has no such anchor) — matches openPayment()\'s own fallback in the same file', () => {
    expect(CISO_HUB).not.toContain("'/upgrade.html#enterprise'");
    const idx = CISO_HUB.indexOf('function openEnterprise()');
    expect(idx).toBeGreaterThan(-1);
    expect(CISO_HUB.slice(idx, idx + 450)).toContain("window.location.href = '/upgrade.html';");
  });

  it('decision-dashboard\'s upgrade link points at cyberdudebivash.in, not the unrelated tools.cyberdudebivash.com subdomain (every other reference in this file uses cyberdudebivash.in)', () => {
    expect(DECISION_DASHBOARD).not.toContain('tools.cyberdudebivash.com');
    expect(DECISION_DASHBOARD).toContain('https://cyberdudebivash.in/#pricing');
  });

  it('sitemap\'s Affiliate Program link points at the real #affiliate-hub section, not the dead /affiliate-hub page (same bug class already fixed in affiliateSystem.js above, missed here)', () => {
    expect(SITEMAP_PAGE).not.toContain('href="/affiliate-hub"');
    expect(SITEMAP_PAGE).toContain('href="/#affiliate-hub"');
  });

  it('user-dashboard\'s empty API-keys state has a working "create your first key" CTA, matching the pattern its sibling empty states (scans, etc.) already use', () => {
    const idx = USER_DASHBOARD.indexOf('No API keys yet.');
    expect(idx).toBeGreaterThan(-1);
    const snippet = USER_DASHBOARD.slice(idx, idx + 120);
    expect(snippet).toContain('onclick="openCreateKeyModal();return false;"');
    // openCreateKeyModal must be a real, already-wired function (the page's
    // header "+" button uses it too), not a new dead reference.
    expect(USER_DASHBOARD).toContain('function openCreateKeyModal()');
  });

  it('homepage hero "Defense Marketplace" button points at the real #defense-solutions section, not the nonexistent #defense-marketplace anchor (2026-07-16 homepage audit)', () => {
    expect(INDEX_HTML).not.toContain('href="#defense-marketplace"');
    expect(INDEX_HTML).toContain('id="defense-solutions"');
    const idx = INDEX_HTML.indexOf('🛡️ Defense Marketplace');
    expect(idx).toBeGreaterThan(-1);
    expect(INDEX_HTML.slice(idx - 250, idx)).toContain('href="#defense-solutions"');
  });

  it('homepage notification bell\'s "View SOC Dashboard" link navigates to the real #autonomous-soc section, not the nonexistent #soc-command id (2026-07-16 homepage audit)', () => {
    expect(INDEX_HTML).not.toContain("cdbNavigate('soc-command')");
    expect(INDEX_HTML).toContain('id="autonomous-soc"');
    expect(INDEX_HTML).toContain("cdbNavigate('autonomous-soc');CDB_NOTIF.close();return false");
  });

  it('homepage FAQ structured data states the real Enterprise plan price (₹4,999/mo), not the MSSP tier\'s ₹9,999/mo (2026-07-16 homepage audit)', () => {
    const idx = INDEX_HTML.indexOf('How much does a security scan cost?');
    expect(idx).toBeGreaterThan(-1);
    const snippet = INDEX_HTML.slice(idx, idx + 400);
    expect(snippet).toContain('₹4,999/month for enterprise plans');
    expect(snippet).not.toContain('₹9,999/month for enterprise plans');
  });

  it('homepage UPI QR image fallbacks point at a real file (/public/upi-qr.png), not the nonexistent /public/assets/payment/upi-qr.png (2026-07-16 homepage audit)', () => {
    expect(INDEX_HTML).not.toContain('/public/assets/payment/upi-qr.png');
    expect((INDEX_HTML.match(/\/public\/upi-qr\.png/g) || []).length).toBeGreaterThanOrEqual(3);
  });
});
