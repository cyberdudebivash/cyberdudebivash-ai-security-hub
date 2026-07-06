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
});
