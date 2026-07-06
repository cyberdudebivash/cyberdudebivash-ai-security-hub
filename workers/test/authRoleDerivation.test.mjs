/* Regression test — authCtx.role was never populated anywhere in the entire
 * auth layer (no JWT claim, no DB column), yet dozens of handlers across the
 * codebase (msspTenantPlatform.js, socCases.js, platformMetricsAuthority.js,
 * revenueMetrics.js, globalSearch.js, notificationPlatform.js,
 * workflowAutomation.js, productAnalytics.js, whiteLabelMSSP.js,
 * reliabilityEngineering.js, customerSuccess.js, and a dozen handlers
 * index.js forwards `role: authCtx.role` into) gate on
 * `authCtx.role === 'admin'` / `'mssp_admin'` / `.includes(role)`. Every one
 * of those checks was permanently false for every caller, including real
 * admins — not a per-file bug, a missing field at the resolver. Fixed once,
 * centrally, in withAuthAliases() so every resolveAuthV5() caller (JWT,
 * API key, admin key, IP fallback) gets a real value.
 * (2026-07-06 revenue-mechanisms audit, P1-4.) */
import { describe, it, expect } from 'vitest';
import { resolveAuthV5 } from '../src/auth/middleware.js';

function makeReq(headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { headers: { get(k) { return lower[k.toLowerCase()] ?? null; } } };
}

describe('resolveAuthV5 populates a real authCtx.role', () => {
  it('the ADMIN_KEY bypass gets role: "admin"', async () => {
    const env = { ADMIN_KEY: 'secret123' };
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'secret123' }), env);
    expect(auth.isAdmin).toBe(true);
    expect(auth.role).toBe('admin');
  });

  it('a real MSSP-tier API key gets role: "mssp_admin"', async () => {
    const env = {
      DB: {
        prepare() {
          return {
            bind() { return this; },
            async first() {
              return {
                id: 'k1', user_id: 'u1', key_prefix: 'cdb_abc...', email: 'buyer@x.com',
                tier: 'MSSP', user_tier: 'MSSP', user_status: 'active', active: 1,
              };
            },
          };
        },
      },
    };
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'cdb_msspKeyTest' }), env);
    expect(auth.tier).toBe('MSSP');
    expect(auth.role).toBe('mssp_admin');
  });

  it('a regular paying tier (PRO) gets no synthetic role — tier-based checks still apply', async () => {
    const env = {
      DB: {
        prepare() {
          return {
            bind() { return this; },
            async first() {
              return {
                id: 'k2', user_id: 'u2', key_prefix: 'cdb_def...', email: 'buyer2@x.com',
                tier: 'PRO', user_tier: 'PRO', user_status: 'active', active: 1,
              };
            },
          };
        },
      },
    };
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'cdb_proKeyTest' }), env);
    expect(auth.tier).toBe('PRO');
    expect(auth.role).toBeUndefined();
  });

  it('the anonymous IP-fallback principal gets no role', async () => {
    const auth = await resolveAuthV5(makeReq({ 'CF-Connecting-IP': '1.2.3.4' }), {});
    expect(auth.method).toBe('ip_fallback');
    expect(auth.role).toBeUndefined();
  });
});
