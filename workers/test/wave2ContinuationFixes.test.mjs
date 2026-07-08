/* Regression tests for the Wave 2 continuation audit (2026-07-08):
 *
 * (handleEnterpriseStats's dual-shape fix has its own dedicated,
 * historically-annotated test file: enterpriseStatsAdminGate.test.mjs.)
 *
 * 1. enterpriseSsoHandler.js's handleEnterpriseSSoConfigure checked a
 *    property `authCtx.isOwner` that is never set anywhere in the auth layer
 *    (the real mechanism is the isOwner(authCtx, env) function). Only the
 *    hardcoded fallback email ever actually worked. Added the real isOwner()
 *    check additively.
 *
 * 2. eop/health.js's handleHealthDetailed checked `authCtx.admin` (no "is"
 *    prefix), which is never set — the real field is `authCtx.isAdmin`.
 *    Fixed for correctness (was masked in practice by the tier==='ENTERPRISE'
 *    condition already covering every real admin path).
 *
 * 3. siemDeploy.js — requireAdmin() was dead code (defined, never called by
 *    any of its 5 exported handlers), and index.js's /api/integrations/*
 *    routes had no admin/owner gate either. Any unauthenticated request could
 *    overwrite SIEM webhook config, trigger outbound deploys (SSRF-capable),
 *    or delete a configured integration. Fixed by requiring authCtx.isAdmin
 *    and wiring the check into every state-changing handler.
 */
import { describe, it, expect, vi } from 'vitest';
import { handleEnterpriseSSoConfigure } from '../src/handlers/enterpriseSsoHandler.js';
import { handleHealthDetailed } from '../src/handlers/eop/health.js';
import { handleConfigure, handleDeploy, handleTestIntegration, handleDeleteIntegration, handleListIntegrations } from '../src/handlers/siemDeploy.js';

describe('enterpriseSsoHandler.js — handleEnterpriseSSoConfigure owner gate', () => {
  function req(body) {
    return new Request('https://x', { method: 'POST', body: JSON.stringify(body ?? {}) });
  }

  it('a non-owner is rejected with 403', async () => {
    const res = await handleEnterpriseSSoConfigure(req({}), {}, { email: 'attacker@evil.com' });
    expect(res.status).toBe(403);
  });

  it('a real admin (isOwner() via isAdmin) passes the owner gate (fails later at body validation, not 403)', async () => {
    const res = await handleEnterpriseSSoConfigure(req({}), {}, { isAdmin: true, email: 'admin@x.com' });
    expect(res.status).not.toBe(403);
    expect(res.status).toBe(400); // missing org_slug/idp_type/etc — proves the gate opened
  });

  it('the default owner email (isOwner() via OWNER_EMAILS) passes the owner gate', async () => {
    const res = await handleEnterpriseSSoConfigure(req({}), {}, { email: 'bivash@cyberdudebivash.com' });
    expect(res.status).toBe(400);
  });

  it('the legacy hardcoded fallback email still works (backward compatible)', async () => {
    const res = await handleEnterpriseSSoConfigure(req({}), {}, { email: 'iambivash.bn@gmail.com' });
    expect(res.status).toBe(400);
  });
});

describe('eop/health.js — handleHealthDetailed admin gate uses the real isAdmin field', () => {
  it('an unauthenticated/free caller is rejected', async () => {
    const res = await handleHealthDetailed(new Request('https://x'), {}, { authenticated: true, tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('authCtx.isAdmin (the real field) is admitted even off the ENTERPRISE tier', async () => {
    const res = await handleHealthDetailed(new Request('https://x'), {}, { authenticated: true, tier: 'FREE', isAdmin: true });
    expect(res.status).toBe(200);
  });

  it('a real ENTERPRISE subscriber is admitted', async () => {
    const res = await handleHealthDetailed(new Request('https://x'), {}, { authenticated: true, tier: 'ENTERPRISE' });
    expect(res.status).toBe(200);
  });
});

describe('siemDeploy.js — SIEM integration management now actually requires authCtx.isAdmin', () => {
  it('handleConfigure: unauthenticated/anonymous request is rejected, not silently accepted', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ platform: 'splunk', webhook_url: 'https://evil.example/hec' }) });
    const res = await handleConfigure(req, {}, {});
    expect(res.status).toBe(403);
  });

  it('handleConfigure: a real admin can still configure an integration', async () => {
    const env = { SECURITY_HUB_KV: { put: vi.fn(async () => {}), get: vi.fn(async () => null) } };
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ platform: 'splunk', webhook_url: 'https://splunk.acme.com:8088/services/collector' }) });
    const res = await handleConfigure(req, env, { isAdmin: true, email: 'admin@x.com' });
    expect(res.status).toBe(200);
    expect(env.SECURITY_HUB_KV.put).toHaveBeenCalled();
  });

  it('handleDeploy: anonymous request cannot trigger an outbound deploy (SSRF vector closed)', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ platform: 'splunk', rule: { raw: 'x' } }) });
    const res = await handleDeploy(req, {}, {});
    expect(res.status).toBe(403);
  });

  it('handleTestIntegration: anonymous request cannot trigger an outbound test call', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ platform: 'splunk' }) });
    const res = await handleTestIntegration(req, {}, {});
    expect(res.status).toBe(403);
  });

  it('handleDeleteIntegration: anonymous request cannot delete a configured integration', async () => {
    const req = new Request('https://x/api/integrations/splunk', { method: 'DELETE' });
    const res = await handleDeleteIntegration(req, { SECURITY_HUB_KV: { delete: vi.fn() } }, {});
    expect(res.status).toBe(403);
  });

  it('handleListIntegrations (read-only, no secrets in response) remains public — unchanged behavior', async () => {
    const env = { SECURITY_HUB_KV: { get: vi.fn(async () => null) } };
    const res  = await handleListIntegrations(new Request('https://x'), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.integrations.length).toBeGreaterThan(0);
    expect(JSON.stringify(body)).not.toMatch(/webhook_url|auth_token|hec_token|api_key|integration_key/);
  });
});
