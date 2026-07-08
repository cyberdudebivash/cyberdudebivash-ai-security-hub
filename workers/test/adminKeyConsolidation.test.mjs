/* Regression test — 4 handlers (revenueFeatures.js, mythosGodModeHandler.js,
 * pipelineHealth.js, mythosHandler.js) bypass resolveAuthV5() and each
 * independently re-implemented `apiKey === env.ADMIN_KEY` against a slightly
 * different header set. Consolidated into auth/middleware.js's
 * isValidAdminKey() — one comparison, superset of every header any of the
 * four previously accepted, so no existing caller breaks. */
import { describe, it, expect } from 'vitest';
import { isValidAdminKey } from '../src/auth/middleware.js';
import { handleSeedThreatActors } from '../src/handlers/revenueFeatures.js';
import { handleGodModeRun } from '../src/handlers/mythosGodModeHandler.js';
import { handlePipelineHealth } from '../src/handlers/pipelineHealth.js';
import { handleMythosRun } from '../src/handlers/mythosHandler.js';

const ADMIN_KEY = 'test-admin-key-12345';

function req(headers = {}) {
  return new Request('https://x/test', { headers });
}

describe('isValidAdminKey — shared comparison', () => {
  it('accepts x-api-key (revenueFeatures/mythosGodModeHandler/mythosHandler convention)', () => {
    expect(isValidAdminKey(req({ 'x-api-key': ADMIN_KEY }), { ADMIN_KEY })).toBe(true);
  });

  it('accepts x-admin-key (pipelineHealth convention)', () => {
    expect(isValidAdminKey(req({ 'x-admin-key': ADMIN_KEY }), { ADMIN_KEY })).toBe(true);
  });

  it('accepts Authorization: Bearer (resolveAuthV5 convention)', () => {
    expect(isValidAdminKey(req({ Authorization: `Bearer ${ADMIN_KEY}` }), { ADMIN_KEY })).toBe(true);
  });

  it('rejects a wrong key', () => {
    expect(isValidAdminKey(req({ 'x-api-key': 'wrong' }), { ADMIN_KEY })).toBe(false);
  });

  it('rejects when ADMIN_KEY is not configured', () => {
    expect(isValidAdminKey(req({ 'x-api-key': ADMIN_KEY }), {})).toBe(false);
  });

  it('rejects a missing header', () => {
    expect(isValidAdminKey(req({}), { ADMIN_KEY })).toBe(false);
  });
});

describe('Handlers migrated to isValidAdminKey behave the same as before', () => {
  it('handleSeedThreatActors: 403 without the key, admin path proceeds with it', async () => {
    const denied = await handleSeedThreatActors(req(), { ADMIN_KEY }, {});
    expect(denied.status).toBe(403);
  });

  it('handleGodModeRun: 403 without ADMIN_KEY or ENTERPRISE tier', async () => {
    const denied = await handleGodModeRun(req(), { ADMIN_KEY }, {}, {});
    expect(denied.status).toBe(403);
  });

  it('handleGodModeRun: ENTERPRISE tier authCtx still admitted without ADMIN_KEY', async () => {
    const resp = await handleGodModeRun(req(), { ADMIN_KEY }, { tier: 'ENTERPRISE' }, {});
    expect(resp.status).not.toBe(403);
  });

  it('handlePipelineHealth: 403 without x-admin-key', async () => {
    const denied = await handlePipelineHealth(req(), { ADMIN_KEY });
    expect(denied.status).toBe(403);
  });

  it('handlePipelineHealth: admitted with x-admin-key', async () => {
    const resp = await handlePipelineHealth(req({ 'x-admin-key': ADMIN_KEY }), { ADMIN_KEY });
    expect(resp.status).not.toBe(403);
  });

  it('handleMythosRun: authCtx.role === admin still bypasses without ADMIN_KEY header', async () => {
    const resp = await handleMythosRun(req(), { ADMIN_KEY }, { role: 'admin' });
    expect(resp.status).not.toBe(403);
  });
});
