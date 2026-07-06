/* handleEnterpriseStats gated on authCtx.role !== 'admin' — a field never
 * populated anywhere in the auth layer, so this admin dashboard was a
 * permanent 403 for everyone, including the real admin. isAdmin (the
 * ADMIN_KEY bypass) is the platform's actual owner-bypass signal.
 * (2026-07-06 revenue-mechanisms audit, P1-4.) */
import { describe, it, expect } from 'vitest';
import { handleEnterpriseStats } from '../src/handlers/enterpriseLayer.js';

function makeEnv() {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return {}; },
          async all() { return { results: [] }; },
        };
      },
    },
  };
}

describe('GET /api/enterprise/stats — admin gate', () => {
  it('rejects a non-admin caller', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { tier: 'ENTERPRISE' });
    expect(res.status).toBe(403);
  });

  it('rejects a caller with a stray role field (never populated in production, but must not accidentally grant access)', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { role: 'admin', isAdmin: false });
    expect(res.status).toBe(403);
  });

  it('allows the real admin (isAdmin bypass)', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { isAdmin: true });
    expect(res.status).not.toBe(403);
  });
});
