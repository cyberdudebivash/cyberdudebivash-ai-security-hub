/* Regression tests — Fix #5: STARTER monthly metering.
 * Guards: correct arg order (env, identity), real overage gate, and fail-open
 * so a metering-table error never 500s a paying customer's scan. */
import { describe, it, expect } from 'vitest';
import { checkMonthlyQuota } from '../src/handlers/subscription.js';

// Minimal D1 mock: returns a fixed SUM(request_count) row, or throws on demand.
function mockEnv(total, { throwOnQuery = false } = {}) {
  return {
    DB: {
      prepare() {
        return {
          bind() {
            return {
              async first() {
                if (throwOnQuery) throw new Error('no such table: api_key_usage');
                return { total };
              },
            };
          },
        };
      },
    },
  };
}

describe('checkMonthlyQuota — STARTER metering gate', () => {
  it('blocks STARTER once monthly usage reaches the limit (600)', async () => {
    const r = await checkMonthlyQuota(mockEnv(600), { plan: 'STARTER', userId: 'u1' });
    expect(r.allowed).toBe(false);
    expect(r.scans_limit).toBe(600);
  });

  it('allows STARTER while under the limit', async () => {
    const r = await checkMonthlyQuota(mockEnv(3), { plan: 'STARTER', userId: 'u1' });
    expect(r.allowed).toBe(true);
    expect(r.scans_used).toBe(3);
    expect(r.scans_remaining).toBe(597);
  });

  it('meters by key_id when an API key identity is supplied', async () => {
    const r = await checkMonthlyQuota(mockEnv(600), { plan: 'STARTER', keyId: 'k1' });
    expect(r.allowed).toBe(false);
  });

  it('PRO is unlimited (scan_limit -1) — never blocked', async () => {
    const r = await checkMonthlyQuota(mockEnv(99999), { plan: 'PRO', userId: 'u1' });
    expect(r.allowed).toBe(true);
    expect(r.scans_limit).toBe(-1);
  });

  it('fails OPEN when the metering query throws — never 500 a scan', async () => {
    const r = await checkMonthlyQuota(mockEnv(10, { throwOnQuery: true }), { plan: 'STARTER', userId: 'u1' });
    expect(r.allowed).toBe(true);
  });

  it('fails OPEN when no DB binding is present', async () => {
    const r = await checkMonthlyQuota({}, { plan: 'STARTER', userId: 'u1' });
    expect(r.allowed).toBe(true);
  });

  it('allows when identity has neither keyId nor userId (cannot meter)', async () => {
    const r = await checkMonthlyQuota(mockEnv(10), { plan: 'STARTER' });
    expect(r.allowed).toBe(true);
  });
});
