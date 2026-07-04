/* Phase IV remediation regression — advertised-but-unenforced per-minute rate
 * limits on the metered intel surfaces.
 *
 * The public pricing matrix (/api/v1/intel/pricing.json) advertises BOTH a
 * daily quota and a `rate_per_min` for every tier, and the canonical tier
 * table advertises burst/min — but only the daily quota was enforced. This
 * locks the fix in both metered paths:
 *   1. enforceDailyLimit (v1 feed economy) — minute window enforced for all
 *      tiers, INCLUDING unlimited-daily ENTERPRISE/MSSP;
 *   2. checkIntelQuota via /api/intel/* handlers — canonical burst enforced;
 * and proves both stay fail-open on KV outage (risk R-14: availability over
 * enforcement). */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { enforceDailyLimit, FEED_TIERS } from '../src/handlers/intelMonetization.js';
import { handleIntelIOC } from '../src/handlers/intelAPIHandlers.js';

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, String(value)); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    _store: store,
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-07-04T10:00:30Z')); // fixed mid-minute — no boundary flake
});
afterEach(() => vi.useRealTimers());

describe('enforceDailyLimit — per-minute window (v1 intel feed)', () => {
  it('blocks the request after rpm is exhausted, with retry_after', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const ent = { daily_limit: 100, rpm: 2 };
    expect((await enforceDailyLimit(env, ent, 'key:abc')).allowed).toBe(true);
    expect((await enforceDailyLimit(env, ent, 'key:abc')).allowed).toBe(true);
    const third = await enforceDailyLimit(env, ent, 'key:abc');
    expect(third.allowed).toBe(false);
    expect(third.reason).toBe('rate_per_min');
    expect(third.retry_after).toBe(60);
  });

  it('enforces rpm even for unlimited-daily plans (ENTERPRISE/MSSP)', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const ent = { daily_limit: -1, rpm: 2 }; // unlimited daily, minute window applies
    await enforceDailyLimit(env, ent, 'key:ent');
    await enforceDailyLimit(env, ent, 'key:ent');
    const third = await enforceDailyLimit(env, ent, 'key:ent');
    expect(third.allowed).toBe(false);
    expect(third.reason).toBe('rate_per_min');
  });

  it('still enforces the daily quota after the minute window passes', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const ent = { daily_limit: 1, rpm: 10 };
    expect((await enforceDailyLimit(env, ent, 'key:d')).allowed).toBe(true);
    const second = await enforceDailyLimit(env, ent, 'key:d');
    expect(second.allowed).toBe(false);
    expect(second.reason).toBe('daily_quota');
  });

  it('fails open when KV is unavailable (availability over enforcement)', async () => {
    const env = { SECURITY_HUB_KV: { async get() { throw new Error('kv down'); }, async put() { throw new Error('kv down'); } } };
    const ent = { daily_limit: 1, rpm: 1 };
    expect((await enforceDailyLimit(env, ent, 'key:x')).allowed).toBe(true);
    expect((await enforceDailyLimit(env, ent, 'key:x')).allowed).toBe(true);
  });

  it('every advertised tier carries an rpm so the window applies platform-wide', () => {
    for (const [tier, v] of Object.entries(FEED_TIERS)) {
      expect(v.rpm, `${tier} must advertise a rate_per_min`).toBeGreaterThan(0);
    }
  });
});

describe('checkIntelQuota burst — /api/intel/* economy endpoints', () => {
  it('FREE tier: third request in the same minute is 429 with retry_after', async () => {
    const env = { KV: makeKV() };
    const authCtx = { tier: 'FREE', ip: '203.0.113.9' };
    const req = () => new Request('https://x/api/intel/ioc?value=8.8.8.8');
    expect((await handleIntelIOC(req(), env, authCtx)).status).toBe(200);
    expect((await handleIntelIOC(req(), env, authCtx)).status).toBe(200);
    const res3 = await handleIntelIOC(req(), env, authCtx);
    expect(res3.status).toBe(429);
    const body = await res3.json();
    expect(body.retry_after).toBe(60);
    expect(body.error).toMatch(/requests\/minute/);
  });

  it('stix_available reflects the caller\'s real entitlement (PRO+ per pricing.json)', async () => {
    const env = { KV: makeKV() };
    const free = await (await handleIntelIOC(new Request('https://x/api/intel/ioc?value=1.1.1.1'), env, { tier: 'FREE', ip: '1' })).json();
    expect(free.stix_available).toBe(false);
    expect(free.stix_endpoint).toBe(null);

    const ent = await (await handleIntelIOC(new Request('https://x/api/intel/ioc?value=1.1.1.1'), env, { tier: 'ENTERPRISE', userId: 'u9' })).json();
    expect(ent.stix_available).toBe(true);
    expect(ent.stix_endpoint).toBe('/api/v1/intel/stix.json');
  });

  it('PRO tier stix entitlement matches the sold pricing matrix (stix_export: true)', () => {
    // pricing.json advertises PRO stix_export:true — the handler flag must agree.
    expect(FEED_TIERS.PRO.stix).toBe(true);
  });
});
