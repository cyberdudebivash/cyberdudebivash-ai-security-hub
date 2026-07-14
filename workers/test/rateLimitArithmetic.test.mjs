// CAP-PROD-002 — Rate Limiting & Structured Request-ID Correlation. The
// registry's own notes named the concrete gap precisely: every existing
// reference to workers/src/middleware/rateLimit.js in the test suite mocks
// checkRateLimitV2 away (always returns {allowed:true}) rather than
// exercising the real tier-based daily/burst/cost arithmetic and KV counter
// behavior. This file calls the real, unmocked functions against a real
// in-memory KV so a regression in the actual limit math would be caught.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  checkRateLimitV2, checkRateLimitCost, rateLimitResponse, injectRateLimitHeaders, ENDPOINT_COST,
} from '../src/middleware/rateLimit.js';
import { TIERS } from '../src/middleware/auth.js';
import { TIER_LIMITS } from '../src/auth/apiKeys.js';

// Real in-memory KV — persists across calls within a test, exactly like the
// real Cloudflare KV binding the production code targets, so the daily/burst
// counters genuinely accumulate rather than being stubbed to a fixed value.
function fakeKV() {
  const store = new Map();
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

function env() { return { SECURITY_HUB_KV: fakeKV() }; }

describe('CAP-PROD-002 — checkRateLimitV2 real tier arithmetic (not mocked)', () => {
  it('FREE tier burst_per_min=2: first 2 calls to the same endpoint succeed, the 3rd is burst_exceeded', async () => {
    const e = env();
    const ctx = { identity: 'user1', tier: 'FREE' };
    const r1 = await checkRateLimitV2(e, ctx, 'scan/domain');
    const r2 = await checkRateLimitV2(e, ctx, 'scan/domain');
    const r3 = await checkRateLimitV2(e, ctx, 'scan/domain');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);
    expect(r3.reason).toBe('burst_exceeded');
  });

  // The daily counter key is per-(identity, endpoint) — rl:day:${id}:${ep}:${day}
  // — not a single global counter, and burst_per_min=2 means the SAME endpoint
  // can only be hit twice within any real 60-second window. To reach the 6th
  // call on the SAME endpoint without tripping burst first, fake-advance the
  // clock by over a minute between each call (staying inside the same UTC day
  // so the daily key doesn't roll over).
  it('FREE tier daily_limit=5: 6th call on the SAME endpoint (spread across minutes to avoid burst) hits daily_limit_reached', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-07-12T00:00:00.000Z'));
      const e = env();
      const ctx = { identity: 'user2', tier: 'FREE' };
      const results = [];
      for (let i = 0; i < 6; i++) {
        results.push(await checkRateLimitV2(e, ctx, 'scan/domain'));
        vi.advanceTimersByTime(61_000); // past the 1-minute burst window
      }
      expect(results.slice(0, 5).every(r => r.allowed)).toBe(true);
      expect(results[5].allowed).toBe(false);
      expect(results[5].reason).toBe('daily_limit_reached');
    } finally {
      vi.useRealTimers();
    }
  });

  it('remaining count decrements correctly across real calls to the same endpoint', async () => {
    const e = env();
    const ctx = { identity: 'user3', tier: 'FREE' };
    const r1 = await checkRateLimitV2(e, ctx, 'scan/domain');
    const r2 = await checkRateLimitV2(e, ctx, 'scan/domain');
    expect(r1.remaining).toBe(4);
    expect(r2.remaining).toBe(3);
  });

  it('remaining count is tracked independently per endpoint, not shared globally', async () => {
    const e = env();
    const ctx = { identity: 'user3b', tier: 'FREE' };
    const r1 = await checkRateLimitV2(e, ctx, 'ep1');
    const r2 = await checkRateLimitV2(e, ctx, 'ep2');
    expect(r1.remaining).toBe(4);
    expect(r2.remaining).toBe(4); // ep2's own counter, independent of ep1's
  });

  it('ENTERPRISE tier (daily_limit -1) is genuinely unlimited across many real calls', async () => {
    const e = env();
    const ctx = { identity: 'user4', tier: 'ENTERPRISE' };
    for (let i = 0; i < 10; i++) {
      const r = await checkRateLimitV2(e, ctx, 'scan/domain');
      expect(r.allowed).toBe(true);
      expect(r.remaining).toBe(9999);
    }
  });

  it('a banned identity is denied immediately regardless of counters', async () => {
    const e = env();
    await e.SECURITY_HUB_KV.put('abuse:user5', 'banned');
    const r = await checkRateLimitV2(e, { identity: 'user5', tier: 'PRO' }, 'scan/domain');
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('banned');
  });

  it('fails open (allowed:true) when the KV binding is unavailable', async () => {
    const r = await checkRateLimitV2({}, { identity: 'user6', tier: 'FREE' }, 'scan/domain');
    expect(r.allowed).toBe(true);
  });

  it('unknown tier falls back to FREE limits, not unlimited', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-07-12T00:00:00.000Z'));
      const e = env();
      const ctx = { identity: 'user7', tier: 'NOT_A_REAL_TIER' };
      const results = [];
      for (let i = 0; i < 6; i++) {
        results.push(await checkRateLimitV2(e, ctx, 'scan/domain'));
        vi.advanceTimersByTime(61_000);
      }
      expect(results[5].allowed).toBe(false);
      expect(results[5].tier).toBe('NOT_A_REAL_TIER');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('CAP-PROD-002 — checkRateLimitCost real cost-weighted arithmetic (not mocked)', () => {
  it('a cost-1 endpoint delegates straight to checkRateLimitV2 (no separate cost budget)', async () => {
    expect(ENDPOINT_COST['scan/domain']).toBe(1);
    const e = env();
    const r = await checkRateLimitCost(e, { identity: 'c1', tier: 'FREE' }, 'scan/domain');
    expect(r.allowed).toBe(true);
    expect(r.cost).toBeUndefined(); // delegated call returns the plain checkRateLimitV2 shape
  });

  it('FREE tier cost budget (dailyLimit*2=10): 2 calls at cost 5 succeed, the 3rd exceeds budget', async () => {
    expect(ENDPOINT_COST['scan/redteam']).toBe(5);
    const e = env();
    const ctx = { identity: 'c2', tier: 'FREE' };
    const r1 = await checkRateLimitCost(e, ctx, 'scan/redteam');
    const r2 = await checkRateLimitCost(e, ctx, 'scan/redteam');
    const r3 = await checkRateLimitCost(e, ctx, 'scan/redteam');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);
    expect(r3.reason).toBe('cost_budget_exceeded');
  });

  it('ENTERPRISE tier is unlimited for cost-weighted endpoints too', async () => {
    const e = env();
    const ctx = { identity: 'c3', tier: 'ENTERPRISE' };
    for (let i = 0; i < 5; i++) {
      const r = await checkRateLimitCost(e, ctx, 'scan/redteam');
      expect(r.allowed).toBe(true);
    }
  });
});

describe('CAP-PROD-002 — rateLimitResponse / injectRateLimitHeaders (real helpers)', () => {
  it('rateLimitResponse points to this platform\'s own real production domain, not an external one', async () => {
    const res = rateLimitResponse({ reason: 'daily_limit_reached', tier: 'FREE', remaining: 0, reset: 'tomorrow UTC midnight', retry_after: 86400 }, 'scan');
    expect(res.status).toBe(429);
    const body = await res.json();
    expect(body.upgrade_url).toBe('https://cyberdudebivash.in/#pricing');
    expect(body.upgrade_url).not.toContain('gumroad');
    expect(res.headers.get('Retry-After')).toBe('86400');
  });

  it('injectRateLimitHeaders sets real tier/remaining/reset headers on the response', () => {
    const base = new Response('ok', { status: 200 });
    const withHeaders = injectRateLimitHeaders(base, { tier: 'PRO', remaining: 42, reset: 'tomorrow UTC midnight' });
    expect(withHeaders.headers.get('X-RateLimit-Tier')).toBe('PRO');
    expect(withHeaders.headers.get('X-RateLimit-Remaining')).toBe('42');
  });
});

// Production Engineering Phase III — rate-limit authority consolidation.
// middleware/auth.js's TIERS previously hardcoded only FREE/PRO/ENTERPRISE.
// STARTER and MSSP were added to the authoritative TIER_LIMITS (auth/apiKeys.js)
// but never mirrored here, so every STARTER/MSSP customer authenticated via
// JWT or IP (not API key) was silently rate-limited at FREE's 5/day, 2/min
// burst on the core scan pipeline (index.js runSyncPipeline) and 5 intel
// handlers. TIERS now derives its numbers from TIER_LIMITS instead of a
// second, independently maintained copy.
describe('CAP-PROD-002 — STARTER/MSSP tier arithmetic (entitlement-drift fix)', () => {
  it('STARTER burst_per_min=5: first 5 calls succeed, the 6th is burst_exceeded', async () => {
    const e = env();
    const ctx = { identity: 'starter1', tier: 'STARTER' };
    const results = [];
    for (let i = 0; i < 6; i++) results.push(await checkRateLimitV2(e, ctx, 'scan/domain'));
    expect(results.slice(0, 5).every(r => r.allowed)).toBe(true);
    expect(results[5].allowed).toBe(false);
    expect(results[5].reason).toBe('burst_exceeded');
  });

  it('STARTER daily_limit=20: the 21st call (spread across minutes) hits daily_limit_reached', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-07-12T00:00:00.000Z'));
      const e = env();
      const ctx = { identity: 'starter2', tier: 'STARTER' };
      const results = [];
      for (let i = 0; i < 21; i++) {
        results.push(await checkRateLimitV2(e, ctx, 'scan/domain'));
        vi.advanceTimersByTime(61_000);
      }
      expect(results.slice(0, 20).every(r => r.allowed)).toBe(true);
      expect(results[20].allowed).toBe(false);
      expect(results[20].reason).toBe('daily_limit_reached');
    } finally {
      vi.useRealTimers();
    }
  });

  it('MSSP tier (daily_limit -1) is genuinely unlimited, not degraded to FREE', async () => {
    const e = env();
    const ctx = { identity: 'mssp1', tier: 'MSSP' };
    for (let i = 0; i < 10; i++) {
      const r = await checkRateLimitV2(e, ctx, 'scan/domain');
      expect(r.allowed).toBe(true);
      expect(r.remaining).toBe(9999);
    }
  });

  it('STARTER cost budget (dailyLimit*2=40): 8 calls at cost 5 succeed, the 9th exceeds budget', async () => {
    expect(ENDPOINT_COST['scan/redteam']).toBe(5);
    const e = env();
    const ctx = { identity: 'starter3', tier: 'STARTER' };
    const results = [];
    for (let i = 0; i < 9; i++) results.push(await checkRateLimitCost(e, ctx, 'scan/redteam'));
    expect(results.slice(0, 8).every(r => r.allowed)).toBe(true);
    expect(results[8].allowed).toBe(false);
    expect(results[8].reason).toBe('cost_budget_exceeded');
  });

  it('MSSP tier is unlimited for cost-weighted endpoints too', async () => {
    const e = env();
    const ctx = { identity: 'mssp2', tier: 'MSSP' };
    for (let i = 0; i < 5; i++) {
      const r = await checkRateLimitCost(e, ctx, 'scan/redteam');
      expect(r.allowed).toBe(true);
    }
  });
});

describe('CAP-PROD-002 — TIERS (middleware/auth.js) stays in sync with TIER_LIMITS (auth/apiKeys.js)', () => {
  it('every real tier is present in TIERS, not just a subset', () => {
    for (const tier of ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'MSSP']) {
      expect(TIERS[tier], `TIERS.${tier} must exist`).toBeDefined();
    }
  });

  it('every real tier\'s daily_limit and burst_per_min match the authoritative TIER_LIMITS table', () => {
    for (const tier of ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'MSSP']) {
      expect(TIERS[tier].daily_limit, `${tier}.daily_limit`).toBe(TIER_LIMITS[tier].daily_limit);
      expect(TIERS[tier].burst_per_min, `${tier}.burst_per_min`).toBe(TIER_LIMITS[tier].burst_per_min);
    }
  });
});
