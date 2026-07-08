/* P0 incident 2026-07-08 — AI provider circuit breaker + redundant-retry fix.
 *
 * Customers (escalated via Microsoft & Cisco) reported the AI Copilot
 * intermittently failing with "Network error — could not reach APEX".
 * Root cause investigation found DeepSeek returning HTTP 402 "Insufficient
 * Balance" on every call, confirmed live via GET /api/copilot/quick-action
 * skill=get_ai_providers_status. DeepSeek sits first (or second) in several
 * Copilot task-routing chains, so every affected request paid the full
 * latency of a doomed attempt -- and orchestrateChat's own last-resort
 * fallback loop didn't check which providers had already failed earlier in
 * the SAME request, so a definitively-broken provider could be retried a
 * third time within one chat turn.
 *
 * This is not "fix DeepSeek" (that's a billing action outside this repo) --
 * it's "make the system behave gracefully and efficiently around a provider
 * that is down", which these tests verify:
 *   1. isProviderCircuitOpen/recordProviderFailure — the KV-backed breaker
 *      itself, fail-open, and only trips on definitive account errors.
 *   2. routeAICall skips a provider whose circuit is already open.
 *   3. orchestrateChat never retries a provider a 3rd time within one
 *      request once it has already failed (main loop + text-fallback),
 *      even when the failure doesn't trip the circuit breaker.
 *   4. orchestrateChat skips a provider outright when its circuit is open,
 *      without making any network call to it at all.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  PROVIDERS,
  isProviderCircuitOpen,
  recordProviderFailure,
  getCircuitBreakerState,
  getAllCircuitBreakerStates,
  getProviderHealthStatus,
  routeAICall,
} from '../src/core/aiProviderRouter.js';
import { orchestrateChat, TOOL_REGISTRY } from '../src/handlers/aiSecurityCopilot.js';

function fakeKV(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    _store: store,
  };
}

// ── 1. Circuit breaker primitives ──────────────────────────────────────────
describe('isProviderCircuitOpen / recordProviderFailure', () => {
  it('fails open when no KV binding is present', async () => {
    expect(await isProviderCircuitOpen({}, PROVIDERS.DEEPSEEK)).toBe(false);
    await expect(recordProviderFailure({}, PROVIDERS.DEEPSEEK, 402)).resolves.toBeUndefined();
  });

  it('fails open when KV throws', async () => {
    const throwingKV = {
      get: () => { throw new Error('KV unavailable'); },
      put: () => { throw new Error('KV unavailable'); },
    };
    expect(await isProviderCircuitOpen({ SECURITY_HUB_KV: throwingKV }, PROVIDERS.DEEPSEEK)).toBe(false);
    await expect(recordProviderFailure({ SECURITY_HUB_KV: throwingKV }, PROVIDERS.DEEPSEEK, 402)).resolves.toBeUndefined();
  });

  it('trips the breaker on a definitive account error (402 Insufficient Balance)', async () => {
    const kv = fakeKV();
    const env = { SECURITY_HUB_KV: kv };
    expect(await isProviderCircuitOpen(env, PROVIDERS.DEEPSEEK)).toBe(false);
    await recordProviderFailure(env, PROVIDERS.DEEPSEEK, 402);
    expect(await isProviderCircuitOpen(env, PROVIDERS.DEEPSEEK)).toBe(true);
  });

  it('also trips on 401 (revoked key) and 403 (forbidden)', async () => {
    for (const status of [401, 403]) {
      const kv = fakeKV();
      const env = { SECURITY_HUB_KV: kv };
      await recordProviderFailure(env, PROVIDERS.GROQ, status);
      expect(await isProviderCircuitOpen(env, PROVIDERS.GROQ)).toBe(true);
    }
  });

  it('does NOT trip on transient errors — 429, 500, or no status (timeout/network)', async () => {
    for (const status of [429, 500, 503, undefined]) {
      const kv = fakeKV();
      const env = { SECURITY_HUB_KV: kv };
      await recordProviderFailure(env, PROVIDERS.GROQ, status);
      expect(await isProviderCircuitOpen(env, PROVIDERS.GROQ)).toBe(false);
    }
  });

  it('never gates Cloudflare Workers AI — the guaranteed no-billing last resort', async () => {
    const kv = fakeKV();
    const env = { SECURITY_HUB_KV: kv };
    await recordProviderFailure(env, PROVIDERS.CF_AI, 402);
    expect(await isProviderCircuitOpen(env, PROVIDERS.CF_AI)).toBe(false);
    expect(kv._store.size).toBe(0); // never even written
  });

  it('circuits are independent per provider', async () => {
    const kv = fakeKV();
    const env = { SECURITY_HUB_KV: kv };
    await recordProviderFailure(env, PROVIDERS.DEEPSEEK, 402);
    expect(await isProviderCircuitOpen(env, PROVIDERS.DEEPSEEK)).toBe(true);
    expect(await isProviderCircuitOpen(env, PROVIDERS.GROQ)).toBe(false);
  });
});

// ── 2. routeAICall skips an open-circuit provider ──────────────────────────
describe('routeAICall — honors the circuit breaker', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('skips a provider whose circuit is already open and falls through to the next candidate', async () => {
    const kv = fakeKV({ [`ai_circuit_breaker:${PROVIDERS.GROQ}`]: '1' }); // pre-tripped
    const env = { GROQ_API_KEY: 'k1', DEEPSEEK_API_KEY: 'k2', SECURITY_HUB_KV: kv };

    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      calls.push(url);
      return new Response(JSON.stringify({
        choices: [{ message: { content: 'deepseek answer' } }], model: 'deepseek-chat', usage: {},
      }), { status: 200 });
    }));

    const result = await routeAICall(env, { prompt: 'hi', task_type: 'executive', max_tokens: 50 });

    expect(result?.provider).toBe('deepseek');
    expect(calls.some(u => String(u).includes('groq'))).toBe(false); // never called — skipped by the breaker
  });

  it('trips the breaker on a live 402 and the NEXT call in the same process skips it', async () => {
    const kv = fakeKV();
    const env = { GROQ_API_KEY: 'k1', DEEPSEEK_API_KEY: 'k2', SECURITY_HUB_KV: kv };

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('groq')) {
        return new Response(JSON.stringify({ error: { message: 'Insufficient Balance' } }), { status: 402 });
      }
      return new Response(JSON.stringify({
        choices: [{ message: { content: 'ok' } }], model: 'deepseek-chat', usage: {},
      }), { status: 200 });
    }));

    const first = await routeAICall(env, { prompt: 'hi', task_type: 'executive', max_tokens: 50 });
    expect(first?.provider).toBe('deepseek'); // groq failed 402, fell through

    const groqCallsAfterFirst = vi.mocked(fetch).mock.calls.filter(c => String(c[0]).includes('groq')).length;
    expect(groqCallsAfterFirst).toBe(1); // groq was attempted exactly once

    const second = await routeAICall(env, { prompt: 'another', task_type: 'executive', max_tokens: 50 });
    expect(second?.provider).toBe('deepseek');

    const groqCallsAfterSecond = vi.mocked(fetch).mock.calls.filter(c => String(c[0]).includes('groq')).length;
    expect(groqCallsAfterSecond).toBe(1); // still 1 — the second call's groq attempt was skipped by the now-open breaker
  });
});

// ── 3 & 4. orchestrateChat — no redundant retries, circuit-aware ───────────
describe('orchestrateChat — fallback chain efficiency', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  const tools = TOOL_REGISTRY.slice(0, 2);
  const messages = [{ role: 'user', content: 'hello, quick question' }]; // classifies general/standard: groq(8b) -> groq(70b) -> deepseek
  const okBody = JSON.stringify({
    choices: [{ message: { content: 'answer', tool_calls: null }, finish_reason: 'stop' }],
    usage: {}, model: 'm',
  });

  it('never makes a 3rd request to a provider that already failed twice in this same turn (main loop + text-fallback), even without a tripped circuit', async () => {
    // 500s never trip the breaker (see suite 1) — isolates this from the
    // circuit-breaker skip so it specifically proves the triedProviders fix.
    const kv = fakeKV();
    const env = { GROQ_API_KEY: 'gk', DEEPSEEK_API_KEY: 'dk', SECURITY_HUB_KV: kv };

    const groqCalls = [];
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('groq')) {
        groqCalls.push(1);
        return new Response(JSON.stringify({ error: 'server error' }), { status: 500 });
      }
      return new Response(okBody, { status: 200 }); // deepseek succeeds
    }));

    const result = await orchestrateChat(env, 'FREE', {}, messages, tools, 512, 'u1', 's1');

    expect(result.provider).toBe(PROVIDERS.DEEPSEEK);
    expect(result.content).toContain('answer');
    // Pre-fix: main-loop groq/8b tool-loop (1) + text-fallback (2) +
    // main-loop groq/70b tool-loop (3, text-fallback correctly skipped as
    // already-tried) + last-resort groq (4, the redundant retry) = 4 calls.
    // Post-fix the last-resort loop skips groq via triedProviders: 3 calls.
    expect(groqCalls.length).toBe(3);
  });

  it('skips a provider outright — zero network calls — when its circuit is already open', async () => {
    const kv = fakeKV({ [`ai_circuit_breaker:${PROVIDERS.GROQ}`]: '1' });
    const env = { GROQ_API_KEY: 'gk', DEEPSEEK_API_KEY: 'dk', SECURITY_HUB_KV: kv };

    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      calls.push(String(url));
      return new Response(okBody, { status: 200 });
    }));

    const result = await orchestrateChat(env, 'FREE', {}, messages, tools, 512, 'u1', 's1');

    expect(result.provider).toBe(PROVIDERS.DEEPSEEK);
    expect(calls.some(u => u.includes('groq'))).toBe(false); // groq never called at all
    expect(calls.filter(u => u.includes('deepseek')).length).toBe(1); // deepseek tried exactly once, succeeded
  });

  it('a definitive 402 during orchestrateChat trips the breaker for subsequent calls', async () => {
    const kv = fakeKV();
    const env = { GROQ_API_KEY: 'gk', DEEPSEEK_API_KEY: 'dk', SECURITY_HUB_KV: kv };

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('groq')) {
        return new Response(JSON.stringify({ error: { message: 'Insufficient Balance' } }), { status: 402 });
      }
      return new Response(okBody, { status: 200 });
    }));

    await orchestrateChat(env, 'FREE', {}, messages, tools, 512, 'u1', 's1');
    expect(await isProviderCircuitOpen(env, PROVIDERS.GROQ)).toBe(true);
  });
});

// ── 5. Circuit-breaker state visibility (GET /api/ai/providers/status) ────
describe('getCircuitBreakerState / getAllCircuitBreakerStates', () => {
  it('reports closed when nothing has tripped', async () => {
    const env = { SECURITY_HUB_KV: fakeKV() };
    expect(await getCircuitBreakerState(env, PROVIDERS.DEEPSEEK)).toEqual({ open: false });
  });

  it('reports full detail after a real trip via recordProviderFailure', async () => {
    const kv = fakeKV();
    const env = { SECURITY_HUB_KV: kv };
    const before = Date.now();
    await recordProviderFailure(env, PROVIDERS.DEEPSEEK, 402);

    const state = await getCircuitBreakerState(env, PROVIDERS.DEEPSEEK);
    expect(state.open).toBe(true);
    expect(state.status).toBe(402);
    expect(new Date(state.trippedAt).getTime()).toBeGreaterThanOrEqual(before);
    expect(state.ttlRemainingS).toBeGreaterThan(295); // just tripped, TTL is 300s
    expect(state.ttlRemainingS).toBeLessThanOrEqual(300);
  });

  it('still reports open (without detail) for a legacy pre-detail record, matching isProviderCircuitOpen', async () => {
    // A circuit tripped by a prior deploy (which wrote the literal string
    // '1', not JSON) must not be silently treated as closed by the newer
    // detail-reading code — open/closed has exactly one source of truth
    // (key existence), detail is optional on top.
    const env = { SECURITY_HUB_KV: fakeKV({ [`ai_circuit_breaker:${PROVIDERS.DEEPSEEK}`]: '1' }) };
    expect(await isProviderCircuitOpen(env, PROVIDERS.DEEPSEEK)).toBe(true);
    const state = await getCircuitBreakerState(env, PROVIDERS.DEEPSEEK);
    expect(state.open).toBe(true);
    expect(state.trippedAt).toBeNull();
  });

  it('fails open (closed-looking) on no KV or a KV read error', async () => {
    expect(await getCircuitBreakerState({}, PROVIDERS.DEEPSEEK)).toEqual({ open: false });
    const throwingKV = { get: () => { throw new Error('KV down'); } };
    expect(await getCircuitBreakerState({ SECURITY_HUB_KV: throwingKV }, PROVIDERS.DEEPSEEK)).toEqual({ open: false });
  });

  it('never reports Cloudflare Workers AI as open, even if a stray key existed for it', async () => {
    const env = { SECURITY_HUB_KV: fakeKV({ [`ai_circuit_breaker:${PROVIDERS.CF_AI}`]: '1' }) };
    expect(await getCircuitBreakerState(env, PROVIDERS.CF_AI)).toEqual({ open: false });
  });

  it('getAllCircuitBreakerStates covers every provider except CF AI, individually', async () => {
    const kv = fakeKV();
    const env = { SECURITY_HUB_KV: kv };
    await recordProviderFailure(env, PROVIDERS.DEEPSEEK, 402);

    const all = await getAllCircuitBreakerStates(env);
    expect(Object.keys(all).sort()).toEqual(
      Object.values(PROVIDERS).filter(p => p !== PROVIDERS.CF_AI).sort()
    );
    expect(all[PROVIDERS.DEEPSEEK].open).toBe(true);
    expect(all[PROVIDERS.GROQ].open).toBe(false);
  });
});

// ── 6. Integration: circuit state surfaces in the real health-status response ──
describe('getProviderHealthStatus — includes circuit_breaker state per provider', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('shows circuit_breaker.open:true for a provider real traffic has quarantined, alongside its fresh probe result', async () => {
    const kv = fakeKV();
    const env = { GROQ_API_KEY: 'gk', DEEPSEEK_API_KEY: 'dk', SECURITY_HUB_KV: kv };
    await recordProviderFailure(env, PROVIDERS.DEEPSEEK, 402); // simulate a real prior customer-traffic failure

    // The health check itself always live-probes regardless of breaker state
    // (that's the point of a health check) — deepseek's probe happens to
    // succeed here, on purpose, to prove circuit_breaker is independent
    // information layered on top of the probe result, not a replacement for it.
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      choices: [{ message: { content: 'APEX NEXUS ONLINE' } }], model: 'm', usage: {},
    }), { status: 200 })));

    const health = await getProviderHealthStatus(env);

    expect(health.providers[PROVIDERS.DEEPSEEK].status).toBe('healthy'); // fresh probe succeeded
    expect(health.providers[PROVIDERS.DEEPSEEK].circuit_breaker.open).toBe(true); // but still quarantined from real traffic
    expect(health.providers[PROVIDERS.DEEPSEEK].circuit_breaker.status).toBe(402);
    expect(health.providers[PROVIDERS.GROQ].circuit_breaker.open).toBe(false);
    expect(health.providers[PROVIDERS.CF_AI].circuit_breaker).toBeUndefined(); // never gated, not included
  });
});
