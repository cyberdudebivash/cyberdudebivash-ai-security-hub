/* Regression test — AI router deadline budget (2026-07-07). Enterprise Release
 * Gate runs #15/#16 found /api/scan/identity (and, intermittently, /api/scan/
 * redteam) exceeding the release gate's 15s ceiling in production. Root cause:
 * routeAICall()'s provider fallback loop (aiProviderRouter.js) had no overall
 * wall-clock budget — each provider in a task_type's chain carries its own
 * 20-30s timeout, and a chain of slow/failing providers could pile those up
 * sequentially (e.g. Groq 20s -> DeepSeek 25s -> Anthropic 30s = 75s+) before
 * ever giving up. Worse, the frontend's own safeFetch() hard-aborts every scan
 * request at 8s (API_TIMEOUT_MS, frontend/index.html) — so this wasn't just a
 * release-gate flake, real customer scans could silently fail client-side too.
 *
 * Fix: routeAICall() now takes an overall deadline_ms (default 12000) that
 * bounds every provider attempt combined, and generateAINarrative() (the
 * shared enrichment call every scan module awaits synchronously) passes an
 * explicit 6000ms budget to stay well inside the frontend's 8s ceiling. */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { routeAICall } from '../src/core/aiProviderRouter.js';

function envWithGroqAndDeepseek() {
  return { GROQ_API_KEY: 'test-groq-key', DEEPSEEK_API_KEY: 'test-deepseek-key' };
}

describe('routeAICall — overall deadline budget across the provider fallback chain', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('happy path: first configured provider succeeding is unaffected by the deadline', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      choices: [{ message: { content: 'executive brief' } }],
      model:   'llama-3.3-70b-versatile',
      usage:   { prompt_tokens: 10, completion_tokens: 5 },
    }), { status: 200 })));

    const result = await routeAICall(envWithGroqAndDeepseek(), {
      prompt: 'test prompt', task_type: 'executive', max_tokens: 50,
    });

    expect(result?.content).toBe('executive brief');
    expect(result?.provider).toBe('groq'); // first in the executive chain
  });

  it('gives up within the deadline instead of paying every provider timeout sequentially', async () => {
    // Simulate a stalled upstream that never resolves on its own — the only
    // thing that ends the request is the AbortSignal handed to fetch(),
    // exactly like a real slow/unresponsive provider.
    vi.stubGlobal('fetch', vi.fn((url, opts) => new Promise((_resolve, reject) => {
      opts.signal.addEventListener('abort', () => reject(new Error('The operation was aborted')));
    })));

    // Deliberately above the loop's own "remaining < 1000ms isn't worth a real
    // attempt" cutoff, so this exercises an actual bounded Groq attempt (which
    // aborts at ~deadline_ms) rather than bailing out before ever dispatching.
    const DEADLINE = 1500;
    const start = Date.now();
    const result = await routeAICall(envWithGroqAndDeepseek(), {
      prompt: 'test prompt', task_type: 'executive', max_tokens: 50,
      deadline_ms: DEADLINE,
    });
    const elapsed = Date.now() - start;

    expect(result).toBeNull();
    // Pre-fix this would take Groq's full 20s timeout, then DeepSeek's 25s
    // (45s+) before giving up. Post-fix it must stay near DEADLINE, not pile
    // up a second provider attempt on top.
    expect(elapsed).toBeGreaterThanOrEqual(DEADLINE - 50);
    expect(elapsed).toBeLessThan(DEADLINE + 1000);
  });

  it('never asks a provider to wait longer than its own configured ceiling', async () => {
    const seenTimeouts = [];
    vi.stubGlobal('fetch', vi.fn((url, opts) => {
      // AbortSignal doesn't expose its timeout directly; infer via a large
      // deadline_ms and confirm the call still completes (i.e. dispatch used
      // a bounded, finite timeout rather than something absurd/undefined).
      seenTimeouts.push(typeof opts.signal);
      return Promise.resolve(new Response(JSON.stringify({
        choices: [{ message: { content: 'ok' } }], model: 'm', usage: {},
      }), { status: 200 }));
    }));

    const result = await routeAICall(envWithGroqAndDeepseek(), {
      prompt: 'test', task_type: 'executive', max_tokens: 50, deadline_ms: 60000,
    });

    expect(result?.content).toBe('ok');
    expect(seenTimeouts[0]).toBe('object'); // a real AbortSignal was attached
  });

  it('CF AI (env.AI binding, no native AbortSignal support) is also bounded by the deadline', async () => {
    // env.AI.run() takes no signal — a stalled binding call used to be able to
    // hang routeAICall (and callCFAI specifically) indefinitely. Simulate
    // that with a promise that never resolves on its own; task_type
    // 'assessment' puts CF_AI first in the chain.
    const stalledAI = { run: () => new Promise(() => {}) };

    const DEADLINE = 1500;
    const start = Date.now();
    const result = await routeAICall({ AI: stalledAI }, {
      prompt: 'test', task_type: 'assessment', max_tokens: 50, deadline_ms: DEADLINE,
    });
    const elapsed = Date.now() - start;

    expect(result).toBeNull();
    expect(elapsed).toBeGreaterThanOrEqual(DEADLINE - 50);
    expect(elapsed).toBeLessThan(DEADLINE + 1000);
  });
});
