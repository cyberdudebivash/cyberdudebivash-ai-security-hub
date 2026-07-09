/* Regression coverage for a full public-API-surface audit (workers/src/index.js's
 * apiInfoResponse() vs the real routing table). Drives the real exported
 * worker.fetch() so the actual route wiring is tested, not just the handlers.
 *
 * Confirmed findings fixed here:
 *   1. GET  /api/insights/:jobId      — documented since v8.0, never wired (404).
 *   2. POST /api/content/generate     — documented alias, never wired (404).
 *   3. POST /api/monitors/:id/trigger — documented alias, never wired (404).
 *   4. POST /api/insights and POST /api/attack-graph resolved authCtx and never
 *      used it — fully open, zero rate limit, and /api/insights makes a real
 *      AI-provider call (generateAIInsights -> routeAICall) for any
 *      caller-fabricated scan_result. Fixed with checkRateLimitV2 (same
 *      mechanism protecting the legitimate scan endpoints) rather than a tier
 *      gate, since frontend/index.html's free scan-results page depends on both
 *      routes staying open to anonymous FREE callers.
 */
import { describe, it, expect, vi } from 'vitest';

vi.mock('../src/lib/aiBrain.js', () => ({
  generateAIInsights: vi.fn().mockResolvedValue({ executive_brief: 'mocked' }),
}));

import worker from '../src/index.js';

function kvStub() {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => { m.set(k, v); }, delete: async (k) => { m.delete(k); }, list: async () => ({ keys: [] }) };
}
function dbStub() {
  const stmt = { bind: () => stmt, first: async () => null, all: async () => ({ results: [] }), run: async () => ({}) };
  return { prepare: () => stmt, batch: async () => [] };
}
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }
function env(extra = {}) {
  return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub(), ...extra };
}

const scanBody = JSON.stringify({ scan_result: { findings: [{ severity: 'HIGH' }], risk_score: 40 }, module: 'domain' });
const fetchOpts = (ip) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
  body: scanBody,
});

describe('phantom endpoints from the API-surface audit are now wired', () => {
  it('GET /api/insights/:jobId no longer 404s (unknown job still 404s, but the ROUTE exists)', async () => {
    const res = await worker.fetch(
      new Request('https://cyberdudebivash.in/api/insights/job_doesnotexist123', { method: 'GET' }),
      env(), ctxStub(),
    );
    // Route is wired now; an unknown job correctly 404s at the handler level
    // (jobOwnedBy fails closed) — the regression this guards is a *routing*
    // 404 (path never matched at all), which we distinguish by confirming the
    // response is the handler's own "Invalid job ID"/"Job not found" shape.
    const body = await res.json();
    expect(res.status).toBe(404);
    expect(body.job_id).toBe('job_doesnotexist123');
  });

  it('POST /api/content/generate is wired to the same handler as POST /api/content', async () => {
    const res = await worker.fetch(
      new Request('https://cyberdudebivash.in/api/content/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      }),
      env(), ctxStub(),
    );
    expect(res.status).not.toBe(404);
  });

  it('POST /api/monitors/:id/trigger is wired to the same handler as .../run', async () => {
    const res = await worker.fetch(
      new Request('https://cyberdudebivash.in/api/monitors/mon_test123/trigger', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      }),
      env(), ctxStub(),
    );
    expect(res.status).not.toBe(404);
  });
});

describe('POST /api/insights and /api/attack-graph — rate limited, still open to FREE', () => {
  it('/api/insights: FREE tier (2/min burst) allows the first calls, then 429s', async () => {
    const sharedEnv = env();
    const ip = '10.10.10.10';
    const first  = await worker.fetch(new Request('https://cyberdudebivash.in/api/insights', fetchOpts(ip)), sharedEnv, ctxStub());
    const second = await worker.fetch(new Request('https://cyberdudebivash.in/api/insights', fetchOpts(ip)), sharedEnv, ctxStub());
    const third  = await worker.fetch(new Request('https://cyberdudebivash.in/api/insights', fetchOpts(ip)), sharedEnv, ctxStub());
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
  });

  it('/api/attack-graph: FREE tier (2/min burst) allows the first calls, then 429s', async () => {
    const sharedEnv = env();
    const ip = '10.10.10.11';
    const first  = await worker.fetch(new Request('https://cyberdudebivash.in/api/attack-graph', fetchOpts(ip)), sharedEnv, ctxStub());
    const second = await worker.fetch(new Request('https://cyberdudebivash.in/api/attack-graph', fetchOpts(ip)), sharedEnv, ctxStub());
    const third  = await worker.fetch(new Request('https://cyberdudebivash.in/api/attack-graph', fetchOpts(ip)), sharedEnv, ctxStub());
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
  });

  it('/api/insights still works anonymously (no login required) — matches the free scan-results UI', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/insights', fetchOpts('10.10.10.12')), env(), ctxStub());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  it('/api/attack-graph still works anonymously (no login required) — matches the free scan-results UI', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/attack-graph', fetchOpts('10.10.10.13')), env(), ctxStub());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });
});
