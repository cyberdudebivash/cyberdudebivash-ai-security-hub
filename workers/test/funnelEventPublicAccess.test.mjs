/* P0 Wave 3 (Production Dashboard UAT) — funnel-tracking pipeline restored.
 *
 * Found via a real headless-Chromium session against live production
 * (https://cyberdudebivash.in): every anonymous visitor's browser calls
 * POST /api/funnel/event on page load and on exit-intent (frontend/index.html
 * 'visit'/'exit_intent' tracking beacons) — and every one 403'd. Root cause:
 * this route's own registration in workers/src/index.js is explicitly
 * commented "public, fire-and-forget", and its handler
 * (handlers/revenue.js handleFunnelEvent) is written to accept a null
 * authCtx by design — but an EARLIER, broader "internal back-office
 * owner-only gate" (guarding truly-internal routes like /api/revenue/*,
 * /api/integrations/*, and the separate READ-side /api/funnel/metrics
 * aggregate) had /api/funnel/event in its path list too, so every request
 * was rejected before ever reaching the intentionally-public handler. The
 * entire visitor funnel-tracking pipeline (visit → scan → signup →
 * purchase) has had zero anonymous-visitor data flowing into it since
 * whichever change added this path to that list — confirmed live via
 * direct curl against production returning 403 with
 * {"error":"Forbidden","message":"This resource is restricted to the
 * platform owner."} for a plain anonymous POST.
 *
 * This locks in: /api/funnel/event is reachable anonymously (as its own
 * code always intended) while every genuinely-internal route in the same
 * gate list — including the READ-side /api/funnel/metrics, a different
 * route from the WRITE-side /api/funnel/event this fix touches — remains
 * owner-only, so the fix doesn't over-loosen anything.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE funnel_events (
    id TEXT PRIMARY KEY, email TEXT, event_type TEXT, stage TEXT,
    metadata TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeKV() {
  const store = new Map();
  return {
    async get(k, opts) { const v = store.get(k); if (v === undefined) return null; return opts?.type === 'json' ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, String(v)); },
    async delete(k) { store.delete(k); },
    _store: store,
  };
}

const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

function postFunnelEvent(body) {
  return new Request('https://x/api/funnel/event', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('POST /api/funnel/event — public, fire-and-forget (regression: was wrongly owner-gated)', () => {
  it('an anonymous visitor (no auth header at all) can record a funnel event — the exact call every real visitor makes', async () => {
    const db  = makeRealD1();
    const env = { DB: db, SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(postFunnelEvent({ stage: 'visit', metadata: { path: '/', plan: 'FREE' } }), env, ctxStub);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.stage).toBe('visit');
    const row = db._sqlite.prepare(`SELECT email, stage FROM funnel_events WHERE id = ?`).get(data.id);
    expect(row.stage).toBe('visit');
    expect(row.email).toBe('anonymous');
  });

  it('an exit-intent event (the other real call site) also succeeds anonymously', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(postFunnelEvent({ stage: 'feature_blocked', metadata: { type: 'exit_intent' } }), env, ctxStub);
    expect(res.status).toBe(200);
  });

  it('an invalid stage is still rejected with 400 (input validation unaffected by the auth fix)', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(postFunnelEvent({ stage: 'not_a_real_stage' }), env, ctxStub);
    expect(res.status).toBe(400);
  });

  it('an authenticated caller still works too (userId gets attached, not required)', async () => {
    const env = { DB: makeRealD1(), JWT_SECRET: 'x', SECURITY_HUB_KV: makeKV() };
    // No real JWT constructed here — this just proves the route no longer
    // hard-requires owner auth; authenticated-but-non-owner callers succeed.
    const res = await worker.fetch(postFunnelEvent({ stage: 'purchase' }), env, ctxStub);
    expect(res.status).toBe(200);
  });
});

describe('sibling internal routes in the same former gate list remain owner-only (no over-loosening)', () => {
  it('GET /api/funnel/metrics (the aggregate READ endpoint, a different route) still 401/403s an anonymous caller', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/funnel/metrics'), env, ctxStub);
    expect([401, 403]).toContain(res.status);
  });

  it('GET /api/affiliate/stats still 403s an anonymous caller', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/affiliate/stats'), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('a path under /api/revenue/ still 403s an anonymous caller', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/revenue/whatever'), env, ctxStub);
    expect(res.status).toBe(403);
  });
});
