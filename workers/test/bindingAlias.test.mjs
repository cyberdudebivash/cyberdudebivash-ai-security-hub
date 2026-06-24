/* Regression test — Cloudflare invokes scheduled() and queue() directly with
 * the raw env (wrangler.toml binds D1 as SECURITY_HUB_DB, KV as
 * SECURITY_HUB_KV); neither passes through fetch() first. The alias that maps
 * those onto the env.DB/env.KV names every handler/service actually reads was
 * previously only applied inside fetch(), so every cron-triggered job
 * (ingestion, AI Threat Radar, etc.) silently no-opped on a falsy env.DB —
 * the radar's KV status snapshot was never written and "last_scan_at" stayed
 * null forever. normalizeBindings() must run at the top of every exported
 * entry point. */
import { describe, it, expect, vi } from 'vitest';
import worker, { normalizeBindings } from '../src/index.js';

function fakeDB() {
  return { _isDB: true };
}
function fakeKV() {
  return { _isKV: true };
}

describe('normalizeBindings', () => {
  it('aliases env.DB/env.KV/env.CDB_KV from the real wrangler.toml binding names', () => {
    const db = fakeDB();
    const kv = fakeKV();
    const env = { SECURITY_HUB_DB: db, SECURITY_HUB_KV: kv };
    normalizeBindings(env);
    expect(env.DB).toBe(db);
    expect(env.KV).toBe(kv);
    expect(env.CDB_KV).toBe(kv);
  });

  it('does not override an already-set env.DB/env.KV', () => {
    const realDB = fakeDB();
    const otherDB = fakeDB();
    const env = { SECURITY_HUB_DB: otherDB, DB: realDB, SECURITY_HUB_KV: fakeKV() };
    normalizeBindings(env);
    expect(env.DB).toBe(realDB);
  });

  it('is a no-op when no bindings are configured (never throws)', () => {
    const env = {};
    expect(() => normalizeBindings(env)).not.toThrow();
    expect(env.DB).toBeUndefined();
    expect(env.KV).toBeUndefined();
  });
});

describe('worker.queue() entry point', () => {
  it('aliases env.DB/env.KV before handing off to processQueueBatch', async () => {
    const db = fakeDB();
    const kv = fakeKV();
    const env = { SECURITY_HUB_DB: db, SECURITY_HUB_KV: kv };
    await worker.queue({ messages: [] }, env);
    expect(env.DB).toBe(db);
    expect(env.KV).toBe(kv);
  });
});

describe('worker.scheduled() entry point', () => {
  it('aliases env.DB/env.KV synchronously before any cron job runs', async () => {
    const db = fakeDB();
    const kv = fakeKV();
    const env = { SECURITY_HUB_DB: db, SECURITY_HUB_KV: kv };
    const seenEnvsAtDispatch = [];
    const ctx = {
      waitUntil(promise) {
        // By the time any cron job is dispatched via waitUntil, the alias
        // must already have been applied to this same env object.
        seenEnvsAtDispatch.push({ DB: env.DB, KV: env.KV });
        promise.catch(() => {}); // never block the worker on a background failure
      },
    };
    const event = { cron: '0 * * * *', scheduledTime: Date.now() };

    await worker.scheduled(event, env, ctx);

    expect(env.DB).toBe(db);
    expect(env.KV).toBe(kv);
    expect(seenEnvsAtDispatch.length).toBeGreaterThan(0);
    for (const seen of seenEnvsAtDispatch) {
      expect(seen.DB).toBe(db);
      expect(seen.KV).toBe(kv);
    }
  });
});
