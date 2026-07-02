// Regression — per-user scan history must persist on a SHARED-CACHE HIT.
//
// The domain scan response cache is keyed by domain only (scan:domain:<domain>)
// and shared across all users. Before this fix, a cache hit returned early
// WITHOUT writing scan_history, so any customer scanning a domain that anyone
// else had recently scanned got the result but no history row — scan history
// was silently incomplete and non-deterministic. This test drives a cache hit
// for an authenticated user and asserts a scan_history INSERT still happens.
import { describe, it, expect, beforeEach } from 'vitest';
import { handleDomainScan } from '../src/handlers/domain.js';

function makeReq(body) {
  return new Request('https://x/api/scan/domain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// KV pre-seeded with a fresh cached scan for example.com
function cachedKV(domain, cachedResult) {
  const store = new Map();
  store.set(`scan:domain:${domain}`, JSON.stringify({ ...cachedResult, _cached_at: Date.now() }));
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
  };
}

// DB that records every INSERT so we can assert on scan_history writes
function recordingDB() {
  const inserts = [];
  return {
    inserts,
    prepare(sql) {
      let bound = [];
      return {
        bind(...args) { bound = args; return this; },
        async run() { inserts.push({ sql, bound }); return { success: true, meta: { changes: 1 } }; },
        async first() { return null; },
        async all() { return { results: [] }; },
      };
    },
  };
}

describe('domain scan — history persists on shared-cache hit', () => {
  const cached = {
    module: 'domain', target: 'example.com', risk_score: 70, risk_level: 'HIGH',
    grade: 'D', data_source: 'live_dns', findings: [],
  };

  it('writes a per-user scan_history row even when the response is cache-served', async () => {
    const db = recordingDB();
    const env = { DB: db, SECURITY_HUB_KV: cachedKV('example.com', cached) };
    const authCtx = { user_id: 'user-123', tier: 'FREE' };

    const res = await handleDomainScan(makeReq({ target: 'example.com' }), env, authCtx);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-Cache')).toBe('HIT'); // proves we took the cache path

    const historyWrites = db.inserts.filter(i => /INSERT OR IGNORE INTO scan_history/.test(i.sql));
    expect(historyWrites.length).toBe(1);
    const w = historyWrites[0];
    expect(w.bound[0]).toBe('user-123');      // user_id
    expect(w.bound).toContain('example.com'); // target
    expect(w.bound).toContain(70);            // risk_score carried from cache
  });

  it('does not write user scan_history for an anonymous cache hit (no user_id)', async () => {
    const db = recordingDB();
    const env = { DB: db, SECURITY_HUB_KV: cachedKV('example.com', cached) };

    const res = await handleDomainScan(makeReq({ target: 'example.com' }), env, {});
    expect(res.status).toBe(200);
    const historyWrites = db.inserts.filter(i => /INSERT OR IGNORE INTO scan_history/.test(i.sql));
    expect(historyWrites.length).toBe(0);
    // But the anonymous scan_jobs telemetry row is still recorded.
    const jobWrites = db.inserts.filter(i => /INSERT OR IGNORE INTO scan_jobs/.test(i.sql));
    expect(jobWrites.length).toBe(1);
  });
});
