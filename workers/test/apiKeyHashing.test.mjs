/* Regression tests — Fix #2: hash sap_ API keys (no plaintext at rest).
 * provisionApiKey must store a SHA-256 hash in D1 and key the KV cache by hash;
 * resolveApiKey must round-trip new (hashed) keys AND still validate legacy
 * plaintext rows during the transition (zero regression for live keys). */
import { describe, it, expect, beforeEach } from 'vitest';
import { provisionApiKey, resolveApiKey } from '../src/services/apiRevenueEngine.js';

function makeEnv() {
  const kv = new Map();
  const rows = [];
  const env = {
    SECURITY_HUB_KV: {
      async get(k) { return kv.has(k) ? kv.get(k) : null; },
      async put(k, v) { kv.set(k, v); },
    },
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async run() {
            if (/INSERT INTO api_keys/.test(sql)) {
              const i = rows.findIndex(r => r.email === b[1]);
              const row = { api_key: b[3], email: b[1], plan: b[2], active: 1 };
              if (i >= 0) rows[i] = row; else rows.push(row);
            }
          },
          async first() {
            if (/SELECT email, plan FROM api_keys/.test(sql)) {
              const [h, raw] = b;
              const r = rows.find(x => (x.api_key === h || x.api_key === raw) && x.active === 1);
              return r ? { email: r.email, plan: r.plan } : null;
            }
            return null;
          },
        };
      },
    },
  };
  return { env, kv, rows };
}

describe('sap_ API key hashing', () => {
  let ctx;
  beforeEach(() => { ctx = makeEnv(); });

  it('issues a sap_-prefixed raw key to the caller', async () => {
    const { api_key } = await provisionApiKey(ctx.env, 'a@b.com', 'pro');
    expect(api_key.startsWith('sap_')).toBe(true);
  });

  it('stores a 64-char SHA-256 hash in D1, NOT the raw key', async () => {
    const { api_key } = await provisionApiKey(ctx.env, 'a@b.com', 'pro');
    const stored = ctx.rows[0].api_key;
    expect(stored).not.toBe(api_key);
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
  });

  it('never embeds the raw key in a KV key-name', async () => {
    const { api_key } = await provisionApiKey(ctx.env, 'a@b.com', 'pro');
    expect([...ctx.kv.keys()].some(k => k.includes(api_key))).toBe(false);
  });

  it('round-trips a freshly provisioned (hashed) key', async () => {
    const { api_key } = await provisionApiKey(ctx.env, 'a@b.com', 'pro');
    const resolved = await resolveApiKey(ctx.env, api_key);
    expect(resolved).toEqual({ email: 'a@b.com', plan: 'pro' });
  });

  it('still validates a legacy plaintext D1 row (transition, no KV)', async () => {
    ctx.rows.push({ api_key: 'sap_LEGACYRAWKEY', email: 'old@b.com', plan: 'starter', active: 1 });
    const noKv = { ...ctx.env, SECURITY_HUB_KV: { async get() { return null; }, async put() {} } };
    const resolved = await resolveApiKey(noKv, 'sap_LEGACYRAWKEY');
    expect(resolved).toEqual({ email: 'old@b.com', plan: 'starter' });
  });
});
