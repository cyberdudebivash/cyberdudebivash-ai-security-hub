// Regression — GET /api/search threw HTTP 500 in production for any query of
// 2+ characters. Root cause: the handler built its cache key with
// Buffer.from(...).toString('base64'), but Buffer does not exist in the
// Cloudflare Workers runtime (no nodejs_compat flag) → ReferenceError →
// Cloudflare error 1101 → 500. Node's Buffer masked this in unit tests, so a
// plain functional test could not catch it. This suite pairs a functional run
// of the query path with a static guard that no EXECUTABLE line references
// Buffer (comments are stripped first so the explanatory comment does not
// trip the check).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { handleGlobalSearch } from '../src/handlers/globalSearch.js';

function emptyDB() {
  return {
    prepare() {
      return {
        bind() { return this; },
        async all() { return { results: [] }; },
        async run() { return { success: true, meta: { changes: 0 } }; },
        async first() { return null; },
      };
    },
  };
}

function kvStub() {
  const store = new Map();
  return {
    async get(k, t) { const v = store.get(k); return v == null ? null : (t === 'json' ? JSON.parse(v) : v); },
    async put(k, v) { store.set(k, v); },
  };
}

function searchReq(q) {
  const req = new Request(`https://x/api/search?q=${encodeURIComponent(q)}`);
  req.user = { id: 'u1', org_id: 'org-1', role: 'user' };
  return req;
}

describe('handleGlobalSearch — query path executes without Buffer', () => {
  it('returns 200 for a real 2+ char query (the path that used to 500)', async () => {
    const env = { DB: emptyDB(), KV: kvStub() };
    const res = await handleGlobalSearch(searchReq('CVE-2024-3400'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.query).toBe('CVE-2024-3400');
    expect(Array.isArray(body.results)).toBe(true);
  });

  it('caches on the second identical query (cache key builds without throwing)', async () => {
    const env = { DB: emptyDB(), KV: kvStub() };
    await handleGlobalSearch(searchReq('lateral movement'), env);
    const res2 = await handleGlobalSearch(searchReq('lateral movement'), env);
    const body2 = await res2.json();
    expect(body2.cached).toBe(true);
  });

  it('handler source has no executable Buffer reference (comments stripped)', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    let src = readFileSync(resolve(dir, '../src/handlers/globalSearch.js'), 'utf8');
    // Strip block comments and line comments before checking executable code.
    src = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    expect(src).not.toMatch(/Buffer\./);
  });
});
