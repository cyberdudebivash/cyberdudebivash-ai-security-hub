/**
 * CYBERDUDEBIVASH AI Security Hub — KV Optimized Wrapper v1.0
 *
 * Wraps all KV reads with an in-memory L1 cache (per-request isolate cache)
 * so that the same key is never read from KV more than once per request.
 *
 * Additionally provides a write-back mechanism where KV puts are fire-and-forget
 * (non-blocking) to avoid adding latency to the response path.
 *
 * Architecture layers:
 *   L0: Cloudflare CDN Cache (edgeCache.js) — cross-request, edge-wide, FREE
 *   L1: In-memory Map (this file)            — per-isolate, per-request dedup
 *   L2: Cloudflare KV                        — persistent, metered (minimize)
 *   L3: D1 Database                          — persistent, low-latency SQL
 *
 * Rules enforced:
 *   - KV is NEVER used in hot paths (health, stats, public feeds)
 *   - KV reads are deduplicated within each Worker invocation
 *   - KV writes are always fire-and-forget (never block response)
 *   - TTL must always be set on every KV put (no immortal keys)
 */

// Per-isolate (per-request) in-memory cache
// Cloudflare Workers run in V8 isolates; this Map lives only for the current request
const _L1 = new Map();

/**
 * KV get with L1 dedup — if this key was already read in this request, return cached value.
 * @param {KVNamespace} kv
 * @param {string} key
 * @param {{ type?: string }} opts
 * @returns {Promise<any>}
 */
export async function kvGet(kv, key, opts = {}) {
  if (!kv) return null;
  const cacheKey = `${key}:${opts.type || 'text'}`;
  if (_L1.has(cacheKey)) {
    return _L1.get(cacheKey);
  }
  try {
    const value = await kv.get(key, opts);
    _L1.set(cacheKey, value);
    return value;
  } catch (e) {
    console.warn('[KVOpt] GET error:', key, e?.message);
    return null;
  }
}

/**
 * KV put — always fire-and-forget (non-blocking), always requires TTL.
 * @param {KVNamespace} kv
 * @param {string} key
 * @param {string} value
 * @param {{ expirationTtl: number }} opts  — expirationTtl is REQUIRED
 */
export function kvPutAsync(kv, key, value, opts = {}) {
  if (!kv) return;
  if (!opts.expirationTtl) {
    console.error('[KVOpt] BLOCKED put without TTL on key:', key, '— add expirationTtl');
    return;
  }
  // Invalidate L1 on write
  _L1.delete(`${key}:text`);
  _L1.delete(`${key}:json`);
  // Non-blocking write
  kv.put(key, value, opts).catch((e) => console.warn('[KVOpt] PUT error:', key, e?.message));
}

/**
 * Batch KV get — fetches multiple keys in parallel, deduplicating via L1.
 * Reduces round-trips when multiple keys are needed at once.
 * @param {KVNamespace} kv
 * @param {Array<{ key: string, type?: string }>} keys
 * @returns {Promise<Map<string, any>>}
 */
export async function kvGetBatch(kv, keys) {
  if (!kv) return new Map();
  const results = new Map();
  const toFetch = [];

  for (const { key, type = 'text' } of keys) {
    const cacheKey = `${key}:${type}`;
    if (_L1.has(cacheKey)) {
      results.set(key, _L1.get(cacheKey));
    } else {
      toFetch.push({ key, type });
    }
  }

  if (toFetch.length > 0) {
    const fetched = await Promise.allSettled(
      toFetch.map(({ key, type }) => kv.get(key, { type }))
    );
    toFetch.forEach(({ key, type }, i) => {
      const val = fetched[i].status === 'fulfilled' ? fetched[i].value : null;
      results.set(key, val);
      _L1.set(`${key}:${type}`, val);
    });
  }

  return results;
}

/**
 * Clear the L1 cache (useful in tests or when you know data is stale).
 */
export function kvClearL1() {
  _L1.clear();
}

export default { get: kvGet, putAsync: kvPutAsync, getBatch: kvGetBatch, clearL1: kvClearL1 };
