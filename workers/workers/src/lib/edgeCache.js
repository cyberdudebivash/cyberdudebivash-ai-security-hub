/**
 * CYBERDUDEBIVASH AI Security Hub — Edge Cache Layer v1.0
 *
 * Wraps Cloudflare's caches.default (CDN Cache API) to eliminate KV hot-path reads.
 * This is the PRIMARY optimization to fix KV overuse.
 *
 * Strategy:
 *   1. Caller checks edgeCache.get(key)  → returns cached Response or null
 *   2. On MISS: caller builds Response, calls edgeCache.put(key, response, ttl)
 *   3. Next request: edgeCache.get() returns the cached Response instantly — ZERO KV reads
 *
 * Cloudflare Cache API guarantees:
 *   - Served from the SAME edge PoP — sub-millisecond latency
 *   - FREE — does not count toward KV read quota
 *   - Automatic eviction via Cache-Control max-age
 *   - Works in all Cloudflare Worker plans (Free included)
 *
 * Usage:
 *   import { edgeCache } from '../lib/edgeCache.js';
 *   const cached = await edgeCache.get(request, cacheKey);
 *   if (cached) return cached;
 *   const fresh = Response.json(data);
 *   await edgeCache.put(request, cacheKey, fresh.clone(), ttlSeconds);
 *   return fresh;
 */

const CACHE_PREFIX = 'https://cdb-internal-cache/';

/**
 * Get a cached response from Cloudflare's CDN cache.
 * @param {string} cacheKey - logical key (will be converted to a synthetic URL)
 * @returns {Response|null}
 */
export async function edgeCacheGet(cacheKey) {
  try {
    const cache = caches.default;
    const syntheticUrl = `${CACHE_PREFIX}${encodeURIComponent(cacheKey)}`;
    const cached = await cache.match(new Request(syntheticUrl));
    if (cached) {
      // Clone and add X-Cache-Hit header for observability
      const headers = new Headers(cached.headers);
      headers.set('X-Cache', 'HIT');
      headers.set('X-Cache-Key', cacheKey.slice(0, 60));
      return new Response(cached.body, { status: cached.status, headers });
    }
  } catch (e) {
    console.warn('[EdgeCache] GET error:', e?.message);
  }
  return null;
}

/**
 * Store a response in Cloudflare's CDN cache.
 * @param {string} cacheKey  - logical key
 * @param {Response} response - response to cache (will be cloned)
 * @param {number} ttlSeconds - cache TTL in seconds
 */
export async function edgeCachePut(cacheKey, response, ttlSeconds = 60) {
  try {
    const cache = caches.default;
    const syntheticUrl = `${CACHE_PREFIX}${encodeURIComponent(cacheKey)}`;

    // Build cacheable response with correct Cache-Control
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', `public, max-age=${ttlSeconds}, s-maxage=${ttlSeconds}`);
    headers.set('X-Cache', 'MISS');
    headers.set('X-Cache-Key', cacheKey.slice(0, 60));
    headers.set('X-Cache-TTL', String(ttlSeconds));

    const cacheableResponse = new Response(response.body, {
      status:  response.status,
      headers,
    });

    // cache.put() stores against a synthetic Request
    await cache.put(new Request(syntheticUrl), cacheableResponse);
  } catch (e) {
    console.warn('[EdgeCache] PUT error:', e?.message);
  }
}

/**
 * Invalidate (purge) a cached key.
 * @param {string} cacheKey
 */
export async function edgeCacheDelete(cacheKey) {
  try {
    const cache = caches.default;
    const syntheticUrl = `${CACHE_PREFIX}${encodeURIComponent(cacheKey)}`;
    await cache.delete(new Request(syntheticUrl));
  } catch (e) {
    console.warn('[EdgeCache] DELETE error:', e?.message);
  }
}

/**
 * Convenience wrapper: get-or-compute pattern.
 * If key is cached, returns cached response.
 * Otherwise, runs computeFn(), caches result, returns fresh response.
 *
 * @param {string}   cacheKey
 * @param {number}   ttlSeconds
 * @param {Function} computeFn  - async function returning a Response
 * @returns {Response}
 */
export async function edgeCacheGetOrSet(cacheKey, ttlSeconds, computeFn) {
  const cached = await edgeCacheGet(cacheKey);
  if (cached) return cached;

  const fresh = await computeFn();

  // Cache a clone (body is a readable stream — can only consume once)
  const [forCache, forClient] = fresh.tee ?
    (() => { const [a,b] = [fresh.clone(), fresh]; return [a, b]; })() :
    [fresh.clone(), fresh];

  await edgeCachePut(cacheKey, forCache, ttlSeconds);
  return forClient;
}

export const edgeCache = {
  get:      edgeCacheGet,
  put:      edgeCachePut,
  delete:   edgeCacheDelete,
  getOrSet: edgeCacheGetOrSet,
};

export default edgeCache;
