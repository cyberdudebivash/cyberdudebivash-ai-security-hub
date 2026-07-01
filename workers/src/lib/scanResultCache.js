/**
 * Shared scan-result cache used to back the "Generate Report" feature
 * (POST /api/report/generate + GET /api/report/:token). Without this, that
 * STARTER+ feature always 422'd — nothing ever wrote the scan_id-keyed
 * cache entry it reads from.
 */
const SCAN_RESULT_CACHE_TTL = 86400 * 7; // 7 days — matches the advertised report retention window

function scanCacheKey(authCtx, scanId) {
  const userId = authCtx?.user_id || authCtx?.userId || authCtx?.key_id || null;
  return userId ? `scan:${userId}:${scanId}` : `scan:${scanId}`;
}

export async function cacheScanResultForReport(env, authCtx, scanId, result) {
  const kv = env?.SECURITY_HUB_KV;
  if (!kv || !scanId || !result) return;
  try {
    await kv.put(scanCacheKey(authCtx, scanId), JSON.stringify(result), { expirationTtl: SCAN_RESULT_CACHE_TTL });
  } catch { /* never break the scan response over a caching failure */ }
}

export async function getCachedScanResult(env, authCtx, scanId) {
  const kv = env?.SECURITY_HUB_KV;
  if (!kv || !scanId) return null;
  try {
    const raw = await kv.get(scanCacheKey(authCtx, scanId));
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
