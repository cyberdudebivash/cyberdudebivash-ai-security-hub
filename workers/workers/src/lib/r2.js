/**
 * CYBERDUDEBIVASH AI Security Hub — R2 Storage Engine v5.0
 * Stores large scan result JSON payloads in Cloudflare R2.
 * Falls back gracefully to KV if R2 is unavailable.
 *
 * R2 key structure: scans/{YYYY-MM}/{job_id}.json
 * Metadata stored as R2 object custom metadata (for listing/filtering).
 */

const R2_PREFIX   = 'scans';
const KV_FALLBACK = 'result';   // KV key prefix for fallback storage
const KV_TTL      = 86400 * 7; // 7 days in KV fallback

// ─── Build R2 object key ──────────────────────────────────────────────────────
function buildR2Key(jobId) {
  const now    = new Date();
  const month  = now.toISOString().slice(0, 7); // YYYY-MM
  return `${R2_PREFIX}/${month}/${jobId}.json`;
}

// ─── Store scan result in R2 (primary) or KV (fallback) ───────────────────────
export async function storeResultR2(env, jobId, scanResult) {
  const key     = buildR2Key(jobId);
  const payload = JSON.stringify(scanResult);

  // Attempt R2 first
  if (env?.SCAN_RESULTS) {
    try {
      await env.SCAN_RESULTS.put(key, payload, {
        httpMetadata: { contentType: 'application/json; charset=utf-8' },
        customMetadata: {
          job_id:     jobId,
          module:     scanResult.module       ?? 'unknown',
          target:     scanResult.target       ?? 'unknown',
          risk_score: String(scanResult.risk_score ?? 0),
          risk_level: scanResult.risk_level   ?? 'UNKNOWN',
          scanned_at: scanResult.scan_metadata?.scan_timestamp ?? new Date().toISOString(),
        },
      });
      return key; // success — return R2 key
    } catch (e) {
      console.warn('[R2] Store failed, falling back to KV:', e?.message);
    }
  }

  // KV fallback (results too large for normal KV? — limit is 25MB, fine for JSON)
  if (env?.SECURITY_HUB_KV) {
    try {
      const kvKey = `${KV_FALLBACK}:${jobId}`;
      await env.SECURITY_HUB_KV.put(kvKey, payload, { expirationTtl: KV_TTL });
      return `kv:${kvKey}`; // indicate fallback storage
    } catch {}
  }

  return null; // storage unavailable
}

// ─── Retrieve scan result from R2 or KV ───────────────────────────────────────
export async function getResultR2(env, r2Key) {
  if (!r2Key) return null;

  // KV fallback path
  if (r2Key.startsWith('kv:')) {
    if (!env?.SECURITY_HUB_KV) return null;
    try {
      const raw = await env.SECURITY_HUB_KV.get(r2Key.slice(3));
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  // R2 primary path
  if (env?.SCAN_RESULTS) {
    try {
      const obj = await env.SCAN_RESULTS.get(r2Key);
      if (!obj) return null;
      const text = await obj.text();
      return JSON.parse(text);
    } catch { return null; }
  }

  return null;
}

// ─── List recent results for a user (via R2 list — PRO/ENTERPRISE only) ───────
export async function listUserResults(env, userId, limit = 20) {
  if (!env?.SCAN_RESULTS) return [];
  try {
    // R2 list with prefix filter — keys structured as scans/YYYY-MM/job_*.json
    const listed = await env.SCAN_RESULTS.list({
      prefix:  R2_PREFIX,
      limit:   Math.min(limit, 1000),
      include: ['customMetadata'],
    });

    return (listed.objects || [])
      .filter(obj => obj.customMetadata?.user_id === userId)
      .slice(0, limit)
      .map(obj => ({
        r2_key:     obj.key,
        job_id:     obj.customMetadata?.job_id,
        module:     obj.customMetadata?.module,
        target:     obj.customMetadata?.target,
        risk_score: parseInt(obj.customMetadata?.risk_score || '0', 10),
        risk_level: obj.customMetadata?.risk_level,
        scanned_at: obj.customMetadata?.scanned_at,
        size_bytes: obj.size,
      }));
  } catch { return []; }
}

// ─── Delete a specific result (GDPR / user request) ──────────────────────────
export async function deleteResultR2(env, r2Key) {
  if (!r2Key) return false;

  if (r2Key.startsWith('kv:') && env?.SECURITY_HUB_KV) {
    try { await env.SECURITY_HUB_KV.delete(r2Key.slice(3)); return true; } catch { return false; }
  }

  if (env?.SCAN_RESULTS) {
    try { await env.SCAN_RESULTS.delete(r2Key); return true; } catch { return false; }
  }

  return false;
}

// ─── Retrieve result by job_id (searches both R2 and KV) ─────────────────────
export async function getResultByJobId(env, jobId) {
  // Try KV job record to get the stored r2_key
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(`job:${jobId}`);
      if (raw) {
        const job = JSON.parse(raw);
        if (job.r2_key) return getResultR2(env, job.r2_key);
      }
    } catch {}
  }
  return null;
}
