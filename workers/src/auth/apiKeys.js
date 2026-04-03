/**
 * CYBERDUDEBIVASH AI Security Hub — API Key Management v5.0
 * Keys are NEVER stored raw — only SHA-256 hash in D1
 * Format: cdb_<64 hex chars> (68 chars total)
 * Prefix (first 12 chars) shown in UI for identification
 */

const KEY_PREFIX = 'cdb_';
const KEY_BYTES  = 32; // 32 random bytes → 64 hex chars

// ─── Tier defaults ────────────────────────────────────────────────────────────
export const TIER_LIMITS = {
  FREE:       { daily_limit: 5,     monthly_limit: 50,    burst_per_min: 2  },
  PRO:        { daily_limit: 500,   monthly_limit: 10000, burst_per_min: 20 },
  ENTERPRISE: { daily_limit: -1,    monthly_limit: -1,    burst_per_min: 60 },
};

// ─── Generate a new API key ───────────────────────────────────────────────────
export function generateRawApiKey() {
  const raw = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(raw);
  const hex = [...raw].map(b => b.toString(16).padStart(2, '0')).join('');
  return KEY_PREFIX + hex;
}

// ─── SHA-256 hash a key (for D1 storage) ─────────────────────────────────────
export async function hashApiKey(key) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Get visible prefix (first 12 chars) ─────────────────────────────────────
export function getKeyPrefix(key) {
  return key.slice(0, 12) + '...';
}

// ─── Create key in D1 ────────────────────────────────────────────────────────
export async function createApiKey(db, userId, userTier, label = 'Default Key') {
  const rawKey = generateRawApiKey();
  const hash   = await hashApiKey(rawKey);
  const prefix = getKeyPrefix(rawKey);
  const limits = TIER_LIMITS[userTier] || TIER_LIMITS.FREE;

  await db.prepare(
    `INSERT INTO api_keys (user_id, key_hash, key_prefix, label, tier, daily_limit, monthly_limit)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(userId, hash, prefix, label, userTier, limits.daily_limit, limits.monthly_limit).run();

  // Return raw key ONCE — never retrievable again
  return { raw_key: rawKey, prefix, tier: userTier, label };
}

// ─── Resolve API key from D1 ─────────────────────────────────────────────────
export async function resolveApiKeyFromDB(db, rawKey) {
  if (!rawKey || !rawKey.startsWith(KEY_PREFIX)) return null;
  try {
    const hash = await hashApiKey(rawKey);
    const row  = await db.prepare(
      `SELECT k.*, u.email, u.tier as user_tier, u.status as user_status
       FROM api_keys k
       JOIN users u ON k.user_id = u.id
       WHERE k.key_hash = ? AND k.active = 1`
    ).bind(hash).first();

    if (!row) return null;
    if (row.user_status !== 'active') return null;
    if (row.expires_at && new Date(row.expires_at) < new Date()) return null;

    return row;
  } catch { return null; }
}

// ─── Track usage in D1 (upsert daily bucket) ─────────────────────────────────
export async function trackApiKeyUsage(db, keyId, userId, module) {
  const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  await db.prepare(
    `INSERT INTO api_key_usage (key_id, user_id, date_bucket, module, request_count)
     VALUES (?, ?, ?, ?, 1)
     ON CONFLICT(key_id, date_bucket, module)
     DO UPDATE SET request_count = request_count + 1`
  ).bind(keyId, userId, date, module).run();

  // Update last_used_at
  await db.prepare(
    `UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`
  ).bind(keyId).run();
}

// ─── Check daily quota ────────────────────────────────────────────────────────
export async function checkDailyQuota(db, keyId, dailyLimit) {
  if (dailyLimit === -1) return { allowed: true, used: 0, remaining: -1 };
  const date  = new Date().toISOString().slice(0, 10);
  const result = await db.prepare(
    `SELECT COALESCE(SUM(request_count), 0) as total
     FROM api_key_usage WHERE key_id = ? AND date_bucket = ?`
  ).bind(keyId, date).first();
  const used = result?.total ?? 0;
  return {
    allowed:   used < dailyLimit,
    used,
    remaining: Math.max(0, dailyLimit - used),
    limit:     dailyLimit,
  };
}

// ─── List user's keys ─────────────────────────────────────────────────────────
export async function listUserApiKeys(db, userId) {
  const { results } = await db.prepare(
    `SELECT id, key_prefix, label, tier, daily_limit, monthly_limit, active,
            created_at, last_used_at, expires_at
     FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`
  ).bind(userId).all();
  return results || [];
}

// ─── Revoke a key ─────────────────────────────────────────────────────────────
export async function revokeApiKey(db, keyId, userId) {
  const result = await db.prepare(
    `UPDATE api_keys SET active = 0 WHERE id = ? AND user_id = ?`
  ).bind(keyId, userId).run();
  return result.meta.changes > 0;
}

// ─── Usage summary for a key ─────────────────────────────────────────────────
export async function getKeyUsageSummary(db, keyId, userId) {
  const today     = new Date().toISOString().slice(0, 10);
  const monthStart = today.slice(0, 7) + '-01';

  const [daily, monthly] = await Promise.all([
    db.prepare(
      `SELECT COALESCE(SUM(request_count), 0) as total, module FROM api_key_usage
       WHERE key_id = ? AND date_bucket = ? GROUP BY module`
    ).bind(keyId, today).all(),
    db.prepare(
      `SELECT COALESCE(SUM(request_count), 0) as total FROM api_key_usage
       WHERE key_id = ? AND date_bucket >= ?`
    ).bind(keyId, monthStart).first(),
  ]);

  return {
    today: { total: daily.results?.reduce((s, r) => s + r.total, 0) ?? 0, by_module: daily.results ?? [] },
    month: { total: monthly?.total ?? 0 },
  };
}
