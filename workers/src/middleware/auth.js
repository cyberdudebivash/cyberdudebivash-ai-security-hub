/**
 * CYBERDUDEBIVASH AI Security Hub — API Key Auth Middleware
 * Tier system: FREE | STARTER | PRO | ENTERPRISE | MSSP
 * Keys resolved from TWO stores (additive, KV-first):
 *   1. Cloudflare KV  apikey:{key} → JSON config (subscription/Stripe-provisioned)
 *   2. D1 api_keys (SHA-256 hashed) → self-serve keys generated via POST /api/keys
 * IP fallback for keyless FREE tier access
 */

import { resolveApiKeyFromDB, TIER_LIMITS } from '../auth/apiKeys.js';
import { resolveApiKey as resolveGrowthApiKey } from '../services/apiRevenueEngine.js';

// ─── Tier Definitions ────────────────────────────────────────────────────────
// Derived from TIER_LIMITS (auth/apiKeys.js) — the platform's one
// authoritative entitlement table — instead of a second, independently
// maintained copy. This object previously hardcoded its own FREE/PRO/
// ENTERPRISE numbers and never gained STARTER/MSSP entries when those tiers
// were added to TIER_LIMITS, so middleware/rateLimit.js's `TIERS[tier] ||
// TIERS.FREE` lookup silently rate-limited STARTER/MSSP customers (JWT/IP
// auth path — API-key callers go through enforceQuota -> TIER_LIMITS instead
// and were unaffected) to FREE's 5/day, 2/min burst across the core scan
// pipeline (index.js runSyncPipeline) and 5 intel handler files. Deriving
// from TIER_LIMITS fixes every call site with no changes needed elsewhere.
export const TIERS = {
  FREE:       { daily_limit: TIER_LIMITS.FREE.daily_limit,       burst_per_min: TIER_LIMITS.FREE.burst_per_min,       priority: 0, label: 'Free'       },
  STARTER:    { daily_limit: TIER_LIMITS.STARTER.daily_limit,    burst_per_min: TIER_LIMITS.STARTER.burst_per_min,    priority: 1, label: 'Starter'    },
  PRO:        { daily_limit: TIER_LIMITS.PRO.daily_limit,        burst_per_min: TIER_LIMITS.PRO.burst_per_min,        priority: 2, label: 'Pro'        },
  ENTERPRISE: { daily_limit: TIER_LIMITS.ENTERPRISE.daily_limit, burst_per_min: TIER_LIMITS.ENTERPRISE.burst_per_min, priority: 3, label: 'Enterprise' },
  MSSP:       { daily_limit: TIER_LIMITS.MSSP.daily_limit,       burst_per_min: TIER_LIMITS.MSSP.burst_per_min,       priority: 4, label: 'MSSP'       },
};

export const UPGRADE_URL   = 'https://cyberdudebivash.in/#pricing';
export const CONTACT_EMAIL = 'contact@cyberdudebivash.in';

// ─── Validate API Key: KV first, then D1 self-serve keys ──────────────────────
async function resolveApiKey(key, env) {
  // 1. KV fast-path — subscription/Stripe-provisioned keys (legacy + paid flow).
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(`apikey:${key}`);
      if (raw) {
        const cfg = JSON.parse(raw);
        if (cfg.active) return cfg; // { tier, owner_email, created_at, active, label } — unchanged KV semantics
      }
    } catch { /* fall through to D1 */ }
  }

  // 2. D1 fallback — self-serve keys generated via POST /api/keys (cdb_* format).
  //    Lets a key created in the developer portal authenticate on the intel API
  //    exactly as the docs promise ("obtain a key at /api/keys"). Tier follows the
  //    user's CURRENT account tier so upgrades/downgrades apply immediately.
  if (env?.DB && typeof key === 'string' && key.startsWith('cdb_')) {
    try {
      const row = await resolveApiKeyFromDB(env.DB, key);
      if (row) {
        return {
          tier:        String(row.user_tier || row.tier || 'FREE').toUpperCase(),
          owner_email: row.email || null,
          active:      true,
          label:       row.label || `${row.tier || 'FREE'} API Key`,
          source:      'd1',
        };
      }
    } catch { /* invalid/unavailable → null below */ }
  }

  // 3. Growth/Plan API keys (sap_* format) — provisioned by POST
  //    /api/growth/api-key (services/apiRevenueEngine.js) for verified paid
  //    leads. Previously unrecognized here: the key would provision
  //    successfully but could never authenticate anything (KV was cached
  //    under a hashed name this function never looks up, and this file's D1
  //    branch only matched cdb_). Delegates to that module's own resolver
  //    (hash-then-match against its D1 rows) instead of duplicating the
  //    lookup, so rotation/revocation there is honored here for free — a
  //    rotated-away key hashes to a value no active row matches.
  if (env?.DB && typeof key === 'string' && key.startsWith('sap_')) {
    try {
      const row = await resolveGrowthApiKey(env, key);
      if (row?.email && row?.plan) {
        return {
          tier:        String(row.plan).toUpperCase(),
          owner_email: row.email,
          active:      true,
          label:       `${String(row.plan).toUpperCase()} API Key`,
          source:      'growth',
        };
      }
    } catch { /* invalid/unavailable → null below */ }
  }

  return null;
}

// ─── Derive identity: key → ctx or IP → ctx ──────────────────────────────────
export async function resolveAuth(request, env) {
  const apiKey = request.headers.get('x-api-key') ||
                 request.headers.get('X-Api-Key')  ||
                 request.headers.get('Authorization')?.replace('Bearer ', '');
  const ip     = request.headers.get('CF-Connecting-IP') ||
                 request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  if (apiKey) {
    const cfg = await resolveApiKey(apiKey, env);
    if (cfg) {
      return {
        authenticated: true,
        method: 'api_key',
        identity: `key:${apiKey.slice(0,8)}...`,
        key: apiKey,
        tier: cfg.tier || 'FREE',
        limits: TIERS[cfg.tier] || TIERS.FREE,
        owner_email: cfg.owner_email || null,
        label: cfg.label || TIERS[cfg.tier]?.label || 'Free',
        ip,
      };
    }
    // Key provided but invalid
    return {
      authenticated: false,
      method: 'api_key',
      identity: null,
      tier: null,
      error: 'invalid_key',
      ip,
    };
  }

  // No key → FREE tier via IP
  return {
    authenticated: true,
    method: 'ip_fallback',
    identity: `ip:${ip}`,
    key: null,
    tier: 'FREE',
    limits: TIERS.FREE,
    owner_email: null,
    label: 'Free (IP)',
    ip,
  };
}

// ─── Auth Guard Middleware ────────────────────────────────────────────────────
export function authError(type = 'missing') {
  const messages = {
    missing:  { error: 'API key required', hint: 'Add header: x-api-key: YOUR_KEY' },
    invalid:  { error: 'Invalid API key', hint: 'Check your key or generate a new one' },
    inactive: { error: 'API key inactive', hint: 'Contact support to reactivate' },
    banned:   { error: 'Access denied', hint: 'This key has been suspended for abuse' },
  };
  return Response.json({
    ...(messages[type] || messages.missing),
    plan: 'FREE',
    upgrade_url: UPGRADE_URL,
    docs: 'https://cyberdudebivash.in/api-docs', // '/docs' doesn't exist (confirmed live 404)
    contact: CONTACT_EMAIL,
  }, { status: 401 });
}
