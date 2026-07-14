// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — API Revenue Engine
// GTM Growth Engine Phase 5: Usage Tracking + Rate Limiting + Billing Hooks
// ═══════════════════════════════════════════════════════════════════════════

// Canonical SHA-256 key hashing (shared with auth/apiKeys.js) — sap_ keys are
// stored and matched as hashes, never plaintext.
import { hashApiKey, getKeyPrefix } from '../auth/apiKeys.js';

// Mask a raw key for safe logging: keep the sap_ prefix + last 4 chars only.
function maskKey(raw) {
  if (!raw || typeof raw !== 'string') return 'anon';
  return `sap_…${raw.slice(-4)}`;
}

// ── Plan API quotas ──────────────────────────────────────────────────────────
export const API_QUOTAS = {
  free:       { daily: 0,     monthly: 0,      rate_per_min: 0   },
  starter:    { daily: 100,   monthly: 2000,   rate_per_min: 10  },
  pro:        { daily: 1000,  monthly: 20000,  rate_per_min: 60  },
  enterprise: { daily: -1,    monthly: -1,     rate_per_min: -1  }, // unlimited
};

// ── Pricing per 1,000 overage API calls (post-quota) ────────────────────────
const OVERAGE_PRICING = {
  starter:    5,    // ₹5 per 1000 calls
  pro:        3,    // ₹3 per 1000 calls
  enterprise: 1,    // ₹1 per 1000 calls (bulk)
};

// ── API endpoint categories ──────────────────────────────────────────────────
export const ENDPOINT_WEIGHTS = {
  '/api/threat-intel':         1,
  '/api/v1/correlations':      2,
  '/api/v1/graph':             3,
  '/api/v1/hunting':           2,
  '/api/v1/alerts':            1,
  '/api/v1/decisions':         2,
  '/api/v1/defense-actions':   2,
  '/api/v1/federation':        3,
  '/api/v1/soc/analyze':       5,
  '/api/v1/soc/posture':       1,
  '/api/soc/dashboard':        1,
  '/api/growth':               1,
};

// ─────────────────────────────────────────────────────────────────────────────
// USAGE TRACKING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Record an API call in D1 and KV usage counter
 * @param {object} env
 * @param {string} apiKey - user API key
 * @param {string} email - user email (resolved from key)
 * @param {string} endpoint - request path
 * @param {number} statusCode - response status
 * @param {number} latencyMs - response time
 */
export async function recordApiUsage(env, apiKey, email, endpoint, statusCode, latencyMs = 0) {
  const weight    = getEndpointWeight(endpoint);
  const dateKey   = todayKey();
  const monthKey  = monthKeyStr();
  const kvDayKey  = `api:usage:${apiKey}:${dateKey}`;
  const kvMonthKey= `api:usage:${apiKey}:month:${monthKey}`;

  // ── KV atomic increment for rate limiting ──
  try {
    const [dayVal, monthVal] = await Promise.all([
      env.SECURITY_HUB_KV?.get(kvDayKey),
      env.SECURITY_HUB_KV?.get(kvMonthKey),
    ]);

    const newDay   = (parseInt(dayVal   || '0', 10)) + weight;
    const newMonth = (parseInt(monthVal || '0', 10)) + weight;

    await Promise.all([
      env.SECURITY_HUB_KV?.put(kvDayKey,   String(newDay),   { expirationTtl: 86400  }),
      env.SECURITY_HUB_KV?.put(kvMonthKey, String(newMonth),  { expirationTtl: 2592000 }),
    ]);
  } catch {
    // KV not available — continue
  }

  // ── D1 async log ── (id is INTEGER PRIMARY KEY AUTOINCREMENT — never
  // supply one; api_usage_log has no `api_key` or `weight` column, only
  // `api_key_id` — the weighted counts above are what KV rate-limiting
  // actually reads, this D1 row is a secondary audit-trail entry)
  try {
    await env.DB.prepare(`
      INSERT INTO api_usage_log (api_key_id, email, endpoint, status_code, latency_ms, logged_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(maskKey(apiKey), email || 'anon', endpoint, statusCode, latencyMs).run();
  } catch {
    // Non-blocking
  }
}

/**
 * Get current usage counts for an API key
 */
export async function getUsageCounts(env, apiKey) {
  const dateKey  = todayKey();
  const monthKey = monthKeyStr();

  try {
    const [dayVal, monthVal] = await Promise.all([
      env.SECURITY_HUB_KV?.get(`api:usage:${apiKey}:${dateKey}`),
      env.SECURITY_HUB_KV?.get(`api:usage:${apiKey}:month:${monthKey}`),
    ]);

    return {
      today:       parseInt(dayVal   || '0', 10),
      this_month:  parseInt(monthVal || '0', 10),
    };
  } catch {
    return { today: 0, this_month: 0 };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a request is within rate limits
 * @param {object} env
 * @param {string} apiKey
 * @param {string} plan - 'free' | 'starter' | 'pro' | 'enterprise'
 * @param {string} endpoint
 * @returns {{ allowed: boolean, reason?, retry_after?, upgrade_cta? }}
 */
export async function checkRateLimit(env, apiKey, plan, endpoint) {
  const quotas = API_QUOTAS[plan] || API_QUOTAS.free;

  // Free plan — block all API access
  if (quotas.daily === 0) {
    return {
      allowed:     false,
      reason:      'api_not_available_on_free',
      upgrade_cta: {
        message: 'API access requires Starter plan or above.',
        upgrade_url: 'https://cyberdudebivash.in/pricing',
        plans:   ['starter', 'pro', 'enterprise'],
      },
    };
  }

  // Unlimited plan
  if (quotas.daily === -1) {
    return { allowed: true };
  }

  const { today, this_month } = await getUsageCounts(env, apiKey);

  // Daily limit check
  if (today >= quotas.daily) {
    return {
      allowed:     false,
      reason:      'daily_limit_reached',
      used:        today,
      limit:       quotas.daily,
      retry_after: secondsUntilMidnight(),
      upgrade_cta: buildUpgradeCTA(plan, 'daily_limit_reached', today, quotas.daily),
    };
  }

  // Monthly limit check
  if (this_month >= quotas.monthly) {
    return {
      allowed:     false,
      reason:      'monthly_limit_reached',
      used:        this_month,
      limit:       quotas.monthly,
      retry_after: secondsUntilMonthEnd(),
      upgrade_cta: buildUpgradeCTA(plan, 'monthly_limit_reached', this_month, quotas.monthly),
    };
  }

  // Per-minute rate limit (simple sliding check via KV)
  if (quotas.rate_per_min > 0) {
    const minKey = `api:rate:${apiKey}:${minuteKey()}`;
    const minVal = await env.SECURITY_HUB_KV?.get(minKey).catch(() => null);
    const minCount = parseInt(minVal || '0', 10);

    if (minCount >= quotas.rate_per_min) {
      return {
        allowed:     false,
        reason:      'rate_limit_exceeded',
        retry_after: 60,
        limit:       quotas.rate_per_min,
        upgrade_cta: { message: `Upgrade for higher rate limits. Current: ${quotas.rate_per_min} req/min` },
      };
    }

    // Increment per-minute counter
    await env.SECURITY_HUB_KV?.put(minKey, String(minCount + 1), { expirationTtl: 60 }).catch(() => {});
  }

  return {
    allowed: true,
    remaining_today:    quotas.daily - today,
    remaining_month:    quotas.monthly - this_month,
    quota_daily:        quotas.daily,
    quota_monthly:      quotas.monthly,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// BILLING HOOKS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calculate overage charges for a billing period
 * @param {string} plan
 * @param {number} totalCalls - calls this month
 * @returns {{ overage_calls: number, overage_charge_inr: number }}
 */
export function calculateOverage(plan, totalCalls) {
  const quotas = API_QUOTAS[plan] || API_QUOTAS.free;
  if (quotas.monthly === -1 || quotas.monthly === 0) {
    return { overage_calls: 0, overage_charge_inr: 0 };
  }

  const overageCalls = Math.max(0, totalCalls - quotas.monthly);
  const pricePerK    = OVERAGE_PRICING[plan] || 5;
  const chargeINR    = Math.ceil(overageCalls / 1000) * pricePerK;

  return {
    overage_calls:      overageCalls,
    overage_charge_inr: chargeINR,
    price_per_1000:     pricePerK,
  };
}

/**
 * Build a Razorpay payment link payload for an upgrade
 * (Returns payload — actual Razorpay API call happens client-side or via webhook)
 */
export function buildRazorpayPayload(email, plan, billingCycle = 'monthly') {
  const PLAN_PRICES = {
    starter:    { monthly: 99900,  annual: 479900  },  // paise
    pro:        { monthly: 149900, annual: 1439900 },
    enterprise: { monthly: 499900, annual: 4799900 },
  };

  const prices  = PLAN_PRICES[plan];
  if (!prices) return null;

  const amount  = billingCycle === 'annual' ? prices.annual : prices.monthly;
  const period  = billingCycle === 'annual' ? 'year' : 'month';

  return {
    type:        'link',
    amount,
    currency:    'INR',
    description: `Sentinel APEX ${plan.toUpperCase()} — ${billingCycle}`,
    customer:    { email },
    notify:      { email: true },
    reminder_enable: true,
    notes: {
      plan,
      billing_cycle: billingCycle,
      product:       'sentinel-apex',
      email,
    },
    callback_url:    `https://cyberdudebivash.in/api/billing/callback`,
    callback_method: 'get',
  };
}

/**
 * Handle a successful payment webhook (Razorpay → Worker)
 * Updates lead plan in D1
 */
export async function handlePaymentSuccess(env, webhookData = {}) {
  const { email, plan, payment_id, order_id } = webhookData;

  if (!email || !plan) {
    return { success: false, error: 'missing_fields' };
  }

  const now = new Date().toISOString();

  try {
    // Upgrade lead plan
    await env.DB.prepare(`
      UPDATE leads SET plan = ?, converted_at = ?, updated_at = ?, funnel_stage = 'converted'
      WHERE email = ?
    `).bind(plan, now, now, email).run();

    // Log billing event
    await env.DB.prepare(`
      INSERT INTO billing_events (id, email, plan, payment_id, order_id, event_type, created_at)
      VALUES (?, ?, ?, ?, ?, 'payment_success', ?)
    `).bind(crypto.randomUUID(), email, plan, payment_id || '', order_id || '', now).run();

    // Provision API key if not exists
    await provisionApiKey(env, email, plan);

    return { success: true, plan, email };
  } catch (err) {
    console.error('[apiRevenueEngine] handlePaymentSuccess error:', err.message);
    return { success: false, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// API KEY MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Provision or rotate an API key for a user
 */
export async function provisionApiKey(env, email, plan) {
  const apiKey  = `sap_${crypto.randomUUID().replace(/-/g, '').slice(0, 32)}`;
  const now     = new Date().toISOString();
  const keyHash = await hashApiKey(apiKey);
  const prefix  = getKeyPrefix(apiKey);
  const tier    = (plan || 'starter').toUpperCase();

  try {
    // api_keys has no UNIQUE constraint on email — ON CONFLICT(email) here
    // previously was rejected by SQLite outright (CAP-DEVPORTAL-004). Fixed
    // without a schema migration: look up any existing active row for this
    // email first, then UPDATE or INSERT explicitly. Also: `plan`/`updated_at`
    // are not real columns (the table has `tier`, no `updated_at`), and
    // `key_hash`/`key_prefix` are NOT NULL with no default — every INSERT
    // must supply them or the row throws.
    const existing = await env.DB.prepare(
      `SELECT id, key_hash FROM api_keys WHERE email = ? AND active = 1 LIMIT 1`
    ).bind(email).first();

    if (existing) {
      await env.DB.prepare(
        `UPDATE api_keys SET tier = ?, api_key = ?, key_hash = ?, key_prefix = ? WHERE id = ?`
      ).bind(tier, keyHash, keyHash, prefix, existing.id).run();
      // Invalidate the rotated-away key's own KV cache entry. Without this,
      // the OLD key keeps authenticating (via KV, bypassing the D1 row this
      // UPDATE just repointed to the NEW hash) for up to its 1-year TTL.
      if (existing.key_hash && existing.key_hash !== keyHash) {
        try { await env.SECURITY_HUB_KV?.delete(`apikey:${existing.key_hash}`); } catch { /* best-effort cache invalidation */ }
      }
    } else {
      await env.DB.prepare(`
        INSERT INTO api_keys (id, email, tier, api_key, key_hash, key_prefix, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
      `).bind(crypto.randomUUID(), email, tier, keyHash, keyHash, prefix, now).run();
    }

    // Cache under the HASHED KV name (raw key never appears in the key-space)
    await env.SECURITY_HUB_KV?.put(`apikey:${keyHash}`, JSON.stringify({ email, plan: tier.toLowerCase() }), {
      expirationTtl: 60 * 60 * 24 * 365, // 1 year
    });

    return { api_key: apiKey };
  } catch (err) {
    console.error('[apiRevenueEngine] provisionApiKey error:', err.message);
    return null;
  }
}

/**
 * Resolve an API key to { email, plan } — checks KV first, then D1
 */
export async function resolveApiKey(env, apiKey) {
  if (!apiKey) return null;

  const keyHash = await hashApiKey(apiKey);

  // KV fast path — hashed name first, then transitional legacy (raw-named) entry
  try {
    const cached = await env.SECURITY_HUB_KV?.get(`apikey:${keyHash}`)
                ?? await env.SECURITY_HUB_KV?.get(`apikey:${apiKey}`);
    if (cached) return JSON.parse(cached);
  } catch {}

  // D1 fallback — match the hashed row (new) or a legacy plaintext row (transition)
  try {
    const dbRow = await env.DB.prepare(
      `SELECT email, tier FROM api_keys WHERE api_key IN (?, ?) AND active = 1 LIMIT 1`
    ).bind(keyHash, apiKey).first();

    if (dbRow) {
      const row = { email: dbRow.email, plan: (dbRow.tier || '').toLowerCase() };
      // Re-cache under the hashed name so future lookups skip the legacy path
      await env.SECURITY_HUB_KV?.put(`apikey:${keyHash}`, JSON.stringify(row), {
        expirationTtl: 3600,
      }).catch(() => {});
      return row;
    }
  } catch {}

  return null;
}

/**
 * Get API usage summary for a user (for dashboard display)
 */
export async function getApiUsageSummary(env, email, plan) {
  const quotas = API_QUOTAS[plan] || API_QUOTAS.free;

  // Get D1 usage for this month
  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);

  try {
    // api_usage_log has no `weight` column (each row is one logged call) —
    // COUNT(*) gives an honest, if unweighted, call count rather than the
    // previous COALESCE(SUM(weight)) query, which always threw "no such
    // column: weight" and made this endpoint 500 on every call.
    const [monthTotal, dayTotal, endpointBreakdown] = await Promise.all([
      env.DB.prepare(`
        SELECT COUNT(*) as total
        FROM api_usage_log
        WHERE email = ? AND logged_at >= ?
      `).bind(email, monthStart.toISOString()).first(),

      env.DB.prepare(`
        SELECT COUNT(*) as total
        FROM api_usage_log
        WHERE email = ? AND logged_at >= date('now')
      `).bind(email).first(),

      env.DB.prepare(`
        SELECT endpoint, COUNT(*) as calls
        FROM api_usage_log
        WHERE email = ? AND logged_at >= ?
        GROUP BY endpoint
        ORDER BY calls DESC
        LIMIT 10
      `).bind(email, monthStart.toISOString()).all(),
    ]);

    const monthCalls = monthTotal?.total || 0;
    const dayCalls   = dayTotal?.total   || 0;
    const overage    = calculateOverage(plan, monthCalls);

    return {
      plan,
      quota_daily:      quotas.daily,
      quota_monthly:    quotas.monthly,
      used_today:       dayCalls,
      used_this_month:  monthCalls,
      remaining_today:  quotas.daily === -1 ? -1 : Math.max(0, quotas.daily - dayCalls),
      remaining_month:  quotas.monthly === -1 ? -1 : Math.max(0, quotas.monthly - monthCalls),
      usage_pct_month:  quotas.monthly > 0 ? Math.min(100, Math.round((monthCalls / quotas.monthly) * 100)) : 0,
      overage,
      top_endpoints:    endpointBreakdown.results || [],
    };
  } catch (err) {
    return { error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function getEndpointWeight(endpoint) {
  for (const [pattern, weight] of Object.entries(ENDPOINT_WEIGHTS)) {
    if (endpoint?.startsWith(pattern)) return weight;
  }
  return 1;
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function monthKeyStr() {
  return new Date().toISOString().slice(0, 7);
}

function minuteKey() {
  const d = new Date();
  return `${d.toISOString().slice(0, 13)}:${Math.floor(d.getMinutes())}`;
}

function secondsUntilMidnight() {
  const now = new Date();
  const midnight = new Date(now);
  midnight.setUTCHours(24, 0, 0, 0);
  return Math.floor((midnight - now) / 1000);
}

function secondsUntilMonthEnd() {
  const now = new Date();
  const end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return Math.floor((end - now) / 1000);
}

function buildUpgradeCTA(plan, reason, used, limit) {
  const next = { free: 'starter', starter: 'pro', pro: 'enterprise' };
  const nextPlan = next[plan] || 'enterprise';

  return {
    message:     `You've used ${used}/${limit} API calls. Upgrade to ${nextPlan.toUpperCase()} for higher limits.`,
    reason,
    upgrade_url: `https://cyberdudebivash.in/pricing?plan=${nextPlan}&utm_source=api&utm_medium=rate_limit`,
    next_plan:   nextPlan,
  };
}
