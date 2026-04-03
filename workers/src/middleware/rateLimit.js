/**
 * CYBERDUDEBIVASH AI Security Hub — Rate Limiting Engine v2
 * Per-identity (key or IP) + per-endpoint + burst protection
 * Backed by Cloudflare KV — fails open on KV unavailability
 */

import { TIERS } from './auth.js';

// ─── KV Key Builders ──────────────────────────────────────────────────────────
function dayStamp()    { return new Date().toISOString().slice(0, 10); }         // 2026-04-03
function hourStamp()   { return new Date().toISOString().slice(0, 13); }         // 2026-04-03T14
function minuteStamp() { return new Date().toISOString().slice(0, 16); }         // 2026-04-03T14:07

const kvDayKey     = (id, ep) => `rl:day:${id}:${ep}:${dayStamp()}`;
const kvBurstKey   = (id, ep) => `rl:burst:${id}:${ep}:${minuteStamp()}`;
const kvGlobalDay  = (id)     => `rl:day:${id}:all:${dayStamp()}`;
const kvAbuseKey   = (id)     => `abuse:${id}`;
const kvStatsKey   = (ep)     => `stats:ep:${ep}:${dayStamp()}`;

// ─── Abuse Detection ──────────────────────────────────────────────────────────
async function isAbusive(env, identity) {
  if (!env?.SECURITY_HUB_KV) return false;
  try {
    const flag = await env.SECURITY_HUB_KV.get(kvAbuseKey(identity));
    return flag === 'banned';
  } catch { return false; }
}

// ─── Atomic Counter (KV) ─────────────────────────────────────────────────────
async function increment(env, key, ttl) {
  if (!env?.SECURITY_HUB_KV) return 0;
  try {
    const cur = parseInt(await env.SECURITY_HUB_KV.get(key) || '0', 10);
    const next = cur + 1;
    await env.SECURITY_HUB_KV.put(key, String(next), { expirationTtl: ttl });
    return next;
  } catch { return 0; }
}

async function getCount(env, key) {
  if (!env?.SECURITY_HUB_KV) return 0;
  try { return parseInt(await env.SECURITY_HUB_KV.get(key) || '0', 10); }
  catch { return 0; }
}

// ─── Main Rate Limit Check ────────────────────────────────────────────────────
export async function checkRateLimitV2(env, authCtx, endpoint) {
  const identity    = authCtx.identity;
  const tier        = authCtx.tier || 'FREE';
  const limits      = TIERS[tier] || TIERS.FREE;
  const dailyLimit  = limits.daily_limit;
  const burstLimit  = limits.burst_per_min;

  // Enterprise: unlimited (skip KV checks)
  if (dailyLimit === -1) {
    await trackStats(env, endpoint);
    return { allowed: true, tier, remaining: 9999, reset: 'never' };
  }

  if (!env?.SECURITY_HUB_KV) {
    return { allowed: true, tier, remaining: dailyLimit, reset: 'unknown' };
  }

  // Abuse check
  if (await isAbusive(env, identity)) {
    return { allowed: false, reason: 'banned', tier, remaining: 0, reset: 'contact_support' };
  }

  // Burst check (per minute)
  const burstCount = await getCount(env, kvBurstKey(identity, endpoint));
  if (burstCount >= burstLimit) {
    return { allowed: false, reason: 'burst_exceeded', tier, remaining: 0, reset: 'in 60 seconds', retry_after: 60 };
  }

  // Daily check
  const dailyCount = await getCount(env, kvDayKey(identity, endpoint));
  if (dailyCount >= dailyLimit) {
    return { allowed: false, reason: 'daily_limit_reached', tier, remaining: 0, reset: 'tomorrow UTC midnight', retry_after: 86400 };
  }

  // Global daily across all endpoints
  const globalCount = await getCount(env, kvGlobalDay(identity));
  const globalCap   = dailyLimit * 3; // allow spread across endpoints
  if (globalCount >= globalCap && tier === 'FREE') {
    return { allowed: false, reason: 'global_daily_limit', tier, remaining: 0, reset: 'tomorrow UTC midnight', retry_after: 86400 };
  }

  // Passed — increment counters (fire-and-forget)
  Promise.all([
    increment(env, kvBurstKey(identity, endpoint), 60),
    increment(env, kvDayKey(identity, endpoint), 86400),
    increment(env, kvGlobalDay(identity), 86400),
    trackStats(env, endpoint),
  ]).catch(() => {});

  const remaining = dailyLimit - dailyCount - 1;
  return { allowed: true, tier, remaining: Math.max(0, remaining), reset: 'tomorrow UTC midnight' };
}

// ─── Stats Tracking (fire-and-forget) ────────────────────────────────────────
async function trackStats(env, endpoint) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    await Promise.all([
      increment(env, kvStatsKey(endpoint), 90000),
      increment(env, `stats:total:${endpoint}`, 0),
      increment(env, `stats:daily:all:${dayStamp()}`, 90000),
    ]);
  } catch {}
}

// ─── Standard 429 Response ───────────────────────────────────────────────────
export function rateLimitResponse(result, module) {
  const reasons = {
    burst_exceeded:       'Too many requests — slow down',
    daily_limit_reached:  `Daily limit reached for ${module} on Free tier`,
    global_daily_limit:   'Global daily limit reached',
    banned:               'Access suspended due to abuse',
  };
  return Response.json({
    error: 'Rate limit exceeded',
    reason: result.reason,
    message: reasons[result.reason] || 'Rate limit exceeded',
    tier: result.tier,
    remaining: result.remaining,
    reset: result.reset,
    retry_after: result.retry_after || 86400,
    upgrade_url: 'https://cyberdudebivash.in/#pricing',
    upgrade_benefits: {
      PRO:        '500 scans/day, 20 req/min burst, priority support',
      ENTERPRISE: 'Unlimited scans, 60 req/min burst, SLA, dedicated support',
    },
  }, {
    status: 429,
    headers: {
      'Retry-After': String(result.retry_after || 86400),
      'X-RateLimit-Tier': result.tier,
      'X-RateLimit-Remaining': String(result.remaining),
    },
  });
}

// ─── Inject Rate Limit Headers into Response ─────────────────────────────────
export function injectRateLimitHeaders(response, rlResult) {
  const h = new Headers(response.headers);
  h.set('X-RateLimit-Tier',      rlResult.tier || 'FREE');
  h.set('X-RateLimit-Remaining', String(rlResult.remaining ?? '?'));
  h.set('X-RateLimit-Reset',     rlResult.reset || 'unknown');
  return new Response(response.body, { status: response.status, headers: h });
}
