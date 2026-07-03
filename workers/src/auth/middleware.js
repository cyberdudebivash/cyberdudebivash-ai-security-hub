/**
 * CYBERDUDEBIVASH AI Security Hub — Auth Middleware v5.0
 * Unified: JWT Bearer + API Key resolution
 * Priority: JWT (authenticated user) → API Key (service access) → IP fallback (free tier)
 * All paths return a normalized authCtx object
 */

import { verifyJWT, extractBearerToken } from './jwt.js';
import { resolveApiKeyFromDB, trackApiKeyUsage, checkDailyQuota, TIER_LIMITS } from './apiKeys.js';

export const UPGRADE_URL   = 'https://tools.cyberdudebivash.com/#pricing';
export const CONTACT_EMAIL = 'contact@cyberdudebivash.in';

// ─── Brute-force check for login ─────────────────────────────────────────────
export async function checkLoginRateLimit(db, email, ip) {
  if (!db) return { allowed: true };
  const window = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  try {
    const [emailAttempts, ipAttempts] = await Promise.all([
      db.prepare(
        `SELECT COUNT(*) as c FROM login_attempts
         WHERE email = ? AND success = 0 AND attempted_at > ?`
      ).bind(email.toLowerCase(), window).first(),
      db.prepare(
        `SELECT COUNT(*) as c FROM login_attempts
         WHERE ip_address = ? AND success = 0 AND attempted_at > ?`
      ).bind(ip, window).first(),
    ]);
    const emailCount = emailAttempts?.c ?? 0;
    const ipCount    = ipAttempts?.c ?? 0;
    if (emailCount >= 10 || ipCount >= 20) {
      return { allowed: false, reason: 'Too many failed login attempts. Try again in 15 minutes.' };
    }
    return { allowed: true };
  } catch (e) {
    console.error('[Auth] checkLoginRateLimit DB failed — allowing request', e?.message);
    return { allowed: true };
  }
}

// ─── Record login attempt ─────────────────────────────────────────────────────
export async function recordLoginAttempt(db, email, ip, success) {
  if (!db) return;
  try {
    await db.prepare(
      `INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)`
    ).bind(email.toLowerCase(), ip || null, success ? 1 : 0).run();
  } catch (e) {
    console.warn('[Auth] recordLoginAttempt failed — brute-force counter not updated', e?.message);
  }
}

// ─── Build auth context from JWT ──────────────────────────────────────────────
async function resolveFromJWT(request, env) {
  const token = extractBearerToken(request);
  if (!token) return null;

  const secret = env?.JWT_SECRET;
  if (!secret) return null;

  const payload = await verifyJWT(token, secret);
  if (!payload || payload.type !== 'access') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    console.warn('[Auth] JWT validation failed', { ip, reason: !payload ? 'verify_failed' : 'wrong_type' });
    return null;
  }

  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  return {
    authenticated: true,
    method:        'jwt',
    identity:      `user:${payload.sub}`,
    user_id:       payload.sub,
    email:         payload.email,
    tier:          payload.tier || 'FREE',
    limits:        TIER_LIMITS[payload.tier] || TIER_LIMITS.FREE,
    label:         `${payload.tier} User`,
    key_id:        null,
    ip,
  };
}

// ─── Build auth context from API key ─────────────────────────────────────────
async function resolveFromApiKey(request, env) {
  const rawKey = request.headers.get('x-api-key') ||
                 request.headers.get('X-Api-Key');
  if (!rawKey || !rawKey.startsWith('cdb_')) return null;

  const db = env?.DB;
  if (!db) return null;

  const keyRow = await resolveApiKeyFromDB(db, rawKey);
  if (!keyRow) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const keyPrefix = rawKey.slice(0, 12) + '***';
    console.warn('[Auth] Invalid API key rejected', { ip, keyPrefix });
    return { authenticated: false, method: 'api_key', error: 'invalid_key' };
  }

  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  return {
    authenticated: true,
    method:        'api_key',
    identity:      `key:${keyRow.key_prefix}`,
    user_id:       keyRow.user_id,
    email:         keyRow.email,
    tier:          keyRow.tier,
    limits:        TIER_LIMITS[keyRow.tier] || TIER_LIMITS.FREE,
    label:         `${keyRow.tier} API Key`,
    key_id:        keyRow.id,
    daily_limit:   keyRow.daily_limit,
    ip,
    _key_row:      keyRow, // internal — used for quota check
  };
}

// ─── Auth-context normalization ───────────────────────────────────────────────
// Consumers across the codebase read camelCase `userId`/`keyId`, while the
// resolvers populate snake_case `user_id`/`key_id`. Without these aliases, org
// CRUD, RBAC, anomaly detection and request audit logging silently read
// `undefined`. Additive only — snake_case fields are left untouched.
function withAuthAliases(ctx) {
  if (ctx && typeof ctx === 'object') {
    if (ctx.userId === undefined) ctx.userId = ctx.user_id ?? null;
    if (ctx.keyId  === undefined) ctx.keyId  = ctx.key_id  ?? null;
    // ── Tenant isolation (root fix) ──────────────────────────────────────────
    // ~15 handlers scope customer data with `authCtx.org_id || 'default'`. Because
    // resolveAuthV5 never set org_id, EVERY authenticated user collapsed into one
    // shared 'default' tenant — a cross-tenant leak (confirmed on SOC cases). Give
    // each authenticated principal a stable per-user tenant id so those handlers
    // isolate correctly. A real org id (from org membership) always wins; an
    // anonymous IP-fallback principal (no user_id) intentionally keeps no org_id so
    // its own 'default' applies. Nothing seeds shared 'default' data, so this only
    // tightens isolation — it never hides another tenant's rows.
    if (ctx.org_id == null && ctx.authenticated) {
      const uid = ctx.user_id ?? ctx.userId;
      if (uid) ctx.org_id = `u:${uid}`;
    }
  }
  return ctx;
}

// ─── Master auth resolver ─────────────────────────────────────────────────────
export async function resolveAuthV5(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  // 0. Admin key — env.ADMIN_KEY bypass (ENTERPRISE tier, all features unlocked)
  if (env.ADMIN_KEY) {
    const rawKey = request.headers.get('x-api-key') ||
                   request.headers.get('x-admin-secret') ||
                   request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || '';
    if (rawKey === env.ADMIN_KEY) {
      return withAuthAliases({
        authenticated: true,
        method:        'admin_key',
        identity:      'admin',
        user_id:       'admin',
        email:         'admin@cyberdudebivash.com',
        tier:          'ENTERPRISE',
        limits:        TIER_LIMITS.ENTERPRISE ?? { daily_limit: -1 },
        label:         'Admin (ENTERPRISE)',
        key_id:        'admin',
        ip,
        isAdmin:       true,
      });
    }
  }

  // 1. Try JWT (authenticated user)
  const jwtCtx = await resolveFromJWT(request, env);
  if (jwtCtx) return withAuthAliases(jwtCtx);

  // 2. Try API key (service/developer access)
  const keyCtx = await resolveFromApiKey(request, env);
  if (keyCtx) return withAuthAliases(keyCtx);

  // 3. IP fallback (free tier, keyless access)
  return withAuthAliases({
    authenticated: true,
    method:        'ip_fallback',
    identity:      `ip:${ip}`,
    user_id:       null,
    email:         null,
    tier:          'FREE',
    limits:        TIER_LIMITS.FREE,
    label:         'Free (IP)',
    key_id:        null,
    ip,
  });
}

// ─── Track usage + enforce quota (call AFTER auth, BEFORE handler) ────────────
export async function enforceQuota(env, authCtx, module) {
  const tier  = authCtx.tier || 'FREE';
  const limit = TIER_LIMITS[tier] || TIER_LIMITS.FREE;

  // Enterprise: unlimited
  if (limit.daily_limit === -1) return { allowed: true, tier, remaining: -1 };

  // API key: use D1 quota
  if (authCtx.method === 'api_key' && authCtx.key_id && env?.DB) {
    const quota = await checkDailyQuota(env.DB, authCtx.key_id, authCtx.daily_limit ?? limit.daily_limit);
    if (!quota.allowed) {
      return { allowed: false, reason: 'daily_limit_reached', tier, remaining: 0, limit: quota.limit };
    }
    // Track usage (fire-and-forget)
    trackApiKeyUsage(env.DB, authCtx.key_id, authCtx.user_id, module).catch(() => {});
    return { allowed: true, tier, remaining: quota.remaining, used: quota.used };
  }

  // JWT user: use KV-backed rate limiting (existing system)
  // IP fallback: use KV-backed rate limiting (existing system)
  // (Handled by the existing checkRateLimitV2 in rateLimit.js)
  return { allowed: true, tier, remaining: limit.daily_limit };
}

// ─── Standard 401 responses ──────────────────────────────────────────────────
export function unauthorized(reason = 'missing') {
  const msgs = {
    missing:    { error: 'Authentication required', hint: 'Provide Authorization: Bearer <token> or x-api-key header' },
    invalid:    { error: 'Invalid credentials', hint: 'Token expired or key invalid — re-authenticate' },
    invalid_key:{ error: 'Invalid API key', hint: 'Check your API key or generate a new one at tools.cyberdudebivash.com' },
    expired:    { error: 'Token expired', hint: 'Use /api/auth/refresh with your refresh token' },
    suspended:  { error: 'Account suspended', hint: 'Contact contact@cyberdudebivash.in' },
  };
  return Response.json({
    ...(msgs[reason] || msgs.missing),
    upgrade_url: UPGRADE_URL,
    contact:     CONTACT_EMAIL,
    docs:        'https://cyberdudebivash.in/docs',
  }, { status: 401 });
}

// ─── Real-principal check ─────────────────────────────────────────────────────
// resolveAuthV5 sets `authenticated: true` even for the anonymous IP-fallback
// tier (user_id === null), so `authCtx.authenticated` means "not an invalid
// API key" — NOT "logged in". Every route that requires a real logged-in
// principal (JWT user, API key, or admin) must gate on this instead.
export function isRealUser(authCtx) {
  if (!authCtx || authCtx.authenticated !== true) return false;
  if (authCtx.isAdmin === true) return true;
  const uid = authCtx.user_id ?? authCtx.userId;
  return uid !== null && uid !== undefined && uid !== '';
}

// ─── Owner identity ───────────────────────────────────────────────────────────
// The internal sales/CRM/proposal/funnel tooling is single-tenant (the owner's own
// business data). "Owner" = the ADMIN_KEY bypass (isAdmin) OR a logged-in user whose
// email matches the configured owner address(es). Default owner email can be
// overridden/extended via env.OWNER_EMAILS (comma-separated).
export function ownerEmails(env) {
  const raw = (env && env.OWNER_EMAILS) || 'bivash@cyberdudebivash.com';
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}
export function isOwner(authCtx, env) {
  if (!authCtx) return false;
  if (authCtx.isAdmin) return true;
  const email = String(authCtx.email || '').toLowerCase();
  return !!email && ownerEmails(env).includes(email);
}

// ─── Standard 403 (owner-only resource) ──────────────────────────────────────
export function forbidden(message = 'This resource is restricted to the platform owner.') {
  return Response.json({
    error:   'Forbidden',
    message,
    contact: CONTACT_EMAIL,
  }, { status: 403 });
}

// ─── Standard 429 (quota exceeded) ───────────────────────────────────────────
export function quotaExceeded(result) {
  return Response.json({
    error:        'Quota exceeded',
    reason:       result.reason,
    tier:         result.tier,
    remaining:    result.remaining,
    limit:        result.limit,
    message:      `Daily scan limit reached for ${result.tier} tier`,
    upgrade_url:  UPGRADE_URL,
    upgrade_benefits: {
      PRO:        '500 scans/day, priority processing, 90-day history',
      ENTERPRISE: 'Unlimited scans, dedicated support, SLA, custom integrations',
    },
  }, { status: 429, headers: { 'Retry-After': '86400' } });
}
