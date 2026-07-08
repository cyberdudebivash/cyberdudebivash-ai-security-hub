/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Discount Coupon System v2.0
 *
 * Server-authoritative discount codes for the live checkout flow
 * (handlers/payments.js handleCreateOrder / handleRazorpayWebhook). The
 * discount is always applied to the server-computed price before the
 * Razorpay order is created — a client can never supply its own amount or
 * discount percentage.
 *
 * Design notes (read before extending):
 *
 * - `id` and `code` are the same value. This is a small, low-volume,
 *   admin-managed table — a separate synthetic id would only add complexity
 *   (two unique-identifier systems to keep in sync) with no real benefit at
 *   this scale. Every response includes both fields for API-shape
 *   compatibility with clients that expect a distinct `id`.
 * - `discountType` supports 'percentage' and 'fixed' end-to-end (both
 *   actually reduce the Razorpay charge in handleCreateOrder). 'trial_extension'
 *   and 'upgrade_promo' are accepted and stored/validated, but there is no
 *   consuming code path for them yet — the platform's only trial mechanism
 *   today is MSSP partner onboarding (handlers/msspOnboardingHandler.js
 *   handleMsspTrial), which is independent of this coupon system. Wiring
 *   trial-extension/upgrade-promo redemption into a real flow is future work,
 *   not silently faked here.
 * - `stackable` is stored but always behaves as non-stackable in practice:
 *   handleCreateOrder accepts exactly one `coupon_code` field, so there is no
 *   way to apply two coupons to one order regardless of this flag. Recorded
 *   for forward-compatibility if multi-coupon checkout is ever built.
 * - `applicableApis` is stored but not enforced by any code path — there is
 *   no separate API-tier billing flow in this codebase to enforce it against.
 * - Tenant isolation: this is a single global coupon catalog (there is no
 *   multi-tenant "organization" concept at the coupon layer). Isolation here
 *   means (a) admin management is isAdmin-gated, (b) per-user limits and
 *   first-purchase checks are scoped by the redeeming customer's own email,
 *   never leaking another customer's redemption state.
 *
 * Tables (self-bootstrapping — CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD
 * COLUMN wrapped in try/catch, same pattern as msspRevenue.js/msspTenantPlatform.js
 * — the discount_coupons table already existed in production with the v1
 * schema before this file was extended, so this uses real ALTER TABLE
 * migrations, not just a fresh CREATE TABLE):
 *   discount_coupons    — coupon definitions (admin-managed)
 *   coupon_redemptions  — one row per order a coupon was applied to
 */

import { ok, fail } from './response.js';

// No module-level "ready" cache here (unlike msspRevenue.js's
// _revenueTablesReady): every statement below is already an idempotent
// no-op once the table/column exists (CREATE TABLE IF NOT EXISTS / ALTER
// TABLE ADD COLUMN wrapped in try/catch), and a ready-flag would only skip
// re-running them within one warm isolate — it buys nothing in production
// but silently breaks tests that spin up a fresh D1 per test case.
async function ensureCouponTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS discount_coupons (
    code            TEXT PRIMARY KEY,
    discount_pct    INTEGER NOT NULL DEFAULT 0,
    applies_to      TEXT NOT NULL DEFAULT 'all',
    max_redemptions INTEGER,
    redeemed_count  INTEGER NOT NULL DEFAULT 0,
    expires_at      TEXT,
    active          INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS coupon_redemptions (
    razorpay_order_id  TEXT PRIMARY KEY,
    code               TEXT NOT NULL,
    module             TEXT,
    original_amount    INTEGER NOT NULL,
    discounted_amount  INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    created_at         TEXT DEFAULT (datetime('now'))
  )`).run();

  // v2.0 enterprise field set — ALTER TABLE ADD COLUMN, each independently
  // caught since D1/SQLite has no "ADD COLUMN IF NOT EXISTS".
  const couponColumns = [
    `description TEXT`,
    `discount_type TEXT NOT NULL DEFAULT 'percentage'`,
    `discount_value INTEGER`,
    `currency TEXT NOT NULL DEFAULT 'INR'`,
    `applicable_plans TEXT`,
    `applicable_products TEXT`,
    `applicable_apis TEXT`,
    `enterprise_only INTEGER NOT NULL DEFAULT 0`,
    `first_purchase_only INTEGER NOT NULL DEFAULT 0`,
    `max_uses_per_user INTEGER`,
    `start_date TEXT`,
    `stackable INTEGER NOT NULL DEFAULT 0`,
    `minimum_purchase INTEGER`,
    `metadata TEXT NOT NULL DEFAULT '{}'`,
    `updated_at TEXT`,
  ];
  for (const col of couponColumns) {
    try { await db.prepare(`ALTER TABLE discount_coupons ADD COLUMN ${col}`).run(); } catch (_) { /* already exists */ }
  }
  const redemptionColumns = [
    `email TEXT`,
    `user_id TEXT`,
    `revoked INTEGER NOT NULL DEFAULT 0`,
    `revoked_at TEXT`,
    `revoked_reason TEXT`,
  ];
  for (const col of redemptionColumns) {
    try { await db.prepare(`ALTER TABLE coupon_redemptions ADD COLUMN ${col}`).run(); } catch (_) { /* already exists */ }
  }
}

// ── Public shape ───────────────────────────────────────────────────────────
function toPublicCoupon(row) {
  if (!row) return null;
  return {
    id: row.code,
    code: row.code,
    description: row.description || null,
    discountType: row.discount_type || 'percentage',
    discountValue: row.discount_value ?? row.discount_pct ?? 0,
    currency: row.currency || 'INR',
    applicablePlans: row.applicable_plans ? row.applicable_plans.split(',').map(s => s.trim()).filter(Boolean) : [],
    applicableProducts: row.applicable_products ? row.applicable_products.split(',').map(s => s.trim()).filter(Boolean) : [],
    applicableApis: row.applicable_apis ? row.applicable_apis.split(',').map(s => s.trim()).filter(Boolean) : [],
    enterpriseOnly: !!row.enterprise_only,
    firstPurchaseOnly: !!row.first_purchase_only,
    maxUses: row.max_redemptions ?? null,
    maxUsesPerUser: row.max_uses_per_user ?? null,
    usageCount: row.redeemed_count || 0,
    startDate: row.start_date || null,
    expiryDate: row.expires_at || null,
    active: !!row.active,
    stackable: !!row.stackable,
    minimumPurchase: row.minimum_purchase ?? null,
    metadata: (() => { try { return JSON.parse(row.metadata || '{}'); } catch { return {}; } })(),
    createdBy: row.created_by || null,
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
  };
}

// applicable_plans / applicable_products / legacy applies_to are unioned:
// if the coupon has ANY restriction list configured, the purchase must match
// at least one entry across all of them (module name or subscription plan
// key). No restriction lists configured at all -> applies to everything.
function couponAppliesTo(coupon, module, planKey) {
  const restrictionLists = [];
  if (coupon.applies_to && coupon.applies_to !== 'all') restrictionLists.push(coupon.applies_to);
  if (coupon.applicable_plans) restrictionLists.push(coupon.applicable_plans);
  if (coupon.applicable_products) restrictionLists.push(coupon.applicable_products);
  if (restrictionLists.length === 0) return true;

  const combined = restrictionLists.join(',').split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  const tags = [module, planKey].filter(Boolean).map(s => String(s).toUpperCase());
  return tags.some(t => combined.includes(t));
}

function isEnterpriseContext(authCtx, planKey) {
  return String(planKey || '').toUpperCase() === 'ENTERPRISE' || (authCtx?.tier || '').toUpperCase() === 'ENTERPRISE';
}

// ── IP-based abuse detection for invalid-coupon guessing ──────────────────
// Reuses the same KV rate-limit idiom as handlers/payments.js handlePaymentConfirm
// (max attempts per IP per hour) rather than a bespoke limiter. This guards the
// coupon namespace specifically against brute-force code discovery; the
// checkout endpoint itself already rate-limits order creation overall.
const MAX_INVALID_COUPON_ATTEMPTS_PER_HOUR = 10;
async function checkCouponAbuseRateLimit(env, ip) {
  if (!env.SECURITY_HUB_KV && !env.KV) return { blocked: false };
  const kv = env.SECURITY_HUB_KV || env.KV;
  const hour = new Date().toISOString().slice(0, 13);
  const key  = `rl:coupon_invalid:${ip}:${hour}`;
  const count = parseInt(await kv.get(key).catch(() => '0') || '0', 10);
  return { blocked: count >= MAX_INVALID_COUPON_ATTEMPTS_PER_HOUR, key, count, kv };
}
async function recordInvalidCouponAttempt({ blocked, key, count, kv }) {
  if (blocked || !kv || !key) return;
  await kv.put(key, String(count + 1), { expirationTtl: 3600 }).catch(() => {});
}

// ── Validate a coupon code against a specific purchase ───────────────────────
// opts: { module, planKey, authCtx, email, amountPaise, ip }
// Returns { valid: true, code, discountType, discountValue, discount_pct } or
// { valid: false, error, code: <machine code> }.
export async function validateCoupon(env, rawCode, opts = {}) {
  const { module, planKey, authCtx, email, amountPaise, ip } = opts;
  if (!env.DB) return { valid: false, error: 'Coupons unavailable', code: 'UNAVAILABLE' };
  const code = String(rawCode || '').trim().toUpperCase();
  if (!code) return { valid: false, error: 'No coupon code provided', code: 'MISSING_CODE' };

  await ensureCouponTables(env.DB);

  let rateLimitState = null;
  if (ip) {
    rateLimitState = await checkCouponAbuseRateLimit(env, ip);
    if (rateLimitState.blocked) {
      return { valid: false, error: 'Too many invalid coupon attempts. Try again later.', code: 'RATE_LIMITED' };
    }
  }

  const invalid = async (error, errCode) => {
    if (rateLimitState) await recordInvalidCouponAttempt(rateLimitState);
    return { valid: false, error, code: errCode };
  };

  const coupon = await env.DB.prepare(`SELECT * FROM discount_coupons WHERE code = ?`).bind(code).first().catch(() => null);
  if (!coupon) return invalid('Invalid coupon code', 'NOT_FOUND');
  if (!coupon.active) return invalid('This coupon is no longer active', 'INACTIVE');
  if (coupon.start_date && new Date(coupon.start_date).getTime() > Date.now()) {
    return invalid('This coupon is not active yet', 'NOT_STARTED');
  }
  if (coupon.expires_at && new Date(coupon.expires_at).getTime() < Date.now()) {
    return invalid('This coupon has expired', 'EXPIRED');
  }
  if (coupon.max_redemptions != null && coupon.redeemed_count >= coupon.max_redemptions) {
    return invalid('This coupon has reached its redemption limit', 'MAX_USES_REACHED');
  }
  if (!couponAppliesTo(coupon, module, planKey)) {
    return invalid('This coupon does not apply to the selected plan/product', 'NOT_APPLICABLE');
  }
  if (coupon.enterprise_only && !isEnterpriseContext(authCtx, planKey)) {
    return invalid('This coupon is restricted to Enterprise plans', 'ENTERPRISE_ONLY');
  }
  if (coupon.minimum_purchase != null && (amountPaise ?? 0) < coupon.minimum_purchase) {
    return invalid(`This coupon requires a minimum purchase of ₹${Math.round(coupon.minimum_purchase / 100)}`, 'MINIMUM_PURCHASE_NOT_MET');
  }
  if (email && coupon.first_purchase_only) {
    const priorPaid = await env.DB.prepare(
      `SELECT id FROM payments WHERE email = ? AND status = 'paid' LIMIT 1`
    ).bind(email).first().catch(() => null);
    if (priorPaid) return invalid('This coupon is only valid for first-time customers', 'FIRST_PURCHASE_ONLY');
  }
  if (email && coupon.max_uses_per_user != null) {
    const used = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM coupon_redemptions WHERE code = ? AND email = ? AND status = 'redeemed' AND revoked = 0`
    ).bind(code, email).first().catch(() => ({ c: 0 }));
    if ((used?.c || 0) >= coupon.max_uses_per_user) {
      return invalid('You have already used this coupon the maximum number of times', 'PER_USER_LIMIT_REACHED');
    }
  }

  return {
    valid: true,
    code,
    discountType: coupon.discount_type || 'percentage',
    discountValue: coupon.discount_value ?? coupon.discount_pct ?? 0,
    discount_pct: coupon.discount_pct ?? 0, // back-compat field name
  };
}

// ── Apply a validated coupon to an amount (paise) ─────────────────────────────
export function applyDiscount(amountPaise, discountPct) {
  const pct = Math.max(0, Math.min(100, discountPct));
  return Math.max(0, Math.round(amountPaise * (1 - pct / 100)));
}

// Type-aware variant — accepts the object returned by validateCoupon().
// 'trial_extension'/'upgrade_promo' don't reduce a charge amount (see file
// header) so they fall back to percentage semantics (discountValue defaults
// to 0 for those types unless explicitly set as a percentage-style value).
export function computeDiscountedAmount(amountPaise, validated) {
  if (validated?.discountType === 'fixed') {
    return Math.max(0, amountPaise - Math.max(0, validated.discountValue || 0));
  }
  return applyDiscount(amountPaise, validated?.discountValue ?? validated?.discount_pct ?? 0);
}

// ── Record that a coupon was applied to a newly-created order (pending) ──────
export async function recordCouponUsage(env, { razorpayOrderId, code, module, originalAmount, discountedAmount, email, userId }) {
  if (!env.DB) return;
  await ensureCouponTables(env.DB);
  await env.DB.prepare(
    `INSERT OR IGNORE INTO coupon_redemptions
       (razorpay_order_id, code, module, original_amount, discounted_amount, status, email, user_id)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).bind(razorpayOrderId, code, module || null, originalAmount, discountedAmount, email || null, userId || null).run();
}

// ── Finalize redemption once Razorpay confirms the payment captured ──────────
// Idempotent: only the caller that flips status pending -> redeemed (checked
// via `changes`) increments the coupon's counter, so this is safe to call
// from both the synchronous /verify path and the async webhook safety net
// without double-counting a single successful payment.
export async function finalizeCouponRedemption(env, razorpayOrderId) {
  if (!env.DB || !razorpayOrderId) return;
  try {
    await ensureCouponTables(env.DB);
    const redemption = await env.DB.prepare(
      `SELECT code FROM coupon_redemptions WHERE razorpay_order_id = ? AND status = 'pending'`
    ).bind(razorpayOrderId).first().catch(() => null);
    if (!redemption) return;

    const flipped = await env.DB.prepare(
      `UPDATE coupon_redemptions SET status = 'redeemed' WHERE razorpay_order_id = ? AND status = 'pending'`
    ).bind(razorpayOrderId).run();
    if (flipped?.meta?.changes) {
      await env.DB.prepare(
        `UPDATE discount_coupons SET redeemed_count = redeemed_count + 1 WHERE code = ?`
      ).bind(redemption.code).run();
    }
  } catch (e) {
    console.error('[Coupons] finalizeCouponRedemption failed (non-fatal):', e.message);
  }
}

// ── Revoke a specific redemption (e.g. after a refund) ────────────────────────
// Decrements the coupon's usage counter and marks the redemption row so it no
// longer counts toward maxUsesPerUser. Does not touch the underlying payment.
export async function revokeRedemption(env, razorpayOrderId, reason) {
  if (!env.DB) return { revoked: false, error: 'DB unavailable' };
  await ensureCouponTables(env.DB);
  const redemption = await env.DB.prepare(
    `SELECT code, revoked FROM coupon_redemptions WHERE razorpay_order_id = ?`
  ).bind(razorpayOrderId).first().catch(() => null);
  if (!redemption) return { revoked: false, error: 'Redemption not found' };
  if (redemption.revoked) return { revoked: false, error: 'Already revoked' };

  await env.DB.prepare(
    `UPDATE coupon_redemptions SET revoked = 1, revoked_at = datetime('now'), revoked_reason = ? WHERE razorpay_order_id = ?`
  ).bind(reason || null, razorpayOrderId).run();
  await env.DB.prepare(
    `UPDATE discount_coupons SET redeemed_count = MAX(0, redeemed_count - 1) WHERE code = ?`
  ).bind(redemption.code).run();
  return { revoked: true, code: redemption.code };
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin REST API
// ═══════════════════════════════════════════════════════════════════════════

function parseListField(v) {
  if (Array.isArray(v)) return v.map(String).map(s => s.trim().toUpperCase()).filter(Boolean).join(',') || null;
  if (typeof v === 'string' && v.trim()) return v.trim().toUpperCase();
  return null;
}

const VALID_DISCOUNT_TYPES = ['percentage', 'fixed', 'trial_extension', 'upgrade_promo'];

function validateCouponPayload(body, { partial = false } = {}) {
  const errors = [];
  const code = String(body.code || '').trim().toUpperCase();
  if (!partial || body.code !== undefined) {
    if (!/^[A-Z0-9_-]{3,32}$/.test(code)) errors.push('code must be 3-32 characters: letters, numbers, - or _');
  }
  if (!partial || body.discountType !== undefined) {
    if (!VALID_DISCOUNT_TYPES.includes(body.discountType || 'percentage')) {
      errors.push(`discountType must be one of: ${VALID_DISCOUNT_TYPES.join(', ')}`);
    }
  }
  if (!partial || body.discountValue !== undefined) {
    const v = Number(body.discountValue);
    if (!Number.isFinite(v) || v < 0) errors.push('discountValue must be a non-negative number');
    if ((body.discountType || 'percentage') === 'percentage' && v > 100) errors.push('discountValue for a percentage coupon cannot exceed 100');
  }
  return { code, errors };
}

// ── GET /api/admin/coupons ────────────────────────────────────────────────────
export async function handleAdminListCoupons(request, env, authCtx) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return ok(request, { coupons: [] });
  await ensureCouponTables(env.DB);
  const { results } = await env.DB.prepare(
    `SELECT * FROM discount_coupons ORDER BY created_at DESC`
  ).all().catch(() => ({ results: [] }));
  return ok(request, { coupons: (results || []).map(toPublicCoupon) });
}

// ── GET /api/admin/coupons/:id ─────────────────────────────────────────────────
export async function handleAdminGetCoupon(request, env, authCtx, id) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);
  const row = await env.DB.prepare(`SELECT * FROM discount_coupons WHERE code = ?`).bind(String(id || '').trim().toUpperCase()).first().catch(() => null);
  if (!row) return fail(request, 'Coupon not found', 404, 'NOT_FOUND');
  return ok(request, { coupon: toPublicCoupon(row) });
}

// ── POST /api/admin/coupons — create ──────────────────────────────────────────
export async function handleAdminCreateCoupon(request, env, authCtx) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  let body = {};
  try { body = await request.json(); } catch {}

  const { code, errors } = validateCouponPayload(body);
  if (errors.length) return fail(request, errors.join('; '), 400, 'INVALID_PAYLOAD');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);

  const discountType = body.discountType || 'percentage';
  const discountValue = Number(body.discountValue ?? 0);

  await env.DB.prepare(
    `INSERT INTO discount_coupons
       (code, discount_pct, discount_type, discount_value, applies_to, description, currency,
        applicable_plans, applicable_products, applicable_apis, enterprise_only, first_purchase_only,
        max_redemptions, max_uses_per_user, start_date, expires_at, active, stackable, minimum_purchase,
        metadata, created_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(code) DO UPDATE SET
       discount_pct=excluded.discount_pct, discount_type=excluded.discount_type, discount_value=excluded.discount_value,
       applies_to=excluded.applies_to, description=excluded.description, currency=excluded.currency,
       applicable_plans=excluded.applicable_plans, applicable_products=excluded.applicable_products,
       applicable_apis=excluded.applicable_apis, enterprise_only=excluded.enterprise_only,
       first_purchase_only=excluded.first_purchase_only, max_redemptions=excluded.max_redemptions,
       max_uses_per_user=excluded.max_uses_per_user, start_date=excluded.start_date,
       expires_at=excluded.expires_at, active=1, stackable=excluded.stackable,
       minimum_purchase=excluded.minimum_purchase, metadata=excluded.metadata, updated_at=datetime('now')`
  ).bind(
    code,
    discountType === 'percentage' ? discountValue : 0,
    discountType,
    discountValue,
    body.applies_to || 'all',
    body.description || null,
    body.currency || 'INR',
    parseListField(body.applicablePlans),
    parseListField(body.applicableProducts),
    parseListField(body.applicableApis),
    body.enterpriseOnly ? 1 : 0,
    body.firstPurchaseOnly ? 1 : 0,
    body.maxUses != null ? parseInt(body.maxUses, 10) : null,
    body.maxUsesPerUser != null ? parseInt(body.maxUsesPerUser, 10) : null,
    body.startDate || null,
    body.expiryDate || body.expires_at || null,
    body.stackable ? 1 : 0,
    body.minimumPurchase != null ? parseInt(body.minimumPurchase, 10) : null,
    JSON.stringify(body.metadata || {}),
    authCtx?.email || 'owner',
  ).run();

  const row = await env.DB.prepare(`SELECT * FROM discount_coupons WHERE code = ?`).bind(code).first();
  return ok(request, { created: true, coupon: toPublicCoupon(row) });
}

// ── PUT /api/admin/coupons/:id — update ───────────────────────────────────────
export async function handleAdminUpdateCoupon(request, env, authCtx, id) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  const code = String(id || '').trim().toUpperCase();
  let body = {};
  try { body = await request.json(); } catch {}

  const { errors } = validateCouponPayload({ ...body, code }, { partial: true });
  if (errors.length) return fail(request, errors.join('; '), 400, 'INVALID_PAYLOAD');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);

  const existing = await env.DB.prepare(`SELECT * FROM discount_coupons WHERE code = ?`).bind(code).first().catch(() => null);
  if (!existing) return fail(request, 'Coupon not found', 404, 'NOT_FOUND');

  const merged = {
    discountType: body.discountType ?? existing.discount_type ?? 'percentage',
    discountValue: body.discountValue ?? existing.discount_value ?? existing.discount_pct ?? 0,
    description: body.description ?? existing.description,
    currency: body.currency ?? existing.currency ?? 'INR',
    applicablePlans: body.applicablePlans !== undefined ? parseListField(body.applicablePlans) : existing.applicable_plans,
    applicableProducts: body.applicableProducts !== undefined ? parseListField(body.applicableProducts) : existing.applicable_products,
    applicableApis: body.applicableApis !== undefined ? parseListField(body.applicableApis) : existing.applicable_apis,
    enterpriseOnly: body.enterpriseOnly !== undefined ? (body.enterpriseOnly ? 1 : 0) : existing.enterprise_only,
    firstPurchaseOnly: body.firstPurchaseOnly !== undefined ? (body.firstPurchaseOnly ? 1 : 0) : existing.first_purchase_only,
    maxUses: body.maxUses !== undefined ? (body.maxUses != null ? parseInt(body.maxUses, 10) : null) : existing.max_redemptions,
    maxUsesPerUser: body.maxUsesPerUser !== undefined ? (body.maxUsesPerUser != null ? parseInt(body.maxUsesPerUser, 10) : null) : existing.max_uses_per_user,
    startDate: body.startDate !== undefined ? body.startDate : existing.start_date,
    expiryDate: (body.expiryDate ?? body.expires_at) !== undefined ? (body.expiryDate ?? body.expires_at) : existing.expires_at,
    stackable: body.stackable !== undefined ? (body.stackable ? 1 : 0) : existing.stackable,
    minimumPurchase: body.minimumPurchase !== undefined ? (body.minimumPurchase != null ? parseInt(body.minimumPurchase, 10) : null) : existing.minimum_purchase,
    metadata: body.metadata !== undefined ? JSON.stringify(body.metadata) : existing.metadata,
  };

  await env.DB.prepare(
    `UPDATE discount_coupons SET
       discount_pct = ?, discount_type = ?, discount_value = ?, description = ?, currency = ?,
       applicable_plans = ?, applicable_products = ?, applicable_apis = ?, enterprise_only = ?,
       first_purchase_only = ?, max_redemptions = ?, max_uses_per_user = ?, start_date = ?,
       expires_at = ?, stackable = ?, minimum_purchase = ?, metadata = ?, updated_at = datetime('now')
     WHERE code = ?`
  ).bind(
    merged.discountType === 'percentage' ? merged.discountValue : 0,
    merged.discountType, merged.discountValue, merged.description, merged.currency,
    merged.applicablePlans, merged.applicableProducts, merged.applicableApis, merged.enterpriseOnly,
    merged.firstPurchaseOnly, merged.maxUses, merged.maxUsesPerUser, merged.startDate,
    merged.expiryDate, merged.stackable, merged.minimumPurchase, merged.metadata,
    code,
  ).run();

  const row = await env.DB.prepare(`SELECT * FROM discount_coupons WHERE code = ?`).bind(code).first();
  return ok(request, { updated: true, coupon: toPublicCoupon(row) });
}

// ── DELETE /api/admin/coupons/:id ─────────────────────────────────────────────
// A coupon with real redemption history is never hard-deleted — that would
// destroy audit trail for payments that already happened. Use /disable
// instead (reversible via /enable); DELETE only removes coupons nobody has
// ever redeemed.
export async function handleAdminDeleteCoupon(request, env, authCtx, id) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  const code = String(id || '').trim().toUpperCase();
  await ensureCouponTables(env.DB);

  const row = await env.DB.prepare(`SELECT redeemed_count FROM discount_coupons WHERE code = ?`).bind(code).first().catch(() => null);
  if (!row) return fail(request, 'Coupon not found', 404, 'NOT_FOUND');
  if (row.redeemed_count > 0) {
    return fail(request, `Coupon has ${row.redeemed_count} redemption(s) on record — disable it instead of deleting to preserve audit history`, 409, 'HAS_REDEMPTIONS');
  }
  await env.DB.prepare(`DELETE FROM discount_coupons WHERE code = ?`).bind(code).run();
  return ok(request, { deleted: true, code });
}

// ── POST /api/admin/coupons/:id/disable  &  /enable ───────────────────────────
export async function handleAdminSetCouponActive(request, env, authCtx, id, active) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);
  const code = String(id || '').trim().toUpperCase();
  const r = await env.DB.prepare(
    `UPDATE discount_coupons SET active = ?, updated_at = datetime('now') WHERE code = ?`
  ).bind(active ? 1 : 0, code).run();
  if (!r?.meta?.changes) return fail(request, 'Coupon not found', 404, 'NOT_FOUND');
  return ok(request, { [active ? 'enabled' : 'disabled']: true, code });
}

// Back-compat alias (previous /disable-only route).
export async function handleAdminDeactivateCoupon(request, env, authCtx, code) {
  return handleAdminSetCouponActive(request, env, authCtx, code, false);
}

// ── POST /api/admin/coupons/validate ──────────────────────────────────────────
// Lets a client (or the frontend, before opening the Razorpay sheet) preview
// whether a code would be accepted without creating a real order.
export async function handleAdminValidateCoupon(request, env, authCtx) {
  let body = {};
  try { body = await request.json(); } catch {}
  const result = await validateCoupon(env, body.code, {
    module: body.module, planKey: body.planKey || body.plan,
    authCtx, email: body.email, amountPaise: body.amountPaise,
    ip: request.headers.get('CF-Connecting-IP'),
  });
  return ok(request, result);
}

// ── GET /api/admin/coupons/:id/redemptions ────────────────────────────────────
export async function handleAdminListRedemptions(request, env, authCtx, id) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return ok(request, { redemptions: [] });
  await ensureCouponTables(env.DB);
  const code = String(id || '').trim().toUpperCase();
  const { results } = await env.DB.prepare(
    `SELECT * FROM coupon_redemptions WHERE code = ? ORDER BY created_at DESC LIMIT 200`
  ).bind(code).all().catch(() => ({ results: [] }));
  return ok(request, { redemptions: results || [] });
}

// ── POST /api/admin/coupons/:id/redemptions/:orderId/revoke ──────────────────
export async function handleAdminRevokeRedemption(request, env, authCtx, orderId) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  let body = {};
  try { body = await request.json(); } catch {}
  const result = await revokeRedemption(env, orderId, body.reason);
  if (!result.revoked) return fail(request, result.error || 'Revoke failed', 400, 'REVOKE_FAILED');
  return ok(request, result);
}
