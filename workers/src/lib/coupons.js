/**
 * CYBERDUDEBIVASH AI Security Hub — Discount Coupons v1.0
 *
 * Server-authoritative discount codes for the live checkout flow
 * (handlers/payments.js handleCreateOrder / handleRazorpayWebhook). The
 * discount is always applied to the server-computed price before the
 * Razorpay order is created — a client can never supply its own amount or
 * discount percentage.
 *
 * Tables (self-bootstrapping, same pattern as enterpriseAutomation.js /
 * msspOnboardingHandler.js — no separate migration required):
 *   discount_coupons    — the coupon definitions (admin-managed)
 *   coupon_redemptions  — one row per order a coupon was applied to; the
 *                         redeemed_count on discount_coupons is only
 *                         incremented once Razorpay confirms the payment
 *                         actually captured (see finalizeCouponRedemption),
 *                         so an abandoned checkout never burns a limited
 *                         redemption slot.
 */

import { ok, fail } from './response.js';

async function ensureCouponTables(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS discount_coupons (
      code            TEXT PRIMARY KEY,
      discount_pct    INTEGER NOT NULL,
      applies_to      TEXT NOT NULL DEFAULT 'all',
      max_redemptions INTEGER,
      redeemed_count  INTEGER NOT NULL DEFAULT 0,
      expires_at      TEXT,
      active          INTEGER NOT NULL DEFAULT 1,
      created_by      TEXT,
      created_at      TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS coupon_redemptions (
      razorpay_order_id  TEXT PRIMARY KEY,
      code               TEXT NOT NULL,
      module             TEXT,
      original_amount    INTEGER NOT NULL,
      discounted_amount  INTEGER NOT NULL,
      status             TEXT NOT NULL DEFAULT 'pending',
      created_at         TEXT DEFAULT (datetime('now'))
    )`),
  ]);
}

// applies_to: 'all', or a comma-separated list of module names
// (domain/ai/redteam/identity/compliance/assessment/package) and/or
// subscription plan keys (STARTER/PRO/ENTERPRISE/MSSP) — a coupon can mix
// both, e.g. "PRO,ENTERPRISE" to restrict to those two subscription tiers.
function couponAppliesTo(coupon, module, planKey) {
  if (coupon.applies_to === 'all') return true;
  const list = coupon.applies_to.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  if (list.includes(String(module || '').toUpperCase())) return true;
  if (planKey && list.includes(String(planKey).toUpperCase())) return true;
  return false;
}

// ── Validate a coupon code against a specific purchase ───────────────────────
// Returns { valid: true, discount_pct } or { valid: false, error }.
export async function validateCoupon(env, rawCode, module, planKey) {
  if (!env.DB) return { valid: false, error: 'Coupons unavailable' };
  const code = String(rawCode || '').trim().toUpperCase();
  if (!code) return { valid: false, error: 'No coupon code provided' };

  await ensureCouponTables(env.DB);
  const coupon = await env.DB.prepare(
    `SELECT * FROM discount_coupons WHERE code = ?`
  ).bind(code).first().catch(() => null);

  if (!coupon) return { valid: false, error: 'Invalid coupon code' };
  if (!coupon.active) return { valid: false, error: 'This coupon is no longer active' };
  if (coupon.expires_at && new Date(coupon.expires_at).getTime() < Date.now()) {
    return { valid: false, error: 'This coupon has expired' };
  }
  if (coupon.max_redemptions != null && coupon.redeemed_count >= coupon.max_redemptions) {
    return { valid: false, error: 'This coupon has reached its redemption limit' };
  }
  if (!couponAppliesTo(coupon, module, planKey)) {
    return { valid: false, error: 'This coupon does not apply to the selected plan/product' };
  }

  return { valid: true, discount_pct: coupon.discount_pct, code };
}

// ── Apply a validated coupon to an amount (paise) ─────────────────────────────
export function applyDiscount(amountPaise, discountPct) {
  const pct = Math.max(0, Math.min(100, discountPct));
  return Math.max(0, Math.round(amountPaise * (1 - pct / 100)));
}

// ── Record that a coupon was applied to a newly-created order (pending) ──────
export async function recordCouponUsage(env, { razorpayOrderId, code, module, originalAmount, discountedAmount }) {
  if (!env.DB) return;
  await ensureCouponTables(env.DB);
  await env.DB.prepare(
    `INSERT OR IGNORE INTO coupon_redemptions
       (razorpay_order_id, code, module, original_amount, discounted_amount, status)
     VALUES (?, ?, ?, ?, ?, 'pending')`
  ).bind(razorpayOrderId, code, module || null, originalAmount, discountedAmount).run();
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

// ── Admin: list all coupons ───────────────────────────────────────────────────
export async function handleAdminListCoupons(request, env, authCtx) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return ok(request, { coupons: [] });
  await ensureCouponTables(env.DB);
  const { results } = await env.DB.prepare(
    `SELECT * FROM discount_coupons ORDER BY created_at DESC`
  ).all().catch(() => ({ results: [] }));
  return ok(request, { coupons: results || [] });
}

// ── Admin: create a coupon ────────────────────────────────────────────────────
// Body: { code, discount_pct, applies_to?, max_redemptions?, expires_at? }
export async function handleAdminCreateCoupon(request, env, authCtx) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  let body = {};
  try { body = await request.json(); } catch {}
  const code = String(body.code || '').trim().toUpperCase();
  const discountPct = parseInt(body.discount_pct, 10);

  if (!/^[A-Z0-9_-]{3,32}$/.test(code)) {
    return fail(request, 'code must be 3-32 characters: letters, numbers, - or _', 400, 'INVALID_CODE');
  }
  if (!Number.isFinite(discountPct) || discountPct < 1 || discountPct > 100) {
    return fail(request, 'discount_pct must be a number between 1 and 100', 400, 'INVALID_DISCOUNT');
  }
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);

  await env.DB.prepare(
    `INSERT INTO discount_coupons (code, discount_pct, applies_to, max_redemptions, expires_at, active, created_by)
     VALUES (?, ?, ?, ?, ?, 1, ?)
     ON CONFLICT(code) DO UPDATE SET
       discount_pct=excluded.discount_pct, applies_to=excluded.applies_to,
       max_redemptions=excluded.max_redemptions, expires_at=excluded.expires_at, active=1`
  ).bind(
    code, discountPct, body.applies_to || 'all',
    body.max_redemptions != null ? parseInt(body.max_redemptions, 10) : null,
    body.expires_at || null,
    authCtx?.email || 'owner',
  ).run();

  return ok(request, { created: true, code, discount_pct: discountPct });
}

// ── Admin: deactivate a coupon ────────────────────────────────────────────────
export async function handleAdminDeactivateCoupon(request, env, authCtx, code) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return fail(request, 'DB unavailable', 503, 'DB_UNAVAILABLE');
  await ensureCouponTables(env.DB);
  const r = await env.DB.prepare(
    `UPDATE discount_coupons SET active = 0 WHERE code = ?`
  ).bind(String(code || '').trim().toUpperCase()).run();
  if (!r?.meta?.changes) return fail(request, 'Coupon not found', 404, 'NOT_FOUND');
  return ok(request, { deactivated: true, code: String(code).toUpperCase() });
}
