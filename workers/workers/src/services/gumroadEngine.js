/**
 * CYBERDUDEBIVASH AI Security Hub — Gumroad Revenue Engine v1.0
 * Tracks Gumroad product sales, verifies licenses, and syncs revenue data
 *
 * Features:
 *   - License verification via Gumroad API
 *   - Webhook handler for purchase events
 *   - Revenue tracking in D1
 *   - Auto-provision PRO tier on purchase
 *   - Upsell nudges based on product purchase
 *
 * Gumroad Products:
 *   Product slug → feature unlock mapping
 *   "sentinel-apex-pro"      → PRO tier (30 days)
 *   "sentinel-apex-enterprise" → ENTERPRISE tier (30 days)
 *   "domain-report-bundle"   → 10 domain scans (credits)
 *   "redteam-report"         → 3 red team scans (credits)
 *   "compliance-toolkit"     → All compliance frameworks
 *   "threat-intel-feed"      → Threat intel API access (30 days)
 *
 * Webhook endpoint: POST /api/webhooks/gumroad
 * License verify:   POST /api/gumroad/verify
 */

// ─── Gumroad Product Catalog ──────────────────────────────────────────────────
export const GUMROAD_PRODUCTS = {
  'sentinel-apex-pro': {
    name:       'Sentinel APEX PRO',
    tier:       'PRO',
    credits:    null,
    duration_days: 30,
    features:   ['full_scans', 'pdf_export', 'api_access', 'email_alerts'],
    price_inr:  1499,
  },
  'sentinel-apex-enterprise': {
    name:       'Sentinel APEX ENTERPRISE',
    tier:       'ENTERPRISE',
    credits:    null,
    duration_days: 30,
    features:   ['full_scans', 'soc_dashboard', 'ai_decisions', 'team_access', 'white_label'],
    price_inr:  4999,
  },
  'domain-report-bundle': {
    name:       'Domain Report Bundle (10 scans)',
    tier:       null,
    credits:    { module: 'domain', count: 10 },
    duration_days: 365,
    features:   ['domain_scans'],
    price_inr:  999,
  },
  'redteam-report': {
    name:       'Red Team Report (3 scans)',
    tier:       null,
    credits:    { module: 'redteam', count: 3 },
    duration_days: 365,
    features:   ['redteam_scans'],
    price_inr:  1799,
  },
  'compliance-toolkit': {
    name:       'Compliance Toolkit (All Frameworks)',
    tier:       null,
    credits:    { module: 'compliance', count: 20 },
    duration_days: 365,
    features:   ['all_compliance'],
    price_inr:  2499,
  },
  'threat-intel-feed': {
    name:       'Threat Intel Feed API (30 days)',
    tier:       'PRO',
    credits:    null,
    duration_days: 30,
    features:   ['threat_intel_api', 'cve_feed', 'ioc_feed'],
    price_inr:  799,
  },
};

// ─── Verify Gumroad License ───────────────────────────────────────────────────
export async function verifyGumroadLicense(env, productPermalink, licenseKey) {
  if (!licenseKey || !productPermalink) {
    return { valid: false, error: 'license_key and product_permalink required' };
  }

  try {
    const resp = await fetch('https://api.gumroad.com/v2/licenses/verify', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        product_permalink: productPermalink,
        license_key:       licenseKey,
        increment_uses_count: 'false',
      }),
    });

    const data = await resp.json();

    if (!data.success) {
      return { valid: false, error: data.message || 'invalid_license' };
    }

    const purchase = data.purchase;
    const product  = GUMROAD_PRODUCTS[productPermalink];

    if (!product) {
      return { valid: false, error: 'unknown_product' };
    }

    // Check if license has been used too many times (per product policy)
    const maxUses = product.tier ? 1 : (product.credits?.count || 10);
    if (purchase.uses > maxUses) {
      return { valid: false, error: 'license_already_used', uses: purchase.uses };
    }

    return {
      valid:           true,
      license_key:     licenseKey,
      product:         product.name,
      tier:            product.tier,
      credits:         product.credits,
      duration_days:   product.duration_days,
      features:        product.features,
      purchaser_email: purchase.email,
      sale_id:         purchase.sale_id || purchase.id,
      purchase_date:   purchase.created_at,
    };

  } catch (err) {
    console.error('[Gumroad] License verify error:', err.message);
    return { valid: false, error: 'verification_failed', details: err.message };
  }
}

// ─── Apply License to User Account ───────────────────────────────────────────
export async function applyGumroadLicense(env, userId, licenseResult) {
  if (!env.DB || !licenseResult.valid) return false;

  try {
    const now       = new Date();
    const expiresAt = new Date(now.getTime() + licenseResult.duration_days * 86400000).toISOString();

    // If tier upgrade — update user tier
    if (licenseResult.tier) {
      await env.DB.prepare(
        `UPDATE users SET tier = ?, updated_at = datetime('now') WHERE id = ?`
      ).bind(licenseResult.tier, userId).run();
    }

    // Store license record
    const licId = crypto.randomUUID?.() || Date.now().toString(36);
    await env.DB.prepare(
      `INSERT OR IGNORE INTO gumroad_licenses
       (id, user_id, license_key, product, tier, credits_json, features_json,
        sale_id, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      licId,
      userId,
      licenseResult.license_key,
      licenseResult.product,
      licenseResult.tier || null,
      JSON.stringify(licenseResult.credits || null),
      JSON.stringify(licenseResult.features || []),
      licenseResult.sale_id,
      expiresAt,
    ).run().catch(() => {});

    // If credits — add to user credit balance
    if (licenseResult.credits) {
      const { module, count } = licenseResult.credits;
      await env.DB.prepare(
        `INSERT INTO user_credits (id, user_id, module, remaining, total, expires_at, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'gumroad', datetime('now'))
         ON CONFLICT(user_id, module) DO UPDATE SET
           remaining = remaining + excluded.remaining,
           total     = total + excluded.total`
      ).bind(
        crypto.randomUUID?.() || Date.now().toString(36),
        userId,
        module,
        count,
        count,
        expiresAt,
      ).run().catch(() => {});
    }

    return true;
  } catch (err) {
    console.error('[Gumroad] Apply license error:', err.message);
    return false;
  }
}

// ─── POST /api/webhooks/gumroad ───────────────────────────────────────────────
export async function handleGumroadWebhook(request, env) {
  // Gumroad sends form-encoded POST with seller_id verification
  let formData;
  try {
    formData = await request.formData();
  } catch {
    return Response.json({ error: 'Invalid form data' }, { status: 400 });
  }

  const toObj = (fd) => {
    const obj = {};
    for (const [k, v] of fd.entries()) obj[k] = v;
    return obj;
  };
  const data = toObj(formData);

  // Verify this is from our Gumroad account
  const expectedSellerId = env.GUMROAD_SELLER_ID || '';
  if (expectedSellerId && data.seller_id !== expectedSellerId) {
    console.warn('[GumroadWebhook] Seller ID mismatch');
    return Response.json({ error: 'Unauthorized webhook' }, { status: 401 });
  }

  const productPermalink = data.product_permalink;
  const licenseKey       = data.license_key;
  const buyerEmail       = data.email;
  const saleId           = data.sale_id;
  const price            = parseFloat(data.price || '0');

  const product = GUMROAD_PRODUCTS[productPermalink];
  if (!product) {
    // Unknown product — log and acknowledge
    console.log('[GumroadWebhook] Unknown product:', productPermalink);
    return Response.json({ received: true, note: 'unknown_product' });
  }

  // Log sale in D1
  if (env.DB) {
    try {
      // Find or create user by email
      let user = await env.DB.prepare(
        `SELECT id, tier FROM users WHERE email = ? LIMIT 1`
      ).bind(buyerEmail).first().catch(() => null);

      if (!user) {
        // Auto-create user account for Gumroad buyer
        const newUserId = crypto.randomUUID?.() || Date.now().toString(36);
        await env.DB.prepare(
          `INSERT OR IGNORE INTO users (id, email, password_hash, password_salt, tier, status, created_at)
           VALUES (?, ?, 'gumroad_sso', 'gumroad', 'FREE', 'active', datetime('now'))`
        ).bind(newUserId, buyerEmail).run().catch(() => {});
        user = { id: newUserId, tier: 'FREE' };
      }

      if (user?.id) {
        await applyGumroadLicense(env, user.id, {
          valid:         true,
          license_key:   licenseKey,
          product:       product.name,
          tier:          product.tier,
          credits:       product.credits,
          duration_days: product.duration_days,
          features:      product.features,
          sale_id:       saleId,
        });
      }

      // Record revenue event
      await env.DB.prepare(
        `INSERT INTO analytics_events (id, event_type, module, metadata, created_at)
         VALUES (?, 'gumroad_sale', ?, ?, datetime('now'))`
      ).bind(
        crypto.randomUUID?.() || Date.now().toString(36),
        productPermalink,
        JSON.stringify({ sale_id: saleId, email: buyerEmail, price, product: product.name }),
      ).run().catch(() => {});

    } catch (err) {
      console.error('[GumroadWebhook] D1 error:', err.message);
    }
  }

  return Response.json({ received: true, product: product.name, email: buyerEmail });
}

// ─── POST /api/gumroad/verify (user-facing license activation) ────────────────
export async function handleLicenseActivation(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { product_permalink, license_key } = body;

  if (!product_permalink || !license_key) {
    return Response.json({
      error: 'product_permalink and license_key are required',
      products: Object.keys(GUMROAD_PRODUCTS),
    }, { status: 400 });
  }

  // Verify with Gumroad
  const result = await verifyGumroadLicense(env, product_permalink, license_key);

  if (!result.valid) {
    return Response.json({
      success: false,
      error:   result.error,
      hint:    'Check your license key in your Gumroad purchase receipt email',
    }, { status: 400 });
  }

  // Apply to authenticated user (if logged in)
  let applied = false;
  if (authCtx?.user_id) {
    applied = await applyGumroadLicense(env, authCtx.user_id, result);
  }

  return Response.json({
    success:     true,
    applied:     applied,
    product:     result.product,
    tier:        result.tier,
    credits:     result.credits,
    features:    result.features,
    expires_in_days: result.duration_days,
    message:     applied
      ? `✅ License activated! Your account has been upgraded to ${result.tier || 'credit bundle'}.`
      : `✅ License verified. Please log in to activate your account.`,
    login_url:   applied ? null : 'https://cyberdudebivash.in/#login',
  });
}

// ─── GET /api/gumroad/products (product catalog for frontend) ─────────────────
export function handleProductCatalog(request, env) {
  const catalog = Object.entries(GUMROAD_PRODUCTS).map(([slug, p]) => ({
    slug,
    name:         p.name,
    price_inr:    p.price_inr,
    tier:         p.tier,
    credits:      p.credits,
    duration_days: p.duration_days,
    features:     p.features,
    buy_url:      `https://cyberdudebivash.gumroad.com/l/${slug}`,
  }));

  return Response.json({
    products:      catalog,
    store_url:     'https://cyberdudebivash.gumroad.com',
    generated_at:  new Date().toISOString(),
  });
}
