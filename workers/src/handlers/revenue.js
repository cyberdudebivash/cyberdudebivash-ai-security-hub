// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Revenue API Handler v8.1
// Phases 4+5: All revenue, monetization, upsell, and funnel API endpoints
//
// Routes (all exported, wired in index.js):
//   GET  /api/revenue/dashboard        — full revenue dashboard (ENTERPRISE)
//   GET  /api/revenue/snapshot         — lightweight KPI snapshot (all plans)
//   GET  /api/revenue/recommendations  — actionable revenue recs (ADMIN)
//   POST /api/revenue/event            — record a revenue event (INTERNAL)
//   GET  /api/monetize/upsell          — upsell trigger for current user
//   GET  /api/monetize/products        — AI product recommendations
//   GET  /api/monetize/churn-risk      — churn risk for current user
//   POST /api/monetize/optimize        — full AI revenue optimization pass
//   POST /api/funnel/event             — record a funnel stage event
//   GET  /api/funnel/metrics           — conversion funnel (ADMIN)
//   GET  /api/defense/catalog          — defense product catalog (PUBLIC)
//   GET  /api/defense/preview          — defense product preview (PUBLIC, with paywall)
//   POST /api/checkout                 — initiate Razorpay checkout
//   POST /api/checkout/verify          — verify Razorpay payment
//   GET  /api/affiliate/stats          — affiliate click stats (ADMIN)
// ═══════════════════════════════════════════════════════════════════════════

import { aggregateAllRevenue, getRevenueSnapshot, recordRevenueEvent, getSubscriptionRevenue } from '../services/revenueEngine.js';
import { runRevenueOptimization, getUpsellTrigger, getProductRecommendations, analyzeChurnRisk, getUserBehaviorProfile, monetizeScanResult, runBulkOptimization } from '../services/aiRevenueOptimizer.js';
import { getProductCatalog, getProductPreview, generateDefenseProducts, DEFENSE_PRODUCTS } from '../services/defenseSolutions.js';

// ── CORS headers ─────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(message, status = 400, code = 'ERR') {
  return json({ success: false, error: message, code }, status);
}

// Plan gating helper
function requirePlan(authCtx, ...plans) {
  if (!authCtx?.userId) return 'UNAUTHENTICATED';
  if (authCtx.role === 'admin') return null; // admin bypasses all gates
  if (!plans.includes(authCtx.plan)) return 'PLAN_REQUIRED';
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/dashboard  — Full Revenue Dashboard (ENTERPRISE / ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueDashboard(request, env, authCtx) {
  const gate = requirePlan(authCtx, 'enterprise');
  if (gate) {
    return err(
      gate === 'UNAUTHENTICATED'
        ? 'Authentication required'
        : 'ENTERPRISE plan required to access revenue dashboard',
      gate === 'UNAUTHENTICATED' ? 401 : 403,
      gate
    );
  }

  try {
    const url  = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30', 10);
    const detailed = url.searchParams.get('detailed') !== 'false';

    const dashboard = await aggregateAllRevenue(env, { days, detailed });

    return json({ success: true, ...dashboard });
  } catch (e) {
    return err(`Revenue dashboard error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/snapshot  — Lightweight KPI Snapshot (all plans)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueSnapshot(request, env, authCtx) {
  try {
    const snapshot = await getRevenueSnapshot(env);
    return json({ success: true, snapshot });
  } catch (e) {
    return err(`Snapshot error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/recommendations  — Actionable Revenue Recs (ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueRecommendations(request, env, authCtx) {
  if (authCtx?.role !== 'admin') {
    return err('Admin access required', 403, 'FORBIDDEN');
  }

  try {
    const url  = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30', 10);

    const dashboard = await aggregateAllRevenue(env, { days, detailed: false });
    return json({
      success:         true,
      recommendations: dashboard.recommendations || [],
      kpis:            dashboard.kpis,
      generated_at:    dashboard.generated_at,
    });
  } catch (e) {
    return err(`Recommendations error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/revenue/event  — Record Revenue Event (INTERNAL / ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueEvent(request, env, authCtx) {
  if (authCtx?.role !== 'admin' && !authCtx?.internal) {
    return err('Admin / internal access required', 403, 'FORBIDDEN');
  }

  try {
    const body = await request.json().catch(() => ({}));
    const { source, amount, user_id, email, metadata, payment_id } = body;

    if (!source || !amount || isNaN(amount)) {
      return err('source and amount are required', 400, 'MISSING_FIELDS');
    }

    const result = await recordRevenueEvent(env, { source, amount: parseFloat(amount), user_id, email, metadata, payment_id });
    return json({ success: true, ...result });
  } catch (e) {
    return err(`Revenue event error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monetize/upsell  — Upsell Trigger for Current User
// ─────────────────────────────────────────────────────────────────────────────

export async function handleUpsellTrigger(request, env, authCtx) {
  try {
    const url     = new URL(request.url);
    const context = url.searchParams.get('context') || 'dashboard';

    let profile;
    if (authCtx?.userId) {
      profile = await getUserBehaviorProfile(env, authCtx.userId);
    } else {
      // Anonymous user profile
      profile = {
        plan:             'free',
        scans:            parseInt(url.searchParams.get('scans') || '0', 10),
        critical_cves:    parseInt(url.searchParams.get('critical') || '0', 10),
        engagement_score: 10,
        days_since_last_scan: 0,
        is_enterprise:    false,
        api_calls_today:  0,
        has_siem:         false,
        total_spent:      0,
      };
    }

    const upsell = getUpsellTrigger(profile, context);

    return json({ success: true, upsell, plan: profile.plan });
  } catch (e) {
    return err(`Upsell error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monetize/products  — AI Product Recommendations
// ─────────────────────────────────────────────────────────────────────────────

export async function handleProductRecommendations(request, env, authCtx) {
  try {
    const url   = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '3', 10);

    let profile;
    if (authCtx?.userId) {
      profile = await getUserBehaviorProfile(env, authCtx.userId);
    } else {
      // Build profile from query params (anonymous / scan context)
      profile = {
        plan:             authCtx?.plan || 'free',
        scans:            parseInt(url.searchParams.get('scans') || '1', 10),
        critical_cves:    parseInt(url.searchParams.get('critical') || '0', 10),
        high_cves:        parseInt(url.searchParams.get('high') || '0', 10),
        engagement_score: 30,
        is_enterprise:    false,
        api_calls_today:  0,
        has_siem:         false,
        total_spent:      0,
      };
    }

    const recommendations = getProductRecommendations(profile, limit);

    return json({ success: true, recommendations, count: recommendations.length });
  } catch (e) {
    return err(`Product recommendations error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monetize/churn-risk  — Churn Risk (ENTERPRISE / ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleChurnRisk(request, env, authCtx) {
  const gate = requirePlan(authCtx, 'enterprise', 'pro');
  if (gate) {
    return err(gate === 'UNAUTHENTICATED' ? 'Auth required' : 'PRO+ required', gate === 'UNAUTHENTICATED' ? 401 : 403, gate);
  }

  try {
    // If admin, can request any user
    const url    = new URL(request.url);
    const target = (authCtx?.role === 'admin' && url.searchParams.get('user_id')) || authCtx.userId;

    const profile   = await getUserBehaviorProfile(env, target);
    const churnRisk = analyzeChurnRisk(profile);

    return json({ success: true, churn_risk: churnRisk, user_id: target });
  } catch (e) {
    return err(`Churn risk error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/monetize/optimize  — Full AI Revenue Optimization Pass
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueOptimize(request, env, authCtx) {
  if (!authCtx?.userId) {
    return err('Authentication required', 401, 'UNAUTHENTICATED');
  }

  try {
    const body    = await request.json().catch(() => ({}));
    const context = body.context || 'dashboard';

    const result = await runRevenueOptimization(env, authCtx.userId, context);

    return json({ success: true, ...result });
  } catch (e) {
    return err(`Optimization error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/funnel/event  — Record Funnel Stage Event (PUBLIC)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleFunnelEvent(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { stage, metadata } = body;

    const VALID_STAGES = [
      'visit', 'scan_start', 'scan_done', 'email_capture',
      'product_view', 'checkout_start', 'purchase',
      'upgrade_click', 'upsell_view', 'siem_view', 'siem_export',
      'feature_blocked', 'api_quota_hit',
    ];

    if (!stage || !VALID_STAGES.includes(stage)) {
      return err(`Invalid stage. Valid: ${VALID_STAGES.join(', ')}`, 400, 'INVALID_STAGE');
    }

    const userId = authCtx?.userId || null;
    const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
    const id     = crypto.randomUUID();

    await env.DB.prepare(`
      INSERT INTO funnel_events (id, stage, user_id, ip_hash, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      id,
      stage,
      userId,
      await hashIP(ip),
      metadata ? JSON.stringify(metadata) : null,
    ).run().catch(() => {});

    return json({ success: true, stage, id });
  } catch (e) {
    return err(`Funnel event error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/funnel/metrics  — Conversion Funnel (ADMIN / ENTERPRISE)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleFunnelMetrics(request, env, authCtx) {
  const gate = requirePlan(authCtx, 'enterprise');
  if (gate && authCtx?.role !== 'admin') {
    return err(gate === 'UNAUTHENTICATED' ? 'Auth required' : 'ENTERPRISE required', gate === 'UNAUTHENTICATED' ? 401 : 403, gate);
  }

  try {
    const url  = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30', 10);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const stages = ['visit', 'scan_start', 'scan_done', 'email_capture', 'product_view', 'checkout_start', 'purchase'];

    const stageRows = await env.DB.prepare(`
      SELECT stage, COUNT(*) as count
      FROM funnel_events
      WHERE created_at >= ?
      GROUP BY stage
    `).bind(since).all();

    const stageCounts = {};
    for (const row of (stageRows.results || [])) {
      stageCounts[row.stage] = row.count;
    }

    const funnel = stages.map((stage, idx) => {
      const count = stageCounts[stage] || 0;
      const prev  = idx > 0 ? (stageCounts[stages[idx - 1]] || 0) : count;
      const drop  = prev > 0 ? ((1 - count / prev) * 100).toFixed(1) : '0.0';
      return { stage, count, drop_rate_pct: `${drop}%` };
    });

    const visitors  = stageCounts['visit'] || 1;
    const purchases = stageCounts['purchase'] || 0;

    return json({
      success:                    true,
      funnel,
      overall_conversion_pct:     `${((purchases / visitors) * 100).toFixed(2)}%`,
      total_visitors:             stageCounts['visit'] || 0,
      total_purchases:            purchases,
      window_days:                days,
    });
  } catch (e) {
    return err(`Funnel metrics error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/defense/catalog  — Defense Product Catalog (PUBLIC)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleDefenseCatalog(request, env, authCtx) {
  try {
    const catalog = getProductCatalog();
    return json({ success: true, catalog, count: catalog.products?.length || 0 });
  } catch (e) {
    return err(`Catalog error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/defense/preview  — Defense Product Preview with Paywall
// ─────────────────────────────────────────────────────────────────────────────

export async function handleDefensePreview(request, env, authCtx) {
  try {
    const url         = new URL(request.url);
    const productType = url.searchParams.get('product') || 'firewall_rules';
    const cveId       = url.searchParams.get('cve') || 'CVE-2024-0001';

    // Build a minimal intel entry for preview
    const entry = {
      cveId,
      title:    `${cveId} Threat Intelligence`,
      severity: url.searchParams.get('severity') || 'HIGH',
      cvss:     parseFloat(url.searchParams.get('cvss') || '8.5'),
      iocs:     [],
      tactics:  ['Initial Access', 'Execution'],
      products: ['Apache', 'Windows Server'],
    };

    // Check if user has already purchased this product
    const hasPurchased = authCtx?.userId
      ? await checkPurchase(env, authCtx.userId, productType, cveId)
      : false;

    const preview = getProductPreview(entry, productType);
    const product = Object.values(DEFENSE_PRODUCTS).find(p => p.id === productType);

    if (hasPurchased) {
      // Return full product
      const full = generateDefenseProducts(entry);
      return json({
        success:     true,
        purchased:   true,
        product_type: productType,
        content:     full[productType] || preview,
      });
    }

    return json({
      success:      true,
      purchased:    false,
      preview,
      product_type: productType,
      product_name: product?.name || productType,
      price_inr:    product?.price || 199,
      buy_url:      `/api/checkout?product=${productType}&cve=${cveId}&price=${product?.price || 199}`,
      gumroad_url:  product?.gumroadSlug ? `https://cyberdudebivash.gumroad.com/l/${product.gumroadSlug}` : null,
    });
  } catch (e) {
    return err(`Preview error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/checkout  — Initiate Razorpay Checkout
// ─────────────────────────────────────────────────────────────────────────────

export async function handleCheckoutInitiate(request, env, authCtx) {
  try {
    const url     = new URL(request.url);
    const body    = await request.json().catch(() => ({}));

    const product  = body.product  || url.searchParams.get('product');
    const price    = parseFloat(body.price || url.searchParams.get('price') || '0');
    const planName = body.plan     || url.searchParams.get('plan');
    const cveId    = body.cve      || url.searchParams.get('cve');
    const email    = body.email    || authCtx?.email;

    if (!product && !planName) {
      return err('product or plan is required', 400, 'MISSING_PRODUCT');
    }
    if (!price || price <= 0) {
      return err('Invalid price', 400, 'INVALID_PRICE');
    }

    // Create Razorpay order via their API
    const orderId   = crypto.randomUUID().replace(/-/g, '').slice(0, 20);
    const amountPaise = Math.round(price * 100); // Razorpay uses paise

    let razorpayOrder = null;
    try {
      const rpRes = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization:  `Basic ${btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`)}`,
        },
        body: JSON.stringify({
          amount:   amountPaise,
          currency: 'INR',
          receipt:  orderId,
          notes: {
            product,
            plan:     planName || '',
            cve_id:   cveId || '',
            user_id:  authCtx?.userId || '',
            email:    email || '',
          },
        }),
      });

      if (rpRes.ok) {
        razorpayOrder = await rpRes.json();
      }
    } catch {
      // Razorpay API unavailable — continue with local order
    }

    // Store pending order in D1
    await env.DB.prepare(`
      INSERT OR IGNORE INTO revenue_events
        (id, source, amount, user_id, email, metadata, payment_id, created_at)
      VALUES (?, 'pending_checkout', ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      orderId,
      price,
      authCtx?.userId || null,
      email || null,
      JSON.stringify({ product, plan: planName, cve_id: cveId }),
      razorpayOrder?.id || null,
    ).run().catch(() => {});

    // Record funnel event
    await env.DB.prepare(`
      INSERT INTO funnel_events (id, stage, user_id, metadata, created_at)
      VALUES (?, 'checkout_start', ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      authCtx?.userId || null,
      JSON.stringify({ product, price }),
    ).run().catch(() => {});

    return json({
      success:        true,
      order_id:       orderId,
      razorpay_order: razorpayOrder,
      amount:         price,
      amount_paise:   amountPaise,
      currency:       'INR',
      product,
      plan:           planName,
      key_id:         env.RAZORPAY_KEY_ID || '',
      prefill: {
        email:  email || '',
        name:   authCtx?.name || '',
      },
    });
  } catch (e) {
    return err(`Checkout error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/checkout/verify  — Verify Razorpay Payment
// ─────────────────────────────────────────────────────────────────────────────

export async function handleCheckoutVerify(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, product, plan, amount, email } = body;

    if (!razorpay_payment_id) {
      return err('razorpay_payment_id required', 400, 'MISSING_PAYMENT_ID');
    }

    // HMAC-SHA256 signature verification
    if (razorpay_order_id && razorpay_signature && env.RAZORPAY_KEY_SECRET) {
      const expectedSig = await hmacSHA256(
        `${razorpay_order_id}|${razorpay_payment_id}`,
        env.RAZORPAY_KEY_SECRET
      );
      if (expectedSig !== razorpay_signature) {
        return err('Payment signature verification failed', 400, 'INVALID_SIGNATURE');
      }
    }

    const source = plan ? 'subscription' :
                   product?.includes('pack') ? 'full_defense_pack' :
                   product?.includes('enterprise_bundle') ? 'enterprise_bundle' :
                   'defense_product';

    // Record confirmed revenue
    await recordRevenueEvent(env, {
      source,
      amount:     parseFloat(amount || 0),
      user_id:    authCtx?.userId,
      email:      email || authCtx?.email,
      metadata:   JSON.stringify({ product, plan, razorpay_order_id }),
      payment_id: razorpay_payment_id,
    });

    // Update subscription plan in D1 if this was a plan purchase
    if (plan && (email || authCtx?.email)) {
      const userEmail = email || authCtx?.email;
      await env.DB.prepare(`
        UPDATE leads SET plan = ?, updated_at = datetime('now'), status = 'active'
        WHERE email = ?
      `).bind(plan, userEmail).run().catch(() => {});
    }

    // Grant product access in KV
    if (product && (authCtx?.userId || email)) {
      const accessKey = `purchase:${authCtx?.userId || email}:${product}`;
      await env.SECURITY_HUB_KV?.put(accessKey, razorpay_payment_id, { expirationTtl: 86400 * 365 });
    }

    // Record funnel conversion
    await env.DB.prepare(`
      INSERT INTO funnel_events (id, stage, user_id, metadata, created_at)
      VALUES (?, 'purchase', ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      authCtx?.userId || null,
      JSON.stringify({ product, plan, payment_id: razorpay_payment_id, amount }),
    ).run().catch(() => {});

    // Send confirmation via email queue
    if (email || authCtx?.email) {
      await env.SECURITY_HUB_KV?.put(
        `email:queue:purchase:${razorpay_payment_id}`,
        JSON.stringify({
          type:       'purchase_confirmation',
          email:      email || authCtx?.email,
          product,
          plan,
          amount,
          payment_id: razorpay_payment_id,
          ts:         Date.now(),
        }),
        { expirationTtl: 86400 }
      ).catch(() => {});
    }

    return json({
      success:    true,
      verified:   true,
      payment_id: razorpay_payment_id,
      product,
      plan,
      message:    plan
        ? `Welcome to ${plan.toUpperCase()} plan! Your account has been upgraded.`
        : `${product} purchased successfully! Check your email for download link.`,
    });
  } catch (e) {
    return err(`Verify error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/affiliate/stats  — Affiliate Click Stats (ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleAffiliateStats(request, env, authCtx) {
  if (authCtx?.role !== 'admin') {
    return err('Admin access required', 403, 'FORBIDDEN');
  }

  try {
    const url  = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30', 10);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [total, byProgram, topReferrers] = await Promise.all([
      env.DB.prepare(`
        SELECT COUNT(*) as clicks,
               COALESCE(SUM(estimated_commission), 0) as est_commission
        FROM affiliate_clicks
        WHERE clicked_at >= ?
      `).bind(since).first(),

      env.DB.prepare(`
        SELECT program,
               COUNT(*) as clicks,
               COALESCE(SUM(estimated_commission), 0) as est_commission
        FROM affiliate_clicks
        WHERE clicked_at >= ?
        GROUP BY program
        ORDER BY clicks DESC
      `).bind(since).all(),

      env.DB.prepare(`
        SELECT referrer_url,
               COUNT(*) as clicks
        FROM affiliate_clicks
        WHERE clicked_at >= ?
        GROUP BY referrer_url
        ORDER BY clicks DESC
        LIMIT 10
      `).bind(since).all(),
    ]);

    return json({
      success:         true,
      total_clicks:    total?.clicks || 0,
      est_commission:  total?.est_commission || 0,
      by_program:      byProgram.results || [],
      top_referrers:   topReferrers.results || [],
      window_days:     days,
    });
  } catch (e) {
    return err(`Affiliate stats error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/monetize/bulk-optimize  — Bulk AI pass (CRON / ADMIN)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleBulkOptimize(request, env, authCtx) {
  if (authCtx?.role !== 'admin' && !authCtx?.cron) {
    return err('Admin / cron access required', 403, 'FORBIDDEN');
  }

  try {
    const result = await runBulkOptimization(env);
    return json({ success: true, ...result });
  } catch (e) {
    return err(`Bulk optimize error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function checkPurchase(env, userId, productType, cveId) {
  try {
    const accessKey = `purchase:${userId}:${productType}`;
    const val = await env.SECURITY_HUB_KV?.get(accessKey);
    return !!val;
  } catch {
    return false;
  }
}

async function hashIP(ip) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  const arr  = Array.from(new Uint8Array(buf));
  return arr.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/metrics  — Full KPI metrics with plan-gated depth
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueMetrics(request, env, authCtx) {
  if (!authCtx?.userId) return err('Authentication required', 401, 'UNAUTHENTICATED');

  const plan = authCtx.plan || 'free';
  const url  = new URL(request.url);
  const days = parseInt(url.searchParams.get('days') || '30', 10);

  // Cache key (5-min TTL)
  const cacheKey = `cache:revenue:metrics:${plan}:${days}`;
  try {
    const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
    if (cached) return json({ success: true, cached: true, ...JSON.parse(cached) });
  } catch { /* miss */ }

  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    // ── FREE: minimal — only their own scan count + upgrade prompt ─────────
    if (plan === 'free') {
      const scans = await env.DB.prepare(
        `SELECT COUNT(*) as n FROM scan_history WHERE user_id = ?`
      ).bind(authCtx.userId).first().catch(() => ({ n: 0 }));

      return json({
        success: true,
        plan,
        metrics: {
          scans_run:       scans?.n || 0,
          reports_unlocked: 0,
          api_calls:        0,
        },
        upgrade_prompt: {
          show:    true,
          message: 'Upgrade to STARTER to unlock full revenue analytics',
          cta:     'Upgrade — ₹499/mo',
          url:     '/upgrade?plan=starter&ref=metrics',
        },
      });
    }

    // ── STARTER: basic own-account metrics ────────────────────────────────
    if (plan === 'starter') {
      const [scans, apiCalls, purchases] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as n FROM scan_history WHERE user_id = ? AND created_at >= ?`).bind(authCtx.userId, since).first(),
        env.DB.prepare(`SELECT COALESCE(SUM(weight),0) as n FROM api_usage_log WHERE (api_key IN (SELECT key FROM api_keys WHERE user_id = ?)) AND logged_at >= ?`).bind(authCtx.userId, since).first(),
        env.DB.prepare(`SELECT COUNT(*) as n, COALESCE(SUM(amount),0) as total FROM revenue_events WHERE user_id = ? AND created_at >= ?`).bind(authCtx.userId, since).first(),
      ]);

      return json({
        success: true,
        plan,
        window_days: days,
        metrics: {
          scans_run:      scans?.n || 0,
          api_calls:      apiCalls?.n || 0,
          purchases_made: purchases?.n || 0,
          amount_spent:   purchases?.total || 0,
        },
      });
    }

    // ── PRO: full platform analytics ──────────────────────────────────────
    // ── ENTERPRISE + ADMIN: advanced insights ─────────────────────────────
    const isEnterprise = plan === 'enterprise' || authCtx?.role === 'admin';

    const queries = [
      // Total revenue
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total, COUNT(*) as events FROM revenue_events WHERE created_at >= ?`).bind(since).first(),
      // By source
      env.DB.prepare(`SELECT source, COALESCE(SUM(amount),0) as amount, COUNT(*) as cnt FROM revenue_events WHERE created_at >= ? GROUP BY source ORDER BY amount DESC`).bind(since).all(),
      // Active subscribers
      env.DB.prepare(`SELECT plan, COUNT(*) as count FROM leads WHERE plan != 'free' AND status = 'active' GROUP BY plan`).all(),
      // Funnel conversions
      env.DB.prepare(`SELECT stage, COUNT(*) as count FROM funnel_events WHERE created_at >= ? GROUP BY stage`).bind(since).all(),
      // Top products
      env.DB.prepare(`SELECT metadata as product, COUNT(*) as sales, COALESCE(SUM(amount),0) as revenue FROM revenue_events WHERE source IN ('defense_product','full_defense_pack','gumroad') AND created_at >= ? GROUP BY metadata ORDER BY revenue DESC LIMIT 5`).bind(since).all(),
    ];

    if (isEnterprise) {
      queries.push(
        // Affiliate clicks
        env.DB.prepare(`SELECT program, COUNT(*) as clicks, COALESCE(SUM(estimated_commission),0) as est FROM affiliate_clicks WHERE clicked_at >= ? GROUP BY program`).bind(since).all(),
        // AdSense
        env.DB.prepare(`SELECT COALESCE(SUM(impressions),0) as impressions, COALESCE(SUM(estimated_revenue),0) as revenue FROM adsense_events WHERE recorded_at >= ?`).bind(since).first(),
        // Daily trend
        env.DB.prepare(`SELECT date(created_at) as day, COALESCE(SUM(amount),0) as revenue, COUNT(*) as events FROM revenue_events WHERE created_at >= ? GROUP BY date(created_at) ORDER BY day ASC`).bind(since).all(),
      );
    }

    const results = await Promise.all(queries);
    const [totals, bySource, subscribers, funnelRows, topProducts] = results;
    const affiliateRows = isEnterprise ? results[5] : null;
    const adSense       = isEnterprise ? results[6] : null;
    const dailyTrend    = isEnterprise ? results[7] : null;

    // Build plan MRR
    const PLAN_PRICE = { starter: 499, pro: 1499, enterprise: 4999 };
    let mrr = 0;
    for (const row of (subscribers.results || [])) {
      mrr += (PLAN_PRICE[row.plan] || 0) * row.count;
    }

    // Funnel map
    const funnelMap = {};
    for (const row of (funnelRows.results || [])) funnelMap[row.stage] = row.count;
    const visitors  = funnelMap['visit'] || 1;
    const purchases = funnelMap['purchase'] || 0;

    const payload = {
      window_days:     days,
      plan,
      total_revenue:   totals?.total || 0,
      total_events:    totals?.events || 0,
      mrr,
      arr:             mrr * 12,
      revenue_by_source: bySource.results || [],
      top_products:    topProducts.results || [],
      subscribers:     subscribers.results || [],
      funnel: {
        visitors,
        purchases,
        conversion_rate: `${((purchases / visitors) * 100).toFixed(2)}%`,
      },
      avg_user_value: mrr > 0 && (subscribers.results || []).reduce((a, r) => a + r.count, 0) > 0
        ? Math.round(mrr / (subscribers.results || []).reduce((a, r) => a + r.count, 0))
        : 0,
      ...(isEnterprise ? {
        affiliate:    affiliateRows?.results || [],
        adsense:      adSense || {},
        daily_trend:  dailyTrend?.results || [],
      } : {}),
    };

    // Cache 5 minutes
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 }).catch(() => {});

    return json({ success: true, ...payload });
  } catch (e) {
    return err(`Metrics error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/products  — All sellable products with live sales data
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueProducts(request, env, authCtx) {
  try {
    const url  = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30', 10);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    // Cache 10 minutes (public-safe, no PII)
    const cacheKey = `cache:revenue:products:${days}`;
    try {
      const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
      if (cached) return json({ success: true, cached: true, ...JSON.parse(cached) });
    } catch { /* miss */ }

    const [salesData, gumroadData, subData] = await Promise.all([
      // Defense product sales
      env.DB.prepare(`
        SELECT source, metadata as product_id,
               COUNT(*) as total_sales,
               COALESCE(SUM(amount),0) as total_revenue,
               MAX(created_at) as last_sale_at
        FROM revenue_events
        WHERE source IN ('defense_product','full_defense_pack','enterprise_bundle','report_purchase')
          AND created_at >= ?
        GROUP BY source, metadata
        ORDER BY total_revenue DESC
        LIMIT 20
      `).bind(since).all(),

      // Gumroad product sales
      env.DB.prepare(`
        SELECT product_id,
               COUNT(*) as total_sales,
               COALESCE(SUM(amount),0) as total_revenue,
               MAX(created_at) as last_sale_at
        FROM gumroad_licenses
        WHERE status = 'active' AND created_at >= ?
        GROUP BY product_id
        ORDER BY total_revenue DESC
        LIMIT 10
      `).bind(since).all(),

      // Subscription products
      env.DB.prepare(`
        SELECT plan as product_id,
               COUNT(*) as total_sales,
               COUNT(*) * CASE plan
                 WHEN 'starter' THEN 499
                 WHEN 'pro'     THEN 1499
                 WHEN 'enterprise' THEN 4999
                 ELSE 0 END as total_revenue
        FROM leads
        WHERE plan != 'free' AND status = 'active'
        GROUP BY plan
        ORDER BY total_revenue DESC
      `).all(),
    ]);

    // Static catalog enrichment
    const CATALOG = {
      firewall_rules:    { name: 'Firewall Rules Pack',      price: 199,   category: 'defense' },
      ids_signatures:    { name: 'IDS/IPS Signatures',       price: 399,   category: 'defense' },
      ir_playbook:       { name: 'IR Playbook',              price: 999,   category: 'defense' },
      hardening_script:  { name: 'Hardening Scripts',        price: 599,   category: 'defense' },
      threat_hunt_pack:  { name: 'Threat Hunt Pack',         price: 799,   category: 'defense' },
      sigma_rules:       { name: 'Sigma Rules',              price: 399,   category: 'detection'},
      exec_briefing:     { name: 'Executive Briefing',       price: 299,   category: 'reporting'},
      full_defense_pack: { name: 'Full Defense Pack',        price: 2499,  category: 'bundle'  },
      enterprise_bundle: { name: 'Enterprise Bundle',        price: 9999,  category: 'bundle'  },
      starter:           { name: 'STARTER Subscription',     price: 499,   category: 'subscription' },
      pro:               { name: 'PRO Subscription',         price: 1499,  category: 'subscription' },
      enterprise:        { name: 'ENTERPRISE Subscription',  price: 4999,  category: 'subscription' },
    };

    // Merge all products
    const allProducts = [
      ...(salesData.results   || []).map(r => ({
        ...r,
        ...(CATALOG[r.product_id] || { name: r.product_id, price: 0, category: 'other' }),
      })),
      ...(gumroadData.results  || []).map(r => ({
        ...r,
        ...(CATALOG[r.product_id] || { name: r.product_id, price: 0, category: 'gumroad' }),
        source: 'gumroad',
      })),
      ...(subData.results || []).map(r => ({
        ...r,
        ...(CATALOG[r.product_id] || {}),
        source: 'subscription',
      })),
    ].sort((a, b) => (b.total_revenue || 0) - (a.total_revenue || 0));

    const totalRevenue = allProducts.reduce((a, p) => a + (p.total_revenue || 0), 0);

    const payload = {
      products:      allProducts,
      count:         allProducts.length,
      total_revenue: totalRevenue,
      top_product:   allProducts[0] || null,
      window_days:   days,
    };

    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 600 }).catch(() => {});

    return json({ success: true, ...payload });
  } catch (e) {
    return err(`Products error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/revenue/track  — Track any revenue-related action (PUBLIC)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueTrack(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { event, source, amount, metadata } = body;

    const VALID_EVENTS = [
      'page_view', 'product_view', 'add_to_cart', 'checkout_start',
      'purchase', 'upgrade_click', 'upsell_dismiss', 'affiliate_click',
      'ad_impression', 'ad_click', 'feature_blocked', 'trial_start',
    ];

    if (!event || !VALID_EVENTS.includes(event)) {
      return err(`Invalid event. Valid: ${VALID_EVENTS.join(', ')}`, 400, 'INVALID_EVENT');
    }

    const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userId = authCtx?.userId || null;
    const id     = crypto.randomUUID();
    const ts     = Date.now();

    // Route to correct table
    if (event === 'purchase' && amount > 0) {
      await recordRevenueEvent(env, {
        source:   source || 'unknown',
        amount:   parseFloat(amount),
        user_id:  userId,
        email:    authCtx?.email,
        metadata: JSON.stringify(metadata || {}),
      });
    } else if (event === 'affiliate_click') {
      const program = metadata?.program || source || 'unknown';
      const cpc     = { hackthebox: 45, tryhackme: 35, udemy: 60, nordvpn: 120 };
      await env.DB.prepare(`
        INSERT INTO affiliate_clicks
          (id, program, user_id, referrer_url, estimated_commission, clicked_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).bind(id, program, userId, metadata?.referrer || '', cpc[program] || 30).run().catch(() => {});
    } else if (event === 'ad_impression' || event === 'ad_click') {
      await env.DB.prepare(`
        INSERT INTO adsense_events
          (id, ad_unit, impressions, clicks, estimated_revenue, recorded_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        id,
        metadata?.ad_unit || 'unknown',
        event === 'ad_impression' ? 1 : 0,
        event === 'ad_click' ? 1 : 0,
        event === 'ad_click' ? 2.5 : 0.025, // estimated ₹
      ).run().catch(() => {});
    }

    // Always log to funnel_events for conversion tracking
    const FUNNEL_MAP = {
      product_view:    'product_view',
      checkout_start:  'checkout_start',
      purchase:        'purchase',
      upgrade_click:   'upgrade_click',
      feature_blocked: 'feature_blocked',
      trial_start:     'scan_start',
    };
    if (FUNNEL_MAP[event]) {
      await env.DB.prepare(`
        INSERT INTO funnel_events (id, stage, user_id, metadata, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).bind(id + '_f', FUNNEL_MAP[event], userId, JSON.stringify({ event, source, ...metadata })).run().catch(() => {});
    }

    // KV real-time counter (fire-and-forget)
    env.SECURITY_HUB_KV?.get(`rt:events:${event}:count`).then(v => {
      env.SECURITY_HUB_KV?.put(`rt:events:${event}:count`, String((parseInt(v || '0')) + 1), { expirationTtl: 86400 });
    }).catch(() => {});

    return json({ success: true, tracked: event, id });
  } catch (e) {
    return err(`Track error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// Export monetizeScanResult re-export for convenience
export { monetizeScanResult };
