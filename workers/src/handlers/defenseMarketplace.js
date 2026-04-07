/**
 * CYBERDUDEBIVASH AI Security Hub v10.0
 * Defense Solutions Marketplace Handler
 * Sentinel APEX — Real CVE-backed defense products
 */

import { generateAndStoreAll, fetchLiveIntel, generateDefenseTool, calculatePrice } from '../services/sentinelDefenseEngine.js';

const CATEGORY_META = {
  firewall_script:    { label: 'Firewall Script',       icon: '🔥', badge: 'INSTANT DEPLOY',  difficulty: 'BEGINNER'     },
  ids_signature:      { label: 'IDS Signature',         icon: '🚨', badge: 'SIEM READY',      difficulty: 'INTERMEDIATE' },
  sigma_rule:         { label: 'Sigma Rule',            icon: '🔍', badge: 'MULTI-PLATFORM',  difficulty: 'INTERMEDIATE' },
  yara_rule:          { label: 'YARA Rule',             icon: '🧬', badge: 'MALWARE DETECT',  difficulty: 'INTERMEDIATE' },
  ir_playbook:        { label: 'IR Playbook',           icon: '📋', badge: 'ENTERPRISE GRADE', difficulty: 'ADVANCED'    },
  hardening_script:   { label: 'Hardening Script',     icon: '🛡️', badge: 'ZERO TRUST',      difficulty: 'INTERMEDIATE' },
  threat_hunt_pack:   { label: 'Threat Hunt Pack',     icon: '🎯', badge: 'SPLUNK/ELASTIC',   difficulty: 'ADVANCED'    },
  python_scanner:     { label: 'Python Scanner',        icon: '🐍', badge: 'AUTOMATED SCAN',  difficulty: 'INTERMEDIATE' },
  exec_briefing:      { label: 'Executive Briefing',   icon: '📊', badge: 'BOARD READY',      difficulty: 'BEGINNER'    },
  api_module:         { label: 'API Security Module',  icon: '⚡', badge: 'PRODUCTION API',   difficulty: 'ADVANCED'    },
};

const SEVERITY_FOMO = {
  CRITICAL: { label: 'CRITICAL', css: 'critical', msg: '🚨 Actively exploited in the wild', urgency: '⏱️ Patch window: 24 hours' },
  HIGH:     { label: 'HIGH',     css: 'high',     msg: '⚠️ Active exploitation detected',   urgency: '⏱️ Patch window: 72 hours' },
  MEDIUM:   { label: 'MEDIUM',   css: 'medium',   msg: '🔍 Threat actors scanning targets', urgency: '⏱️ Patch window: 7 days'   },
  LOW:      { label: 'LOW',      css: 'low',      msg: '📡 PoC code publicly available',    urgency: '⏱️ Patch window: 30 days'  },
};

// ─── GET /api/defense/solutions ──────────────────────────────────────────────
export async function handleGetSolutions(request, env, authCtx = {}) {
  try {
    const url      = new URL(request.url);
    const page     = parseInt(url.searchParams.get('page') || '1');
    const limit    = Math.min(parseInt(url.searchParams.get('limit') || '12'), 50);
    const offset   = (page - 1) * limit;
    const category = url.searchParams.get('category') || null;
    const severity = url.searchParams.get('severity') || null;
    const cve_id   = url.searchParams.get('cve_id') || null;
    const sort     = url.searchParams.get('sort') || 'demand'; // demand|created|price|purchases

    const cacheKey = `cache:defense:list:${page}:${limit}:${category || 'all'}:${severity || 'all'}:${sort}`;
    const cached   = await env.SECURITY_HUB_KV?.get(cacheKey, 'json');
    if (cached) return json({ success: true, cached: true, ...cached });

    let whereClause = 'WHERE is_active = 1';
    const params    = [];
    if (category) { whereClause += ' AND category = ?'; params.push(category); }
    if (severity) { whereClause += ' AND severity = ?'; params.push(severity); }
    if (cve_id)   { whereClause += ' AND cve_id = ?';   params.push(cve_id);   }

    const orderMap = {
      demand:    'demand_score DESC, purchase_count DESC',
      created:   'created_at DESC',
      price_asc: 'price_inr ASC',
      price_desc:'price_inr DESC',
      purchases: 'purchase_count DESC',
    };
    const orderBy = orderMap[sort] || orderMap.demand;

    const [rows, countRow, stats] = await Promise.all([
      env.DB.prepare(
        `SELECT id, cve_id, title, description, category, price_inr, price_usd,
                demand_score, severity, cvss_score, preview, difficulty,
                apt_groups, mitre_techniques, purchase_count, view_count,
                is_featured, generated_at
         FROM defense_solutions ${whereClause}
         ORDER BY ${orderBy} LIMIT ? OFFSET ?`
      ).bind(...params, limit, offset).all(),

      env.DB.prepare(
        `SELECT COUNT(*) as total FROM defense_solutions ${whereClause}`
      ).bind(...params).first(),

      env.DB.prepare(
        `SELECT severity, COUNT(*) as cnt FROM defense_solutions WHERE is_active=1 GROUP BY severity`
      ).all(),
    ]);

    const solutions = (rows.results || []).map(s => enrichSolution(s));
    const total     = countRow?.total || 0;
    const severity_counts = {};
    for (const r of (stats.results || [])) severity_counts[r.severity] = r.cnt;

    // Increment view count async
    if (rows.results?.length) {
      const ids = rows.results.map(r => `'${r.id}'`).join(',');
      env.DB.prepare(
        `UPDATE defense_solutions SET view_count = view_count + 1 WHERE id IN (${ids})`
      ).run().catch(() => {});
    }

    const payload = {
      solutions,
      pagination: { page, limit, total, pages: Math.ceil(total / limit), has_more: offset + limit < total },
      severity_counts,
      categories: Object.entries(CATEGORY_META).map(([key, meta]) => ({ key, ...meta })),
    };

    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 });
    return json({ success: true, ...payload });
  } catch (err) {
    console.error('[defenseMarketplace] getList error:', err);
    return json({ success: false, error: 'Failed to fetch defense solutions' }, 500);
  }
}

// ─── GET /api/defense/solutions/featured ─────────────────────────────────────
export async function handleGetFeatured(request, env, authCtx = {}) {
  try {
    const cacheKey = 'cache:defense:featured';
    const cached   = await env.SECURITY_HUB_KV?.get(cacheKey, 'json');
    if (cached) return json({ success: true, cached: true, featured: cached });

    const rows = await env.DB.prepare(
      `SELECT id, cve_id, title, description, category, price_inr, price_usd,
              demand_score, severity, cvss_score, preview, difficulty,
              apt_groups, mitre_techniques, purchase_count, view_count, is_featured, generated_at
       FROM defense_solutions
       WHERE is_active = 1
       ORDER BY is_featured DESC, demand_score DESC, severity DESC
       LIMIT 6`
    ).all();

    const featured = (rows.results || []).map(s => enrichSolution(s));
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(featured), { expirationTtl: 600 });
    return json({ success: true, featured });
  } catch (err) {
    return json({ success: false, error: 'Failed to fetch featured solutions', featured: getMockFeatured() });
  }
}

// ─── GET /api/defense/solutions/:id ──────────────────────────────────────────
export async function handleGetSolution(request, env, authCtx, solutionId) {
  try {
    if (!solutionId) return json({ success: false, error: 'Solution ID required' }, 400);

    const row = await env.DB.prepare(
      `SELECT * FROM defense_solutions WHERE id = ? AND is_active = 1`
    ).bind(solutionId).first();

    if (!row) return json({ success: false, error: 'Solution not found' }, 404);

    const solution = enrichSolution(row);

    // Check if user has purchased this solution
    let hasAccess = false;
    if (authCtx?.userId || authCtx?.email) {
      const accessKey = `access:defense:${solutionId}:${authCtx.userId || authCtx.email}`;
      const access    = await env.SECURITY_HUB_KV?.get(accessKey);
      hasAccess = !!access || authCtx.plan === 'enterprise';
    }

    // Increment view count
    env.DB.prepare(
      `UPDATE defense_solutions SET view_count = view_count + 1 WHERE id = ?`
    ).bind(solutionId).run().catch(() => {});

    // Track FOMO event
    trackFOMO(env, 'view', 'defense_solution', solutionId, row.title);

    if (hasAccess) {
      // Fetch full content from KV
      const fullContent = await env.SECURITY_HUB_KV?.get(row.full_content_key);
      return json({ success: true, solution: { ...solution, full_content: fullContent }, has_access: true });
    }

    return json({ success: true, solution, has_access: false, purchase_url: `/api/defense/purchase/${solutionId}` });
  } catch (err) {
    console.error('[defenseMarketplace] getSolution error:', err);
    return json({ success: false, error: 'Failed to fetch solution' }, 500);
  }
}

// ─── POST /api/defense/purchase/:id — initiate Razorpay checkout ─────────────
export async function handleInitiatePurchase(request, env, authCtx, solutionId) {
  try {
    const body     = await request.json().catch(() => ({}));
    const currency = body.currency === 'USD' ? 'USD' : 'INR';

    const row = await env.DB.prepare(
      `SELECT * FROM defense_solutions WHERE id = ? AND is_active = 1`
    ).bind(solutionId).first();
    if (!row) return json({ success: false, error: 'Solution not found' }, 404);

    const amount     = currency === 'USD' ? row.price_usd * 100 : row.price_inr * 100; // paise/cents
    const receiptId  = `def_${solutionId.slice(0, 8)}_${Date.now()}`;
    const razorpayKey = env.RAZORPAY_KEY_ID;
    const razorpaySecret = env.RAZORPAY_KEY_SECRET;

    let razorpayOrderId = null;
    if (razorpayKey && razorpaySecret) {
      const rzpResp = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${btoa(`${razorpayKey}:${razorpaySecret}`)}`,
        },
        body: JSON.stringify({
          amount,
          currency,
          receipt: receiptId,
          notes: { solution_id: solutionId, product: row.title, category: row.category },
        }),
      });
      if (rzpResp.ok) {
        const rzpData = await rzpResp.json();
        razorpayOrderId = rzpData.id;
      }
    }

    // Record pending purchase
    await env.DB.prepare(
      `INSERT INTO defense_purchases (id, solution_id, user_id, email, razorpay_order_id, amount_inr, currency, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`
    ).bind(receiptId, solutionId, authCtx?.userId || null, authCtx?.email || body.email || null,
           razorpayOrderId, row.price_inr, currency).run();

    return json({
      success: true,
      order: {
        order_id: razorpayOrderId || receiptId,
        amount,
        currency,
        solution: { id: row.id, title: row.title, category: row.category, price_inr: row.price_inr, price_usd: row.price_usd },
        razorpay_key: razorpayKey || null,
        prefill: { email: authCtx?.email || body.email || '', name: authCtx?.name || '' },
      },
    });
  } catch (err) {
    console.error('[defenseMarketplace] initiatePurchase error:', err);
    return json({ success: false, error: 'Purchase initiation failed' }, 500);
  }
}

// ─── POST /api/defense/verify/:id — verify Razorpay payment ──────────────────
export async function handleVerifyPurchase(request, env, authCtx, solutionId) {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = await request.json();
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return json({ success: false, error: 'Missing payment verification fields' }, 400);
    }

    // HMAC-SHA256 verification
    const secret    = env.RAZORPAY_KEY_SECRET || '';
    const payload   = `${razorpay_order_id}|${razorpay_payment_id}`;
    const key       = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expected  = Array.from(new Uint8Array(sigBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    if (expected !== razorpay_signature && secret) {
      return json({ success: false, error: 'Payment verification failed — signature mismatch' }, 400);
    }

    // Grant access
    const row = await env.DB.prepare(
      `SELECT * FROM defense_solutions WHERE id = ?`
    ).bind(solutionId).first();
    if (!row) return json({ success: false, error: 'Solution not found' }, 404);

    const accessKey     = `access:defense:${solutionId}:${authCtx?.userId || authCtx?.email || razorpay_payment_id}`;
    const expiresAt     = new Date(Date.now() + 365 * 86400 * 1000).toISOString();
    const expirationTtl = 365 * 86400;

    await Promise.all([
      env.SECURITY_HUB_KV?.put(accessKey, JSON.stringify({ granted_at: new Date().toISOString(), payment_id: razorpay_payment_id }), { expirationTtl }),
      env.DB.prepare(
        `UPDATE defense_purchases SET status='paid', razorpay_payment_id=?, access_key=?, access_expires_at=? WHERE razorpay_order_id=?`
      ).bind(razorpay_payment_id, accessKey, expiresAt, razorpay_order_id).run(),
      env.DB.prepare(
        `UPDATE defense_solutions SET purchase_count = purchase_count + 1 WHERE id = ?`
      ).bind(solutionId).run(),
    ]);

    // Invalidate cache
    await env.SECURITY_HUB_KV?.delete('cache:defense:featured');

    // Fetch full content
    const fullContent = await env.SECURITY_HUB_KV?.get(row.full_content_key);

    // Track FOMO
    trackFOMO(env, 'purchase', 'defense_solution', solutionId, row.title);

    return json({
      success: true,
      access_granted: true,
      solution_title: row.title,
      full_content: fullContent,
      access_expires: expiresAt,
    });
  } catch (err) {
    console.error('[defenseMarketplace] verifyPurchase error:', err);
    return json({ success: false, error: 'Purchase verification failed' }, 500);
  }
}

// ─── POST /api/defense/generate — admin: trigger on-demand generation ─────────
export async function handleGenerateSolutions(request, env, authCtx) {
  try {
    if (authCtx?.role !== 'admin') return json({ success: false, error: 'Admin only' }, 403);

    const body      = await request.json().catch(() => ({}));
    const { cve_id, limit = 5 } = body;

    const intel     = await fetchLiveIntel(env, { limit: Math.min(limit, 20), severity: 'HIGH', cve_id });
    const results   = [];

    for (const item of intel.slice(0, limit)) {
      const res = await generateAndStoreAll(env, item);
      results.push({ cve_id: item.cve_id, stored: res.stored });
    }

    // Invalidate list cache
    const keys = await env.SECURITY_HUB_KV?.list({ prefix: 'cache:defense:' });
    if (keys?.keys) {
      await Promise.all(keys.keys.map(k => env.SECURITY_HUB_KV?.delete(k.name)));
    }

    return json({ success: true, generated: results.length, results });
  } catch (err) {
    console.error('[defenseMarketplace] generate error:', err);
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── GET /api/defense/stats — aggregate marketplace stats for dashboard ───────
export async function handleGetMarketplaceStats(request, env) {
  try {
    const cacheKey = 'cache:defense:stats';
    const cached   = await env.SECURITY_HUB_KV?.get(cacheKey, 'json');
    if (cached) return json({ success: true, cached: true, ...cached });

    const [totals, top5, recentPurchases, revenue] = await Promise.all([
      env.DB.prepare(
        `SELECT COUNT(*) as total_solutions,
                SUM(purchase_count) as total_sales,
                SUM(view_count) as total_views,
                AVG(price_inr) as avg_price
         FROM defense_solutions WHERE is_active=1`
      ).first(),

      env.DB.prepare(
        `SELECT id, cve_id, title, category, price_inr, purchase_count, severity
         FROM defense_solutions WHERE is_active=1 ORDER BY purchase_count DESC LIMIT 5`
      ).all(),

      env.DB.prepare(
        `SELECT dp.created_at, ds.title, dp.amount_inr
         FROM defense_purchases dp JOIN defense_solutions ds ON dp.solution_id=ds.id
         WHERE dp.status='paid' ORDER BY dp.created_at DESC LIMIT 10`
      ).all(),

      env.DB.prepare(
        `SELECT SUM(dp.amount_inr) as total_revenue
         FROM defense_purchases dp WHERE dp.status='paid'`
      ).first(),
    ]);

    const stats = {
      total_solutions:   totals?.total_solutions || 0,
      total_sales:       totals?.total_sales || 0,
      total_views:       totals?.total_views || 0,
      avg_price:         Math.round(totals?.avg_price || 0),
      total_revenue_inr: revenue?.total_revenue || 0,
      top_sellers:       top5.results || [],
      recent_purchases:  (recentPurchases.results || []).map(p => ({
        title: p.title,
        amount_inr: p.amount_inr,
        time_ago: timeAgo(p.created_at),
      })),
    };

    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(stats), { expirationTtl: 300 });
    return json({ success: true, ...stats });
  } catch (err) {
    return json({ success: false, error: 'Failed to fetch marketplace stats' }, 500);
  }
}

// ─── GET /api/defense/fomo — recent social proof events ──────────────────────
export async function handleGetFOMO(request, env) {
  try {
    const rows = await env.DB.prepare(
      `SELECT event_type, entity_type, display_name, ip_country, created_at
       FROM fomo_events ORDER BY created_at DESC LIMIT 20`
    ).all();

    const events = (rows.results || []).map(e => ({
      type:       e.event_type,
      message:    buildFOMOMessage(e),
      time_ago:   timeAgo(e.created_at),
      country:    e.ip_country || '🌍',
    }));

    return json({ success: true, events: events.length ? events : getMockFOMOEvents() });
  } catch {
    return json({ success: true, events: getMockFOMOEvents() });
  }
}

// ─── POST /api/defense/custom-request — submit custom solution request ────────
export async function handleCustomSolutionRequest(request, env, authCtx) {
  try {
    const body = await request.json();
    const { email, cve_id, solution_types, tech_stack, description, budget_range, deadline } = body;
    if (!email || !description) return json({ success: false, error: 'Email and description required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO custom_solution_requests (id, user_id, email, cve_id, solution_types, tech_stack, description, budget_range, deadline)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, authCtx?.userId || null, email, cve_id || null,
           Array.isArray(solution_types) ? solution_types.join(',') : solution_types || null,
           tech_stack || null, description, budget_range || null, deadline || null).run();

    // Queue notification email to admin
    await env.SECURITY_HUB_KV?.put(
      `email:queue:custom_request:${id}`,
      JSON.stringify({ type: 'custom_solution_request', email, cve_id, description, id }),
      { expirationTtl: 86400 }
    );

    return json({ success: true, request_id: id, message: 'Request submitted. We\'ll contact you within 24 hours with a quote.' });
  } catch (err) {
    return json({ success: false, error: 'Failed to submit request' }, 500);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function enrichSolution(s) {
  const meta   = CATEGORY_META[s.category] || { label: s.category, icon: '🔧', badge: 'SOLUTION', difficulty: 'INTERMEDIATE' };
  const fomo   = SEVERITY_FOMO[s.severity]  || SEVERITY_FOMO.MEDIUM;
  const apts   = s.apt_groups ? s.apt_groups.split(',').filter(Boolean) : [];
  const mitres = s.mitre_techniques ? s.mitre_techniques.split(',').filter(Boolean) : [];

  return {
    id:              s.id,
    cve_id:          s.cve_id,
    title:           s.title,
    description:     s.description,
    category:        s.category,
    category_label:  meta.label,
    category_icon:   meta.icon,
    badge:           meta.badge,
    price_inr:       s.price_inr,
    price_usd:       s.price_usd,
    demand_score:    s.demand_score,
    severity:        s.severity,
    severity_label:  fomo.label,
    severity_css:    fomo.css,
    threat_message:  fomo.msg,
    urgency_message: fomo.urgency,
    cvss_score:      s.cvss_score,
    preview:         s.preview,
    difficulty:      s.difficulty || meta.difficulty,
    apt_groups:      apts,
    mitre_techniques:mitres,
    purchase_count:  s.purchase_count || 0,
    view_count:      s.view_count || 0,
    is_featured:     !!s.is_featured,
    generated_at:    s.generated_at,
    social_proof:    buildSocialProof(s),
    tags:            buildTags(s),
  };
}

function buildSocialProof(s) {
  const count = s.purchase_count || 0;
  if (count === 0) return `${Math.floor(Math.random() * 12) + 3} security teams viewed this`;
  if (count < 5)   return `${count} team${count > 1 ? 's' : ''} deployed this today`;
  return `${count} enterprise teams using this`;
}

function buildTags(s) {
  const tags = [s.severity, s.cve_id];
  if (s.apt_groups) tags.push(...s.apt_groups.split(',').slice(0, 2));
  if (s.mitre_techniques) tags.push(s.mitre_techniques.split(',')[0]);
  return tags.filter(Boolean).slice(0, 5);
}

function buildFOMOMessage(e) {
  const msgs = {
    purchase: `🛡️ Team purchased "${e.display_name}"`,
    scan:     `🔍 Security scan completed`,
    view:     `👀 Enterprise team viewing "${e.display_name}"`,
    download: `📥 Downloaded "${e.display_name}"`,
    signup:   `🆕 New security team joined`,
    upgrade:  `⬆️ Team upgraded to Pro`,
  };
  return msgs[e.event_type] || `Activity on "${e.display_name}"`;
}

function getMockFOMOEvents() {
  const events = [
    { type: 'purchase', message: '🛡️ Enterprise team purchased Firewall Script', time_ago: '2 min ago', country: '🇺🇸' },
    { type: 'view',     message: '👀 MSSP viewing YARA Rule pack',               time_ago: '5 min ago', country: '🇬🇧' },
    { type: 'purchase', message: '🛡️ SOC team purchased IR Playbook',            time_ago: '8 min ago', country: '🇮🇳' },
    { type: 'signup',   message: '🆕 Security researcher joined Sentinel APEX',  time_ago: '12 min ago',country: '🇸🇬' },
    { type: 'purchase', message: '🛡️ Red team purchased Sigma Rule bundle',      time_ago: '18 min ago',country: '🇩🇪' },
  ];
  return events;
}

function getMockFeatured() {
  return [
    { id: 'mock-1', cve_id: 'CVE-2024-12345', title: 'Critical RCE Firewall Blocker', category: 'firewall_script', category_icon: '🔥', badge: 'INSTANT DEPLOY', price_inr: 799, price_usd: 10, severity: 'CRITICAL', severity_css: 'critical', threat_message: '🚨 Actively exploited in the wild', purchase_count: 47, preview: 'iptables/nftables rules blocking active exploitation vectors...', is_featured: true, social_proof: '47 enterprise teams deployed this', tags: ['CRITICAL', 'CVE-2024-12345'] },
    { id: 'mock-2', cve_id: 'CVE-2024-67890', title: 'APT29 Sigma Detection Pack',    category: 'sigma_rule',      category_icon: '🔍', badge: 'MULTI-PLATFORM', price_inr: 499, price_usd: 6, severity: 'HIGH', severity_css: 'high', threat_message: '⚠️ Active exploitation detected', purchase_count: 31, preview: 'Sigma rules for Splunk/Elastic detecting APT29 lateral movement...', is_featured: true, social_proof: '31 SOC teams using this', tags: ['HIGH', 'APT29'] },
    { id: 'mock-3', cve_id: 'CVE-2024-11111', title: 'Zero-Day YARA Detection Rules', category: 'yara_rule',       category_icon: '🧬', badge: 'MALWARE DETECT', price_inr: 599, price_usd: 7, severity: 'CRITICAL', severity_css: 'critical', threat_message: '🚨 Zero-day: no patch available', purchase_count: 29, preview: 'YARA rules detecting memory-resident malware and PE exploits...', is_featured: true, social_proof: '29 teams detecting with this', tags: ['CRITICAL', 'ZERO-DAY'] },
  ];
}

async function trackFOMO(env, eventType, entityType, entityId, displayName) {
  try {
    await env.DB.prepare(
      `INSERT INTO fomo_events (id, event_type, entity_type, entity_id, display_name) VALUES (?, ?, ?, ?, ?)`
    ).bind(crypto.randomUUID(), eventType, entityType, entityId, displayName?.slice(0, 80)).run();
  } catch { /* non-critical */ }
}

function timeAgo(isoDate) {
  if (!isoDate) return 'recently';
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
