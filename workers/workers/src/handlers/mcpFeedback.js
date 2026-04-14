/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — MCP Feedback Handler v17.0
 *
 * Endpoints:
 *   POST /api/mcp/feedback       — track user interaction with MCP recommendations
 *   GET  /api/mcp/feedback/stats — item performance stats (admin)
 *   GET  /api/mcp/feedback/scores— top/bottom scoring items (admin)
 *   GET  /api/mcp/ab/results     — A/B experiment results (admin)
 *   POST /api/mcp/feedback/batch — batch submit multiple events (frontend performance)
 *
 * Security:
 *   - Rate limited: 100 events/min per IP
 *   - Input sanitized + validated
 *   - Revenue field capped (set server-side from D1 delivery_tokens, not client)
 *   - Admin endpoints require authentication
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { storeFeedback, validateFeedback } from '../services/mcpLearningEngine.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────
function jsonOk(data, extra = {}) {
  return new Response(JSON.stringify({ success: true, data, error: null, ts: new Date().toISOString() }), {
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}
function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ success: false, data: null, error: msg }), {
    status, headers: { 'Content-Type': 'application/json' },
  });
}

function sanitize(str, maxLen = 80) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').replace(/['"`;\\]/g, '').slice(0, maxLen).trim();
}

// ─── Rate limiter: 100 events/min/IP via KV ───────────────────────────────────
async function checkRateLimit(env, ip) {
  if (!env?.SECURITY_HUB_KV) return false; // no KV = skip rate limit
  const key   = `mcp:fb:rl:${ip}`;
  const count = parseInt(await env.SECURITY_HUB_KV.get(key).catch(() => '0') || '0', 10);
  if (count >= 100) return true; // limited
  env.SECURITY_HUB_KV.put(key, String(count + 1), { expirationTtl: 60 }).catch(() => {});
  return false;
}

// ─── POST /api/mcp/feedback ───────────────────────────────────────────────────
/**
 * Track a single user interaction with an MCP recommendation.
 *
 * Request body:
 * {
 *   action:              'click' | 'purchase' | 'ignore' | 'dismiss' | 'share'
 *   recommendation_type: 'tool' | 'training' | 'bundle' | 'upsell' | 'enterprise'
 *   item_id:             string (max 80 chars)
 *   item_name:           string (optional, max 120 chars)
 *   context:             'scan_result' | 'dashboard' | 'exit_intent' | ... (optional)
 *   module:              'domain' | 'ai' | ... (optional)
 *   risk_level:          'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' (optional)
 *   tier:                'FREE' | 'STARTER' | 'PRO' | 'ENTERPRISE' (optional)
 *   ab_variant:          'A' | 'B' (optional)
 *   experiment_id:       string (optional, for A/B)
 *   session_id:          string (optional, client-side session fingerprint)
 * }
 *
 * NOTE: revenue_inr is NEVER trusted from client. Set server-side for purchases.
 */
export async function handleMCPFeedback(request, env, authCtx = {}) {
  const ip = authCtx?.ip || request.headers.get('CF-Connecting-IP') || 'anon';

  // Rate limit
  if (await checkRateLimit(env, ip)) {
    return jsonErr('Rate limit exceeded. Max 100 events/minute.', 429);
  }

  // Parse body
  let body = {};
  try { body = await request.json(); }
  catch { return jsonErr('Invalid JSON body'); }

  // Sanitize all fields
  const sanitized = {
    action:              sanitize(body.action, 20),
    recommendation_type: sanitize(body.recommendation_type, 20),
    item_id:             sanitize(body.item_id, 80),
    item_name:           sanitize(body.item_name || '', 120),
    context:             sanitize(body.context || 'scan_result', 40),
    module:              sanitize(body.module || '', 30),
    risk_level:          sanitize(body.risk_level || '', 20),
    tier:                sanitize(body.tier || 'FREE', 20),
    ab_variant:          (body.ab_variant === 'A' || body.ab_variant === 'B') ? body.ab_variant : null,
    experiment_id:       sanitize(body.experiment_id || '', 60),
    session_id:          sanitize(body.session_id || '', 64),
    revenue_inr:         0, // NEVER from client — server-side only
  };

  // For purchase events: look up actual revenue from D1 delivery_tokens
  // This prevents client-side revenue inflation
  if (sanitized.action === 'purchase' && env?.DB) {
    try {
      const userId = authCtx?.userId || authCtx?.user_id;
      const email  = authCtx?.email  || '';
      if (userId || email) {
        const row = await env.DB.prepare(`
          SELECT amount_inr FROM delivery_tokens
          WHERE (user_id = ? OR payer_email = ?)
            AND product_id = ?
            AND status IN ('active','used')
          ORDER BY activated_at DESC
          LIMIT 1
        `).bind(userId || '', email || '', sanitized.item_id).first().catch(() => null);
        if (row?.amount_inr) sanitized.revenue_inr = parseInt(row.amount_inr, 10) || 0;
      }
    } catch { /* revenue stays 0 if lookup fails */ }
  }

  // Validate
  const errors = validateFeedback(sanitized);
  if (errors.length) return jsonErr(`Validation failed: ${errors.join('; ')}`);

  // Store (fire-and-forget internally — storeFeedback catches all errors)
  await storeFeedback(env, sanitized, authCtx);

  return jsonOk({
    recorded: true,
    action:   sanitized.action,
    item_id:  sanitized.item_id,
    learning: 'event stored — MCP will adapt in next decision',
  });
}

// ─── POST /api/mcp/feedback/batch ─────────────────────────────────────────────
/**
 * Batch submit up to 20 feedback events. Used by frontend for buffered tracking.
 * Each event processed independently — partial success is OK.
 */
export async function handleMCPFeedbackBatch(request, env, authCtx = {}) {
  const ip = authCtx?.ip || request.headers.get('CF-Connecting-IP') || 'anon';

  if (await checkRateLimit(env, ip)) {
    return jsonErr('Rate limit exceeded.', 429);
  }

  let body = {};
  try { body = await request.json(); }
  catch { return jsonErr('Invalid JSON'); }

  const events = Array.isArray(body.events) ? body.events.slice(0, 20) : [];
  if (!events.length) return jsonErr('No events provided');

  let stored = 0, failed = 0;

  for (const ev of events) {
    const sanitized = {
      action:              sanitize(ev.action, 20),
      recommendation_type: sanitize(ev.recommendation_type, 20),
      item_id:             sanitize(ev.item_id, 80),
      item_name:           sanitize(ev.item_name || '', 120),
      context:             sanitize(ev.context || 'scan_result', 40),
      module:              sanitize(ev.module || '', 30),
      risk_level:          sanitize(ev.risk_level || '', 20),
      tier:                sanitize(ev.tier || 'FREE', 20),
      ab_variant:          (ev.ab_variant === 'A' || ev.ab_variant === 'B') ? ev.ab_variant : null,
      experiment_id:       sanitize(ev.experiment_id || '', 60),
      session_id:          sanitize(ev.session_id || '', 64),
      revenue_inr:         0, // always 0 from client batch
    };

    const errors = validateFeedback(sanitized);
    if (errors.length) { failed++; continue; }

    const ok = await storeFeedback(env, sanitized, authCtx).catch(() => false);
    ok ? stored++ : failed++;
  }

  return jsonOk({ stored, failed, total: events.length });
}

// ─── GET /api/mcp/feedback/stats ─────────────────────────────────────────────
/**
 * Returns top performing items + context breakdown. Auth required.
 */
export async function handleMCPFeedbackStats(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '10', 10), 50);
  const rec_type = url.searchParams.get('type') || null;

  if (!env?.DB) return jsonErr('Database unavailable', 503);

  try {
    const [topItems, recentFeedback, contextStats] = await Promise.all([
      // Top performing items
      env.DB.prepare(`
        SELECT item_id, item_name, recommendation_type,
               total_shown, total_clicks, total_purchases,
               click_rate, purchase_rate, mcp_score, total_revenue_inr
        FROM mcp_item_scores
        ${rec_type ? 'WHERE recommendation_type = ?' : ''}
        ORDER BY mcp_score DESC
        LIMIT ?
      `).bind(...(rec_type ? [rec_type, limit] : [limit])).all().catch(() => ({ results: [] })),

      // Recent feedback events (last 50)
      env.DB.prepare(`
        SELECT action, recommendation_type, item_id, context, module,
               risk_level, tier, success, created_at
        FROM mcp_feedback
        ORDER BY created_at DESC
        LIMIT 50
      `).all().catch(() => ({ results: [] })),

      // Context conversion summary
      env.DB.prepare(`
        SELECT context, recommendation_type,
               COUNT(*) as total_events,
               SUM(success) as total_conversions,
               ROUND(CAST(SUM(success) AS REAL) / COUNT(*), 3) as conversion_rate
        FROM mcp_feedback
        GROUP BY context, recommendation_type
        ORDER BY conversion_rate DESC
      `).all().catch(() => ({ results: [] })),
    ]);

    return jsonOk({
      top_items:      topItems.results,
      recent_events:  recentFeedback.results,
      context_stats:  contextStats.results,
      generated_at:   new Date().toISOString(),
    });
  } catch (e) {
    return jsonErr(`Stats error: ${e.message}`, 500);
  }
}

// ─── GET /api/mcp/feedback/scores ────────────────────────────────────────────
/**
 * Returns all item scores sorted by mcp_score. Auth required.
 * Useful for admin dashboard to see which items are learning well.
 */
export async function handleMCPItemScores(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);
  if (!env?.DB) return jsonErr('Database unavailable', 503);

  const url    = new URL(request.url);
  const order  = url.searchParams.get('order') === 'asc' ? 'ASC' : 'DESC';
  const type   = url.searchParams.get('type') || null;

  try {
    const result = await env.DB.prepare(`
      SELECT item_id, item_name, recommendation_type,
             total_shown, total_clicks, total_purchases, total_ignores,
             click_rate, purchase_rate, ignore_rate, mcp_score,
             total_revenue_inr, last_updated
      FROM mcp_item_scores
      ${type ? 'WHERE recommendation_type = ?' : ''}
      ORDER BY mcp_score ${order}
      LIMIT 100
    `).bind(...(type ? [type] : [])).all().catch(() => ({ results: [] }));

    return jsonOk({
      scores:      result.results,
      total:       result.results.length,
      order:       order.toLowerCase(),
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return jsonErr(`Scores error: ${e.message}`, 500);
  }
}

// ─── GET /api/mcp/ab/results ──────────────────────────────────────────────────
/**
 * Returns A/B experiment results from KV + D1. Auth required.
 */
export async function handleMCPABResults(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);
  if (!env?.SECURITY_HUB_KV) return jsonErr('KV unavailable', 503);

  const EXPERIMENT_IDS = ['cta_urgency_v1', 'discount_signal_v1', 'bundle_urgency_v1'];

  try {
    const results = await Promise.all(
      EXPERIMENT_IDS.map(async id => {
        const [data, winner] = await Promise.all([
          env.SECURITY_HUB_KV.get(`mcp:ab:${id}`, 'json').catch(() => null),
          env.SECURITY_HUB_KV.get(`mcp:ab:winner:${id}`).catch(() => null),
        ]);
        return { experiment_id: id, variants: data, winner, status: winner ? 'decided' : 'running' };
      })
    );

    return jsonOk({ experiments: results, generated_at: new Date().toISOString() });
  } catch (e) {
    return jsonErr(`A/B results error: ${e.message}`, 500);
  }
}
