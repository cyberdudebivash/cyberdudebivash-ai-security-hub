/**
 * CYBERDUDEBIVASH AI Security Hub — Analytics Engine v1.0
 * Tracks platform events: scans, payments, conversions, downloads
 * Stores to D1 analytics_events table
 * Admin read endpoint: GET /api/admin/analytics (admin-tier only)
 */

// ─── Track a platform event (non-blocking, call with ctx.waitUntil) ──────────
export async function trackEvent(env, eventType, module = null, userId = null, ip = null, metadata = {}) {
  if (!env?.DB) return;
  try {
    const id = crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2);
    await env.DB.prepare(
      `INSERT INTO analytics_events (id, event_type, module, user_id, ip, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      id,
      eventType,
      module || null,
      userId || null,
      ip ? ip.slice(0, 45) : null,  // Truncate IPv6
      metadata ? JSON.stringify(metadata) : null,
    ).run();
  } catch (e) {
    // Non-critical — never block the main request
    console.warn('[Analytics] trackEvent failed:', e?.message);
  }
}

// ─── GET /api/admin/analytics ────────────────────────────────────────────────
export async function handleGetAnalytics(request, env, authCtx = {}) {
  // Admin-only — require ENTERPRISE tier with admin identity
  if (authCtx.tier !== 'ENTERPRISE' && authCtx.identity !== 'system') {
    return Response.json({ error: 'Admin access required' }, { status: 403 });
  }
  if (!env.DB) {
    return Response.json({ error: 'Database not available' }, { status: 503 });
  }

  const url    = new URL(request.url);
  const days   = Math.min(parseInt(url.searchParams.get('days') || '7', 10), 90);
  const module = url.searchParams.get('module') || null;

  try {
    // Summary stats
    const [
      totalScans,
      totalPayments,
      totalRevenue,
      recentEvents,
      eventBreakdown,
      moduleBreakdown,
    ] = await Promise.all([
      // Total scans
      env.DB.prepare(
        `SELECT COUNT(*) as count FROM analytics_events
         WHERE event_type IN ('scan_completed','scan_started')
         AND created_at > datetime('now', '-' || ? || ' days')`
      ).bind(days).first(),

      // Total payments
      env.DB.prepare(
        `SELECT COUNT(*) as count FROM payments
         WHERE status = 'paid'
         AND created_at > datetime('now', '-' || ? || ' days')`
      ).bind(days).first(),

      // Revenue (sum of paid payments)
      env.DB.prepare(
        `SELECT COALESCE(SUM(amount), 0) as total FROM payments
         WHERE status = 'paid'
         AND created_at > datetime('now', '-' || ? || ' days')`
      ).bind(days).first(),

      // Recent events (last 50)
      env.DB.prepare(
        `SELECT id, event_type, module, user_id, ip, metadata, created_at
         FROM analytics_events
         ORDER BY created_at DESC LIMIT 50`
      ).all(),

      // Event type breakdown
      env.DB.prepare(
        `SELECT event_type, COUNT(*) as count
         FROM analytics_events
         WHERE created_at > datetime('now', '-' || ? || ' days')
         GROUP BY event_type ORDER BY count DESC`
      ).bind(days).all(),

      // Module breakdown
      env.DB.prepare(
        `SELECT module, COUNT(*) as count
         FROM analytics_events
         WHERE module IS NOT NULL
         AND created_at > datetime('now', '-' || ? || ' days')
         GROUP BY module ORDER BY count DESC`
      ).bind(days).all(),
    ]);

    // Daily scan activity (last N days)
    const dailyActivity = await env.DB.prepare(
      `SELECT DATE(created_at) as date, COUNT(*) as count
       FROM analytics_events
       WHERE event_type = 'scan_completed'
       AND created_at > datetime('now', '-' || ? || ' days')
       GROUP BY DATE(created_at) ORDER BY date ASC`
    ).bind(days).all();

    // Recent payments
    const recentPayments = await env.DB.prepare(
      `SELECT id, module, target, amount, status, created_at, paid_at
       FROM payments
       ORDER BY created_at DESC LIMIT 20`
    ).all();

    return Response.json({
      period_days:       days,
      generated_at:      new Date().toISOString(),
      summary: {
        total_scans:     totalScans?.count   ?? 0,
        total_payments:  totalPayments?.count ?? 0,
        total_revenue_paise: totalRevenue?.total ?? 0,
        total_revenue_inr:   `₹${((totalRevenue?.total ?? 0) / 100).toLocaleString('en-IN')}`,
      },
      event_breakdown:   eventBreakdown?.results   ?? [],
      module_breakdown:  moduleBreakdown?.results  ?? [],
      daily_scan_activity: dailyActivity?.results  ?? [],
      recent_events:     recentEvents?.results      ?? [],
      recent_payments:   recentPayments?.results    ?? [],
    });
  } catch (e) {
    return Response.json({ error: 'Analytics query failed', details: e.message }, { status: 500 });
  }
}

// ─── GET /api/admin/analytics/scans ──────────────────────────────────────────
export async function handleScanStats(request, env, authCtx = {}) {
  if (authCtx.tier !== 'ENTERPRISE') {
    return Response.json({ error: 'Admin access required' }, { status: 403 });
  }
  if (!env.DB) return Response.json({ error: 'Database not available' }, { status: 503 });

  const url  = new URL(request.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '25', 10));
  const offset = (page - 1) * limit;

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT id, module, target, risk_score, risk_level, status, created_at, completed_at
       FROM scan_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(limit, offset).all(),
    env.DB.prepare(`SELECT COUNT(*) as count FROM scan_jobs`).first(),
  ]);

  return Response.json({
    scans:      rows?.results ?? [],
    total:      countRow?.count ?? 0,
    page,
    limit,
    total_pages: Math.ceil((countRow?.count ?? 0) / limit),
  });
}
