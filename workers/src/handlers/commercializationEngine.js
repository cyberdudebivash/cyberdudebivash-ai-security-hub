import { isRealUser } from '../auth/middleware.js';
/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * Commercialization Engine — /api/commercial/*
 *
 * Extends existing subscription/billing logic without touching it.
 * Adds: expansion scoring, upsell trigger detection, customer segmentation,
 *        upsell event logging, feature gate signals.
 *
 * Tables: expansion_scores, upsell_events (schema_phase4.sql)
 */

function genId() {
  return `com_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}

function requireAuth(authCtx)  { return isRealUser(authCtx); }
function requireAdmin(authCtx) { return authCtx?.isAdmin === true; }

// ─── Expansion signal engine ──────────────────────────────────────────────────
// Returns { score: 0-100, signals: [...], recommended_tier, segment }
async function computeExpansionScore(env, orgId, role) {
  const signals  = [];
  let   score    = 0;

  async function count(sql, ...params) {
    try {
      const r = await env.SECURITY_HUB_DB.prepare(sql).bind(...params).first();
      return r?.cnt ?? r?.count ?? 0;
    } catch { return 0; }
  }

  const [
    scans30d,
    apiCalls7d,
    openCases,
    teamSize,
    reportsGenerated,
    reportScheduled,
    ctiIocs,
    msspClients,
  ] = await Promise.allSettled([
    count(`SELECT COUNT(*) cnt FROM scan_results WHERE org_id = ? AND created_at >= datetime('now','-30 days')`, orgId),
    count(`SELECT COUNT(*) cnt FROM scan_results WHERE org_id = ? AND created_at >= datetime('now','-7 days')`, orgId),
    count(`SELECT COUNT(*) cnt FROM soc_cases WHERE org_id = ? AND status IN ('OPEN','INVESTIGATING')`, orgId),
    count(`SELECT COUNT(*) cnt FROM users WHERE org_id = ?`, orgId),
    count(`SELECT COUNT(*) cnt FROM executive_reports WHERE org_id = ? AND created_at >= datetime('now','-30 days')`, orgId),
    count(`SELECT COUNT(*) cnt FROM enterprise_report_schedules WHERE org_id = ? AND status = 'active'`, orgId),
    count(`SELECT COUNT(*) cnt FROM cti_iocs WHERE org_id = ? AND created_at >= datetime('now','-30 days')`, orgId),
    count(`SELECT COUNT(DISTINCT client_org_id) cnt FROM mssp_workspace WHERE mssp_org_id = ?`, orgId),
  ]).then(r => r.map(x => x.status === 'fulfilled' ? x.value : 0));

  // Signal: high scan volume → approaching limit
  if (scans30d >= 1000) {
    signals.push({ signal: 'SCAN_LIMIT_80PCT', weight: 25, label: `${scans30d} scans in 30d` });
    score += 25;
  } else if (scans30d >= 500) {
    signals.push({ signal: 'SCAN_VOLUME_HIGH', weight: 15, label: `${scans30d} scans in 30d` });
    score += 15;
  }

  // Signal: active API usage
  if (apiCalls7d >= 200) {
    signals.push({ signal: 'HEAVY_API_USAGE', weight: 15, label: `${apiCalls7d} API calls this week` });
    score += 15;
  }

  // Signal: SOC is being used seriously
  if (openCases >= 10) {
    signals.push({ signal: 'HIGH_CASE_LOAD', weight: 10, label: `${openCases} open cases` });
    score += 10;
  }

  // Signal: growing team
  if (teamSize >= 5) {
    signals.push({ signal: 'TEAM_GROWTH', weight: 10, label: `${teamSize} team members` });
    score += 10;
  }

  // Signal: report automation activity
  if (reportScheduled >= 1) {
    signals.push({ signal: 'SCHEDULED_REPORTS', weight: 10, label: `${reportScheduled} scheduled reports` });
    score += 10;
  } else if (reportsGenerated >= 3) {
    signals.push({ signal: 'FREQUENT_REPORTS', weight: 5, label: `${reportsGenerated} reports this month` });
    score += 5;
  }

  // Signal: active CTI usage
  if (ctiIocs >= 50) {
    signals.push({ signal: 'CTI_HEAVY_USAGE', weight: 10, label: `${ctiIocs} IOCs this month` });
    score += 10;
  }

  // Signal: multi-tenant MSSP usage
  if (msspClients >= 3) {
    signals.push({ signal: 'MSSP_MULTI_CLIENT', weight: 15, label: `${msspClients} managed clients` });
    score += 15;
  }

  score = Math.min(100, score);

  // Determine recommended tier based on signals
  let recommended_tier = null;
  const signalIds = signals.map(s => s.signal);

  if (signalIds.includes('MSSP_MULTI_CLIENT') || msspClients >= 1) {
    recommended_tier = 'MSSP';
  } else if (role === 'enterprise' || (score >= 70 && (scans30d >= 500 || teamSize >= 10))) {
    recommended_tier = 'ENTERPRISE';
  } else if (score >= 40 || scans30d >= 100) {
    recommended_tier = role === 'pro' ? 'ENTERPRISE' : 'PRO';
  }

  // Segment
  const segment = score >= 80 ? 'CHAMPION'
                : score >= 60 ? 'MATURE'
                : score >= 35 ? 'GROWING'
                : 'STARTER';

  return {
    score,
    signals,
    segment,
    recommended_tier,
    upsell_ready: score >= 40 && recommended_tier !== null,
    primary_signal: signals[0]?.label || null,
  };
}

// ─── GET /api/commercial/expansion/:orgId ────────────────────────────────────
// Get expansion score for an org (admin sees any org, others see own)
export async function handleGetExpansionScore(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url    = new URL(request.url);
  const pathOrgId = url.pathname.split('/')[4];
  const orgId  = (requireAdmin(authCtx) && pathOrgId) ? pathOrgId : (authCtx.org_id || 'default');

  try {
    // Check if we have a recent cached score (within 1 hour)
    const cached = await env.SECURITY_HUB_DB.prepare(
      `SELECT * FROM expansion_scores WHERE org_id = ?
       AND computed_at >= datetime('now', '-1 hour')`
    ).bind(orgId).first();

    if (cached) {
      return Response.json({ expansion: cached, source: 'cache' });
    }

    // Compute fresh score
    const result = await computeExpansionScore(env, orgId, authCtx.role || 'free');

    // Upsert into expansion_scores
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO expansion_scores
         (org_id, expansion_score, segment, recommended_tier, primary_signal, signals_json, upsell_ready, computed_at, updated_at)
       VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now'))
       ON CONFLICT(org_id) DO UPDATE SET
         expansion_score=excluded.expansion_score,
         segment=excluded.segment,
         recommended_tier=excluded.recommended_tier,
         primary_signal=excluded.primary_signal,
         signals_json=excluded.signals_json,
         upsell_ready=excluded.upsell_ready,
         computed_at=excluded.computed_at,
         updated_at=excluded.updated_at`
    ).bind(
      orgId, result.score, result.segment, result.recommended_tier,
      result.primary_signal, JSON.stringify(result.signals),
      result.upsell_ready ? 1 : 0
    ).run();

    return Response.json({ expansion: { org_id: orgId, ...result, computed_at: new Date().toISOString() }, source: 'computed' });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/commercial/segments ────────────────────────────────────────────
// Admin: full customer segmentation table
export async function handleListSegments(request, env) {
  const authCtx = request.user || {};
  if (!requireAdmin(authCtx)) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const url    = new URL(request.url);
  const segment = url.searchParams.get('segment');  // optional filter
  const tier    = url.searchParams.get('tier');      // optional filter

  try {
    let sql = `SELECT e.org_id, e.expansion_score, e.segment, e.recommended_tier,
                      e.primary_signal, e.upsell_ready, e.computed_at
               FROM expansion_scores e
               WHERE 1=1`;
    const params = [];

    if (segment) { sql += ` AND e.segment = ?`; params.push(segment.toUpperCase()); }
    if (tier)    { sql += ` AND e.recommended_tier = ?`; params.push(tier.toUpperCase()); }

    sql += ` ORDER BY e.expansion_score DESC LIMIT 200`;

    const rows = await env.SECURITY_HUB_DB.prepare(sql).bind(...params).all();

    // Aggregate summary
    const all = rows.results || [];
    const summary = {
      total: all.length,
      upsell_ready: all.filter(r => r.upsell_ready).length,
      by_segment: {
        CHAMPION: all.filter(r => r.segment === 'CHAMPION').length,
        MATURE:   all.filter(r => r.segment === 'MATURE').length,
        GROWING:  all.filter(r => r.segment === 'GROWING').length,
        STARTER:  all.filter(r => r.segment === 'STARTER').length,
      },
      avg_expansion_score: all.length > 0
        ? Math.round(all.reduce((a, r) => a + r.expansion_score, 0) / all.length)
        : 0,
    };

    return Response.json({ segments: all, summary });
  } catch (e) {
    return Response.json({ error: e.message, segments: [] }, { status: 500 });
  }
}

// ─── POST /api/commercial/upsell/event ───────────────────────────────────────
// Log a upsell interaction (TRIGGER/IMPRESSION/CLICK/DISMISSED/CONVERTED)
export async function handleLogUpsellEvent(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const {
    event_type, trigger_reason, recommended_tier, current_tier,
    dismissed = false, converted = false,
  } = body;

  const VALID_EVENTS = ['TRIGGER','IMPRESSION','CLICK','DISMISSED','CONVERTED'];
  if (!event_type || !VALID_EVENTS.includes(event_type)) {
    return Response.json({ error: `event_type must be one of: ${VALID_EVENTS.join(', ')}` }, { status: 400 });
  }

  const orgId  = authCtx.org_id || 'default';
  const userId = authCtx.userId || authCtx.email || null;
  const id     = genId();

  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO upsell_events
         (id, org_id, user_id, event_type, trigger_reason, recommended_tier, current_tier, dismissed, converted, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))`
    ).bind(
      id, orgId, userId, event_type,
      trigger_reason || null, recommended_tier || null,
      current_tier || authCtx.role || 'free',
      dismissed ? 1 : 0, converted ? 1 : 0
    ).run();

    return Response.json({ success: true, event_id: id });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/commercial/upsell/funnel ───────────────────────────────────────
// Upsell conversion funnel stats (admin only)
export async function handleUpsellFunnel(request, env) {
  const authCtx = request.user || {};
  if (!requireAdmin(authCtx)) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const url  = new URL(request.url);
  const days = Math.min(parseInt(url.searchParams.get('days') || '30'), 365);

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT event_type, COUNT(*) cnt, COUNT(DISTINCT org_id) unique_orgs
       FROM upsell_events
       WHERE created_at >= datetime('now', ? || ' days')
       GROUP BY event_type`
    ).bind(`-${days}`).all();

    const funnel = Object.fromEntries((rows.results || []).map(r => [r.event_type, { count: r.cnt, unique_orgs: r.unique_orgs }]));

    const triggers    = funnel.TRIGGER?.count || 0;
    const impressions = funnel.IMPRESSION?.count || 0;
    const clicks      = funnel.CLICK?.count || 0;
    const conversions = funnel.CONVERTED?.count || 0;

    return Response.json({
      funnel,
      rates: {
        impression_rate: triggers  > 0 ? Math.round((impressions / triggers) * 100) : 0,
        click_rate:      impressions > 0 ? Math.round((clicks / impressions) * 100) : 0,
        conversion_rate: clicks    > 0 ? Math.round((conversions / clicks) * 100) : 0,
      },
      days,
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/commercial/features/gates ──────────────────────────────────────
// Feature gate check — returns allowed features for the caller's current plan
export async function handleFeatureGates(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const role = (authCtx.role || 'FREE').toLowerCase();

  const GATES = {
    soc_cases:               ['pro', 'enterprise', 'mssp_admin', 'admin'],
    soc_investigations:      ['enterprise', 'mssp_admin', 'admin'],
    cti_platform:            ['pro', 'enterprise', 'mssp_admin', 'admin'],
    cti_watchlists:          ['enterprise', 'mssp_admin', 'admin'],
    stix_export:             ['enterprise', 'mssp_admin', 'admin'],
    reporting_engine:        ['pro', 'enterprise', 'mssp_admin', 'admin'],
    executive_reports:       ['enterprise', 'mssp_admin', 'admin'],
    workflow_builder:        ['enterprise', 'mssp_admin', 'admin'],
    mssp_workspace:          ['mssp_admin'],
    white_label:             ['mssp_admin', 'admin'],
    revenue_intelligence:    ['admin'],
    commercialization_engine:['admin'],
    scan_limit:              { free: 10, pro: 500, enterprise: 5000, mssp_admin: -1, admin: -1 },
  };

  const allowed   = {};
  const at_limit  = {};

  for (const [feature, access] of Object.entries(GATES)) {
    if (Array.isArray(access)) {
      allowed[feature] = access.includes(role);
    } else if (typeof access === 'object') {
      const limit = access[role] ?? access['free'] ?? 10;
      allowed[feature] = true; // available to all, but rate-limited
      at_limit[feature] = { limit, unlimited: limit === -1 };
    }
  }

  return Response.json({ role, allowed, limits: at_limit });
}
