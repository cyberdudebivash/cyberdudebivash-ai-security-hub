// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Conversion Funnel Engine
// GTM Growth Engine Phase 2: Visitor → Scan → Report → Upgrade → Paid
// ═══════════════════════════════════════════════════════════════════════════



// ── Plan limits ──────────────────────────────────────────────────────────────
export const PLAN_LIMITS = {
  free:       { scans_per_day: 3,  scans_per_month: 10, results_visible: 5,  api_calls: 0   },
  starter:    { scans_per_day: 20, scans_per_month: 200, results_visible: 20, api_calls: 100 },
  pro:        { scans_per_day: 100,scans_per_month: 1000,results_visible: 50, api_calls: 1000},
  enterprise: { scans_per_day: -1, scans_per_month: -1,  results_visible: -1, api_calls: -1  },
};

// ── Lead scoring weights ─────────────────────────────────────────────────────
const SCORE_WEIGHTS = {
  scan_performed:        5,
  critical_finding:      20,
  high_finding:          10,
  medium_finding:        5,
  returned_user:         15,
  multiple_domains:      25,
  api_key_requested:     30,
  enterprise_domain:     40,
  report_downloaded:     20,
  upgrade_page_visited:  25,
  email_opened:          10,
  email_clicked:         20,
  shared_on_social:      15,
};

// ── Enterprise domain indicators ────────────────────────────────────────────
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com',
  'protonmail.com','mail.com','yandex.com','zoho.com','aol.com',
  'live.com','msn.com','me.com','mac.com','googlemail.com',
]);

// ── Upgrade trigger thresholds ───────────────────────────────────────────────
const UPGRADE_TRIGGERS = {
  scan_limit_reached:        { score_boost: 30, urgency: 'high'   },
  critical_vuln_found:       { score_boost: 40, urgency: 'urgent' },
  report_locked:             { score_boost: 35, urgency: 'high'   },
  api_limit_reached:         { score_boost: 45, urgency: 'urgent' },
  high_lead_score:           { score_boost: 0,  urgency: 'medium' },
  multiple_sessions:         { score_boost: 20, urgency: 'medium' },
};

// ── Funnel stage definitions ─────────────────────────────────────────────────
export const FUNNEL_STAGES = {
  visitor:    'visitor',
  scan_start: 'scan_start',
  scan_done:  'scan_done',
  email_cap:  'email_captured',
  report_view:'report_viewed',
  upgrade_cta:'upgrade_cta_shown',
  converted:  'converted',
  churned:    'churned',
};

// ─────────────────────────────────────────────────────────────────────────────
// LEAD MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Capture or update a lead in D1
 * @param {object} env - Cloudflare env
 * @param {object} leadData - { email, name?, domain?, source?, fingerprint? }
 * @returns {object} lead record
 */
export async function captureEmail(env, leadData = {}) {
  const { email, name = null, domain = null, source = 'scan', fingerprint = null } = leadData;

  if (!email || !isValidEmail(email)) {
    return { success: false, error: 'invalid_email' };
  }

  const emailDomain = email.split('@')[1]?.toLowerCase() || '';
  const isEnterprise = !FREE_EMAIL_PROVIDERS.has(emailDomain);
  const leadDomain = domain || emailDomain;
  const now = new Date().toISOString();

  try {
    // Upsert lead
    await env.DB.prepare(`
      INSERT INTO leads (id, email, name, domain, source, is_enterprise, plan, lead_score, funnel_stage, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 'free', 0, 'email_captured', ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        name         = COALESCE(excluded.name, leads.name),
        domain       = COALESCE(excluded.domain, leads.domain),
        updated_at   = excluded.updated_at
    `).bind(
      crypto.randomUUID(), email, name, leadDomain, source,
      isEnterprise ? 1 : 0, now, now
    ).run();

    // Record funnel event
    await recordFunnelEvent(env, email, FUNNEL_STAGES.email_cap, { source });

    // Fetch updated lead
    const lead = await getLead(env, email);

    return { success: true, lead, isEnterprise };
  } catch (err) {
    console.error('[funnelEngine] captureEmail error:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Retrieve a lead by email
 */
export async function getLead(env, email) {
  try {
    const result = await env.DB.prepare(
      `SELECT * FROM leads WHERE email = ? LIMIT 1`
    ).bind(email).first();
    return result || null;
  } catch {
    return null;
  }
}

/**
 * Update lead plan after payment
 */
export async function upgradeLead(env, email, plan) {
  const validPlans = ['starter', 'pro', 'enterprise'];
  if (!validPlans.includes(plan)) return { success: false, error: 'invalid_plan' };

  const now = new Date().toISOString();
  try {
    await env.DB.prepare(`
      UPDATE leads SET plan = ?, funnel_stage = 'converted', converted_at = ?, updated_at = ?
      WHERE email = ?
    `).bind(plan, now, now, email).run();

    await recordFunnelEvent(env, email, FUNNEL_STAGES.converted, { plan });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LEAD SCORING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Add score points to a lead based on an action
 * @param {object} env
 * @param {string} email
 * @param {string} action - key from SCORE_WEIGHTS
 * @param {object} meta - extra context
 */
export async function scoreLeadAction(env, email, action, meta = {}) {
  const points = SCORE_WEIGHTS[action] || 0;
  if (points === 0) return;

  const now = new Date().toISOString();
  try {
    await env.DB.prepare(`
      UPDATE leads
      SET lead_score = MIN(lead_score + ?, 100),
          updated_at = ?
      WHERE email = ?
    `).bind(points, now, email).run();

    // Persist scoring event
    await recordFunnelEvent(env, email, `score:${action}`, { points, ...meta });
  } catch (err) {
    console.error('[funnelEngine] scoreLeadAction error:', err.message);
  }
}

/**
 * Compute lead score from scratch (for new leads without existing score)
 * @param {object} signals - arbitrary signal object
 * @returns {number} score 0–100
 */
export function computeLeadScore(signals = {}) {
  let score = 0;

  if (signals.scan_count)       score += Math.min(signals.scan_count * SCORE_WEIGHTS.scan_performed, 30);
  if (signals.critical_count)   score += Math.min(signals.critical_count * SCORE_WEIGHTS.critical_finding, 40);
  if (signals.high_count)       score += Math.min(signals.high_count * SCORE_WEIGHTS.high_finding, 20);
  if (signals.is_enterprise)    score += SCORE_WEIGHTS.enterprise_domain;
  if (signals.returned)         score += SCORE_WEIGHTS.returned_user;
  if (signals.multiple_domains) score += SCORE_WEIGHTS.multiple_domains;
  if (signals.api_requested)    score += SCORE_WEIGHTS.api_key_requested;
  if (signals.report_downloaded)score += SCORE_WEIGHTS.report_downloaded;

  return Math.min(Math.round(score), 100);
}

/**
 * Get lead tier from score
 */
export function getLeadTier(score) {
  if (score >= 80) return 'hot';
  if (score >= 50) return 'warm';
  if (score >= 20) return 'cool';
  return 'cold';
}

// ─────────────────────────────────────────────────────────────────────────────
// UPGRADE TRIGGERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a user should see an upgrade prompt
 * @param {object} env
 * @param {string} email
 * @param {string} plan - current plan
 * @param {object} context - { scan_count, critical_found, api_calls_today }
 * @returns {object} { shouldUpgrade, trigger, urgency, cta }
 */
export async function checkUpgradeTriggers(env, email, plan, context = {}) {
  if (plan === 'enterprise') return { shouldUpgrade: false };

  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
  const triggers = [];

  // 1. Scan limit reached
  if (limits.scans_per_day > 0 && (context.scan_count || 0) >= limits.scans_per_day) {
    triggers.push({ trigger: 'scan_limit_reached', ...UPGRADE_TRIGGERS.scan_limit_reached });
  }

  // 2. Critical vulnerability found on free plan
  if (plan === 'free' && context.critical_found) {
    triggers.push({ trigger: 'critical_vuln_found', ...UPGRADE_TRIGGERS.critical_vuln_found });
  }

  // 3. Report locked (visible results cap)
  if (limits.results_visible > 0 && (context.results_count || 0) >= limits.results_visible) {
    triggers.push({ trigger: 'report_locked', ...UPGRADE_TRIGGERS.report_locked });
  }

  // 4. API limit reached
  if (limits.api_calls > 0 && (context.api_calls_today || 0) >= limits.api_calls) {
    triggers.push({ trigger: 'api_limit_reached', ...UPGRADE_TRIGGERS.api_limit_reached });
  }

  if (triggers.length === 0) return { shouldUpgrade: false };

  // Pick highest urgency trigger
  const urgencyOrder = { urgent: 3, high: 2, medium: 1 };
  triggers.sort((a, b) => (urgencyOrder[b.urgency] || 0) - (urgencyOrder[a.urgency] || 0));
  const top = triggers[0];

  // Score boost for triggered leads
  if (email) {
    await scoreLeadAction(env, email, 'upgrade_page_visited');
    if (top.score_boost > 0) {
      const now = new Date().toISOString();
      await env.DB.prepare(`
        UPDATE leads SET lead_score = MIN(lead_score + ?, 100), updated_at = ?
        WHERE email = ?
      `).bind(top.score_boost, now, email).run().catch(() => {});
    }
    await recordFunnelEvent(env, email, FUNNEL_STAGES.upgrade_cta, { trigger: top.trigger });
  }

  return {
    shouldUpgrade: true,
    trigger:       top.trigger,
    urgency:       top.urgency,
    suggested_plan: recommendPlan(plan, top.trigger),
    cta:           buildUpgradeCTA(plan, top.trigger),
    all_triggers:  triggers.map(t => t.trigger),
  };
}

/**
 * Recommend next plan
 */
function recommendPlan(currentPlan, trigger) {
  const progression = { free: 'starter', starter: 'pro', pro: 'enterprise' };
  if (trigger === 'api_limit_reached' && currentPlan === 'starter') return 'pro';
  if (trigger === 'critical_vuln_found' && currentPlan === 'free') return 'starter';
  return progression[currentPlan] || 'pro';
}

/**
 * Build upgrade CTA copy
 */
function buildUpgradeCTA(plan, trigger) {
  const ctas = {
    scan_limit_reached: {
      headline: '🚫 Daily Scan Limit Reached',
      body:     'You\'ve used all your free scans for today. Upgrade to scan unlimited domains and stay ahead of threats.',
      button:   'Unlock Unlimited Scans',
      urgency:  'high',
    },
    critical_vuln_found: {
      headline: '🔴 Critical Vulnerability Detected',
      body:     'A CRITICAL severity vulnerability was found. Upgrade to see full details, CVE analysis, remediation steps, and IOCs.',
      button:   'View Full Report — Upgrade Now',
      urgency:  'urgent',
    },
    report_locked: {
      headline: '🔒 Full Report Locked',
      body:     `Your free plan shows ${PLAN_LIMITS.free.results_visible} results. Upgrade to see everything, including exploit status and EPSS scores.`,
      button:   'Unlock Full Report',
      urgency:  'high',
    },
    api_limit_reached: {
      headline: '⚡ API Rate Limit Reached',
      body:     'Your API quota is exhausted. Upgrade to PRO or Enterprise for higher limits and SLA-backed uptime.',
      button:   'Upgrade API Access',
      urgency:  'urgent',
    },
    default: {
      headline: '🚀 Upgrade Your Security Coverage',
      body:     'Get real-time threat intel, AI-powered SOC automation, and enterprise-grade defense.',
      button:   'View Plans',
      urgency:  'medium',
    },
  };
  return ctas[trigger] || ctas.default;
}

// ─────────────────────────────────────────────────────────────────────────────
// FUNNEL EVENTS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Record a funnel event in D1
 */
export async function recordFunnelEvent(env, email, stage, meta = {}) {
  try {
    await env.DB.prepare(`
      INSERT INTO funnel_events (id, email, stage, meta, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).bind(crypto.randomUUID(), email || 'anonymous', stage, JSON.stringify(meta)).run();
  } catch {
    // Non-blocking
  }
}

/**
 * Record a scan event and update lead scoring
 */
export async function recordScanEvent(env, email, scanResult = {}) {
  const { domain, severity_counts = {}, total_found = 0 } = scanResult;

  // Record funnel stage
  await recordFunnelEvent(env, email, FUNNEL_STAGES.scan_done, { domain, total_found });

  if (!email) return;

  // Score the lead
  await scoreLeadAction(env, email, 'scan_performed', { domain });

  if ((severity_counts.CRITICAL || 0) > 0) {
    await scoreLeadAction(env, email, 'critical_finding', { count: severity_counts.CRITICAL });
  }
  if ((severity_counts.HIGH || 0) > 0) {
    await scoreLeadAction(env, email, 'high_finding', { count: severity_counts.HIGH });
  }

  // Update scan count on lead
  const now = new Date().toISOString();
  await env.DB.prepare(`
    UPDATE leads SET scan_count = COALESCE(scan_count, 0) + 1, updated_at = ?
    WHERE email = ?
  `).bind(now, email).run().catch(() => {});
}

// ─────────────────────────────────────────────────────────────────────────────
// FUNNEL ANALYTICS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get funnel conversion metrics
 */
export async function getFunnelMetrics(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

    const [total, emails, conversions, hot, warm] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM funnel_events WHERE created_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(DISTINCT email) as n FROM leads WHERE created_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free' AND converted_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE lead_score >= 80`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE lead_score >= 50 AND lead_score < 80`).first(),
    ]);

    const emailCount    = emails?.n || 0;
    const convCount     = conversions?.n || 0;
    const convRate      = emailCount > 0 ? ((convCount / emailCount) * 100).toFixed(1) : '0.0';

    // Stage breakdown
    const stageRows = await env.DB.prepare(`
      SELECT stage, COUNT(*) as n
      FROM funnel_events
      WHERE created_at >= ?
      GROUP BY stage
      ORDER BY n DESC
    `).bind(since).all();

    const stageBreakdown = {};
    (stageRows.results || []).forEach(r => { stageBreakdown[r.stage] = r.n; });

    return {
      period_days:      days,
      total_events:     total?.n || 0,
      unique_leads:     emailCount,
      conversions:      convCount,
      conversion_rate:  `${convRate}%`,
      hot_leads:        hot?.n || 0,
      warm_leads:       warm?.n || 0,
      stage_breakdown:  stageBreakdown,
    };
  } catch (err) {
    console.error('[funnelEngine] getFunnelMetrics error:', err.message);
    return { error: err.message };
  }
}

/**
 * Get hot leads ready for sales outreach
 */
export async function getHotLeads(env, limit = 20) {
  try {
    const result = await env.DB.prepare(`
      SELECT email, name, domain, plan, lead_score, is_enterprise,
             scan_count, created_at, updated_at
      FROM leads
      WHERE lead_score >= 50
      ORDER BY lead_score DESC, updated_at DESC
      LIMIT ?
    `).bind(limit).all();

    return (result.results || []).map(lead => ({
      ...lead,
      tier:       getLeadTier(lead.lead_score),
      is_enterprise: lead.is_enterprise === 1,
    }));
  } catch (err) {
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────────────────────────────────────

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Parse scan context from request query params or body
 */
export function parseScanContext(data = {}) {
  return {
    domain:        data.domain     || null,
    email:         data.email      || null,
    scan_count:    parseInt(data.scan_count, 10)    || 0,
    critical_found:!!data.critical_found,
    results_count: parseInt(data.results_count, 10) || 0,
    api_calls_today: parseInt(data.api_calls_today, 10) || 0,
  };
}

/**
 * Get all leads (paginated) for admin/sales
 */
export async function listLeads(env, { limit = 50, offset = 0, tier = null, plan = null } = {}) {
  try {
    let query = `SELECT * FROM leads WHERE 1=1`;
    const params = [];

    if (plan) {
      query += ` AND plan = ?`;
      params.push(plan);
    }
    if (tier === 'hot')  { query += ` AND lead_score >= 80`; }
    if (tier === 'warm') { query += ` AND lead_score >= 50 AND lead_score < 80`; }
    if (tier === 'cold') { query += ` AND lead_score < 20`; }

    query += ` ORDER BY lead_score DESC, updated_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await env.DB.prepare(query).bind(...params).all();
    return result.results || [];
  } catch (err) {
    return [];
  }
}
