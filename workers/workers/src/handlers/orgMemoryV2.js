/**
 * CYBERDUDEBIVASH AI Security Hub — Organization Memory System v2.0
 *
 * Provides persistent threat intelligence memory per organization.
 * Stores scan history, threat encounters, actions taken, and derives
 * AI-powered recommendations based on accumulated patterns.
 *
 * Endpoints:
 *   GET  /api/org-memory              → full memory snapshot (history + patterns + recommendations)
 *   POST /api/org-memory/record       → record a threat event or action
 *   GET  /api/org-memory/history      → paginated event history
 *   GET  /api/org-memory/patterns     → AI pattern analysis
 *   GET  /api/org-memory/recommend    → AI recommendations based on history
 *   DELETE /api/org-memory            → clear memory for org (requires ENTERPRISE)
 */

import { ok, fail } from '../lib/response.js';

const KV_MEMORY_PREFIX    = 'org_memory:events:';
const KV_PATTERNS_PREFIX  = 'org_memory:patterns:';
const KV_PROFILE_PREFIX   = 'org_memory:profile:';
const MAX_EVENTS          = 500;
const DEFAULT_ORG         = 'default';

// ── Helpers ───────────────────────────────────────────────────────────────────
function getOrgId(authCtx) {
  return authCtx?.orgId || authCtx?.userId || DEFAULT_ORG;
}

async function loadEvents(env, orgId) {
  if (!env?.SECURITY_HUB_KV) return [];
  try {
    return (await env.SECURITY_HUB_KV.get(`${KV_MEMORY_PREFIX}${orgId}`, { type: 'json' })) || [];
  } catch { return []; }
}

async function saveEvents(env, orgId, events) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(
    `${KV_MEMORY_PREFIX}${orgId}`,
    JSON.stringify(events.slice(0, MAX_EVENTS)),
    { expirationTtl: 86400 * 90 }
  );
}

// ── Pattern Analysis Engine ────────────────────────────────────────────────────
function analyzePatterns(events) {
  if (!events || events.length === 0) {
    return { total_events: 0, top_threats: [], top_cves: [], top_ttps: [], attack_trend: 'NO_DATA', severity_distribution: {} };
  }

  // Frequency analysis
  const threatFreq    = {};
  const cveFreq       = {};
  const ttpFreq       = {};
  const severityDist  = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const monthlyTrend  = {};

  events.forEach(ev => {
    // Threats
    if (ev.threat_title) threatFreq[ev.threat_title] = (threatFreq[ev.threat_title] || 0) + 1;
    // CVEs
    if (ev.cve_id) {
      const ids = ev.cve_id.split(',').map(c => c.trim()).filter(Boolean);
      ids.forEach(c => { cveFreq[c] = (cveFreq[c] || 0) + 1; });
    }
    // TTPs
    if (ev.ttps) {
      const ttps = Array.isArray(ev.ttps) ? ev.ttps : [ev.ttps];
      ttps.forEach(t => { ttpFreq[t] = (ttpFreq[t] || 0) + 1; });
    }
    // Severity
    const sev = (ev.severity || 'INFO').toUpperCase();
    if (severityDist[sev] !== undefined) severityDist[sev]++;
    // Monthly trend
    const month = ev.ts ? ev.ts.slice(0, 7) : 'unknown';
    monthlyTrend[month] = (monthlyTrend[month] || 0) + 1;
  });

  // Trend direction
  const months = Object.keys(monthlyTrend).sort();
  let trendDir = 'STABLE';
  if (months.length >= 2) {
    const last = monthlyTrend[months[months.length - 1]];
    const prev = monthlyTrend[months[months.length - 2]];
    if (last > prev * 1.2) trendDir = 'INCREASING';
    else if (last < prev * 0.8) trendDir = 'DECREASING';
  }

  const sortDesc = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => ({ name: k, count: v }));

  return {
    total_events:          events.length,
    top_threats:           sortDesc(threatFreq),
    top_cves:              sortDesc(cveFreq),
    top_ttps:              sortDesc(ttpFreq),
    attack_trend:          trendDir,
    severity_distribution: severityDist,
    monthly_trend:         monthlyTrend,
    most_recent:           events[0]?.ts || null,
    oldest_event:          events[events.length - 1]?.ts || null,
    critical_count:        severityDist.CRITICAL,
    high_count:            severityDist.HIGH,
    repeat_threats:        Object.values(threatFreq).filter(v => v > 1).length,
  };
}

// ── AI Recommendation Engine ───────────────────────────────────────────────────
function generateRecommendations(patterns, events) {
  const recs = [];

  if (!patterns || patterns.total_events === 0) {
    return [{
      priority: 1,
      type:     'onboarding',
      title:    'Start threat scanning to build your memory profile',
      detail:   'Run your first scan to enable AI-driven threat pattern analysis and personalized recommendations.',
      action:   'Run Scan',
      action_target: '#dashboard',
      icon:     '🚀',
    }];
  }

  // Critical CVE repeat exposure
  const repeatCVEs = patterns.top_cves.filter(c => c.count >= 2);
  if (repeatCVEs.length > 0) {
    recs.push({
      priority:  1,
      type:      'patch',
      title:     `Patch ${repeatCVEs[0].name} — seen ${repeatCVEs[0].count}x`,
      detail:    `This CVE has been detected ${repeatCVEs[0].count} times. Repeat exposure indicates this vulnerability is not remediated. Apply vendor patch immediately.`,
      action:    'Generate Fix Rule',
      action_target: '#ai-analyst',
      icon:      '🚨',
      cve_id:    repeatCVEs[0].name,
      urgency:   'CRITICAL',
    });
  }

  // Increasing attack trend
  if (patterns.attack_trend === 'INCREASING') {
    recs.push({
      priority: 2,
      type:     'trend',
      title:    'Attack volume is increasing month-over-month',
      detail:   'Detected threat events have increased by more than 20% vs. last month. Consider upgrading to ENTERPRISE for autonomous defense and real-time blocking.',
      action:   'Upgrade Plan',
      action_target: '#pricing',
      icon:     '📈',
      urgency:  'HIGH',
    });
  }

  // High critical density
  if (patterns.critical_count >= 5) {
    recs.push({
      priority: 2,
      type:     'response',
      title:    `${patterns.critical_count} CRITICAL events require IR playbook`,
      detail:   'Your organization has accumulated multiple CRITICAL severity events. Generate an Incident Response playbook using MYTHOS AI Analyst.',
      action:   'Generate IR Plan',
      action_target: '#ai-analyst',
      icon:     '🔥',
      urgency:  'HIGH',
    });
  }

  // Top TTP mapping
  if (patterns.top_ttps.length > 0) {
    recs.push({
      priority: 3,
      type:     'ttp_hardening',
      title:    `Deploy detections for ${patterns.top_ttps[0].name}`,
      detail:   `MITRE technique ${patterns.top_ttps[0].name} appears most frequently in your threat history (${patterns.top_ttps[0].count}x). Deploy targeted Sigma/KQL rules to improve coverage.`,
      action:   'Generate Detection Rule',
      action_target: '#ai-analyst',
      icon:     '🎯',
      urgency:  'MEDIUM',
    });
  }

  // SIEM integration suggestion
  if (patterns.total_events >= 10 && patterns.critical_count >= 2) {
    recs.push({
      priority: 3,
      type:     'integration',
      title:    'Connect your SIEM for automated rule deployment',
      detail:   'Your threat history has enough volume to benefit from automated SIEM integration. Configure Splunk, Elastic, or Sentinel to auto-deploy generated rules.',
      action:   'Configure SIEM',
      action_target: '#siem-deploy',
      icon:     '🔌',
      urgency:  'MEDIUM',
    });
  }

  // Auto-mode suggestion
  if (patterns.total_events >= 20) {
    recs.push({
      priority: 4,
      type:     'automation',
      title:    'Enable Autonomous SOC Mode for hands-free defense',
      detail:   'With your threat history depth, MYTHOS Auto Mode can detect, analyze, and deploy rules without manual intervention — reducing MTTR from hours to minutes.',
      action:   'Enable Auto Mode',
      action_target: '#autonomous-soc',
      icon:     '🤖',
      urgency:  'LOW',
    });
  }

  return recs.sort((a, b) => a.priority - b.priority).slice(0, 6);
}

// ── GET /api/org-memory ───────────────────────────────────────────────────────
export async function handleGetMemory(request, env, authCtx = {}) {
  const orgId    = getOrgId(authCtx);
  const events   = await loadEvents(env, orgId);
  const patterns = analyzePatterns(events);
  const recs     = generateRecommendations(patterns, events);

  // Load org profile
  let profile = {};
  if (env?.SECURITY_HUB_KV) {
    try { profile = (await env.SECURITY_HUB_KV.get(`${KV_PROFILE_PREFIX}${orgId}`, { type: 'json' })) || {}; } catch {}
  }

  return ok(request, {
    org_id:          orgId,
    profile,
    patterns,
    recommendations: recs,
    event_count:     events.length,
    fetched_at:      new Date().toISOString(),
  });
}

// ── POST /api/org-memory/record ───────────────────────────────────────────────
export async function handleRecordEvent(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const {
    event_type,   // 'scan' | 'alert' | 'rule_deployed' | 'threat_detected' | 'incident' | 'action_taken'
    threat_title,
    cve_id,
    severity,
    cvss,
    ttps,
    action_taken,
    module,
    metadata,
  } = body;

  if (!event_type) {
    return fail(request, 'event_type is required', 400, 'MISSING_EVENT_TYPE');
  }

  const orgId  = getOrgId(authCtx);
  const events = await loadEvents(env, orgId);

  const newEvent = {
    id:           `ev_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    ts:           new Date().toISOString(),
    event_type,
    threat_title: threat_title || null,
    cve_id:       cve_id       || null,
    severity:     severity     || 'INFO',
    cvss:         cvss         || null,
    ttps:         ttps         || [],
    action_taken: action_taken || null,
    module:       module       || 'manual',
    user:         authCtx?.email || 'system',
    metadata:     metadata    || {},
  };

  events.unshift(newEvent);
  await saveEvents(env, orgId, events);

  // Update pattern cache
  const patterns = analyzePatterns(events);
  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `${KV_PATTERNS_PREFIX}${orgId}`,
      JSON.stringify(patterns),
      { expirationTtl: 86400 }
    );
  }

  return ok(request, { recorded: true, event_id: newEvent.id, total_events: events.length });
}

// ── GET /api/org-memory/history ───────────────────────────────────────────────
export async function handleGetHistory(request, env, authCtx = {}) {
  const orgId  = getOrgId(authCtx);
  const url    = new URL(request.url);
  const limit  = Math.min(100, parseInt(url.searchParams.get('limit') || '20', 10));
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const filter = url.searchParams.get('event_type') || '';
  const sev    = url.searchParams.get('severity') || '';

  let events = await loadEvents(env, orgId);
  if (filter) events = events.filter(e => e.event_type === filter);
  if (sev)    events = events.filter(e => (e.severity || '').toUpperCase() === sev.toUpperCase());

  return ok(request, {
    events:      events.slice(offset, offset + limit),
    total:       events.length,
    offset,
    limit,
  });
}

// ── GET /api/org-memory/patterns ──────────────────────────────────────────────
export async function handleGetPatterns(request, env, authCtx = {}) {
  const orgId  = getOrgId(authCtx);
  const events = await loadEvents(env, orgId);
  const pats   = analyzePatterns(events);
  return ok(request, { org_id: orgId, patterns: pats, analysed_at: new Date().toISOString() });
}

// ── GET /api/org-memory/recommend ─────────────────────────────────────────────
export async function handleGetRecommendations(request, env, authCtx = {}) {
  const orgId    = getOrgId(authCtx);
  const events   = await loadEvents(env, orgId);
  const patterns = analyzePatterns(events);
  const recs     = generateRecommendations(patterns, events);
  return ok(request, { org_id: orgId, recommendations: recs, generated_at: new Date().toISOString() });
}

// ── DELETE /api/org-memory ────────────────────────────────────────────────────
export async function handleClearMemory(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  if (tier !== 'ENTERPRISE') {
    return fail(request, 'Clearing org memory requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }
  const orgId = getOrgId(authCtx);
  if (env?.SECURITY_HUB_KV) {
    await Promise.all([
      env.SECURITY_HUB_KV.delete(`${KV_MEMORY_PREFIX}${orgId}`),
      env.SECURITY_HUB_KV.delete(`${KV_PATTERNS_PREFIX}${orgId}`),
    ]);
  }
  return ok(request, { cleared: true, org_id: orgId });
}
