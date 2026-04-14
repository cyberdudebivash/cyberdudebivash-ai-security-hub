/**
 * CYBERDUDEBIVASH AI Security Hub — Adaptive Cyber Brain Engine v21.0
 * ═══════════════════════════════════════════════════════════════════
 * Self-learning, cross-tenant, feedback-driven intelligence engine.
 * Extends the base CyberBrain (v20) with:
 *
 *   MODULE 1 — Feedback Learning Engine
 *     learnFromFeedback()     — ingests user actions to refine weights
 *
 *   MODULE 2 — Global Intelligence Aggregator
 *     aggregateGlobalSignals() — cross-tenant threat heatmap + trends
 *
 *   MODULE 3 — Adaptive Risk Engine
 *     computeAdaptiveRisk()   — dynamic score fusing CVSS+EPSS+KEV+learned weights
 *
 *   MODULE 4 — Attack Prediction Engine
 *     predictAttackPaths()    — multi-step exploit chain simulation
 *
 *   MODULE 5 — Smart Recommendation Engine
 *     generateAdaptiveRecommendations() — priority-ranked, context-aware actions
 *
 * Storage:
 *   D1  — brain_feedback, brain_weights, brain_global_signals, brain_predictions
 *   KV  — fast weight lookup, global intel cache, prediction cache
 *
 * Revenue Gate:
 *   FREE      — base risk score only (no adaptive layer)
 *   STARTER   — adaptive risk + basic recommendations
 *   PRO       — global intel + full predictions + smart recommendations
 *   ENTERPRISE — all features + cross-tenant correlation + custom weights
 *
 * Integration:
 *   Called by /api/cyber-brain/learn|global-intel|adaptive-risk|predictions
 *   Enriches  /api/scan/*, /api/vulns, /api/hunt (non-blocking, fire-and-forget
 *             on FREE; full enrichment on PRO+)
 *
 * Performance:
 *   - All D1 writes are fire-and-forget (never block response path)
 *   - KV cache for global signals (TTL 1h) and predictions (TTL 15m)
 *   - Batch aggregation runs on cron slot 1 (hourly)
 *   - Adaptive weights loaded once per request, cached in closure
 */

import { enforceFeatureGate } from './revenueGate.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const PLATFORM = 'CYBERDUDEBIVASH AI Security Hub v21.0';

// Default base weights — these evolve per-user via feedback
const DEFAULT_WEIGHTS = {
  cvss_critical:     30,
  cvss_high:         20,
  cvss_medium:       10,
  in_kev:            25,
  epss_high:         20,   // EPSS > 0.70
  epss_medium:       10,   // EPSS 0.30–0.70
  public_exploit:    15,
  ransomware_linked: 20,
  zero_day:          35,
  external_exposure: 20,
  no_mfa:            12,
  weak_tls:          12,
  dns_weakness:       8,
  lateral_movement:  15,
  credential_access: 18,
};

// Weight change limits per feedback event — prevent over-correction
const MAX_WEIGHT_DELTA  = 8;
const MIN_WEIGHT_VALUE  = 2;
const MAX_WEIGHT_VALUE  = 50;
const GLOBAL_CACHE_TTL  = 3600;        // 1 hour
const PREDICT_CACHE_TTL = 900;         // 15 minutes
const FEEDBACK_TABLE    = 'brain_feedback';
const WEIGHTS_TABLE     = 'brain_weights';
const SIGNALS_TABLE     = 'brain_global_signals';
const PREDICTIONS_TABLE = 'brain_predictions';

// ─── Tier capabilities for adaptive features ──────────────────────────────────
const ADAPTIVE_TIERS = {
  FREE:       { adaptive_risk: false, global_intel: false, predictions: false, smart_rec: false, cross_tenant: false },
  STARTER:    { adaptive_risk: true,  global_intel: false, predictions: false, smart_rec: true,  cross_tenant: false },
  PRO:        { adaptive_risk: true,  global_intel: true,  predictions: true,  smart_rec: true,  cross_tenant: false },
  ENTERPRISE: { adaptive_risk: true,  global_intel: true,  predictions: true,  smart_rec: true,  cross_tenant: true  },
};

function tierCan(tier, feature) {
  return ADAPTIVE_TIERS[tier]?.[feature] ?? false;
}

// ─── KV helpers ───────────────────────────────────────────────────────────────
async function kvGet(env, key, fallback = null) {
  if (!env?.SECURITY_HUB_KV) return fallback;
  try {
    const raw = await env.SECURITY_HUB_KV.get(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}

async function kvSet(env, key, value, ttl = 3600) {
  if (!env?.SECURITY_HUB_KV) return;
  try { await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); } catch {}
}

// ─── D1 fire-and-forget ───────────────────────────────────────────────────────
function d1Run(env, sql, bindings = []) {
  if (!env?.SECURITY_HUB_DB) return;
  env.SECURITY_HUB_DB.prepare(sql).bind(...bindings).run().catch(() => {});
}

async function d1All(env, sql, bindings = []) {
  if (!env?.SECURITY_HUB_DB) return [];
  try {
    const res = await env.SECURITY_HUB_DB.prepare(sql).bind(...bindings).all();
    return res?.results || [];
  } catch { return []; }
}

async function d1First(env, sql, bindings = []) {
  if (!env?.SECURITY_HUB_DB) return null;
  try { return await env.SECURITY_HUB_DB.prepare(sql).bind(...bindings).first(); }
  catch { return null; }
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 1 — FEEDBACK LEARNING ENGINE
// ══════════════════════════════════════════════════════════════════════════════
/**
 * learnFromFeedback()
 * Ingests user actions on scan findings to refine risk weights.
 *
 * @param {object} env        - CF Worker env bindings
 * @param {object} scanResult - Original scan output (findings, riskScore, target)
 * @param {object} userAction - { action, finding_id, finding_type, severity, false_positive }
 * @param {string} userId     - Authenticated user ID (or tenant ID)
 * @param {string} tier       - User plan tier
 *
 * Actions:
 *   'ignored'   → lower weight of this finding type (possible false positive)
 *   'fixed'     → confirm true positive, slightly raise weight confidence
 *   'escalated' → strong signal — raise weight for this finding type
 *   'false_positive' → aggressively lower weight, flag pattern
 *
 * Returns:
 *   { learned: bool, weight_deltas: object, feedback_id: string }
 */
export async function learnFromFeedback(env, scanResult, userAction, userId, tier = 'FREE') {
  if (!tierCan(tier, 'adaptive_risk')) {
    return { learned: false, reason: 'Requires STARTER plan or higher', tier };
  }

  const {
    action,          // 'ignored' | 'fixed' | 'escalated' | 'false_positive'
    finding_id,
    finding_type,    // e.g. 'weak_tls', 'no_mfa', 'public_exploit'
    severity,        // 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'
    target    = scanResult?.target || '',
    risk_score = scanResult?.riskScore || 0,
  } = userAction;

  if (!action || !finding_type) {
    return { learned: false, reason: 'action and finding_type are required' };
  }

  const feedbackId = `fb_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const now        = new Date().toISOString();

  // ── Persist feedback event to D1 ──────────────────────────────────────────
  d1Run(env,
    `INSERT OR IGNORE INTO ${FEEDBACK_TABLE}
       (id, user_id, target, finding_id, finding_type, severity, action, risk_score_at_time, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [feedbackId, userId, target, finding_id || null, finding_type, severity || 'MEDIUM', action, risk_score, now]
  );

  // ── Compute weight delta based on action ──────────────────────────────────
  const severityMultiplier = { CRITICAL: 1.5, HIGH: 1.2, MEDIUM: 1.0, LOW: 0.7 }[severity] || 1.0;
  const actionDeltas = {
    escalated:      +Math.round(4 * severityMultiplier),   // raise weight
    fixed:          +Math.round(1 * severityMultiplier),   // mild positive confirmation
    ignored:        -Math.round(3 * severityMultiplier),   // lower weight
    false_positive: -Math.round(6 * severityMultiplier),   // aggressive lower
  };

  const rawDelta = actionDeltas[action] ?? 0;
  const clampedDelta = Math.max(-MAX_WEIGHT_DELTA, Math.min(MAX_WEIGHT_DELTA, rawDelta));

  // ── Load current user weights from KV ────────────────────────────────────
  const weightsKey     = `brain:weights:${userId}`;
  const currentWeights = await kvGet(env, weightsKey, { ...DEFAULT_WEIGHTS });

  // Map finding_type to the weight key it affects
  const weightKeyMap = {
    weak_tls:          'weak_tls',
    tls:               'weak_tls',
    no_mfa:            'no_mfa',
    mfa:               'no_mfa',
    public_exploit:    'public_exploit',
    exploit:           'public_exploit',
    ransomware:        'ransomware_linked',
    ransomware_linked: 'ransomware_linked',
    kev:               'in_kev',
    in_kev:            'in_kev',
    external:          'external_exposure',
    dns:               'dns_weakness',
    lateral:           'lateral_movement',
    credential:        'credential_access',
    zero_day:          'zero_day',
    cvss_critical:     'cvss_critical',
    cvss_high:         'cvss_high',
    cvss_medium:       'cvss_medium',
  };

  const affectedKey = weightKeyMap[finding_type.toLowerCase()] || null;
  const weightDeltas = {};

  if (affectedKey && affectedKey in currentWeights) {
    const oldVal = currentWeights[affectedKey];
    const newVal = Math.max(MIN_WEIGHT_VALUE, Math.min(MAX_WEIGHT_VALUE, oldVal + clampedDelta));
    currentWeights[affectedKey] = newVal;
    weightDeltas[affectedKey]   = { old: oldVal, new: newVal, delta: clampedDelta };
  }

  // ── Persist updated weights to KV (30-day TTL) ───────────────────────────
  await kvSet(env, weightsKey, {
    ...currentWeights,
    _updated_at:     now,
    _feedback_count: (currentWeights._feedback_count || 0) + 1,
    _user_id:        userId,
  }, 86400 * 30);

  // ── Also persist to D1 brain_weights for audit + cross-tenant aggregate ──
  const existingWeight = await d1First(env,
    `SELECT id FROM ${WEIGHTS_TABLE} WHERE user_id = ? AND weight_key = ?`,
    [userId, affectedKey]
  );

  if (affectedKey) {
    if (existingWeight) {
      d1Run(env,
        `UPDATE ${WEIGHTS_TABLE} SET weight_value = ?, feedback_count = feedback_count + 1, updated_at = ?
         WHERE user_id = ? AND weight_key = ?`,
        [currentWeights[affectedKey], now, userId, affectedKey]
      );
    } else {
      d1Run(env,
        `INSERT INTO ${WEIGHTS_TABLE} (id, user_id, weight_key, weight_value, feedback_count, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
        [`wt_${Date.now().toString(36)}`, userId, affectedKey, currentWeights[affectedKey] ?? DEFAULT_WEIGHTS[affectedKey], now, now]
      );
    }
  }

  // ── Track false positive pattern for global model ─────────────────────────
  if (action === 'false_positive') {
    d1Run(env,
      `INSERT OR IGNORE INTO ${SIGNALS_TABLE}
         (id, signal_type, finding_type, severity, source_tier, created_at)
       VALUES (?, 'false_positive_pattern', ?, ?, ?, ?)`,
      [`sig_${Date.now().toString(36)}`, finding_type, severity || 'MEDIUM', tier, now]
    );
  }

  return {
    learned:       true,
    feedback_id:   feedbackId,
    action,
    finding_type,
    weight_deltas: weightDeltas,
    model_updated: Object.keys(weightDeltas).length > 0,
    feedback_count: (currentWeights._feedback_count || 0) + 1,
    message:       `Risk model updated based on your ${action} action on "${finding_type}"`,
    platform:      PLATFORM,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 2 — GLOBAL INTELLIGENCE AGGREGATOR
// ══════════════════════════════════════════════════════════════════════════════
/**
 * aggregateGlobalSignals()
 * Collects cross-tenant scan patterns, CVE trends, IOC clustering.
 * Results are cached in KV for 1 hour — this is NOT a per-request operation.
 *
 * @param {object} env    - CF Worker env bindings
 * @param {string} tier   - Caller's tier (ENTERPRISE gets raw cross-tenant data)
 * @param {string} sector - Filter for sector-specific heatmap
 *
 * Returns: global risk heatmap, emerging threats, sector attack patterns
 */
export async function aggregateGlobalSignals(env, tier = 'PRO', sector = null) {
  if (!tierCan(tier, 'global_intel')) {
    return { available: false, reason: 'Global intelligence requires PRO plan or higher', tier };
  }

  const cacheKey = `brain:global_intel:${sector || 'all'}`;
  const cached   = await kvGet(env, cacheKey);
  if (cached && cached._cached_at && (Date.now() - cached._cached_at < GLOBAL_CACHE_TTL * 1000)) {
    return { ...cached, from_cache: true };
  }

  // ── Aggregate from D1 scan history ───────────────────────────────────────
  const [topFindings, severityDist, scanVolume, falsePositivePatterns, recentCVEs] = await Promise.all([
    // Most common high-severity finding types across all scans (anonymized)
    d1All(env,
      `SELECT module, COUNT(*) as cnt
       FROM scan_jobs
       WHERE created_at >= datetime('now','-7 days') AND status = 'done'
       GROUP BY module ORDER BY cnt DESC LIMIT 10`
    ),

    // Severity distribution from analytics events
    d1All(env,
      `SELECT event_type, COUNT(*) as cnt
       FROM analytics_events
       WHERE created_at >= datetime('now','-7 days')
         AND event_type LIKE 'scan.%'
       GROUP BY event_type ORDER BY cnt DESC LIMIT 20`
    ),

    // Daily scan volume trend (7 days)
    d1All(env,
      `SELECT date(created_at) as day, COUNT(*) as scans, module
       FROM scan_jobs
       WHERE created_at >= datetime('now','-7 days')
       GROUP BY day, module ORDER BY day ASC`
    ),

    // Cross-tenant false positive patterns (anonymized)
    d1All(env,
      `SELECT finding_type, severity, COUNT(*) as fp_count
       FROM ${SIGNALS_TABLE}
       WHERE signal_type = 'false_positive_pattern'
         AND created_at >= datetime('now','-30 days')
       GROUP BY finding_type, severity
       ORDER BY fp_count DESC LIMIT 15`
    ),

    // Recent CVE/threat intel with high CVSS
    d1All(env,
      `SELECT cve_id, title, cvss_score, in_kev, source, ingested_at
       FROM threat_intel
       WHERE cvss_score >= 7.0
         AND ingested_at >= datetime('now','-7 days')
       ORDER BY cvss_score DESC, in_kev DESC LIMIT 20`
    ),
  ]);

  // ── Build global risk heatmap ─────────────────────────────────────────────
  const moduleActivity = {};
  for (const row of topFindings) {
    moduleActivity[row.module] = (moduleActivity[row.module] || 0) + row.cnt;
  }

  // ── Detect emerging threats from CVE spike ────────────────────────────────
  const criticalCVEs = recentCVEs.filter(c => c.cvss_score >= 9.0);
  const kevCVEs      = recentCVEs.filter(c => c.in_kev === 1);

  const emergingThreats = criticalCVEs.slice(0, 5).map(c => ({
    id:          c.cve_id || 'N/A',
    title:       c.title  || 'Unnamed Vulnerability',
    cvss:        c.cvss_score,
    in_kev:      c.in_kev === 1,
    severity:    c.cvss_score >= 9.0 ? 'CRITICAL' : 'HIGH',
    ingested_at: c.ingested_at,
    signal:      c.in_kev ? 'ACTIVE_EXPLOITATION' : 'NEW_DISCLOSURE',
  }));

  // ── Scan volume trend ─────────────────────────────────────────────────────
  const volumeTrend = {};
  for (const row of scanVolume) {
    if (!volumeTrend[row.day]) volumeTrend[row.day] = { total: 0 };
    volumeTrend[row.day][row.module] = (volumeTrend[row.day][row.module] || 0) + row.scans;
    volumeTrend[row.day].total += row.scans;
  }

  // ── Attack pattern clustering ─────────────────────────────────────────────
  const sectorPatterns = buildSectorPatterns(recentCVEs, severityDist);

  // ── Derive global risk level ──────────────────────────────────────────────
  const globalRiskScore = Math.min(100, Math.round(
    (criticalCVEs.length * 8) +
    (kevCVEs.length * 12) +
    (falsePositivePatterns.length * 2) +
    30  // baseline
  ));

  const result = {
    global_risk_score:   globalRiskScore,
    global_risk_level:   globalRiskScore >= 80 ? 'CRITICAL' : globalRiskScore >= 60 ? 'HIGH' : globalRiskScore >= 40 ? 'MEDIUM' : 'LOW',
    emerging_threats:    emergingThreats,
    cve_stats: {
      total_last_7d:   recentCVEs.length,
      critical:        criticalCVEs.length,
      actively_exploited: kevCVEs.length,
      avg_cvss:        recentCVEs.length > 0
        ? parseFloat((recentCVEs.reduce((s, c) => s + c.cvss_score, 0) / recentCVEs.length).toFixed(1))
        : 0,
    },
    scan_activity: {
      module_distribution: moduleActivity,
      volume_trend:        Object.entries(volumeTrend)
        .map(([day, v]) => ({ day, ...v }))
        .sort((a, b) => a.day.localeCompare(b.day)),
    },
    false_positive_patterns: tier === 'ENTERPRISE'
      ? falsePositivePatterns
      : falsePositivePatterns.slice(0, 5).map(p => ({ finding_type: p.finding_type, severity: p.severity })),
    sector_attack_patterns: sector
      ? sectorPatterns[sector] || sectorPatterns.all
      : sectorPatterns.all,
    all_sector_patterns:    tier === 'ENTERPRISE' ? sectorPatterns : undefined,
    data_freshness:         'last 7 days',
    _cached_at:             Date.now(),
    generated_at:           new Date().toISOString(),
    platform:               PLATFORM,
  };

  // Cache for 1 hour
  await kvSet(env, cacheKey, result, GLOBAL_CACHE_TTL);

  return result;
}

function buildSectorPatterns(cves, severityDist) {
  // Derive attack patterns from CVE titles and techniques
  const patterns = {
    all:            [],
    finance:        [],
    healthcare:     [],
    technology:     [],
    government:     [],
    critical_infra: [],
  };

  const knownSectorKeywords = {
    finance:        ['banking', 'payment', 'swift', 'fintech', 'atm', 'pos'],
    healthcare:     ['hospital', 'ehr', 'health', 'medical', 'dicom', 'hl7'],
    government:     ['gov', 'military', 'nato', 'scada', 'election'],
    critical_infra: ['ics', 'ot', 'scada', 'modbus', 'dnp3', 'power', 'grid'],
    technology:     ['cloud', 'kubernetes', 'docker', 'api', 'saas', 'code'],
  };

  for (const cve of cves) {
    const title = (cve.title || '').toLowerCase();
    let placed  = false;

    for (const [sector, keywords] of Object.entries(knownSectorKeywords)) {
      if (keywords.some(k => title.includes(k))) {
        patterns[sector].push({ cve_id: cve.cve_id, cvss: cve.cvss_score, in_kev: cve.in_kev === 1 });
        placed = true;
      }
    }
    if (!placed) patterns.all.push({ cve_id: cve.cve_id, cvss: cve.cvss_score, in_kev: cve.in_kev === 1 });
  }

  return patterns;
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 3 — ADAPTIVE RISK ENGINE
// ══════════════════════════════════════════════════════════════════════════════
/**
 * computeAdaptiveRisk()
 * Computes a dynamic, feedback-adjusted risk score.
 * Fuses: CVSS + EPSS + KEV + user-learned weights + global false-positive signals.
 *
 * @param {object} env      - CF Worker env
 * @param {object} input    - { findings, vulns, assets, sector, target }
 * @param {string} userId   - For personalized weight loading
 * @param {string} tier
 *
 * Returns: { adaptiveScore, baseScore, confidence, weightProfile, scoreDelta }
 */
export async function computeAdaptiveRisk(env, input, userId, tier = 'FREE') {
  if (!tierCan(tier, 'adaptive_risk')) {
    return {
      adaptive: false,
      reason:   'Adaptive risk requires STARTER plan or higher',
      baseScore: input.baseScore || 0,
      tier,
    };
  }

  const { findings = [], vulns = [], assets = {}, sector = 'technology', baseScore = 0, target = '' } = input;

  // ── Load user-specific learned weights ────────────────────────────────────
  const weightsKey     = `brain:weights:${userId}`;
  const learnedWeights = await kvGet(env, weightsKey, null);
  const weights        = learnedWeights ? { ...DEFAULT_WEIGHTS, ...learnedWeights } : { ...DEFAULT_WEIGHTS };

  // ── Load global false-positive patterns (reduce noise) ───────────────────
  const fpPatterns = await kvGet(env, 'brain:fp_patterns', {});

  // ── Score each finding with adaptive weights ──────────────────────────────
  let rawScore   = 0;
  let maxPossible = 0;
  const signalBreakdown = [];

  for (const finding of findings) {
    const sev     = (finding.severity || 'MEDIUM').toUpperCase();
    const type    = (finding.category || '').toLowerCase();
    const isFP    = fpPatterns[type] && fpPatterns[type] > 5;  // global FP signal

    // Base severity contribution
    let contribution = 0;
    if (sev === 'CRITICAL') contribution += weights.cvss_critical || DEFAULT_WEIGHTS.cvss_critical;
    else if (sev === 'HIGH') contribution += weights.cvss_high    || DEFAULT_WEIGHTS.cvss_high;
    else if (sev === 'MEDIUM') contribution += weights.cvss_medium || DEFAULT_WEIGHTS.cvss_medium;

    // Modifier flags
    if (finding.in_kev)       contribution += weights.in_kev       || DEFAULT_WEIGHTS.in_kev;
    if (finding.has_exploit)  contribution += weights.public_exploit || DEFAULT_WEIGHTS.public_exploit;
    if (finding.external)     contribution += weights.external_exposure || DEFAULT_WEIGHTS.external_exposure;
    if (finding.epss > 0.70)  contribution += weights.epss_high    || DEFAULT_WEIGHTS.epss_high;
    else if (finding.epss > 0.30) contribution += weights.epss_medium || DEFAULT_WEIGHTS.epss_medium;
    if (finding.cve?.includes('zero_day')) contribution += weights.zero_day || DEFAULT_WEIGHTS.zero_day;

    // Dampen if global FP pattern detected
    if (isFP) contribution = Math.round(contribution * 0.4);

    signalBreakdown.push({ finding: finding.title || type, contribution: Math.round(contribution), is_fp: isFP });
    rawScore    += contribution;
    maxPossible += weights.cvss_critical + weights.in_kev + weights.public_exploit + weights.epss_high;
  }

  // ── Vuln-level scoring ────────────────────────────────────────────────────
  for (const v of vulns) {
    const cvss = parseFloat(v.cvss || v.cvss_score || 5.0);
    const epss = parseFloat(v.epss || v.epss_score || 0.1);
    let vScore = cvss * 3;
    if (v.in_kev)       vScore += weights.in_kev;
    if (epss > 0.70)    vScore += weights.epss_high;
    if (v.has_exploit)  vScore += weights.public_exploit;
    rawScore    += vScore;
    maxPossible += cvss * 3 + weights.in_kev + weights.epss_high + weights.public_exploit;
  }

  // ── Normalise to 0–100 ────────────────────────────────────────────────────
  const adaptiveScore = maxPossible > 0
    ? Math.min(100, Math.round((rawScore / maxPossible) * 100))
    : baseScore;

  const scoreDelta    = adaptiveScore - baseScore;
  const confidence    = computeConfidence(findings.length, vulns.length, learnedWeights?._feedback_count || 0);

  // ── Cache adaptive score in KV ────────────────────────────────────────────
  const hour = new Date().toISOString().slice(0, 13);
  await kvSet(env, `brain:adaptive_score:${userId}:${target}:${hour}`, {
    adaptiveScore, baseScore, scoreDelta, confidence, computed_at: new Date().toISOString(),
  }, 3600);

  return {
    adaptive:        true,
    adaptiveScore,
    baseScore,
    scoreDelta,
    adaptiveLevel:   adaptiveScore >= 80 ? 'CRITICAL' : adaptiveScore >= 60 ? 'HIGH' : adaptiveScore >= 40 ? 'MEDIUM' : 'LOW',
    confidence,
    confidence_label: confidence >= 80 ? 'HIGH' : confidence >= 50 ? 'MEDIUM' : 'LOW',
    weight_profile: {
      personalized: learnedWeights !== null,
      feedback_events: learnedWeights?._feedback_count || 0,
      key_deviations: Object.entries(weights)
        .filter(([k, v]) => typeof v === 'number' && Math.abs(v - (DEFAULT_WEIGHTS[k] || 0)) >= 3)
        .map(([k, v]) => ({ key: k, learned: v, default: DEFAULT_WEIGHTS[k], delta: v - DEFAULT_WEIGHTS[k] })),
    },
    top_signals:     signalBreakdown.sort((a, b) => b.contribution - a.contribution).slice(0, 8),
    platform:        PLATFORM,
  };
}

function computeConfidence(findingCount, vulnCount, feedbackCount) {
  let score = 30;  // base confidence
  if (findingCount >= 5)   score += 15;
  if (findingCount >= 15)  score += 10;
  if (vulnCount >= 3)      score += 10;
  if (feedbackCount >= 5)  score += 15;
  if (feedbackCount >= 20) score += 10;
  if (feedbackCount >= 50) score += 10;
  return Math.min(100, score);
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 4 — ATTACK PREDICTION ENGINE
// ══════════════════════════════════════════════════════════════════════════════
/**
 * predictAttackPaths()
 * Builds a multi-step exploit chain by simulating an attacker's decision tree
 * across asset topology, vulnerability presence, and global threat actor TTPs.
 *
 * Algorithm:
 *   1. Score each vulnerability as an entry point (CVSS × EPSS × exposure)
 *   2. Chain findings into feasible attack sequences based on MITRE ATT&CK flow
 *   3. Simulate lateral movement from each entry point
 *   4. Calculate breach probability for each chain
 *   5. Return top N chains sorted by probability
 *
 * @param {object} env
 * @param {Array}  assets  - asset list { name, type, external, services, vulns }
 * @param {Array}  vulns   - vulnerability list
 * @param {string} sector
 * @param {string} tier
 *
 * Returns: { chains, top_chain, breach_probability, predicted_ttb, lateral_paths }
 */
export async function predictAttackPaths(env, assets = [], vulns = [], sector = 'technology', tier = 'PRO') {
  if (!tierCan(tier, 'predictions')) {
    return {
      available:   false,
      reason:      'Attack predictions require PRO plan or higher',
      tier,
      upgrade_cta: { message: 'Upgrade to PRO for ₹999/mo', route: '/pricing#pro' },
    };
  }

  // ── Cache check ───────────────────────────────────────────────────────────
  const cacheKey  = `brain:predictions:${sector}:${JSON.stringify(vulns.map(v => v.cve_id || v.id)).slice(0, 80)}`;
  const cached    = await kvGet(env, cacheKey);
  if (cached && cached._cached_at && (Date.now() - cached._cached_at < PREDICT_CACHE_TTL * 1000)) {
    return { ...cached, from_cache: true };
  }

  // ── Identify entry points ─────────────────────────────────────────────────
  const entryPoints = buildEntryPoints(vulns, assets);

  // ── Build attack chains ───────────────────────────────────────────────────
  const chains = [];
  for (const entry of entryPoints.slice(0, 8)) {
    const chain = simulateAttackChain(entry, vulns, assets, sector);
    if (chain) chains.push(chain);
  }

  // Sort by probability descending
  chains.sort((a, b) => b.probability - a.probability);

  // ── Lateral movement map ──────────────────────────────────────────────────
  const lateralPaths = simulateLateralMovement(assets, vulns);

  // ── Breach probability (combined chains) ─────────────────────────────────
  const breachProbability = chains.length > 0
    ? Math.min(0.99, 1 - chains.reduce((p, c) => p * (1 - c.probability), 1))
    : 0.05;

  // ── Time-to-breach estimate ───────────────────────────────────────────────
  const topChain = chains[0];
  const ttbHours = topChain
    ? Math.round(
        topChain.steps.length * (topChain.probability > 0.7 ? 2 : topChain.probability > 0.4 ? 8 : 24)
      )
    : 168;

  const result = {
    available:           true,
    chains:              chains.slice(0, 10),
    top_chain:           topChain || null,
    chain_count:         chains.length,
    breach_probability:  parseFloat(breachProbability.toFixed(3)),
    breach_risk_level:   breachProbability >= 0.7 ? 'CRITICAL' : breachProbability >= 0.4 ? 'HIGH' : breachProbability >= 0.2 ? 'MEDIUM' : 'LOW',
    predicted_ttb_hours: ttbHours,
    predicted_ttb_label: ttbHours <= 12  ? 'Within hours'
                       : ttbHours <= 72  ? 'Within days'
                       : ttbHours <= 336 ? 'Within 2 weeks' : 'Longer term',
    lateral_paths:       lateralPaths,
    entry_point_count:   entryPoints.length,
    assets_at_risk:      assets.filter(a => a.external).length,
    sector,
    _cached_at:          Date.now(),
    generated_at:        new Date().toISOString(),
    platform:            PLATFORM,
  };

  // Cache predictions for 15 minutes
  await kvSet(env, cacheKey, result, PREDICT_CACHE_TTL);

  // Persist summary to D1 (non-blocking)
  d1Run(env,
    `INSERT OR IGNORE INTO ${PREDICTIONS_TABLE}
       (id, sector, breach_probability, chain_count, ttb_hours, generated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [`pred_${Date.now().toString(36)}`, sector, breachProbability, chains.length, ttbHours, new Date().toISOString()]
  );

  return result;
}

function buildEntryPoints(vulns, assets) {
  const entries = [];

  for (const v of vulns) {
    const cvss    = parseFloat(v.cvss || v.cvss_score || 5.0);
    const epss    = parseFloat(v.epss || v.epss_score || 0.05);
    const isKEV   = v.in_kev || false;
    const hasExpl = v.has_exploit || v.public_exploit || false;
    const external = assets.some(a => a.external) || v.external || false;

    const entryScore = (cvss / 10) * 0.4
                     + epss        * 0.3
                     + (isKEV  ? 0.2 : 0)
                     + (hasExpl? 0.1 : 0)
                     + (external? 0.1 : 0);

    if (entryScore >= 0.15) {
      entries.push({
        vuln_id:      v.cve_id || v.id || `vuln_${Math.random().toString(36).slice(2,7)}`,
        title:        v.title  || v.description?.slice(0, 60) || 'Unnamed vulnerability',
        cvss, epss,
        in_kev:       isKEV,
        has_exploit:  hasExpl,
        external,
        entry_score:  parseFloat(entryScore.toFixed(3)),
      });
    }
  }

  return entries.sort((a, b) => b.entry_score - a.entry_score);
}

// MITRE ATT&CK step templates per attack category
const ATTACK_STEP_TEMPLATES = {
  web_exploit: [
    { tactic: 'Reconnaissance',    technique: 'T1595', description: 'Active scanning of web application' },
    { tactic: 'Initial Access',    technique: 'T1190', description: 'Exploit public-facing application' },
    { tactic: 'Execution',         technique: 'T1059', description: 'Command execution via web shell' },
    { tactic: 'Privilege Escalation', technique: 'T1548', description: 'Abuse elevation control mechanism' },
    { tactic: 'Lateral Movement',  technique: 'T1021', description: 'Remote services exploitation' },
    { tactic: 'Exfiltration',      technique: 'T1041', description: 'Data exfiltration over C2 channel' },
  ],
  credential_attack: [
    { tactic: 'Reconnaissance',    technique: 'T1589', description: 'Gather target identity information' },
    { tactic: 'Initial Access',    technique: 'T1566', description: 'Spear phishing for credential theft' },
    { tactic: 'Credential Access', technique: 'T1078', description: 'Use valid credentials for access' },
    { tactic: 'Persistence',       technique: 'T1547', description: 'Establish persistent access' },
    { tactic: 'Discovery',         technique: 'T1057', description: 'Internal network enumeration' },
    { tactic: 'Collection',        technique: 'T1005', description: 'Data collection from local system' },
  ],
  ransomware: [
    { tactic: 'Initial Access',    technique: 'T1190', description: 'Exploit vulnerable service' },
    { tactic: 'Execution',         technique: 'T1059', description: 'Script-based execution' },
    { tactic: 'Defense Evasion',   technique: 'T1027', description: 'Obfuscated payload delivery' },
    { tactic: 'Discovery',         technique: 'T1083', description: 'File and directory discovery' },
    { tactic: 'Impact',            technique: 'T1486', description: 'Data encrypted for ransom' },
    { tactic: 'Impact',            technique: 'T1490', description: 'Inhibit system recovery' },
  ],
  supply_chain: [
    { tactic: 'Initial Access',    technique: 'T1195', description: 'Supply chain compromise' },
    { tactic: 'Execution',         technique: 'T1543', description: 'Create or modify system process' },
    { tactic: 'Command & Control', technique: 'T1071', description: 'Covert C2 via application layer' },
    { tactic: 'Exfiltration',      technique: 'T1020', description: 'Automated long-term exfiltration' },
  ],
};

function simulateAttackChain(entryPoint, allVulns, assets, sector) {
  // Classify entry point into attack type
  const isRansomware  = allVulns.some(v => (v.title || '').toLowerCase().includes('ransom'));
  const isCredential  = entryPoint.cvss < 7 || (allVulns.some(v => (v.title || '').toLowerCase().includes('auth')));
  const isSupplyChain = (allVulns.some(v => (v.title || '').toLowerCase().includes('supply')));

  let chainType = 'web_exploit';
  if (isSupplyChain) chainType = 'supply_chain';
  else if (isRansomware) chainType = 'ransomware';
  else if (isCredential && entryPoint.cvss < 7) chainType = 'credential_attack';

  const template = ATTACK_STEP_TEMPLATES[chainType];
  if (!template) return null;

  // Probability = entry_score × chain_multiplier × sector_modifier
  const sectorModifiers = {
    finance: 1.3, healthcare: 1.2, government: 1.25, critical_infra: 1.4, technology: 1.1, default: 1.0,
  };
  const sectorMod = sectorModifiers[sector] || sectorModifiers.default;
  const chainMult = { web_exploit: 1.2, ransomware: 1.3, credential_attack: 1.0, supply_chain: 0.8 }[chainType] || 1.0;

  const probability = Math.min(0.97, parseFloat((entryPoint.entry_score * chainMult * sectorMod).toFixed(3)));

  return {
    chain_id:    `chain_${chainType}_${Date.now().toString(36).slice(-4)}`,
    name:        {
      web_exploit:       'Web Exploitation → RCE → Lateral Movement',
      credential_attack: 'Credential Theft → Persistence → Exfiltration',
      ransomware:        'Initial Access → Ransomware Deployment',
      supply_chain:      'Supply Chain Compromise → Long-Term APT',
    }[chainType],
    type:        chainType,
    entry_point: entryPoint,
    steps:       template,
    probability,
    probability_label: probability >= 0.7 ? 'HIGH' : probability >= 0.4 ? 'MEDIUM' : 'LOW',
    estimated_impact:  probability >= 0.7
      ? 'Full system compromise, data breach, potential ransomware'
      : probability >= 0.4
      ? 'Partial access, lateral movement, data exposure risk'
      : 'Limited access, reconnaissance activity',
    detection_opportunity: template.length > 3
      ? `Step ${Math.floor(template.length / 2)}: ${template[Math.floor(template.length / 2)].tactic} — deploy detection rules for ${template[Math.floor(template.length / 2)].technique}`
      : 'Initial Access — block at perimeter',
    mitre_techniques: template.map(s => s.technique),
  };
}

function simulateLateralMovement(assets, vulns) {
  const paths = [];
  const external = assets.filter(a => a.external).map(a => a.name || 'external_asset');
  const internal = assets.filter(a => !a.external).map(a => a.name || 'internal_asset');

  if (external.length > 0 && internal.length > 0) {
    paths.push({
      from:      external[0],
      to:        internal[0] || 'internal_network',
      technique: 'T1021',
      path:      'Remote Services (RDP/SMB/WMI)',
      risk:      'HIGH',
    });
  }
  if (vulns.some(v => (v.title || '').toLowerCase().includes('rdp'))) {
    paths.push({ from: 'compromised_host', to: 'domain_controller', technique: 'T1021.001', path: 'RDP Lateral Movement', risk: 'CRITICAL' });
  }
  if (vulns.some(v => parseFloat(v.cvss || 0) >= 9.0)) {
    paths.push({ from: 'entry_point', to: 'admin_systems', technique: 'T1078', path: 'Valid Accounts → Admin Access', risk: 'CRITICAL' });
  }

  return paths;
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 5 — SMART RECOMMENDATION ENGINE
// ══════════════════════════════════════════════════════════════════════════════
/**
 * generateAdaptiveRecommendations()
 * Produces a priority-ranked, context-aware remediation action plan.
 * Accounts for: adaptive risk score, user history, sector context, tier,
 * global FP patterns, and predicted attack chain inputs.
 *
 * @param {object} env
 * @param {object} context - { findings, vulns, adaptiveScore, attackChains, sector, tier, userId }
 *
 * Returns: { actions, quick_wins, soc_playbook, automated_fixes }
 */
export async function generateAdaptiveRecommendations(env, context) {
  const {
    findings      = [],
    vulns         = [],
    adaptiveScore = 50,
    attackChains  = [],
    sector        = 'technology',
    tier          = 'FREE',
    userId        = null,
  } = context;

  // Load user feedback history to avoid re-recommending ignored items
  const fbKey    = `brain:weights:${userId}`;
  const weights  = await kvGet(env, fbKey, {});
  const fpCount  = weights._feedback_count || 0;

  // ── Base priority actions ─────────────────────────────────────────────────
  const actions = [];

  // KEV-based (always highest priority)
  const kevVulns = vulns.filter(v => v.in_kev);
  for (const v of kevVulns.slice(0, 3)) {
    actions.push({
      priority:   1,
      urgency:    'IMMEDIATE',
      category:   'patch',
      title:      `Patch ${v.cve_id || 'KEV vulnerability'} immediately`,
      detail:     `CISA KEV confirmed exploitation. CVSS ${v.cvss || '?'}. Apply vendor patch within 24 hours.`,
      effort:     '2–4h',
      impact:     'CRITICAL',
      mitre_ref:  'T1190',
      automated:  false,
      cve:        v.cve_id || null,
    });
  }

  // Critical findings
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
  for (const f of criticalFindings.slice(0, 3)) {
    actions.push({
      priority:   2,
      urgency:    'WITHIN_24H',
      category:   'harden',
      title:      `Remediate: ${f.title || 'Critical finding'}`,
      detail:     f.remediation || f.description || `Address ${f.title} to reduce critical risk surface.`,
      effort:     '4–8h',
      impact:     'HIGH',
      automated:  f.category === 'weak_tls' || f.category === 'dns_weakness',
      automation_cmd: f.category === 'weak_tls' ? 'Add HSTS header; enforce TLS 1.3' : null,
    });
  }

  // Attack chain mitigations
  const topChain = attackChains?.[0];
  if (topChain && topChain.probability >= 0.4) {
    actions.push({
      priority:   2,
      urgency:    'WITHIN_24H',
      category:   'detection',
      title:      `Deploy detection rule for predicted chain: ${topChain.name}`,
      detail:     `${topChain.detection_opportunity}. Probability: ${(topChain.probability * 100).toFixed(0)}%.`,
      effort:     '1–2h',
      impact:     'HIGH',
      mitre_ref:  topChain.mitre_techniques?.[0],
      automated:  false,
    });
  }

  // High findings
  const highFindings = findings.filter(f => f.severity === 'HIGH');
  for (const f of highFindings.slice(0, 4)) {
    actions.push({
      priority:   3,
      urgency:    'WITHIN_72H',
      category:   'harden',
      title:      `Harden: ${f.title || 'High severity finding'}`,
      detail:     f.remediation || `Address ${f.title} to reduce high risk exposure.`,
      effort:     '2–4h',
      impact:     'MEDIUM',
      automated:  false,
    });
  }

  // Sector-specific recommendations
  const sectorRecs = getSectorSpecificRecs(sector, adaptiveScore);
  actions.push(...sectorRecs);

  // PRO+ SOC playbook
  let socPlaybook = null;
  if (tierCan(tier, 'smart_rec')) {
    socPlaybook = buildSOCPlaybook(findings, vulns, adaptiveScore, attackChains);
  }

  // Quick wins (low effort, high impact)
  const quickWins = actions
    .filter(a => a.effort?.startsWith('1') && ['HIGH', 'CRITICAL'].includes(a.impact))
    .map(a => ({ title: a.title, effort: a.effort, impact: a.impact }))
    .slice(0, 5);

  // Automated fixes (items with automation_cmd)
  const automatedFixes = actions
    .filter(a => a.automated && a.automation_cmd)
    .map(a => ({ title: a.title, cmd: a.automation_cmd }));

  // Sort by priority, then by urgency
  const urgencyOrder = { IMMEDIATE: 0, WITHIN_24H: 1, WITHIN_72H: 2, WITHIN_WEEK: 3 };
  actions.sort((a, b) => (a.priority - b.priority) || (urgencyOrder[a.urgency] || 9) - (urgencyOrder[b.urgency] || 9));

  // Apply personalization: if user has high feedback count, add personalisation note
  const personalizationNote = fpCount >= 5
    ? `Risk model personalized from ${fpCount} feedback events — recommendations tuned to your environment.`
    : null;

  return {
    adaptive:              true,
    total_actions:         actions.length,
    actions:               actions.slice(0, 15),
    quick_wins:            quickWins,
    soc_playbook:          socPlaybook,
    automated_fixes:       automatedFixes,
    personalization_note:  personalizationNote,
    estimated_total_effort: summariseEffort(actions),
    risk_reduction_estimate: `${Math.min(40, Math.round(actions.length * 3 + kevVulns.length * 8))}% risk reduction if all actions completed`,
    platform:              PLATFORM,
  };
}

function getSectorSpecificRecs(sector, riskScore) {
  const recs = [];
  if (riskScore < 50) return recs;

  const map = {
    finance: [
      { priority: 2, urgency: 'WITHIN_24H', category: 'compliance', title: 'Verify PCI-DSS scope controls', detail: 'Finance sector targeted for payment data. Verify cardholder data environment segmentation.', effort: '4h', impact: 'HIGH', automated: false },
    ],
    healthcare: [
      { priority: 2, urgency: 'WITHIN_24H', category: 'compliance', title: 'Audit HIPAA access controls for patient data', detail: 'Healthcare sector at elevated ransomware risk. Audit PHI access logs and MFA enforcement.', effort: '3h', impact: 'HIGH', automated: false },
    ],
    government: [
      { priority: 1, urgency: 'IMMEDIATE', category: 'harden', title: 'Review privileged account access for nation-state indicators', detail: 'State-sponsored APT groups actively targeting government sector.', effort: '2h', impact: 'CRITICAL', automated: false },
    ],
    critical_infra: [
      { priority: 1, urgency: 'IMMEDIATE', category: 'isolation', title: 'Verify OT/IT network segmentation', detail: 'Critical infrastructure ICS/SCADA systems must remain air-gapped from IT network.', effort: '4h', impact: 'CRITICAL', automated: false },
    ],
  };

  return map[sector] || [];
}

function buildSOCPlaybook(findings, vulns, adaptiveScore, chains) {
  const topChain = chains?.[0];
  return {
    playbook_id:   `pb_${Date.now().toString(36)}`,
    severity:      adaptiveScore >= 80 ? 'P1' : adaptiveScore >= 60 ? 'P2' : 'P3',
    trigger:       `Adaptive risk score: ${adaptiveScore}/100`,
    steps: [
      { seq: 1, role: 'Tier 1 SOC', action: 'Acknowledge alert and begin initial triage', sla: '15 min' },
      { seq: 2, role: 'Tier 1 SOC', action: `Confirm affected assets: ${findings.slice(0,2).map(f => f.title).join(', ')}`, sla: '30 min' },
      { seq: 3, role: 'Tier 2 SOC', action: topChain ? `Block predicted entry point: ${topChain.entry_point?.title}` : 'Isolate highest-risk asset', sla: '1h' },
      { seq: 4, role: 'CISO',       action: 'Executive notification if P1 or confirmed breach', sla: '1h' },
      { seq: 5, role: 'Tier 2 SOC', action: 'Deploy detection rules for predicted MITRE techniques', sla: '2h' },
      { seq: 6, role: 'IR Team',    action: 'Begin forensic evidence collection if exploitation confirmed', sla: '4h' },
      { seq: 7, role: 'Tier 2 SOC', action: 'Patch or mitigate all KEV vulnerabilities', sla: '24h' },
      { seq: 8, role: 'All',        action: 'Post-incident review and adaptive model update', sla: '72h' },
    ],
    escalation_path: ['Tier 1 SOC', 'Tier 2 SOC', 'CISO', 'IR Team'],
    tools:           ['SIEM', 'EDR', 'Vulnerability Scanner', 'CYBERDUDEBIVASH AI Security Hub'],
  };
}

function summariseEffort(actions) {
  let totalHours = 0;
  for (const a of actions) {
    const m = (a.effort || '').match(/(\d+)/);
    if (m) totalHours += parseInt(m[1], 10);
  }
  return totalHours <= 8 ? `~${totalHours}h` : totalHours <= 40 ? `~${Math.round(totalHours / 8)} days` : `~${Math.round(totalHours / 40)} weeks`;
}

// ══════════════════════════════════════════════════════════════════════════════
// MASTER ORCHESTRATOR — enrichScanAdaptive()
// ══════════════════════════════════════════════════════════════════════════════
/**
 * enrichScanAdaptive()
 * Drop-in post-scan enrichment — called after every scan run.
 * Adds the full adaptive layer to the scan result without blocking.
 * FREE users get base enrichment; PRO+ get the full adaptive overlay.
 *
 * @param {object} env
 * @param {object} scanResult  - Raw scan output
 * @param {object} opts        - { module, target, tier, userId, sector }
 *
 * Returns: scanResult enriched with adaptive_brain field
 */
export async function enrichScanAdaptive(env, scanResult, {
  module   = 'domain',
  target   = '',
  tier     = 'FREE',
  userId   = null,
  sector   = 'technology',
} = {}) {
  try {
    const findings = scanResult?.findings || scanResult?.checks || [];
    const vulns    = scanResult?.cves     || scanResult?.vulns  || [];
    const assets   = [{ name: target, external: true, type: module }];
    const baseScore = scanResult?.riskScore || scanResult?.cyber_brain?.riskScore || 0;

    // All tiers get base info overlay
    const overlay = {
      engine_version:  'AdaptiveCyberBrain v21.0',
      tier_features:   ADAPTIVE_TIERS[tier] || ADAPTIVE_TIERS.FREE,
    };

    // STARTER+ gets adaptive risk scoring
    if (tierCan(tier, 'adaptive_risk') && userId) {
      const adaptiveRisk = await computeAdaptiveRisk(env, {
        findings, vulns, assets, sector, baseScore, target,
      }, userId, tier);
      overlay.adaptive_risk = adaptiveRisk;
    }

    // PRO+ gets predictions + global intel
    if (tierCan(tier, 'predictions')) {
      const [predictions, globalIntel] = await Promise.all([
        predictAttackPaths(env, assets, vulns, sector, tier),
        aggregateGlobalSignals(env, tier, sector),
      ]);
      overlay.predictions  = predictions;
      overlay.global_intel = globalIntel;
    }

    // STARTER+ gets adaptive recommendations
    if (tierCan(tier, 'smart_rec')) {
      const recs = await generateAdaptiveRecommendations(env, {
        findings, vulns,
        adaptiveScore: overlay.adaptive_risk?.adaptiveScore || baseScore,
        attackChains:  overlay.predictions?.chains || [],
        sector, tier, userId,
      });
      overlay.adaptive_recommendations = recs;
    }

    return { ...scanResult, adaptive_brain: overlay };

  } catch (err) {
    // Never crash the scan pipeline
    console.error('[AdaptiveBrain] Enrichment error:', err?.message);
    return scanResult;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTE HANDLERS — /api/cyber-brain/*
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/cyber-brain/learn ───────────────────────────────────────────────
export async function handleLearnFeedback(request, env, authCtx) {
  // Require authentication
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required to submit feedback' }, { status: 401 });
  }

  // Feature gate — STARTER+
  const gate = enforceFeatureGate('ai_brain', authCtx.tier || 'FREE');
  if (gate) return gate;

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { scan_result = {}, user_action } = body;

  if (!user_action || !user_action.action || !user_action.finding_type) {
    return Response.json({
      error: 'user_action.action and user_action.finding_type are required',
      valid_actions: ['ignored', 'fixed', 'escalated', 'false_positive'],
      example: { action: 'false_positive', finding_type: 'weak_tls', severity: 'HIGH' },
    }, { status: 400 });
  }

  const result = await learnFromFeedback(
    env, scan_result, user_action,
    authCtx.userId, authCtx.tier || 'FREE'
  );

  return Response.json(result);
}

// ── GET /api/cyber-brain/global-intel ─────────────────────────────────────────
export async function handleGlobalIntel(request, env, authCtx) {
  // Feature gate — PRO+
  const gate = enforceFeatureGate('dark_web', authCtx?.tier || 'FREE');
  if (gate) return gate;

  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || null;
  const result = await aggregateGlobalSignals(env, authCtx?.tier || 'PRO', sector);

  return Response.json(result);
}

// ── GET /api/cyber-brain/adaptive-risk ────────────────────────────────────────
export async function handleAdaptiveRisk(request, env, authCtx) {
  // Feature gate — STARTER+
  const gate = enforceFeatureGate('ai_brain', authCtx?.tier || 'FREE');
  if (gate) return gate;

  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required for adaptive risk scoring' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const target = url.searchParams.get('target') || '';
  const sector = url.searchParams.get('sector') || 'technology';

  // Try to retrieve last scan findings for this target from KV
  let findings = [];
  let vulns    = [];
  let baseScore = 0;

  if (env?.SECURITY_HUB_KV && target) {
    const cached = await kvGet(env, `scan:domain:${target}`);
    if (cached) {
      findings  = cached.findings || cached.checks || [];
      vulns     = cached.cves     || cached.vulns  || [];
      baseScore = cached.riskScore || 0;
    }
  }

  // Also accept findings/vulns in query body for direct invocation
  if (!findings.length) {
    try {
      const body = await request.json().catch(() => ({}));
      findings   = body.findings || [];
      vulns      = body.vulns    || [];
      baseScore  = body.base_score || 0;
    } catch {}
  }

  const result = await computeAdaptiveRisk(
    env,
    { findings, vulns, sector, baseScore, target },
    authCtx.userId,
    authCtx.tier || 'FREE'
  );

  return Response.json({ target, sector, ...result });
}

// ── GET /api/cyber-brain/predictions ──────────────────────────────────────────
export async function handleAttackPredictions(request, env, authCtx) {
  // Feature gate — PRO+
  const gate = enforceFeatureGate('threat_hunting', authCtx?.tier || 'FREE');
  if (gate) return gate;

  const url    = new URL(request.url);
  const target = url.searchParams.get('target') || '';
  const sector = url.searchParams.get('sector') || 'technology';

  // Retrieve last scan data for target
  let assets = [];
  let vulns  = [];

  if (env?.SECURITY_HUB_KV && target) {
    const cached = await kvGet(env, `scan:domain:${target}`);
    if (cached) {
      vulns  = cached.cves || cached.vulns || [];
      assets = [{ name: target, external: true, services: cached.open_ports || [] }];
    }
  }

  // Accept direct POST body
  if (!vulns.length) {
    try {
      const body = await request.json().catch(() => ({}));
      vulns  = body.vulns  || body.vulnerabilities || [];
      assets = body.assets || [{ name: target, external: true }];
    } catch {}
  }

  const result = await predictAttackPaths(env, assets, vulns, sector, authCtx?.tier || 'PRO');

  return Response.json({ target, sector, ...result });
}

// ── Cron batch — called from scheduled handler to refresh global signals ───────
export async function runAdaptiveBrainCron(env) {
  try {
    // 1. Refresh global signals cache (forces fresh D1 aggregate)
    await kvSet(env, 'brain:global_intel:all', null, 1);
    const signals = await aggregateGlobalSignals(env, 'ENTERPRISE', null);

    // 2. Compute and cache global false-positive patterns
    const fpRows = await d1All(env,
      `SELECT finding_type, COUNT(*) as cnt FROM ${SIGNALS_TABLE}
       WHERE signal_type = 'false_positive_pattern' AND created_at >= datetime('now','-30 days')
       GROUP BY finding_type ORDER BY cnt DESC LIMIT 20`
    );
    const fpMap = {};
    for (const row of fpRows) fpMap[row.finding_type] = row.cnt;
    await kvSet(env, 'brain:fp_patterns', fpMap, 86400);

    return {
      status:             'ok',
      global_risk_score:  signals.global_risk_score,
      emerging_threats:   signals.emerging_threats?.length || 0,
      fp_patterns_cached: Object.keys(fpMap).length,
      ran_at:             new Date().toISOString(),
    };
  } catch (err) {
    return { status: 'error', message: err?.message };
  }
}
