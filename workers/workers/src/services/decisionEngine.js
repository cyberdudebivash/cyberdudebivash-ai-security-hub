/**
 * CYBERDUDEBIVASH AI Security Hub — AI Decision Engine v1.0
 * Sentinel APEX v3 Phase 2c: AI SOC Automation — Decision Making
 *
 * Combines threat intelligence + detection alerts + risk scoring
 * to produce actionable security decisions with confidence scores.
 *
 * Decision types:
 *   escalate        → Immediate SOC team escalation required
 *   auto_contain    → Automated containment should be applied
 *   fast_patch      → Emergency patch cycle within 24–72h
 *   monitor_closely → Enhanced monitoring, no immediate action
 *   low_priority    → Standard patch cycle, no urgent action
 *   false_positive  → Likely a false positive, investigate
 *
 * Output:
 *   { decision, reason, confidence, priority, actions_recommended, risk_score }
 */

// ─── Decision catalog ─────────────────────────────────────────────────────────
export const DECISIONS = {
  ESCALATE:        'escalate',
  AUTO_CONTAIN:    'auto_contain',
  FAST_PATCH:      'fast_patch',
  MONITOR_CLOSELY: 'monitor_closely',
  LOW_PRIORITY:    'low_priority',
  FALSE_POSITIVE:  'false_positive',
};

// ─── Risk score computation (0–100) ──────────────────────────────────────────
function computeRiskScore(entry, alert = null) {
  let score = 0;

  // CVSS contribution (max 35 points)
  const cvss = parseFloat(entry?.cvss || alert?.cvss || 0);
  score += Math.min(35, (cvss / 10) * 35);

  // EPSS contribution (max 20 points)
  const epss = parseFloat(entry?.epss_score || alert?.epss_score || 0);
  score += Math.min(20, epss * 20);

  // Exploit status (max 25 points)
  const exploitStatus = entry?.exploit_status || alert?.exploit_status || 'unconfirmed';
  if (exploitStatus === 'confirmed')       score += 25;
  else if (exploitStatus === 'poc_available') score += 15;
  else                                      score += 0;

  // Active exploitation bonus (max 10 points)
  const activelyExploited = entry?.actively_exploited || alert?.actively_exploited;
  if (activelyExploited) score += 10;

  // KEV listing (max 5 points)
  if (entry?.known_ransomware || alert?.evidence?.kev) score += 5;

  // Ransomware link (max 5 points)
  try {
    const tags = JSON.parse(entry?.tags || alert?.tags || '[]');
    if (tags.some(t => ['Ransomware', 'RansomwareLinked'].includes(t))) score += 5;
  } catch {}

  return Math.min(100, Math.round(score));
}

// ─── Confidence scoring (0–100) ───────────────────────────────────────────────
function computeConfidence(factors) {
  let confidence = 50; // baseline

  // More authoritative sources → higher confidence
  if (factors.sources?.includes('cisa_kev'))  confidence += 20;
  if (factors.sources?.includes('nvd'))        confidence += 10;
  if (factors.sources?.includes('exploitdb'))  confidence += 10;

  // Multiple detection signals → higher confidence
  if (factors.alert_count >= 3)  confidence += 10;
  if (factors.alert_count >= 5)  confidence += 5;

  // Confirmed exploitation → maximum confidence
  if (factors.exploit_confirmed) confidence += 15;

  // High EPSS agreement → higher confidence
  if ((factors.epss || 0) >= 0.7) confidence += 10;

  return Math.min(100, Math.round(confidence));
}

// ─── Core decision logic ──────────────────────────────────────────────────────
function makeDecision(riskScore, factors, alert = null) {
  const {
    exploit_confirmed,
    epss,
    cvss,
    kev,
    ransomware,
    alert_count,
    alert_types,
  } = factors;

  // Rule 1: Active KEV + high CVSS + exploit → ESCALATE + AUTO_CONTAIN
  if (kev && exploit_confirmed && cvss >= 9.0) {
    return {
      decision:   DECISIONS.ESCALATE,
      reason:     `Active exploit confirmed (CISA KEV), CVSS ${cvss} — immediate escalation and containment required`,
      sub_action: DECISIONS.AUTO_CONTAIN,
    };
  }

  // Rule 2: CVSS ≥ 9 + confirmed exploit → ESCALATE
  if (exploit_confirmed && cvss >= 9.0) {
    return {
      decision: DECISIONS.ESCALATE,
      reason:   `CVSS ${cvss} with confirmed active exploitation — SOC escalation mandatory`,
    };
  }

  // Rule 3: Ransomware + any exploit → AUTO_CONTAIN
  if (ransomware && (exploit_confirmed || epss >= 0.6)) {
    return {
      decision: DECISIONS.AUTO_CONTAIN,
      reason:   `Ransomware campaign association with exploit vector — automated containment recommended`,
    };
  }

  // Rule 4: Zero-day with no patch → ESCALATE
  if (alert_types?.includes('zero_day_active') && exploit_confirmed) {
    return {
      decision: DECISIONS.ESCALATE,
      reason:   `Zero-day exploit actively used in the wild — no vendor patch available`,
    };
  }

  // Rule 5: High risk score (≥ 80) → ESCALATE
  if (riskScore >= 80) {
    return {
      decision: DECISIONS.ESCALATE,
      reason:   `Combined risk score ${riskScore}/100 exceeds escalation threshold`,
    };
  }

  // Rule 6: KEV + CVSS ≥ 8 → FAST_PATCH
  if (kev && cvss >= 8.0) {
    return {
      decision: DECISIONS.FAST_PATCH,
      reason:   `CISA KEV listed with CVSS ${cvss} — emergency patch cycle within 24h`,
    };
  }

  // Rule 7: High EPSS (≥ 0.75) → FAST_PATCH
  if (epss >= 0.75) {
    return {
      decision: DECISIONS.FAST_PATCH,
      reason:   `EPSS ${(epss * 100).toFixed(1)}% indicates imminent exploitation — fast-track patching`,
    };
  }

  // Rule 8: Risk ≥ 60 → FAST_PATCH
  if (riskScore >= 60) {
    return {
      decision: DECISIONS.FAST_PATCH,
      reason:   `Risk score ${riskScore}/100 — fast-track patch cycle recommended`,
    };
  }

  // Rule 9: Multiple high-severity alerts → MONITOR_CLOSELY
  if (alert_count >= 3 && riskScore >= 40) {
    return {
      decision: DECISIONS.MONITOR_CLOSELY,
      reason:   `${alert_count} alerts generated — enhanced monitoring activated`,
    };
  }

  // Rule 10: Low risk → LOW_PRIORITY
  if (riskScore < 40) {
    return {
      decision: DECISIONS.LOW_PRIORITY,
      reason:   `Risk score ${riskScore}/100 — standard patch cycle, no urgent action required`,
    };
  }

  // Default
  return {
    decision: DECISIONS.MONITOR_CLOSELY,
    reason:   `Risk score ${riskScore}/100 — monitor and assess during next review cycle`,
  };
}

// ─── Decision priority label ──────────────────────────────────────────────────
function decisionToPriority(decision) {
  const map = {
    [DECISIONS.ESCALATE]:        'P1-CRITICAL',
    [DECISIONS.AUTO_CONTAIN]:    'P1-CRITICAL',
    [DECISIONS.FAST_PATCH]:      'P2-HIGH',
    [DECISIONS.MONITOR_CLOSELY]: 'P3-MEDIUM',
    [DECISIONS.LOW_PRIORITY]:    'P4-LOW',
    [DECISIONS.FALSE_POSITIVE]:  'P5-INFO',
  };
  return map[decision] || 'P3-MEDIUM';
}

// ─── Recommended actions per decision ────────────────────────────────────────
const DECISION_ACTIONS = {
  [DECISIONS.ESCALATE]:        ['alert_admin', 'isolate_system', 'patch_advisory', 'threat_hunt'],
  [DECISIONS.AUTO_CONTAIN]:    ['block_ip', 'block_domain', 'isolate_system', 'rotate_secrets'],
  [DECISIONS.FAST_PATCH]:      ['patch_advisory', 'ids_signature', 'alert_admin'],
  [DECISIONS.MONITOR_CLOSELY]: ['monitor_enhanced', 'ids_signature'],
  [DECISIONS.LOW_PRIORITY]:    ['patch_advisory'],
  [DECISIONS.FALSE_POSITIVE]:  [],
};

// ─── Analyze a single entry + its detection alerts ────────────────────────────
export function analyzeEntry(entry, alerts = []) {
  const cvss         = parseFloat(entry?.cvss || 0);
  const epss         = parseFloat(entry?.epss_score || 0);
  const exploitConf  = entry?.exploit_status === 'confirmed' || !!entry?.actively_exploited;
  const kev          = !!entry?.known_ransomware || entry?.source === 'cisa_kev';
  let ransomware     = false;
  try {
    const tags = JSON.parse(entry?.tags || '[]');
    ransomware = tags.some(t => ['Ransomware', 'RansomwareLinked'].includes(t));
  } catch {}

  const entryAlerts  = alerts.filter(a => a.cve_id === entry.id);
  const alertTypes   = entryAlerts.map(a => a.alert_type);
  const sources      = [entry.source, ...(entry._sources || [])].filter(Boolean);

  const factors = {
    exploit_confirmed: exploitConf,
    epss,
    cvss,
    kev,
    ransomware,
    alert_count: entryAlerts.length,
    alert_types: alertTypes,
    sources,
  };

  const riskScore  = computeRiskScore(entry);
  const decResult  = makeDecision(riskScore, factors, entryAlerts[0]);
  const confidence = computeConfidence(factors);

  return {
    decision_id:           `DEC-${entry.id}-${Date.now().toString(36)}`,
    cve_id:                entry.id,
    decision:              decResult.decision,
    sub_action:            decResult.sub_action || null,
    reason:                decResult.reason,
    confidence,
    priority:              decisionToPriority(decResult.decision),
    risk_score:            riskScore,
    actions_recommended:   DECISION_ACTIONS[decResult.decision] || [],
    factors: {
      cvss,
      epss_score:          epss,
      exploit_confirmed:   exploitConf,
      kev_listed:          kev,
      ransomware_linked:   ransomware,
      alert_count:         entryAlerts.length,
    },
    decided_at:            new Date().toISOString(),
  };
}

// ─── Analyze full detection result → decision report ──────────────────────────
export function runDecisionEngine(entries = [], detectionResult = null) {
  const alerts = detectionResult?.alerts || [];

  // Focus on CRITICAL/HIGH entries first
  const prioritized = [...entries].sort((a, b) => {
    const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
  });

  const decisions = [];
  for (const entry of prioritized.slice(0, 30)) { // cap at 30 for performance
    const decision = analyzeEntry(entry, alerts);
    decisions.push(decision);
  }

  // Sort by priority
  decisions.sort((a, b) => {
    const p = { 'P1-CRITICAL': 0, 'P2-HIGH': 1, 'P3-MEDIUM': 2, 'P4-LOW': 3, 'P5-INFO': 4 };
    return (p[a.priority] ?? 5) - (p[b.priority] ?? 5);
  });

  // Count by decision type
  const byDecision = {};
  for (const d of decisions) {
    byDecision[d.decision] = (byDecision[d.decision] || 0) + 1;
  }

  // Overall platform threat level
  const escalations = byDecision[DECISIONS.ESCALATE]     || 0;
  const autoContain = byDecision[DECISIONS.AUTO_CONTAIN]  || 0;
  const fastPatch   = byDecision[DECISIONS.FAST_PATCH]    || 0;

  let overallThreatLevel = 'LOW';
  if (escalations >= 1)              overallThreatLevel = 'CRITICAL';
  else if (autoContain >= 1)         overallThreatLevel = 'HIGH';
  else if (fastPatch >= 2)           overallThreatLevel = 'HIGH';
  else if (fastPatch >= 1)           overallThreatLevel = 'MEDIUM';

  return {
    decisions,
    total:               decisions.length,
    by_decision:         byDecision,
    overall_threat_level: overallThreatLevel,
    escalation_required: escalations > 0 || autoContain > 0,
    p1_count:            escalations + autoContain,
    p2_count:            fastPatch,
    decided_at:          new Date().toISOString(),
  };
}

// ─── Quick decision for single CVE (API endpoint) ─────────────────────────────
export function quickDecision(entry) {
  return analyzeEntry(entry, []);
}

// ─── Store decisions in D1 ────────────────────────────────────────────────────
export async function storeDecisions(env, decisionResult) {
  if (!env?.DB || !decisionResult?.decisions?.length) return;

  const toStore = decisionResult.decisions
    .filter(d => ['P1-CRITICAL', 'P2-HIGH'].includes(d.priority))
    .slice(0, 15);

  for (const dec of toStore) {
    env.DB.prepare(`
      INSERT OR IGNORE INTO soc_decisions
        (id, cve_id, decision, priority, confidence, risk_score, reason, factors, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      dec.decision_id,
      dec.cve_id,
      dec.decision,
      dec.priority,
      dec.confidence,
      dec.risk_score,
      dec.reason,
      JSON.stringify(dec.factors || {}),
    ).run().catch(() => {});
  }
}
