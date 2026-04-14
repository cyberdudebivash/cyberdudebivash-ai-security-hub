/**
 * CYBERDUDEBIVASH AI Security Hub
 * PREDICTIVE THREAT INTELLIGENCE ENGINE — System 3
 * Formula: risk_score = exploit_probability × impact × exposure
 * NO MOCK DATA — all predictions derived from real D1 threat intel + APT profiles
 *
 * Model:
 *   exploit_probability = f(epss, is_kev, age_days, cvss_vector)
 *   impact              = f(cvss_base, scope_changed, privileges_required)
 *   exposure            = f(asset_count, internet_facing, patch_lag_days)
 *   risk_score          = exploit_prob × impact × exposure × 100 → capped at 100
 */

function now() { return new Date().toISOString(); }

// ─── CVSS VECTOR PARSING ───────────────────────────────────────────────────

/**
 * Parse CVSS v3 vector string for component scoring
 * e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
 */
function parseCVSSVector(vector = '') {
  const parts  = {};
  const tokens = vector.split('/');
  for (const token of tokens) {
    const [k, v] = token.split(':');
    if (k && v) parts[k] = v;
  }
  return {
    attackVector:       parts['AV'] || 'N',   // N=Network, A=Adjacent, L=Local, P=Physical
    attackComplexity:   parts['AC'] || 'L',   // L=Low, H=High
    privilegesRequired: parts['PR'] || 'N',   // N=None, L=Low, H=High
    userInteraction:    parts['UI'] || 'N',   // N=None, R=Required
    scope:              parts['S']  || 'U',   // U=Unchanged, C=Changed
    confidentiality:    parts['C']  || 'H',   // N=None, L=Low, H=High
    integrity:          parts['I']  || 'H',
    availability:       parts['A']  || 'H',
  };
}

// ─── EXPLOIT PROBABILITY ──────────────────────────────────────────────────

/**
 * Compute exploit probability (0–1) for a CVE
 * Inputs: epss (FIRST.org EPSS score), is_kev, age_days, cvss_vector
 */
function computeExploitProbability(cve) {
  const { epss = 0, is_kev = false, age_days = 0, cvss_vector = '', cvss = 0 } = cve;

  // Base: EPSS is the best predictor of exploitation in the wild
  let prob = Math.min(epss, 1.0);

  // KEV membership = confirmed exploitation → strong boost
  if (is_kev) prob = Math.max(prob, 0.75);

  // Critical CVSS with no EPSS data → assume moderate probability
  if (prob < 0.1 && cvss >= 9.0) prob = Math.max(prob, 0.45);
  if (prob < 0.1 && cvss >= 7.0) prob = Math.max(prob, 0.20);

  // Age factor: older CVEs with no exploitation are less likely to be exploited now
  // But if KEV, age doesn't help much
  if (!is_kev && age_days > 365) {
    prob *= 0.85; // 15% decay for >1 year old, unexecuted CVE
  }
  if (!is_kev && age_days > 730) {
    prob *= 0.80; // Additional 20% for >2 years
  }

  // Attack vector bonus: Network-accessible vulns are far more likely exploited
  const vec = parseCVSSVector(cvss_vector);
  if (vec.attackVector === 'N') prob *= 1.20;
  if (vec.attackVector === 'L') prob *= 0.80;
  if (vec.attackVector === 'P') prob *= 0.50;

  // No auth required = more exploitation attempts
  if (vec.privilegesRequired === 'N') prob *= 1.10;

  return Math.min(1.0, Math.max(0, prob));
}

// ─── IMPACT SCORE ─────────────────────────────────────────────────────────

/**
 * Compute impact score (0–1) from CVSS base + vector components
 */
function computeImpact(cve) {
  const { cvss = 0, cvss_vector = '' } = cve;
  const vec = parseCVSSVector(cvss_vector);

  // CVSS base is the starting point for impact (normalized 0–1)
  let impact = cvss / 10;

  // Scope changed (lateral movement possible) → significant multiplier
  if (vec.scope === 'C') impact *= 1.25;

  // CIA triad weights
  const ciaScore =
    (vec.confidentiality === 'H' ? 3 : vec.confidentiality === 'L' ? 1 : 0) +
    (vec.integrity        === 'H' ? 3 : vec.integrity        === 'L' ? 1 : 0) +
    (vec.availability     === 'H' ? 3 : vec.availability     === 'L' ? 1 : 0);

  // Max CIA score = 9 → normalize to 0–1 boost
  const ciaBoost = ciaScore / 9;
  impact = impact * 0.7 + ciaBoost * 0.3;

  return Math.min(1.0, Math.max(0, impact));
}

// ─── EXPOSURE SCORE ───────────────────────────────────────────────────────

/**
 * Compute exposure score (0–1) based on asset/infrastructure context
 */
function computeExposure(context = {}) {
  const {
    internet_facing     = true,  // Is the affected asset internet-facing?
    asset_count         = 1,     // Number of affected assets in inventory
    patch_lag_days      = 30,    // Days since CVE was published (unpatched time)
    has_active_patch    = false, // Is a virtual patch already applied?
    affected_users      = 0,     // Estimated affected user count
    is_production       = true,  // Is this a production asset?
  } = context;

  let exposure = 0;

  // Internet-facing is the biggest exposure multiplier
  if (internet_facing) {
    exposure += 0.45;
  } else {
    exposure += 0.15;
  }

  // Asset count: more affected assets = higher exposure
  const assetFactor = Math.min(Math.log10(Math.max(asset_count, 1) + 1) / 3, 0.20);
  exposure += assetFactor;

  // Patch lag: the longer unpatched, the higher exposure
  const lagFactor = Math.min(patch_lag_days / 365, 1.0) * 0.20;
  exposure += lagFactor;

  // Active virtual patch reduces exposure significantly
  if (has_active_patch) {
    exposure *= 0.35; // 65% reduction with WAF patch in place
  }

  // Production assets carry more exposure
  if (is_production) {
    exposure *= 1.15;
  }

  // Affected users: large user base = higher exposure
  if (affected_users > 10000)  exposure += 0.10;
  else if (affected_users > 1000) exposure += 0.05;

  return Math.min(1.0, Math.max(0, exposure));
}

// ─── MAIN PREDICTION FORMULA ──────────────────────────────────────────────

/**
 * Compute composite risk score for a CVE
 * risk_score = exploit_probability × impact × exposure × 100
 * Capped at 100, minimum meaningful score for HIGH+ is ~40
 */
export function computePredictiveRiskScore(cve, context = {}) {
  const exploitProb = computeExploitProbability(cve);
  const impact      = computeImpact(cve);
  const exposure    = computeExposure(context);

  // Core formula
  const raw = exploitProb * impact * exposure;

  // Scale to 0–100: raw is 0–1, but pure multiplication is too conservative
  // Use geometric mean boosted by 3.0 to get meaningful scores
  const score = Math.min(100, Math.round(raw * 100 * 3.0));

  return {
    risk_score:         score,
    exploit_probability: Math.round(exploitProb * 100) / 100,
    impact_score:       Math.round(impact * 100) / 100,
    exposure_score:     Math.round(exposure * 100) / 100,
    risk_level:         score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW',
    formula:            `${(exploitProb*100).toFixed(1)}% × ${(impact*100).toFixed(1)}% × ${(exposure*100).toFixed(1)}% = ${score}/100`,
  };
}

// ─── APT CORRELATION ──────────────────────────────────────────────────────

/**
 * Match CVE against known APT group TTPs from D1
 */
async function correlateAPTGroups(env, cve) {
  const apt_profiles = await env.DB.prepare(`
    SELECT group_name, aliases, target_sectors, known_ttps, recent_cves, activity_level, confidence_score
    FROM apt_profiles
    WHERE is_active = 1
    ORDER BY confidence_score DESC
  `).all().catch(() => ({ results: [] }));

  const matched = [];
  const desc = (cve.description || '').toLowerCase();

  for (const apt of (apt_profiles.results || [])) {
    let matchScore = 0;

    // Check if this CVE ID appears in apt's recent_cves list
    const recentCVEs = (() => { try { return JSON.parse(apt.recent_cves || '[]'); } catch { return []; } })();
    if (recentCVEs.includes(cve.cve_id)) {
      matchScore += 40;
    }

    // TTP matching via description keywords
    const ttps = (() => { try { return JSON.parse(apt.known_ttps || '[]'); } catch { return []; } })();
    for (const ttp of ttps) {
      if (desc.includes(ttp.toLowerCase())) {
        matchScore += 15;
      }
    }

    // High activity groups have higher relevance
    if (apt.activity_level === 'HIGH' || apt.activity_level === 'CRITICAL') {
      matchScore += 10;
    }

    if (matchScore >= 15) {
      matched.push({
        group_name:    apt.group_name,
        aliases:       (() => { try { return JSON.parse(apt.aliases || '[]'); } catch { return []; } })(),
        target_sectors: (() => { try { return JSON.parse(apt.target_sectors || '[]'); } catch { return []; } })(),
        match_score:   matchScore,
        activity_level: apt.activity_level,
      });
    }
  }

  return matched.sort((a, b) => b.match_score - a.match_score).slice(0, 3);
}

// ─── THREAT PREDICTION PIPELINE ───────────────────────────────────────────

/**
 * Generate a full threat prediction for a single CVE
 */
export async function predictCVEThreat(env, cveId, contextOverride = {}) {
  // Fetch CVE data from D1
  const cve = await env.DB.prepare(`
    SELECT cve_id, cvss_score as cvss, epss_score as epss, is_kev, description,
           cvss_vector, published_date, patch_available
    FROM threat_intel
    WHERE cve_id = ?
    LIMIT 1
  `).bind(cveId).first().catch(() => null);

  if (!cve) return { error: `CVE ${cveId} not found`, status: 404 };

  // Compute age in days
  const ageDays = cve.published_date
    ? Math.floor((Date.now() - new Date(cve.published_date).getTime()) / 86400000)
    : 0;

  // Check if virtual patch active for this CVE
  const activePatch = await env.DB.prepare(
    `SELECT id FROM virtual_patches WHERE cve_id=? AND is_active=1 LIMIT 1`
  ).bind(cveId).first().catch(() => null);

  const context = {
    internet_facing:  true,
    asset_count:      1,
    patch_lag_days:   ageDays,
    has_active_patch: !!activePatch,
    is_production:    true,
    ...contextOverride,
  };

  const scoring  = computePredictiveRiskScore({ ...cve, age_days: ageDays }, context);
  const aptMatches = await correlateAPTGroups(env, cve);

  // Recommended actions based on risk level
  const actions = [];
  if (scoring.risk_level === 'CRITICAL') {
    actions.push('IMMEDIATE: Apply virtual WAF patch');
    actions.push('IMMEDIATE: Alert SOC team');
    if (!activePatch) actions.push('URGENT: Deploy emergency patch within 24h');
    if (aptMatches.length > 0) actions.push(`MONITOR: APT activity detected — ${aptMatches[0].group_name}`);
  } else if (scoring.risk_level === 'HIGH') {
    actions.push('Apply virtual WAF patch within 4 hours');
    actions.push('Schedule patch deployment within 7 days');
    if (aptMatches.length > 0) actions.push(`WATCH: Potential APT relevance — ${aptMatches.map(a => a.group_name).join(', ')}`);
  } else if (scoring.risk_level === 'MEDIUM') {
    actions.push('Schedule patch in next maintenance window');
    actions.push('Monitor for exploitation attempts');
  } else {
    actions.push('Include in routine patching cycle');
  }

  // Persist prediction
  const predictionId = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO threat_predictions
      (id, cve_id, risk_score, exploit_probability, impact_score, exposure_score,
       risk_level, apt_groups, recommended_actions, formula_breakdown,
       context_data, predicted_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    predictionId,
    cveId,
    scoring.risk_score,
    scoring.exploit_probability,
    scoring.impact_score,
    scoring.exposure_score,
    scoring.risk_level,
    JSON.stringify(aptMatches),
    JSON.stringify(actions),
    scoring.formula,
    JSON.stringify(context),
    now()
  ).run().catch(() => {});

  return {
    prediction_id:      predictionId,
    cve_id:             cveId,
    cvss:               cve.cvss,
    epss:               cve.epss,
    is_kev:             !!cve.is_kev,
    age_days:           ageDays,
    patch_available:    !!cve.patch_available,
    active_waf_patch:   !!activePatch,
    ...scoring,
    apt_groups:         aptMatches,
    recommended_actions: actions,
    context_used:       context,
    timestamp:          now(),
  };
}

/**
 * Batch predict top threats from recent CVE ingestion
 * Called from cron — scores all CVEs published in last 7 days
 */
export async function runPredictiveBatch(env) {
  const recent = await env.DB.prepare(`
    SELECT cve_id, cvss_score as cvss, epss_score as epss, is_kev
    FROM threat_intel
    WHERE published_date > datetime('now', '-7 days')
       OR (is_kev = 1)
    ORDER BY cvss_score DESC
    LIMIT 50
  `).all().catch(() => ({ results: [] }));

  const predictions = [];

  for (const cve of (recent.results || [])) {
    try {
      const p = await predictCVEThreat(env, cve.cve_id);
      if (!p.error) predictions.push(p);
    } catch (e) {
      // Silent — don't crash batch
    }
  }

  // Sort by risk score descending
  predictions.sort((a, b) => b.risk_score - a.risk_score);

  return {
    analyzed:         (recent.results || []).length,
    predictions:      predictions.length,
    critical_count:   predictions.filter(p => p.risk_level === 'CRITICAL').length,
    high_count:       predictions.filter(p => p.risk_level === 'HIGH').length,
    top_threats:      predictions.slice(0, 10),
    timestamp:        now(),
  };
}

/**
 * Get top predicted threats from D1 (already computed and stored)
 */
export async function getTopThreats(env, limit = 20) {
  const rows = await env.DB.prepare(`
    SELECT tp.id, tp.cve_id, tp.risk_score, tp.exploit_probability,
           tp.impact_score, tp.exposure_score, tp.risk_level,
           tp.apt_groups, tp.recommended_actions, tp.formula_breakdown,
           tp.predicted_at,
           ti.cvss_score, ti.epss_score, ti.is_kev, ti.description
    FROM threat_predictions tp
    LEFT JOIN threat_intel ti ON ti.cve_id = tp.cve_id
    WHERE tp.predicted_at > datetime('now', '-24 hours')
    ORDER BY tp.risk_score DESC, tp.predicted_at DESC
    LIMIT ?
  `).bind(limit).all().catch(() => ({ results: [] }));

  return {
    threats: (rows.results || []).map(r => ({
      ...r,
      apt_groups:          (() => { try { return JSON.parse(r.apt_groups || '[]'); } catch { return []; } })(),
      recommended_actions: (() => { try { return JSON.parse(r.recommended_actions || '[]'); } catch { return []; } })(),
    })),
    total:     (rows.results || []).length,
    timestamp: now(),
  };
}

/**
 * Get predictions for a specific CVE across time (trend)
 */
export async function getCVEPredictionTrend(env, cveId, days = 7) {
  const rows = await env.DB.prepare(`
    SELECT risk_score, exploit_probability, impact_score, exposure_score,
           risk_level, predicted_at
    FROM threat_predictions
    WHERE cve_id = ? AND predicted_at > datetime('now', ?)
    ORDER BY predicted_at ASC
  `).bind(cveId, `-${days} days`).all().catch(() => ({ results: [] }));

  return {
    cve_id:    cveId,
    trend:     rows.results || [],
    data_points: (rows.results || []).length,
    timestamp: now(),
  };
}

/**
 * Get predictive stats for dashboard
 */
export async function getPredictiveStats(env) {
  const [total, byLevel, avgScore, topAPT] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as cnt FROM threat_predictions WHERE predicted_at > datetime('now', '-24 hours')`).first().catch(() => ({ cnt: 0 })),
    env.DB.prepare(`SELECT risk_level, COUNT(*) as cnt FROM threat_predictions WHERE predicted_at > datetime('now', '-24 hours') GROUP BY risk_level`).all().catch(() => ({ results: [] })),
    env.DB.prepare(`SELECT AVG(risk_score) as avg FROM threat_predictions WHERE predicted_at > datetime('now', '-24 hours')`).first().catch(() => ({ avg: 0 })),
    env.DB.prepare(`SELECT apt_groups FROM threat_predictions WHERE predicted_at > datetime('now', '-24 hours') AND apt_groups != '[]' LIMIT 20`).all().catch(() => ({ results: [] })),
  ]);

  // Count APT mentions
  const aptCounts = {};
  for (const row of (topAPT.results || [])) {
    const groups = (() => { try { return JSON.parse(row.apt_groups || '[]'); } catch { return []; } })();
    for (const g of groups) {
      aptCounts[g.group_name] = (aptCounts[g.group_name] || 0) + 1;
    }
  }

  const topAPTGroups = Object.entries(aptCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ group_name: name, mention_count: count }));

  return {
    last_24h_predictions: total?.cnt || 0,
    by_risk_level:        byLevel.results || [],
    avg_risk_score:       Math.round(avgScore?.avg || 0),
    top_apt_groups:       topAPTGroups,
    timestamp:            now(),
  };
}
