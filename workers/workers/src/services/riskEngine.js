/**
 * CYBERDUDEBIVASH AI Security Hub — Dynamic Risk Scoring Engine v1.0
 * service: services/riskEngine.js
 *
 * Computes a composite risk score (0–10) for a scan result.
 * Factors: CVSS scores, exposure, exploit availability, asset criticality,
 *          finding severity distribution, scan module, threat actor activity.
 *
 * Outputs:
 *   risk_score         (0.0 – 10.0, 1 decimal)
 *   severity           (LOW | MEDIUM | HIGH | CRITICAL)
 *   exploit_probability (LOW | MEDIUM | HIGH | CRITICAL)
 *   confidence_score   (0–100)
 *   risk_breakdown     { cvss_factor, exposure_factor, exploit_factor, severity_factor }
 *   recommendations    [ { priority, action, effort, impact } ]
 */

import { correlateScanToCVEs } from './cveEngine.js';

// ─── Severity weight table ────────────────────────────────────────────────────
const SEV_WEIGHTS = { CRITICAL: 4.0, HIGH: 2.5, MEDIUM: 1.2, LOW: 0.4, INFO: 0.0 };

// ─── Module exposure multipliers ─────────────────────────────────────────────
// Higher multiplier = more publicly exposed / directly internet-facing
const MODULE_EXPOSURE = {
  domain:     1.0,   // fully public-facing
  ai:         0.85,  // API-facing, semi-public
  redteam:    0.95,  // simulated internal+external
  identity:   0.90,  // auth surface — high value target
  compliance: 0.75,  // configuration/process risk
};

// ─── Threat actor activity index (0–1) per module ────────────────────────────
const THREAT_ACTOR_ACTIVITY = {
  domain:     0.80,  // phishing, subdomain hijacking — very active
  ai:         0.90,  // LLM abuse, prompt injection — rapidly growing
  redteam:    0.85,
  identity:   0.95,  // credential theft — most active threat category
  compliance: 0.60,
};

// ─── Risk score → severity label ─────────────────────────────────────────────
function riskToSeverity(score) {
  if (score >= 8.0) return 'CRITICAL';
  if (score >= 6.0) return 'HIGH';
  if (score >= 3.5) return 'MEDIUM';
  return 'LOW';
}

// ─── Risk score → exploit probability label ───────────────────────────────────
function riskToExploitProb(score, exploitedInWild, maxCVSS) {
  if (exploitedInWild > 0 && score >= 7.0) return 'CRITICAL';
  if (exploitedInWild > 0 || (score >= 7.5 && maxCVSS >= 9.0)) return 'HIGH';
  if (score >= 5.0 || maxCVSS >= 7.0) return 'MEDIUM';
  return 'LOW';
}

// ─── Compute CVSS factor (0–1) ───────────────────────────────────────────────
function computeCVSSFactor(cveSummary) {
  if (!cveSummary || !cveSummary.total_unique_cves) return 0;
  const maxCVSS       = cveSummary.max_cvss || 0;
  const criticalCount = cveSummary.critical_cves || 0;
  const exploited     = cveSummary.exploited_in_wild || 0;

  const normalizedMax = maxCVSS / 10.0;
  const critBonus     = Math.min(0.2, criticalCount * 0.05);
  const exploitBonus  = Math.min(0.2, exploited * 0.07);

  return Math.min(1.0, normalizedMax + critBonus + exploitBonus);
}

// ─── Compute severity distribution factor (0–1) ───────────────────────────────
function computeSeverityFactor(findings) {
  if (!findings?.length) return 0;
  const total  = findings.length;
  let weightSum = 0;
  for (const f of findings) {
    weightSum += (SEV_WEIGHTS[f.severity] || 0);
  }
  // Max possible: all CRITICAL = 4.0 per finding
  const maxPossible = total * SEV_WEIGHTS.CRITICAL;
  return maxPossible > 0 ? Math.min(1.0, weightSum / maxPossible) : 0;
}

// ─── Compute exposure factor (0–1) ────────────────────────────────────────────
function computeExposureFactor(module, findings) {
  const baseExposure = MODULE_EXPOSURE[module] || 0.8;
  // Amplify if specific high-exposure findings exist
  const hasPublicPort = findings.some(f => (f.id || '').includes('PORT') || (f.title || '').toLowerCase().includes('open port'));
  const hasNoAuth     = findings.some(f => (f.title || '').toLowerCase().includes('no authentication') || (f.detail || '').toLowerCase().includes('unauthenticated'));
  const exposureBonus = (hasPublicPort ? 0.08 : 0) + (hasNoAuth ? 0.12 : 0);
  return Math.min(1.0, baseExposure + exposureBonus);
}

// ─── Main scoring function ────────────────────────────────────────────────────
export function computeRiskScore(scanResult, module) {
  const allFindings = [
    ...(scanResult.findings        || []),
    ...(scanResult.locked_findings || []),
  ];

  // Get CVE correlation data
  const cveData   = correlateScanToCVEs(scanResult);
  const cveSummary = cveData.summary;

  // Compute individual factors (each 0–1)
  const cvssFactor     = computeCVSSFactor(cveSummary);
  const severityFactor = computeSeverityFactor(allFindings);
  const exposureFactor = computeExposureFactor(module, allFindings);
  const exploitFactor  = cveSummary.exploited_in_wild > 0
    ? Math.min(1.0, 0.5 + (cveSummary.exploited_in_wild * 0.15))
    : severityFactor * 0.6;
  const actorFactor    = THREAT_ACTOR_ACTIVITY[module] || 0.75;

  // Weighted composite (weights sum to 1.0)
  const composite =
    cvssFactor     * 0.28 +
    severityFactor * 0.25 +
    exposureFactor * 0.20 +
    exploitFactor  * 0.18 +
    actorFactor    * 0.09;

  // Scale to 0–10 (use raw scan risk_score as a floor)
  const rawScore     = (scanResult.risk_score || 0) / 100; // normalize to 0–1
  const engineScore  = composite;
  const blendedScore = engineScore * 0.65 + rawScore * 0.35;
  const finalScore   = Math.min(10.0, Math.round(blendedScore * 100) / 10);

  const severity         = riskToSeverity(finalScore);
  const exploitProbLabel = riskToExploitProb(finalScore, cveSummary.exploited_in_wild, cveSummary.max_cvss);

  // Confidence: based on number of findings + CVE matches
  const confidence = Math.min(100, 40
    + Math.min(30, allFindings.length * 3)
    + Math.min(20, cveSummary.total_unique_cves * 4)
    + (cveSummary.exploited_in_wild > 0 ? 10 : 0)
  );

  return {
    risk_score:        finalScore,
    severity,
    exploit_probability: exploitProbLabel,
    confidence_score:  confidence,
    cve_summary:       cveSummary,
    risk_breakdown: {
      cvss_factor:      Math.round(cvssFactor * 100),
      severity_factor:  Math.round(severityFactor * 100),
      exposure_factor:  Math.round(exposureFactor * 100),
      exploit_factor:   Math.round(exploitFactor * 100),
      threat_actor_activity: Math.round(actorFactor * 100),
    },
    recommendations: buildRecommendations(allFindings, severity, module),
  };
}

// ─── Generate priority recommendations ───────────────────────────────────────
function buildRecommendations(findings, severity, module) {
  const recs = [];
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
  const highFindings     = findings.filter(f => f.severity === 'HIGH');

  if (criticalFindings.length > 0) {
    recs.push({
      priority: 1,
      action:   `Remediate ${criticalFindings.length} CRITICAL finding(s) immediately.`,
      effort:   'HIGH',
      impact:   'CRITICAL',
      timeframe: '24-48 hours',
    });
  }

  if (highFindings.length > 0) {
    recs.push({
      priority: 2,
      action:   `Address ${highFindings.length} HIGH-severity finding(s) within the sprint.`,
      effort:   'MEDIUM',
      impact:   'HIGH',
      timeframe: '1-2 weeks',
    });
  }

  // Module-specific top recommendation
  const moduleRecs = {
    domain:     { action: 'Enforce DNSSEC and HTTPS everywhere. Rotate exposed certificates.', effort: 'MEDIUM', timeframe: '1 week' },
    ai:         { action: 'Implement prompt sanitization, rate limiting, and model output filtering.', effort: 'HIGH', timeframe: '2-4 weeks' },
    redteam:    { action: 'Patch all exploitable entry points and review lateral movement paths.', effort: 'HIGH', timeframe: '2 weeks' },
    identity:   { action: 'Enforce phishing-resistant MFA and implement Privileged Access Management.', effort: 'MEDIUM', timeframe: '2 weeks' },
    compliance: { action: 'Run a full gap assessment and document remediation roadmap.', effort: 'HIGH', timeframe: '4 weeks' },
  };

  if (moduleRecs[module]) {
    recs.push({ priority: recs.length + 1, impact: severity, ...moduleRecs[module] });
  }

  recs.push({
    priority: recs.length + 1,
    action:   'Schedule quarterly security review and subscribe to CVE alerts for affected technologies.',
    effort:   'LOW',
    impact:   'MEDIUM',
    timeframe: 'Ongoing',
  });

  return recs;
}

// ─── Batch score multiple scan results ────────────────────────────────────────
export function batchRiskScore(scanResults) {
  return scanResults.map(({ scanResult, module }) => ({
    module,
    ...computeRiskScore(scanResult, module),
  }));
}
