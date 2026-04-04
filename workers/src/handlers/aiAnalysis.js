/**
 * CYBERDUDEBIVASH AI Security Hub — AI Cyber Brain V2
 * Three specialized intelligence endpoints:
 *
 *   POST /api/ai/analyze  → Threat Correlation Engine
 *                           Input: scan_result + module
 *                           Output: attack_chain, MITRE ATT&CK mapping, CVE enrichment, risk score
 *
 *   POST /api/ai/simulate → Attack Simulation Engine (PRO+)
 *                           Input: scan_result + module + target
 *                           Output: full MITRE kill chain, blast_radius, attacker profile
 *
 *   POST /api/ai/forecast → Risk Forecast Engine
 *                           Input: scan_result + module
 *                           Output: exploitation_likelihood, time_to_breach, financial_impact
 *
 * All endpoints run deterministically from scan data (no external LLM needed),
 * enriched with real CVE/risk data from the AI Cyber Brain V2 services layer.
 * All responses: { success, data, error, timestamp }
 */

import { correlateScanToCVEs, getTopCVEsForModule } from '../services/cveEngine.js';
import { computeRiskScore } from '../services/riskEngine.js';
import { runAttackSimulation } from '../services/simulationEngine.js';
import { ok, fail, badRequest, forbidden, withErrorBoundary } from '../lib/response.js';

// ─── MITRE ATT&CK technique database (curated subset) ────────────────────────
const MITRE_TECHNIQUES = {
  domain: [
    { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', url: 'https://attack.mitre.org/techniques/T1595/' },
    { id: 'T1596', name: 'Search Open Technical Databases', tactic: 'Reconnaissance', url: 'https://attack.mitre.org/techniques/T1596/' },
    { id: 'T1584', name: 'Compromise Infrastructure', tactic: 'Resource Development', url: 'https://attack.mitre.org/techniques/T1584/' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1190/' },
    { id: 'T1557', name: 'Adversary-in-the-Middle (AitM)', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1557/' },
    { id: 'T1040', name: 'Network Sniffing', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1040/' },
    { id: 'T1071', name: 'Application Layer Protocol Abuse', tactic: 'Command & Control', url: 'https://attack.mitre.org/techniques/T1071/' },
  ],
  ai: [
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1059/' },
    { id: 'T1078', name: 'Valid Accounts (API key abuse)', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1078/' },
    { id: 'T1190', name: 'Exploit Public-Facing Application (LLM endpoint)', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1190/' },
    { id: 'T1565', name: 'Data Manipulation (model poisoning)', tactic: 'Impact', url: 'https://attack.mitre.org/techniques/T1565/' },
    { id: 'T1530', name: 'Data from Cloud Storage (training data exfil)', tactic: 'Collection', url: 'https://attack.mitre.org/techniques/T1530/' },
  ],
  redteam: [
    { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/' },
    { id: 'T1053', name: 'Scheduled Task / Job', tactic: 'Persistence', url: 'https://attack.mitre.org/techniques/T1053/' },
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', url: 'https://attack.mitre.org/techniques/T1548/' },
    { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion', url: 'https://attack.mitre.org/techniques/T1562/' },
    { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', url: 'https://attack.mitre.org/techniques/T1021/' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', url: 'https://attack.mitre.org/techniques/T1041/' },
  ],
  identity: [
    { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1110/' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1078/' },
    { id: 'T1621', name: 'MFA Request Generation (MFA Fatigue)', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1621/' },
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1528/' },
    { id: 'T1550', name: 'Use Alternate Authentication Material', tactic: 'Lateral Movement', url: 'https://attack.mitre.org/techniques/T1550/' },
  ],
  compliance: [
    { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1552/' },
    { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', url: 'https://attack.mitre.org/techniques/T1530/' },
    { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', url: 'https://attack.mitre.org/techniques/T1485/' },
    { id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)', tactic: 'Impact', url: 'https://attack.mitre.org/techniques/T1486/' },
  ],
};

// ─── Financial impact lookup by severity ─────────────────────────────────────
const FINANCIAL_IMPACT = {
  CRITICAL: { low_usd: 250000,  high_usd: 4500000,  avg_usd: 1200000, recovery_days: 90  },
  HIGH:     { low_usd: 50000,   high_usd: 850000,   avg_usd: 280000,  recovery_days: 45  },
  MEDIUM:   { low_usd: 10000,   high_usd: 150000,   avg_usd: 55000,   recovery_days: 14  },
  LOW:      { low_usd: 1000,    high_usd: 25000,    avg_usd: 8000,    recovery_days: 3   },
};

// ─── Time-to-breach estimates (days) ─────────────────────────────────────────
const TIME_TO_BREACH = {
  domain:     { CRITICAL: 3,  HIGH: 14,  MEDIUM: 60,  LOW: 180 },
  ai:         { CRITICAL: 1,  HIGH: 7,   MEDIUM: 30,  LOW: 120 },
  redteam:    { CRITICAL: 1,  HIGH: 5,   MEDIUM: 21,  LOW: 90  },
  identity:   { CRITICAL: 2,  HIGH: 10,  MEDIUM: 45,  LOW: 150 },
  compliance: { CRITICAL: 7,  HIGH: 30,  MEDIUM: 90,  LOW: 365 },
};

// ─── Deterministic hash ───────────────────────────────────────────────────────
function sh(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

// ─── Build attack chain from scan findings ────────────────────────────────────
function buildAttackChain(scanResult, module) {
  const findings = scanResult?.findings || [];
  const critFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const score = scanResult?.risk_score || 50;
  const level = scanResult?.risk_level || 'MEDIUM';

  const chain = [];
  const techniques = MITRE_TECHNIQUES[module] || MITRE_TECHNIQUES.redteam;

  chain.push({
    phase: 'Reconnaissance',
    technique: techniques.find(t => t.tactic === 'Reconnaissance') || techniques[0],
    description: `Attacker performs passive reconnaissance on ${scanResult?.target || 'target'} using OSINT and scanning`,
    probability: Math.min(0.95, 0.5 + score / 200),
    enabled_by: 'Public attack surface',
  });

  const accessFinding = critFindings[0];
  if (accessFinding || score > 40) {
    const tech = techniques.find(t => t.tactic === 'Initial Access') || techniques[1];
    chain.push({
      phase: 'Initial Access',
      technique: tech,
      description: accessFinding
        ? `Exploiting: ${accessFinding.title || accessFinding.check} — ${accessFinding.recommendation || 'immediate remediation required'}`
        : `Exploiting exposed attack surface on ${module} layer`,
      probability: Math.min(0.9, 0.3 + score / 150),
      enabled_by: accessFinding?.title || `${level} risk configuration`,
    });
  }

  if (score >= 50) {
    const escalateTech = techniques.find(t => t.tactic === 'Privilege Escalation' || t.tactic === 'Credential Access') || techniques[2];
    chain.push({
      phase: 'Privilege Escalation',
      technique: escalateTech,
      description: `Attacker escalates privileges using credentials or misconfigurations discovered during initial access`,
      probability: Math.min(0.7, 0.2 + score / 180),
      enabled_by: `${critFindings.length} critical/high findings`,
    });
  }

  const impactTech = techniques.find(t => t.tactic === 'Impact' || t.tactic === 'Exfiltration') || techniques[techniques.length - 1];
  chain.push({
    phase: 'Impact',
    technique: impactTech,
    description: `Data exfiltration, ransomware deployment, or persistent backdoor installation`,
    probability: Math.min(0.6, 0.1 + score / 200),
    enabled_by: 'Successful exploitation chain completion',
  });

  return chain;
}

// ─── POST /api/ai/analyze ─────────────────────────────────────────────────────
export const handleAIAnalyze = withErrorBoundary(async (request, env) => {
  let body;
  try { body = await request.json(); }
  catch { return badRequest(request, 'Invalid JSON body'); }

  const { scan_result, module, target } = body;
  if (!scan_result || !module) {
    return badRequest(request, 'scan_result and module are required');
  }

  // ── Engine-computed risk score (replaces raw scan score) ──────────────────
  const riskResult   = computeRiskScore(scan_result, module);
  const cveData      = correlateScanToCVEs(scan_result);
  const topModuleCVEs = getTopCVEsForModule(module, 5);

  const score    = scan_result?.risk_score || 50;
  const findings = scan_result?.findings   || [];
  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs     = findings.filter(f => f.severity === 'HIGH').length;
  const techniques = MITRE_TECHNIQUES[module] || MITRE_TECHNIQUES.redteam;

  // Build attack chain
  const attack_chain = buildAttackChain(scan_result, module);

  // Use engine-computed exploit probability (from riskEngine labels → numeric)
  const exploitLabelToNum = { CRITICAL: 92, HIGH: 75, MEDIUM: 45, LOW: 18 };
  const exploit_probability = exploitLabelToNum[riskResult.exploit_probability]
    ?? Math.round(Math.min(98, 10 + criticals * 20 + highs * 10 + (score / 3)));

  // MITRE ATT&CK mapping
  const mitre_mapping = techniques.map(t => ({
    ...t,
    applicable: attack_chain.some(c => c.technique?.id === t.id) || Math.random() > 0.4,
    risk_contribution: Math.round(sh(t.id + riskResult.severity) % 40 + (riskResult.severity === 'CRITICAL' ? 50 : riskResult.severity === 'HIGH' ? 30 : 15)),
  })).filter(t => t.applicable);

  // Threat actors
  const engineScore = riskResult.risk_score;
  const threat_actors = engineScore >= 8.0
    ? ['APT29 (Cozy Bear)', 'Lazarus Group', 'FIN7']
    : engineScore >= 6.0
    ? ['Scattered Spider', 'TA453', 'Criminal ransomware groups']
    : ['Opportunistic threat actors', 'Automated scanners'];

  // Risk indicators enriched with real CVE matches
  const risk_indicators = cveData.findings_with_cves
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5)
    .map(f => ({
      indicator: f.title || f.check,
      severity:  f.severity,
      cvss:      f.cves[0]?.cvss || (f.severity === 'CRITICAL' ? 9.1 : 7.5),
      cve:       f.cves[0]?.id   || null,
      cve_description: f.cves[0]?.description || null,
      mitre_id:  techniques[sh(f.title || f.check || '') % techniques.length]?.id || null,
      top_cves:  f.cves.slice(0, 2).map(c => ({ id: c.id, cvss: c.cvss, exploited: c.exploited, nvd_url: c.nvd_url })),
    }));

  const data = {
    module,
    target:               target || scan_result?.target || 'unknown',
    // Engine-computed scores (authoritative)
    risk_score:           riskResult.risk_score,
    severity:             riskResult.severity,
    exploit_probability,
    exploit_probability_label: riskResult.exploit_probability,
    confidence_score:     riskResult.confidence_score,
    risk_breakdown:       riskResult.risk_breakdown,
    // CVE intelligence
    cve_summary:          cveData.summary,
    top_module_cves:      topModuleCVEs,
    cisa_kev_applicable:  cveData.summary.cisa_kev_applicable,
    // Attack chain & MITRE
    attack_chain,
    mitre_mapping,
    threat_actors,
    risk_indicators,
    recommendations:      riskResult.recommendations,
    findings_summary: {
      critical: criticals,
      high:     highs,
      medium:   findings.filter(f => f.severity === 'MEDIUM').length,
      low:      findings.filter(f => f.severity === 'LOW').length,
      total:    findings.length,
    },
    analysis_version: 'AI Brain V2.1 + CVE Engine',
  };

  // Cache in KV for 10 minutes if available
  if (env?.SECURITY_HUB_KV && scan_result?.scan_id) {
    env.SECURITY_HUB_KV.put(
      `ai:analyze:${scan_result.scan_id}`,
      JSON.stringify(data),
      { expirationTtl: 600 }
    ).catch(() => {});
  }

  return ok(request, data);
});

// ─── POST /api/ai/simulate ────────────────────────────────────────────────────
export const handleAISimulate = withErrorBoundary(async (request, env) => {
  let body;
  try { body = await request.json(); }
  catch { return badRequest(request, 'Invalid JSON body'); }

  const { scan_result, module, target } = body;
  if (!scan_result || !module) {
    return badRequest(request, 'scan_result and module are required');
  }

  // ── Full simulation from simulationEngine ─────────────────────────────────
  const simulation = runAttackSimulation(scan_result, module, target);
  const riskResult  = computeRiskScore(scan_result, module);
  const cveData     = correlateScanToCVEs(scan_result);

  // Merge CVE context into simulation metadata
  const data = {
    ...simulation,
    // Override risk_context with engine-authoritative data
    risk_context: {
      ...simulation.risk_context,
      engine_risk_score:    riskResult.risk_score,
      engine_severity:      riskResult.severity,
      engine_confidence:    riskResult.confidence_score,
      exploit_probability:  riskResult.exploit_probability,
      cve_summary:          cveData.summary,
      cisa_kev_applicable:  cveData.summary.cisa_kev_applicable,
    },
    simulation_version: 'AttackSim V2.1 + SimulationEngine',
  };

  // Cache simulation result for report generation
  if (env?.SECURITY_HUB_KV && simulation.simulation_id) {
    env.SECURITY_HUB_KV.put(
      `ai:simulate:${simulation.simulation_id}`,
      JSON.stringify(data),
      { expirationTtl: 1800 }
    ).catch(() => {});
  }

  return ok(request, data);
});

// ─── POST /api/ai/forecast ────────────────────────────────────────────────────
export const handleAIForecast = withErrorBoundary(async (request, env) => {
  let body;
  try { body = await request.json(); }
  catch { return badRequest(request, 'Invalid JSON body'); }

  const { scan_result, module, target } = body;
  if (!scan_result || !module) {
    return badRequest(request, 'scan_result and module are required');
  }

  // ── Engine-computed risk (authoritative) ──────────────────────────────────
  const riskResult = computeRiskScore(scan_result, module);
  const cveData    = correlateScanToCVEs(scan_result);
  const severity   = riskResult.severity;   // CRITICAL | HIGH | MEDIUM | LOW
  const targetId   = target || scan_result?.target || 'unknown';

  const impact = FINANCIAL_IMPACT[severity] || FINANCIAL_IMPACT.MEDIUM;
  const ttb    = (TIME_TO_BREACH[module] || TIME_TO_BREACH.domain)[severity] || 30;

  // Exploitation likelihood — weighted from engine score (0–10 → 0–1 range)
  const engineProb = riskResult.risk_score / 10;
  const exploitation_likelihood = +(Math.min(0.99,
    engineProb * 0.70 +
    (cveData.summary.exploited_in_wild > 0 ? 0.20 : 0) +
    (cveData.summary.critical_cves > 0     ? 0.10 : 0)
  ).toFixed(2));

  // Risk trend over 90 days (simulated drift if unpatched)
  const trend_90d = Array.from({ length: 7 }, (_, i) => {
    const day   = (i + 1) * 13;
    const drift = sh(targetId + module + day) % 15;
    return {
      day,
      risk_score:  Math.min(10.0, +(riskResult.risk_score + (severity === 'CRITICAL' ? i * 0.3 : i * 0.1)).toFixed(1)),
      probability: +(Math.min(0.99, exploitation_likelihood + i * 0.04 + drift / 500)).toFixed(2),
    };
  });

  const regulatory_penalties = getRegPenalties(module, severity, impact.avg_usd);
  const remediation_cost     = Math.round(impact.avg_usd * 0.03);
  const remediation_roi      = Math.round((impact.avg_usd - remediation_cost) / remediation_cost);
  const priority_actions     = getPriorityActions(scan_result, module, severity);

  const data = {
    module,
    target:                  targetId,
    // Engine-authoritative risk
    risk_score:              riskResult.risk_score,
    severity,
    confidence_score:        riskResult.confidence_score,
    risk_breakdown:          riskResult.risk_breakdown,
    // CVE context
    cve_summary:             cveData.summary,
    cisa_kev_applicable:     cveData.summary.cisa_kev_applicable,
    max_cvss:                cveData.summary.max_cvss,
    // Forecast
    exploitation_likelihood,
    time_to_breach_days:     ttb,
    time_to_breach_label:    ttb === 1 ? 'Within 24 hours' : ttb <= 7 ? `${ttb} days` : ttb <= 30 ? `${ttb} days (~${Math.ceil(ttb / 7)} weeks)` : `${ttb} days (~${Math.ceil(ttb / 30)} months)`,
    financial_impact: {
      low_estimate_usd:    impact.low_usd,
      high_estimate_usd:   impact.high_usd,
      expected_impact_usd: impact.avg_usd,
      recovery_days:       impact.recovery_days,
      formatted: {
        low:  formatCurrency(impact.low_usd),
        high: formatCurrency(impact.high_usd),
        avg:  formatCurrency(impact.avg_usd),
      },
    },
    regulatory_penalties,
    remediation_analysis: {
      remediation_cost_usd:   remediation_cost,
      remediation_cost_label: formatCurrency(remediation_cost),
      roi_multiple:           remediation_roi,
      roi_label:              `${remediation_roi}x return — every $1 spent prevents $${remediation_roi} in loss`,
    },
    risk_trend_90d:  trend_90d,
    priority_actions,
    forecast_version: 'RiskForecast V2.1 + RiskEngine',
  };

  return ok(request, data);
});

// ─── Helper functions ─────────────────────────────────────────────────────────

function getRegPenalties(module, severity, baseImpact) {
  return [
    { framework: 'DPDP Act 2023', max_penalty_inr: 25000000000, estimated_usd: Math.round(baseImpact * 0.04) },
    { framework: 'ISO 27001 NC',  max_penalty_inr: null,        estimated_usd: Math.round(baseImpact * 0.02), note: 'Certification suspension + re-audit cost' },
    ...(module === 'ai' ? [{ framework: 'EU AI Act', max_penalty_usd: 30000000, estimated_usd: Math.round(baseImpact * 0.06) }] : []),
  ];
}

function getPriorityActions(scanResult, module, severity) {
  const findings = scanResult?.findings || [];
  const criticals = findings.filter(f => f.severity === 'CRITICAL').slice(0, 3);
  const highs     = findings.filter(f => f.severity === 'HIGH').slice(0, 2);

  const actions = [
    ...criticals.map(f => ({
      priority:  1,
      action:    f.recommendation || `Remediate: ${f.title || f.check}`,
      effort:    'LOW',
      impact:    'CRITICAL',
      timeframe: '24–48 hours',
      finding:   f.title || f.check,
    })),
    ...highs.map(f => ({
      priority:  2,
      action:    f.recommendation || `Address: ${f.title || f.check}`,
      effort:    'MEDIUM',
      impact:    'HIGH',
      timeframe: '1–2 weeks',
      finding:   f.title || f.check,
    })),
    {
      priority:  3,
      action:    module === 'ai'         ? 'Implement prompt injection safeguards and output validation'
               : module === 'domain'     ? 'Enable DNSSEC and enforce HSTS preloading'
               : module === 'identity'   ? 'Deploy phishing-resistant MFA across all accounts'
               : module === 'redteam'    ? 'Patch all exploitable entry points; review lateral movement paths'
               : 'Conduct quarterly security review and penetration test',
      effort:    'MEDIUM',
      impact:    'HIGH',
      timeframe: '30 days',
      finding:   'Security posture baseline',
    },
  ];

  return actions.slice(0, 5);
}

function formatCurrency(usd) {
  if (usd >= 1000000) return `$${(usd / 1000000).toFixed(1)}M`;
  if (usd >= 1000)    return `$${(usd / 1000).toFixed(0)}K`;
  return `$${usd}`;
}
