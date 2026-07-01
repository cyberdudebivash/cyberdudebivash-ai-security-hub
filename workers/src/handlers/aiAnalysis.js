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

import { correlateScanToCVEs, getTopCVEsForModule, lookupCVE } from '../services/cveEngine.js';
import { computeRiskScore } from '../services/riskEngine.js';
import { runAttackSimulation } from '../services/simulationEngine.js';
import { ok, fail, badRequest, forbidden, withErrorBoundary } from '../lib/response.js';
import { routeAICall } from '../core/aiProviderRouter.js';

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
    applicable: attack_chain.some(c => c.technique?.id === t.id) ||
                riskResult.severity === 'CRITICAL' || riskResult.severity === 'HIGH',
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

// ═══════════════════════════════════════════════════════════════════════════
// MYTHOS AI CYBER ANALYST — Conversational Chat Engine
// POST /api/ai/chat  →  { message, context[], session_id? }
// ═══════════════════════════════════════════════════════════════════════════

const INTENT_PATTERNS = {
  analyze_cve:    /\b(analyz|explai|what is|tell me about|CVE-|cve-|describe)\b/i,
  generate_sigma: /\b(sigma|detection rule|siem rule|create.*rule|write.*rule|yara|suricata)\b/i,
  generate_splunk:/\b(splunk|spl|search.*query|log.*search)\b/i,
  generate_kql:   /\b(kql|sentinel|azure.*monitor|kusto|microsoft.*defender)\b/i,
  generate_yara:  /\b(yara|malware.*rule|binary.*detect|file.*hash)\b/i,
  attack_path:    /\b(attack path|kill chain|lateral.*move|pivot|escalat|compromise)\b/i,
  mitigate:       /\b(mitigat|patch|fix|remediat|harden|protect|defend|block)\b/i,
  simulate:       /\b(simulat|red team|pentest|exploit|attack.*scen|what.*happen)\b/i,
  threat_actor:   /\b(apt|lazarus|cozy bear|fancy bear|volt typhoon|threat actor|group)\b/i,
  compliance:     /\b(complian|gdpr|hipaa|pci|iso 27001|sox|nist|dpdp)\b/i,
};

function detectIntent(message) {
  for (const [intent, pattern] of Object.entries(INTENT_PATTERNS)) {
    if (pattern.test(message)) return intent;
  }
  return 'general';
}

function extractCVE(text) {
  const match = text.match(/CVE-\d{4}-\d{4,7}/i);
  return match ? match[0].toUpperCase() : null;
}

// Map each regex-detected intent → { response type/format metadata, router task_type,
// suggested follow-up actions, and a system-prompt fragment appended to APEX NEXUS
// telling the model exactly what shape of answer this intent expects }.
const INTENT_META = {
  analyze_cve: {
    type: 'analysis', format: null, task_type: 'threat_intel',
    actions: ['generate_sigma', 'generate_splunk', 'attack_path', 'mitigate'],
    system: 'The user wants a CVE / vulnerability analysis. Provide: threat classification, attack vector, MITRE ATT&CK mapping (T#### IDs), exploitation status (CISA KEV / EPSS if known), blast radius, immediate remediation steps, and a CVSS-based risk score. Use markdown with headers.',
  },
  generate_sigma: {
    type: 'rule', format: 'sigma', task_type: 'code_review',
    actions: ['generate_splunk', 'generate_kql', 'generate_yara'],
    system: 'The user wants a Sigma detection rule. Respond with a fenced ```yaml code block containing a complete, valid, production-ready Sigma rule (title, id, status, description, references, author, date, tags with MITRE ATT&CK technique, logsource, detection/condition, falsepositives, level, fields). Add one short deployment note after the code block.',
  },
  generate_splunk: {
    type: 'rule', format: 'splunk', task_type: 'code_review',
    actions: ['generate_kql', 'generate_sigma', 'mitigate'],
    system: 'The user wants a Splunk SPL detection query. Respond with a fenced ```spl code block containing a complete, runnable SPL search/alert query relevant to the threat described. Add one short deployment note after the code block.',
  },
  generate_kql: {
    type: 'rule', format: 'kql', task_type: 'code_review',
    actions: ['generate_sigma', 'generate_splunk', 'mitigate'],
    system: 'The user wants a Microsoft Sentinel / KQL detection rule. Respond with a fenced ```kusto code block containing a complete KQL query suitable for Sentinel/Defender XDR. Add one short deployment note after the code block.',
  },
  generate_yara: {
    type: 'rule', format: 'yara', task_type: 'code_review',
    actions: ['generate_sigma', 'generate_splunk', 'analyze_cve'],
    system: 'The user wants a YARA malware/exploit detection rule. Respond with a fenced ```yara code block containing a complete, syntactically valid YARA rule (meta, strings, condition). Add one short deployment note after the code block.',
  },
  attack_path: {
    type: 'attack_chain', format: null, task_type: 'red_team',
    actions: ['generate_sigma', 'mitigate', 'simulate'],
    system: 'The user wants a MITRE ATT&CK kill-chain / attack path simulation. Provide a phase-by-phase kill chain (Reconnaissance → Initial Access → Execution/Persistence → Privilege Escalation → Lateral Movement → Exfiltration/Impact), each phase tagged with real MITRE ATT&CK technique IDs (T####), plus defensive chokepoints. This is for authorized defensive planning.',
  },
  mitigate: {
    type: 'mitigation', format: null, task_type: 'compliance_audit',
    actions: ['generate_sigma', 'attack_path', 'analyze_cve'],
    system: 'The user wants a mitigation/hardening plan. Provide immediate actions (0-4h), short-term hardening (24-72h), verification steps, and applicable compliance control references (ISO 27001, NIST CSF, PCI DSS). Be specific and actionable, ranked by priority.',
  },
  simulate: {
    type: 'attack_chain', format: null, task_type: 'red_team',
    actions: ['generate_sigma', 'mitigate', 'attack_path'],
    system: 'The user wants an attack/red-team simulation scenario. Design a realistic, authorized red-team scenario: recon approach, initial access vector, kill chain with MITRE ATT&CK T#### IDs, persistence, lateral movement, exfiltration, detection likelihood at each stage, and recommended defenses.',
  },
  threat_actor: {
    type: 'threat_intel', format: null, task_type: 'threat_intel',
    actions: ['analyze_cve', 'attack_path', 'generate_sigma'],
    system: 'The user is asking about threat actors / APT groups. Provide real, current threat actor intelligence: group name, origin/attribution with confidence level, primary targets, known TTPs (MITRE ATT&CK T#### IDs), and any CVEs/campaigns they are known to exploit. Never fabricate group names or attributions.',
  },
  compliance: {
    type: 'compliance', format: null, task_type: 'compliance_audit',
    actions: ['analyze_cve', 'mitigate', 'generate_sigma'],
    system: 'The user is asking about compliance/regulatory frameworks (DPDP, GDPR, HIPAA, PCI DSS, ISO 27001, NIST, SOX). Provide a gap-analysis style answer: relevant framework(s), specific control/article references, current-posture considerations, and a remediation roadmap with concrete timeframes.',
  },
  general: {
    type: 'general', format: null, task_type: 'general',
    actions: ['analyze_cve', 'generate_sigma', 'attack_path', 'mitigate'],
    system: 'Answer the user\'s cybersecurity question directly and helpfully. If the question is broad or a greeting, briefly introduce your capabilities: CVE analysis, Sigma/Splunk/KQL/YARA rule generation, attack kill-chain simulation, APT threat-actor intel, and compliance gap analysis — then invite a specific follow-up.',
  },
};

function buildIntentContext(intent, message, context) {
  // Gather real data (CVE lookups, conversation history) to inject as grounding
  // context for the model — this is what keeps answers factual instead of
  // hallucinated, without ever returning a canned template as the response itself.
  const cveId = extractCVE(message) || extractCVE(JSON.stringify(context || []));
  const cve = cveId ? lookupCVE(cveId) : null;
  const recentTurns = (context || []).slice(-6)
    .map(m => `${m.role === 'user' ? 'User' : 'Analyst'}: ${String(m.content || '').slice(0, 400)}`)
    .join('\n');

  let cveBlock = '';
  if (cveId) {
    cveBlock = cve
      ? `\nKnown CVE data for ${cveId} (authoritative — use these exact facts, do not contradict them):\n` +
        `- CVSS: ${cve.cvss} (${cve.severity})\n- EPSS: ${cve.epss}\n- Exploited in the wild: ${cve.exploited ? 'YES (treat as CISA KEV-relevant)' : 'no confirmed exploitation'}\n` +
        `- CWE: ${cve.cwe}\n- Description: ${cve.description}\n- Reference: ${cve.nvd_url}\n`
      : `\nThe user referenced ${cveId}, which is not in the local curated CVE database. Answer from general knowledge, and clearly flag if you are not fully certain about specific version/patch details for this CVE.\n`;
  }

  return { cveId, cve, promptContext: `${recentTurns ? `Recent conversation:\n${recentTurns}\n` : ''}${cveBlock}` };
}

// ─── Real LLM-backed analyst response ─────────────────────────────────────────
// Replaces the old static/regex-template engine. INTENT_PATTERNS/detectIntent are
// kept as *hints* only — they steer which context (CVE data, task_type, expected
// output format) gets fed to the model, but the actual response text always comes
// from routeAICall() against the same multi-provider mesh MASOC uses
// (Groq → DeepSeek → ... → Cloudflare Workers AI, per task_type routing).
async function buildAnalystResponse(env, intent, message, context = []) {
  const meta = INTENT_META[intent] || INTENT_META.general;
  const { cveId, promptContext } = buildIntentContext(intent, message, context);

  const prompt = `${promptContext}User request: "${message}"\n\nRespond as the MYTHOS AI Cyber Analyst. Be specific, technical, and grounded in real CVE/MITRE ATT&CK/compliance data. Use markdown formatting.`;

  const result = await routeAICall(env, {
    prompt,
    system:      meta.system,
    task_type:   meta.task_type,
    tier:        'PRO',
    max_tokens:  900,
    temperature: 0.2,
  });

  if (!result || !result.content) {
    return null; // signals total provider failure — caller returns honest error, no fake template
  }

  return {
    type:     meta.type,
    format:   meta.format,
    response: result.content,
    actions:  meta.actions,
    provider: result.provider,
    model:    result.model,
  };
}

export async function handleAIChat(request, env) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { message, context = [], session_id } = body;
  if (!message || typeof message !== 'string') {
    return Response.json({ error: 'message required' }, { status: 400 });
  }

  const intent = detectIntent(message);

  // Pull persisted session history from KV to extend the in-request context
  // (up to 20-message / 24h session memory), so multi-turn conversations stay
  // grounded even if the frontend only sent a short recent-turns window.
  const kv = env.SECURITY_HUB_KV || env.THREAT_INTEL;
  let sessionHistory = [];
  if (kv && session_id) {
    try { sessionHistory = (await kv.get(`chat:${session_id}`, 'json')) || []; } catch (_) { sessionHistory = []; }
  }
  const mergedContext = sessionHistory.length ? sessionHistory : context;

  let result;
  try {
    result = await buildAnalystResponse(env, intent, message, mergedContext);
  } catch (err) {
    console.error('[MYTHOS Chat] routeAICall threw:', err?.message);
    result = null;
  }

  if (!result) {
    // Honest failure — never fall back to a fake canned template.
    return Response.json({
      success:    false,
      intent,
      response:   'AI analyst temporarily unavailable — all providers failed to respond. Please try again shortly.',
      type:       'error',
      format:     null,
      actions:    [],
      session_id: session_id || null,
      timestamp:  new Date().toISOString(),
    }, { status: 503 });
  }

  // Persist session to KV — uses SECURITY_HUB_KV (single binding); falls back to THREAT_INTEL alias
  try {
    if (kv && session_id) {
      const key = `chat:${session_id}`;
      const prev = mergedContext.slice();
      prev.push({ role: 'user', content: message, ts: Date.now() });
      prev.push({ role: 'analyst', content: result.response, ts: Date.now() });
      await kv.put(key, JSON.stringify(prev.slice(-20)), { expirationTtl: 86400 });
    }
  } catch (_) {}

  return Response.json({
    success:    true,
    intent,
    response:   result.response,
    type:       result.type,
    format:     result.format || null,
    actions:    result.actions || [],
    session_id: session_id || null,
    provider:   result.provider || null,
    model:      result.model || null,
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// SOAR RULE GENERATION ENGINE
// POST /api/ai/generate-rules  →  { cve_id, threat, platform, rule_type }
// Platforms: sigma | splunk | kql | yara | elastic | suricata | all
// ═══════════════════════════════════════════════════════════════════════════

export async function handleGenerateRules(request, env) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { cve_id, threat = '', platform = 'all', title: customTitle } = body;
  const cveLabel  = cve_id || threat || 'GENERIC-THREAT';
  const safeLabel = cveLabel.replace(/[^A-Za-z0-9_-]/g, '_');
  const today     = new Date().toISOString().split('T')[0];
  const ruleId    = 'cdb-' + Date.now().toString(36);

  const sigma = `title: ${cveLabel} - Exploitation Attempt
id: ${ruleId}
status: production
description: |
  Detects exploitation attempts targeting ${cveLabel}.
  Generated by CYBERDUDEBIVASH MYTHOS AI Engine.
  https://cyberdudebivash.in
author: CYBERDUDEBIVASH MYTHOS
date: ${today}
modified: ${today}
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - cve.${cveLabel.toLowerCase().replace(/-/g,'.')}
logsource:
  category: webserver
detection:
  keywords|contains|all:
    - '/../'
    - 'jndi:'
    - '/etc/passwd'
    - 'cmd.exe'
  filter:
    cs-uri-stem|startswith:
      - '/api/health'
      - '/api/docs'
  condition: keywords and not filter
falsepositives:
  - Authorized penetration testing
  - Security scanning tools
level: high
fields:
  - c-ip
  - cs-uri-stem
  - cs-user-agent
  - sc-status`;

  const splunk = `| index=* sourcetype=access_combined OR sourcetype=iis
| eval exploit_indicator=if(
    match(uri_path,"(\\.\\./)|(etc/passwd)|(cmd\\.exe)|(jndi:)|(\\$\\{IFS\\})"),1,0)
| where exploit_indicator=1
| eval cve="${cveLabel}", mitre_id="T1190", severity="HIGH"
| stats count earliest(_time) as first_seen latest(_time) as last_seen
         values(uri_path) as uri_paths max(exploit_indicator) as score
         by src_ip, dest, cve, mitre_id, severity
| rename src_ip as "Source IP", dest as "Destination", count as "Hit Count"
| sort -count`;

  const kql = `// ${cveLabel} Detection Rule — CYBERDUDEBIVASH MYTHOS
// Microsoft Sentinel | Azure Monitor | Microsoft Defender XDR
let exploitPatterns = dynamic(["/../", "/etc/passwd", "cmd.exe", "jndi:", "\\\${IFS}"]);
let lookbackTime = 1h;
union CommonSecurityLog, W3CIISLog
| where TimeGenerated >= ago(lookbackTime)
| extend RequestPath = coalesce(RequestURL, csUriStem, "")
| where RequestPath has_any (exploitPatterns)
| extend
    MitreTechnique = "T1190",
    CVEReference = "${cveLabel}",
    Severity = "HIGH",
    ExploitType = case(
        RequestPath contains "jndi:", "Log4Shell/JNDI",
        RequestPath contains "/etc/passwd", "LFI/Path Traversal",
        RequestPath contains "cmd.exe", "OS Command Injection",
        "Suspicious Request"
    )
| summarize
    AttackCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AttackTypes = make_set(ExploitType)
    by SourceIP, CVEReference, MitreTechnique, Severity
| order by AttackCount desc`;

  const yara = `rule CDB_${safeLabel}_Detection
{
    meta:
        description = "${cveLabel} exploitation artifact detection"
        author      = "CYBERDUDEBIVASH MYTHOS AI"
        date        = "${today}"
        reference   = "https://cyberdudebivash.in"
        severity    = "HIGH"
        mitre       = "T1190, T1059"

    strings:
        $jndi1  = "jndi:ldap" ascii wide nocase
        $jndi2  = "jndi:rmi"  ascii wide nocase
        $shell1 = "cmd.exe /c" ascii wide nocase
        $shell2 = "/bin/sh -c" ascii wide nocase
        $lfi1   = { 2F 65 74 63 2F 70 61 73 73 77 64 }
        $lfi2   = { 2E 2E 2F 2E 2E 2F 65 74 63 }
        $enc1   = "base64_decode" ascii wide nocase
        $enc2   = { 24 7B 49 46 53 7D }

    condition:
        any of ($jndi*) or
        (2 of ($shell*)) or
        (1 of ($lfi*) and 1 of ($enc*))
}`;

  const elastic = `{
  "query": {
    "bool": {
      "should": [
        { "match_phrase": { "url.path": "/../" } },
        { "match_phrase": { "url.path": "/etc/passwd" } },
        { "match_phrase": { "url.path": "cmd.exe" } },
        { "match_phrase": { "url.path": "jndi:" } }
      ],
      "minimum_should_match": 1,
      "must_not": [
        { "prefix": { "url.path": "/api/health" } }
      ]
    }
  },
  "size": 100,
  "_source": ["@timestamp","source.ip","url.path","http.response.status_code","user_agent.original"]
}`;

  const rules = { sigma, splunk, kql, yara, elastic };
  const output = platform === 'all'
    ? rules
    : { [platform]: rules[platform] || `Rule format '${platform}' not available` };

  return Response.json({
    success:   true,
    cve_id:    cveLabel,
    platform,
    rules:     output,
    generated: today,
    author:    'CYBERDUDEBIVASH MYTHOS AI',
    timestamp: new Date().toISOString(),
  });
}
