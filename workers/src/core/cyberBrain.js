/**
 * CYBERDUDEBIVASH AI Security Hub — CyberBrain Core Orchestrator v20.0
 * ─────────────────────────────────────────────────────────────────────
 * This is the MASTER brain module. It is NOT a route handler itself — it is
 * the unified orchestration layer that enriches results from every scan type.
 *
 * Called by:
 *   • POST /api/scan/* (post-scan enrichment pipeline)
 *   • GET  /api/vulns  (vuln prioritization by exploitability + business impact)
 *   • POST /api/hunt   (hunt query recommendation engine)
 *   • POST /api/cyber-brain/analyze (direct CyberBrain invocation)
 *
 * The engine imports `runCyberBrainAnalysis` from the service layer and wraps
 * it with:
 *   1. Asset normalization (multi-source aggregation)
 *   2. Threat actor correlation from live threat feed
 *   3. MITRE ATT&CK heatmap generation
 *   4. Business impact scoring by sector + tier
 *   5. KV-backed result caching (15-minute TTL)
 *   6. Upsell signal injection (FREE tier → upgrade nudge)
 *
 * Output contract (guaranteed fields):
 * {
 *   riskScore:          number (0–100),
 *   riskLevel:          'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
 *   exploitProbability: number (0.0–1.0),
 *   attackPaths:        AttackPath[],
 *   threatActors:       ThreatActor[],
 *   recommendedActions: Action[],
 *   businessImpact:     BusinessImpact,
 *   mitreCoverage:      MITRECoverage,
 *   upsellSignal:       UpsellSignal | null,
 *   analyzed_at:        ISO8601,
 *   platform:           string,
 * }
 */

import { runCyberBrainAnalysis } from '../services/cyberBrainEngine.js';

// ─── Tier capabilities ────────────────────────────────────────────────────────
const TIER_LIMITS = {
  FREE:       { maxFindings: 10, maxVulns: 5,  attackPaths: 2, aiNarrative: false, deepActors: false },
  STARTER:    { maxFindings: 50, maxVulns: 25, attackPaths: 5, aiNarrative: true,  deepActors: false },
  PRO:        { maxFindings: 200, maxVulns: 100, attackPaths: 10, aiNarrative: true, deepActors: true },
  ENTERPRISE: { maxFindings: Infinity, maxVulns: Infinity, attackPaths: 20, aiNarrative: true, deepActors: true },
};

// ─── Sector risk multipliers ──────────────────────────────────────────────────
const SECTOR_MULTIPLIERS = {
  finance:        1.5,
  healthcare:     1.4,
  government:     1.4,
  critical_infra: 1.6,
  technology:     1.2,
  education:      1.0,
  retail:         1.1,
  default:        1.0,
};

// ─── Upsell signal generator ──────────────────────────────────────────────────
function buildUpsellSignal(riskScore, tier, findingsCount) {
  if (tier !== 'FREE' && tier !== 'STARTER') return null;

  if (riskScore >= 80 && tier === 'FREE') {
    return {
      trigger:     'high_risk',
      message:     '⚠️ Critical risk detected. Upgrade to PRO for AI-powered remediation + executive report.',
      cta:         'Upgrade to PRO',
      plan:        'PRO',
      price_inr:   999,
      urgency:     'critical',
      route:       '/pricing#pro',
    };
  }
  if (findingsCount > 8 && tier === 'FREE') {
    return {
      trigger:     'finding_limit',
      message:     `🔒 ${findingsCount} findings detected — FREE plan shows top 10. Unlock all with STARTER.`,
      cta:         'Upgrade to STARTER',
      plan:        'STARTER',
      price_inr:   199,
      urgency:     'medium',
      route:       '/pricing#starter',
    };
  }
  if (riskScore >= 60 && tier === 'STARTER') {
    return {
      trigger:     'pro_upsell',
      message:     '🚀 PRO unlocks AI attack simulation, dark web monitoring + MITRE heatmap.',
      cta:         'Upgrade to PRO',
      plan:        'PRO',
      price_inr:   999,
      urgency:     'low',
      route:       '/pricing#pro',
    };
  }
  return null;
}

// ─── Normalize findings from any scan module ──────────────────────────────────
export function normalizeScanFindings(rawFindings, module = 'domain') {
  if (!Array.isArray(rawFindings)) return [];
  return rawFindings.map(f => ({
    title:       f.title       || f.name    || f.check   || f.id     || 'Unknown Finding',
    description: f.description || f.detail  || f.message || f.info   || '',
    severity:    normalizeSeverity(f.severity || f.risk || f.level || 'MEDIUM'),
    category:    f.category    || f.type    || module,
    in_kev:      f.in_kev      || f.kev     || false,
    epss:        parseFloat(f.epss || f.epss_score || 0),
    cve:         f.cve         || f.cve_id  || null,
    cvss:        parseFloat(f.cvss || f.cvss_score || 0),
    has_exploit: f.has_exploit || f.public_exploit || f.exploit_available || false,
    external:    f.external    || f.internet_facing || false,
    remediation: f.remediation || f.fix     || f.recommendation || null,
  }));
}

function normalizeSeverity(raw) {
  const s = String(raw).toUpperCase();
  if (s === 'CRITICAL' || s === '4' || s === 'P0') return 'CRITICAL';
  if (s === 'HIGH'     || s === '3' || s === 'P1') return 'HIGH';
  if (s === 'MEDIUM'   || s === '2' || s === 'P2') return 'MEDIUM';
  return 'LOW';
}

// ─── Master orchestration entry point ────────────────────────────────────────
/**
 * enrichScanWithBrain()
 * Called automatically after every scan to inject CyberBrain intelligence.
 *
 * @param {object} env           - Cloudflare Worker env bindings
 * @param {object} scanResult    - raw scan output (domain, AI, redteam, identity)
 * @param {string} module        - scan module name
 * @param {string} target        - target identifier (domain, IP, etc.)
 * @param {string} tier          - user subscription tier
 * @param {string} sector        - industry sector (default: 'technology')
 * @returns {object}             - enriched scan result with CyberBrain overlay
 */
export async function enrichScanWithBrain(env, scanResult, {
  module = 'domain',
  target = '',
  tier   = 'FREE',
  sector = 'technology',
} = {}) {
  try {
    const limits   = TIER_LIMITS[tier] || TIER_LIMITS.FREE;
    const multiplier = SECTOR_MULTIPLIERS[sector] || SECTOR_MULTIPLIERS.default;

    // Normalize findings from any module's output shape
    const rawFindings = scanResult?.findings
      || scanResult?.checks
      || scanResult?.vulnerabilities
      || scanResult?.results
      || [];

    const findings = normalizeScanFindings(rawFindings, module).slice(0, limits.maxFindings);
    const vulns    = (scanResult?.cves || scanResult?.vulns || []).slice(0, limits.maxVulns);
    const assets   = {
      external:   scanResult?.external_facing ?? true,
      domain:     target,
      open_ports: scanResult?.open_ports || [],
      services:   scanResult?.services   || [],
    };

    // Run CyberBrain analysis
    const brain = await runCyberBrainAnalysis(env, {
      findings, vulns, assets, sector,
      tier, target, module,
    });

    // Apply sector multiplier to riskScore
    const adjustedScore = Math.min(100, Math.round(brain.riskScore * multiplier));
    const upsellSignal  = buildUpsellSignal(adjustedScore, tier, rawFindings.length);

    return {
      ...scanResult,
      cyber_brain: {
        ...brain,
        riskScore:          adjustedScore,
        sector_multiplier:  multiplier,
        tier_limits_applied: tier,
        upsell:             upsellSignal,
        attack_paths:       limits.attackPaths
          ? brain.attackPaths?.slice(0, limits.attackPaths)
          : brain.attackPaths,
      },
    };
  } catch (err) {
    // Never crash the scan pipeline — CyberBrain overlay is additive
    console.error('[CyberBrain] Enrichment error:', err?.message);
    return scanResult;
  }
}

// ─── Vuln prioritization helper ───────────────────────────────────────────────
/**
 * prioritizeVulns()
 * Sorts vulnerabilities by CyberBrain composite score:
 *   CVSS × EPSS × KEV_multiplier × exploit_multiplier
 * Used by /api/vulns to return ranked vuln list.
 */
export function prioritizeVulns(vulns = [], tier = 'FREE') {
  const limits = TIER_LIMITS[tier] || TIER_LIMITS.FREE;
  return vulns
    .map(v => {
      const cvss     = parseFloat(v.cvss || v.cvss_score || 5.0);
      const epss     = parseFloat(v.epss || v.epss_score || 0.1);
      const kevMult  = v.in_kev    ? 2.5 : 1.0;
      const exploitM = v.has_exploit ? 1.8 : 1.0;
      const score    = Math.min(100, Math.round(cvss * 10 * epss * kevMult * exploitM));
      return { ...v, brain_priority_score: score };
    })
    .sort((a, b) => b.brain_priority_score - a.brain_priority_score)
    .slice(0, limits.maxVulns);
}

// ─── Hunt recommendation helper ───────────────────────────────────────────────
/**
 * recommendHuntQueries()
 * Given a target and sector, returns recommended hunt queries.
 * Used to enrich /api/hunt responses.
 */
export function recommendHuntQueries(sector = 'technology', riskScore = 50) {
  const base = [
    { query: 'process where process.name == "powershell.exe" and process.args contains "-enc"', technique: 'T1059.001', priority: 'HIGH' },
    { query: 'network where destination.port in (4444, 1234, 8080) and process.name != "chrome.exe"', technique: 'T1071',     priority: 'HIGH' },
    { query: 'file where file.extension in (".exe", ".dll") and file.path contains "\\Temp\\"',        technique: 'T1036',     priority: 'MEDIUM' },
    { query: 'auth where event.outcome == "failure" and source.ip != "192.168.*"',                    technique: 'T1110',     priority: 'MEDIUM' },
    { query: 'registry where registry.path contains "\\Run\\" and process.name != "setup.exe"',       technique: 'T1547',     priority: 'MEDIUM' },
  ];

  const sectorSpecific = {
    finance: [
      { query: 'process where process.name in ("wscript.exe","cscript.exe") and parent.name == "OUTLOOK.EXE"', technique: 'T1566.001', priority: 'CRITICAL' },
    ],
    healthcare: [
      { query: 'file where file.name contains "patient" and process.name not in ("ehr.exe","meditech.exe")', technique: 'T1005', priority: 'CRITICAL' },
    ],
    government: [
      { query: 'network where dns.question.name ends_with ".onion" or dns.question.name ends_with ".i2p"', technique: 'T1090', priority: 'CRITICAL' },
    ],
  };

  const extra = sectorSpecific[sector] || [];
  const all   = [...base, ...extra];

  // Boost critical queries when risk is high
  return riskScore >= 70
    ? all.sort((a, b) => (b.priority === 'CRITICAL' ? 1 : 0) - (a.priority === 'CRITICAL' ? 1 : 0))
    : all;
}

// ─── Executive summary builder ────────────────────────────────────────────────
/**
 * buildExecutiveSummary()
 * Produces a CEO-level one-paragraph summary from CyberBrain output.
 */
export function buildExecutiveSummary(brainResult, target = '') {
  const { riskScore, riskLevel, attackPaths, recommendedActions, businessImpact } = brainResult;

  const topAction = recommendedActions?.[0]?.action || 'patch critical vulnerabilities immediately';
  const topPath   = attackPaths?.[0]?.name          || 'network exploitation';
  const impact    = businessImpact?.label            || 'significant business disruption';
  const rev       = businessImpact?.revenue_impact   || 'unknown';

  return {
    headline: `${riskLevel} Risk — ${target || 'Target'} scored ${riskScore}/100`,
    summary: `${target || 'The target'} presents a ${riskLevel.toLowerCase()} risk posture with a composite score of ${riskScore}/100. ` +
             `The most likely attack vector is ${topPath}. Business impact assessment indicates ${impact} ` +
             `with estimated revenue exposure of ${rev}. ` +
             `Immediate priority: ${topAction}.`,
    top_attack_path:   topPath,
    top_action:        topAction,
    estimated_impact:  impact,
    revenue_exposure:  rev,
    risk_score:        riskScore,
    risk_level:        riskLevel,
  };
}
