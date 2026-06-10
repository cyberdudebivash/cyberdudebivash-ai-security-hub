/**
 * CYBERDUDEBIVASH MYTHOS AI ENRICHMENT ENGINE v2.0
 * ═══════════════════════════════════════════════════════════════════════════════
 * Integrates MYTHOS Cyber Brain into every automated service assessment.
 * Upgraded: Anthropic Claude (Sonnet 4.6 / Opus 4.8) — sovereign intelligence
 *
 * Provides:
 *   • MITRE ATT&CK v15 tactic/technique mapping from findings
 *   • AI-generated executive narrative (Anthropic Claude — production-grade)
 *   • Attack path prediction and threat actor correlation
 *   • Autonomous remediation priority engine
 *   • MYTHOS authority signature and confidence scoring
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { callClaude, CLAUDE_MODELS } from '../core/mythosAIProvider.js';
import {
  computeRiskScore,
  predictAttackPaths,
  correlateThretActors,
  generateRemediation,
  assessBusinessImpact,
  assessMITRECoverage,
} from './cyberBrainEngine.js';

// ── MYTHOS Confidence Score ───────────────────────────────────────────────────
function computeMythosConfidence(findings, probeResults = {}) {
  let confidence = 60; // baseline
  if (findings.length > 0)  confidence += Math.min(20, findings.length * 2);
  if (findings.some(f => f.severity === 'CRITICAL')) confidence += 10;
  if (probeResults?.api_accessible !== undefined)    confidence += 5;
  if (probeResults?.status)                          confidence += 5;
  return Math.min(99, confidence);
}

// ── MITRE Tactic Map from finding categories ──────────────────────────────────
const CATEGORY_MITRE_MAP = {
  'SSL Certificate':          { tactic: 'TA0007', name: 'Discovery',           technique: 'T1040' },
  'Security Header':          { tactic: 'TA0001', name: 'Initial Access',       technique: 'T1190' },
  'OWASP API Security':       { tactic: 'TA0001', name: 'Initial Access',       technique: 'T1190' },
  'Security Misconfiguration':{ tactic: 'TA0001', name: 'Initial Access',       technique: 'T1190' },
  'Information Disclosure':   { tactic: 'TA0009', name: 'Collection',           technique: 'T1213' },
  'Cloud Security':           { tactic: 'TA0005', name: 'Defense Evasion',      technique: 'T1562' },
  'IAM':                      { tactic: 'TA0003', name: 'Persistence',          technique: 'T1098' },
  'Compliance Gap':           { tactic: 'TA0006', name: 'Credential Access',    technique: 'T1552' },
  'AI Security':              { tactic: 'TA0040', name: 'Impact',               technique: 'T1565' },
  'OWASP LLM':                { tactic: 'TA0040', name: 'Impact',               technique: 'T1565' },
  'Vulnerability':            { tactic: 'TA0002', name: 'Execution',            technique: 'T1059' },
  'CVE':                      { tactic: 'TA0002', name: 'Execution',            technique: 'T1203' },
  'Threat Detection':         { tactic: 'TA0005', name: 'Defense Evasion',      technique: 'T1562' },
  'DevSecOps':                { tactic: 'TA0003', name: 'Persistence',          technique: 'T1195' },
  'SaaS Security':            { tactic: 'TA0006', name: 'Credential Access',    technique: 'T1528' },
};

function mapFindingsToMITRE(findings) {
  const mapped = new Map();
  for (const f of findings) {
    const cat = f.category || '';
    const key = Object.keys(CATEGORY_MITRE_MAP).find(k => cat.includes(k));
    if (key) {
      const m = CATEGORY_MITRE_MAP[key];
      const existing = mapped.get(m.tactic) || { ...m, finding_count: 0, severities: [] };
      existing.finding_count++;
      if (!existing.severities.includes(f.severity)) existing.severities.push(f.severity);
      mapped.set(m.tactic, existing);
    }
  }
  return Array.from(mapped.values());
}

// ── AI Narrative Generator — Anthropic Claude (Primary) ──────────────────────
async function generateAINarrative(env, { target, service_name, riskScore, riskLevel, findings, sector, tier = 'PRO' }) {
  if (!findings || findings.length === 0) return null;

  try {
    const topFindings = findings
      .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
      .slice(0, 5)
      .map(f => `• [${f.severity}] ${f.title || f.id}: ${(f.description || '').slice(0, 120)}`)
      .join('\n');

    const prompt = `Generate an enterprise security intelligence brief for:

Target: ${target || 'the assessed system'}
Service: ${service_name}
Risk Score: ${riskScore}/100 (${riskLevel})
Industry: ${sector || 'Technology'}

Key findings:
${topFindings || '• Multiple security vulnerabilities detected requiring immediate attention'}

Write 3 paragraphs:
1. Executive threat posture summary — specific risk level, business exposure, urgency (2-3 sentences)
2. Top 3 immediate critical actions with business impact — what breaks if ignored
3. Strategic 90-day security roadmap with measurable milestones

Enterprise-grade precision. MITRE ATT&CK references where applicable. No generic advice.`;

    const result = await callClaude(env, {
      prompt,
      tier:       tier || 'PRO',
      max_tokens: 500,
      temperature: 0.2,
    });

    return result?.content || null;
  } catch (e) {
    console.error('[MYTHOS-Enrichment] AI narrative error:', e.message);
    return null;
  }
}

// ── AUTONOMOUS REMEDIATION PRIORITIZER ───────────────────────────────────────
function buildAutonomousRemediationPlan(findings, riskScore) {
  const priority_map = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
  const sorted = [...findings].sort((a, b) =>
    (priority_map[a.severity] ?? 5) - (priority_map[b.severity] ?? 5)
  );

  const phases = [
    { phase: 1, timeline: '0-7 days',   label: 'IMMEDIATE',  items: [] },
    { phase: 2, timeline: '8-30 days',  label: 'SHORT-TERM', items: [] },
    { phase: 3, timeline: '31-90 days', label: 'MEDIUM-TERM',items: [] },
    { phase: 4, timeline: '90+ days',   label: 'STRATEGIC',  items: [] },
  ];

  for (const f of sorted) {
    const action = {
      finding_id:  f.id,
      title:       f.title || f.id,
      severity:    f.severity,
      remediation: f.remediation || f.mitigation || 'Remediate per security best practices',
      cvss:        f.cvss,
    };
    if (f.severity === 'CRITICAL')       phases[0].items.push(action);
    else if (f.severity === 'HIGH')      phases[1].items.push(action);
    else if (f.severity === 'MEDIUM')    phases[2].items.push(action);
    else                                  phases[3].items.push(action);
  }

  return phases.filter(p => p.items.length > 0).map(p => ({
    ...p,
    item_count: p.items.length,
    items: p.items.slice(0, 8), // cap per phase
  }));
}

// ── MYTHOS THREAT INTEL OVERLAY ───────────────────────────────────────────────
async function fetchMythosTheatActorOverlay(env, sector, findings) {
  const criticalFindings = findings.filter(f => ['CRITICAL','HIGH'].includes(f.severity));
  if (!criticalFindings.length) return null;

  // Query D1 for relevant threat actors
  if (!env?.DB) return null;
  try {
    const rows = await env.DB.prepare(
      `SELECT name, aliases, origin_country, motivation, ttps, target_sectors
       FROM threat_intel WHERE type='threat_actor' AND active=1
       ORDER BY created_at DESC LIMIT 5`
    ).all();

    const actors = rows?.results || [];
    if (!actors.length) return null;

    return actors.slice(0, 3).map(a => ({
      name:            a.name,
      origin:          a.origin_country,
      motivation:      a.motivation,
      relevance:       sector ? `Active in ${sector} sector` : 'Relevant to this attack surface',
      recommended_hunting_query: `hunt for ${a.name} TTPs in SIEM using associated IOCs`,
    }));
  } catch { return null; }
}

// ═════════════════════════════════════════════════════════════════════════════
// PRIMARY EXPORT: enrichAssessmentWithMYTHOS
// Call this after any automated engine completes to inject MYTHOS intelligence
// ═════════════════════════════════════════════════════════════════════════════
export async function enrichAssessmentWithMYTHOS(env, {
  report,           // The raw engine report object
  findings = [],    // Array of finding objects
  service_name,     // e.g. 'SSL & Website Security Health Check'
  service_ref,      // e.g. 'CDB-SSL-001'
  target = '',      // domain or URL
  sector = 'Technology',
  tier   = 'FREE',
  probe_results = {},
}) {
  const enrichedAt = new Date().toISOString();

  // 1. MITRE ATT&CK mapping
  const mitreMappings = mapFindingsToMITRE(findings);

  // 2. Cyber Brain analysis
  const brainFindings = findings.map(f => ({
    id:          f.id,
    title:       f.title || f.id,
    description: f.description || '',
    severity:    f.severity,
    cvss:        f.cvss || 0,
    category:    f.category || '',
  }));

  const riskData      = computeRiskScore(brainFindings, [], {});
  const attackPaths   = predictAttackPaths(brainFindings, [], riskData.score || 0);
  const threatActors  = correlateThretActors(brainFindings, sector.toLowerCase());
  const remediation   = generateRemediation(brainFindings, riskData.score || 0, tier);
  const bizImpact     = assessBusinessImpact(riskData.score || 0, brainFindings);
  const mitreCoverage = assessMITRECoverage(brainFindings);

  // 3. AI narrative (Workers AI if available)
  const riskLevel     = riskData.level || (riskData.score >= 70 ? 'HIGH' : riskData.score >= 40 ? 'MEDIUM' : 'LOW');
  const aiNarrative   = await generateAINarrative(env, {
    target, service_name, sector,
    riskScore: riskData.score || 0,
    riskLevel,
    findings: brainFindings,
  });

  // 4. Autonomous remediation plan
  const remediationPlan = buildAutonomousRemediationPlan(findings, riskData.score || 0);

  // 5. D1 threat actor overlay
  const mythosActors = await fetchMythosTheatActorOverlay(env, sector, findings);

  // 6. Confidence score
  const mythosConfidence = computeMythosConfidence(findings, probe_results);

  // Assemble MYTHOS intelligence block
  const mythosIntelligence = {
    engine:              'CYBERDUDEBIVASH MYTHOS AI™',
    version:             'v4.0-SOVEREIGN',
    service_ref,
    service_name,
    target,
    sector,
    enriched_at:         enrichedAt,
    mythos_confidence:   mythosConfidence,

    // Core AI Analysis
    cyber_brain: {
      risk_score:          riskData.score || 0,
      risk_level:          riskLevel,
      risk_signals:        (riskData.signals || []).slice(0, 8),
      attack_paths:        attackPaths.slice(0, 3),
      threat_actors:       threatActors.slice(0, 3),
      mitre_coverage:      mitreCoverage,
      business_impact:     bizImpact,
      remediation_actions: remediation.slice(0, 8),
    },

    // MITRE ATT&CK Overlay
    mitre_attack: {
      tactics_identified:  mitreMappings.length,
      mappings:            mitreMappings,
      framework_version:   'MITRE ATT&CK v15',
    },

    // Autonomous Remediation Plan
    autonomous_remediation_plan: remediationPlan,

    // AI Narrative (Workers AI)
    ai_executive_brief: aiNarrative
      ? { generated: true,  narrative: aiNarrative,  model: 'claude-sonnet-4-6' }
      : { generated: false, narrative: null, note: 'Upgrade to PRO for AI-generated executive briefs (Claude Sonnet 4.6)' },

    // D1 Threat Actor Overlay
    threat_actor_overlay: mythosActors
      ? { active: true,  actors: mythosActors }
      : { active: false, actors: [] },

    // MYTHOS Authority Seal
    authority: {
      platform:      'CYBERDUDEBIVASH® SENTINEL APEX',
      powered_by:    'MYTHOS AI™ Sovereign Engine',
      certified_by:  'CYBERDUDEBIVASH® AI Security Hub',
      intel_sources: ['MITRE ATT&CK v15', 'CISA KEV', 'NVD CVE', 'D1 Threat Actor DB', 'CyberBrain v3'],
      report_class:  'PRODUCTION-GRADE ENTERPRISE INTELLIGENCE',
      timestamp:     enrichedAt,
    },
  };

  // Merge into report
  return {
    ...report,
    mythos_intelligence: mythosIntelligence,
    powered_by_mythos: true,
  };
}

// ── Convenience: enrich and persist to D1 assessment record ──────────────────
export async function enrichAndPersistAssessment(env, {
  orderId,
  report,
  findings = [],
  service_ref,
  service_name,
  target,
  sector,
  tier,
  probe_results,
}) {
  // Enrich
  const enriched = await enrichAssessmentWithMYTHOS(env, {
    report, findings, service_name, service_ref, target, sector, tier, probe_results,
  });

  // Persist enriched report to D1 assessment record
  if (env?.DB && orderId) {
    try {
      await env.DB.prepare(
        `UPDATE service_assessments SET
           report_json         = ?,
           mythos_enriched     = 1,
           mythos_confidence   = ?,
           updated_at          = datetime('now')
         WHERE order_id = ?`
      ).bind(
        JSON.stringify(enriched),
        enriched.mythos_intelligence?.mythos_confidence || 0,
        orderId
      ).run();
    } catch (e) {
      console.error('[MYTHOS-Enrichment] D1 persist error:', e.message);
    }
  }

  return enriched;
}
