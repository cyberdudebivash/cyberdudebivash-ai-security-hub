/**
 * CYBERDUDEBIVASH AI Security Hub — AI Governance Assessment Engine v1.0
 * Service: CDB-AIGOV-001 (₹19,999) — EU AI Act + NIST AI RMF Governance Framework
 * MYTHOS-Powered: Autonomous AI governance gap analysis and compliance roadmap
 */

// ── EU AI Act Risk Classification ─────────────────────────────────────────────
const EU_AI_ACT_RISK_TIERS = {
  UNACCEPTABLE: {
    level:       'UNACCEPTABLE',
    description: 'AI systems that pose unacceptable risk — prohibited under EU AI Act Article 5',
    examples:    ['Social scoring systems', 'Real-time biometric surveillance in public', 'Subliminal manipulation systems'],
    action:      'PROHIBITED — Must be decommissioned or fundamentally redesigned',
    severity:    'CRITICAL',
  },
  HIGH: {
    level:       'HIGH',
    description: 'AI systems in critical domains requiring strict compliance before deployment',
    examples:    ['AI in hiring/HR decisions', 'AI in credit scoring', 'AI in healthcare diagnostics', 'AI in law enforcement'],
    action:      'Requires conformity assessment, data governance, human oversight, and technical documentation',
    severity:    'HIGH',
  },
  LIMITED: {
    level:       'LIMITED',
    description: 'AI systems with transparency obligations — users must be informed they are interacting with AI',
    examples:    ['Chatbots', 'Deepfake content', 'Emotion recognition systems'],
    action:      'Transparency obligations: disclose AI nature to end users',
    severity:    'MEDIUM',
  },
  MINIMAL: {
    level:       'MINIMAL',
    description: 'Low-risk AI systems with minimal regulatory requirements',
    examples:    ['AI-powered spam filters', 'Recommendation engines', 'AI in video games'],
    action:      'Voluntary codes of conduct recommended; no mandatory requirements',
    severity:    'LOW',
  },
};

// ── NIST AI RMF Functions ─────────────────────────────────────────────────────
const NIST_AI_RMF = [
  {
    function:    'GOVERN',
    description: 'Organizational policies, culture, and accountability for AI risk management',
    subcategories: [
      { id: 'GOV-1.1', name: 'AI Risk Governance Policy',              q: 'has_ai_risk_policy',        weight: 20 },
      { id: 'GOV-1.2', name: 'AI Executive Ownership (CAIO/CTO)',      q: 'has_ai_executive_ownership', weight: 15 },
      { id: 'GOV-1.3', name: 'AI Ethics Committee or Board',           q: 'has_ai_ethics_board',       weight: 15 },
      { id: 'GOV-2.1', name: 'Organizational AI Awareness Training',   q: 'has_ai_training',           weight: 10 },
      { id: 'GOV-3.1', name: 'Third-Party AI Vendor Risk Program',     q: 'has_vendor_ai_risk',        weight: 15 },
    ],
  },
  {
    function:    'MAP',
    description: 'Contextualize and categorize AI risks relative to business context',
    subcategories: [
      { id: 'MAP-1.1', name: 'AI Use Case Risk Classification',        q: 'has_use_case_classification', weight: 20 },
      { id: 'MAP-2.1', name: 'AI Impact Assessment (individuals)',      q: 'has_impact_assessment',      weight: 20 },
      { id: 'MAP-3.1', name: 'AI System Documentation',                q: 'has_ai_documentation',       weight: 15 },
      { id: 'MAP-4.1', name: 'Bias & Fairness Risk Assessment',        q: 'has_bias_assessment',        weight: 20 },
      { id: 'MAP-5.1', name: 'AI Supply Chain Risk Mapping',           q: 'has_supply_chain_mapping',   weight: 15 },
    ],
  },
  {
    function:    'MEASURE',
    description: 'Analysis, assessment, and measurement of AI risk',
    subcategories: [
      { id: 'MEA-1.1', name: 'AI Performance Monitoring',              q: 'has_performance_monitoring', weight: 20 },
      { id: 'MEA-2.1', name: 'AI Fairness & Bias Metrics',            q: 'has_fairness_metrics',       weight: 20 },
      { id: 'MEA-3.1', name: 'AI Explainability Assessment',           q: 'has_explainability',         weight: 15 },
      { id: 'MEA-4.1', name: 'AI Security & Adversarial Testing',      q: 'has_adversarial_testing',    weight: 20 },
      { id: 'MEA-5.1', name: 'Data Lineage & Provenance Tracking',    q: 'has_data_lineage',           weight: 15 },
    ],
  },
  {
    function:    'MANAGE',
    description: 'Prioritize, respond to, monitor, and improve AI risk',
    subcategories: [
      { id: 'MNG-1.1', name: 'AI Incident Response Plan',              q: 'has_ai_ir_plan',             weight: 20 },
      { id: 'MNG-2.1', name: 'Human Override & Shutdown Controls',     q: 'has_human_override',         weight: 25 },
      { id: 'MNG-3.1', name: 'Model Version Control & Rollback',       q: 'has_model_versioning',       weight: 15 },
      { id: 'MNG-4.1', name: 'Continuous AI Risk Monitoring',          q: 'has_continuous_monitoring',  weight: 15 },
      { id: 'MNG-5.1', name: 'Regulatory Change Management (AI Laws)', q: 'has_regulatory_tracking',    weight: 15 },
    ],
  },
];

// ── EU AI Act Compliance Checks ───────────────────────────────────────────────
const EU_AI_ACT_ARTICLES = [
  { article: 'Art. 9',  name: 'Risk Management System',     q: 'has_risk_mgmt_system',      weight: 20 },
  { article: 'Art. 10', name: 'Training Data Governance',   q: 'has_data_governance',        weight: 20 },
  { article: 'Art. 11', name: 'Technical Documentation',    q: 'has_technical_docs',         weight: 15 },
  { article: 'Art. 12', name: 'Record-Keeping & Logging',   q: 'has_record_keeping',         weight: 15 },
  { article: 'Art. 13', name: 'Transparency & Information', q: 'has_transparency_notices',   weight: 15 },
  { article: 'Art. 14', name: 'Human Oversight Mechanism',  q: 'has_human_oversight',        weight: 20 },
  { article: 'Art. 15', name: 'Accuracy & Robustness',      q: 'has_accuracy_measures',      weight: 15 },
  { article: 'Art. 72', name: 'Incident Reporting (GPAI)',  q: 'has_incident_reporting',     weight: 10 },
];

// ── Score NIST AI RMF ─────────────────────────────────────────────────────────
function scoreNISTAIRMF(inputs) {
  return NIST_AI_RMF.map(fn => {
    let score = 0, max = 0;
    const controls = fn.subcategories.map(sc => {
      const pass = !!inputs[sc.q];
      max += sc.weight;
      if (pass) score += sc.weight;
      return {
        id:      sc.id,
        name:    sc.name,
        weight:  sc.weight,
        status:  pass ? 'IMPLEMENTED' : 'GAP',
        finding: pass ? null : {
          id:          `AIGOV-NIST-${sc.id}`,
          severity:    sc.weight >= 20 ? 'HIGH' : sc.weight >= 14 ? 'MEDIUM' : 'LOW',
          category:    `AI Governance — NIST AI RMF`,
          title:       `NIST AI RMF Gap: ${sc.name} (${sc.id})`,
          description: `${sc.name} is not implemented. This is required under NIST AI RMF ${fn.function} function for responsible AI deployment.`,
          remediation: `Implement ${sc.name} per NIST AI RMF ${fn.function} guidance. Assign ownership, define process, validate effectiveness.`,
          cvss:        sc.weight >= 20 ? 6.5 : sc.weight >= 14 ? 4.5 : 2.5,
          framework:   `NIST AI RMF — ${fn.function}`,
        },
      };
    });

    return {
      function:    fn.function,
      description: fn.description,
      score, max,
      pct:         Math.round(score / max * 100),
      grade:       score/max >= 0.8 ? 'A' : score/max >= 0.6 ? 'B' : score/max >= 0.4 ? 'C' : 'D',
      controls,
    };
  });
}

// ── Score EU AI Act Articles ──────────────────────────────────────────────────
function scoreEUAIAct(inputs) {
  let score = 0, max = 0;
  const articleResults = EU_AI_ACT_ARTICLES.map(art => {
    const pass = !!inputs[art.q];
    max += art.weight;
    if (pass) score += art.weight;
    return {
      article:   art.article,
      name:      art.name,
      weight:    art.weight,
      status:    pass ? 'COMPLIANT' : 'NON-COMPLIANT',
      finding: pass ? null : {
        id:          `AIGOV-EU-${art.article.replace('.', '_')}`,
        severity:    art.weight >= 18 ? 'HIGH' : art.weight >= 12 ? 'MEDIUM' : 'LOW',
        category:    'AI Governance — EU AI Act',
        title:       `EU AI Act Gap: ${art.name} (${art.article})`,
        description: `${art.name} requirement under ${art.article} is not met. Organizations deploying AI in the EU market risk non-compliance penalties up to €30M or 6% global turnover.`,
        remediation: `Implement ${art.name} controls per EU AI Act ${art.article} requirements. Engage legal counsel for compliance validation.`,
        cvss:        art.weight >= 18 ? 7.0 : art.weight >= 12 ? 5.0 : 3.0,
        regulation:  `EU AI Act ${art.article}`,
      },
    };
  });

  return { articles: articleResults, score, max, pct: Math.round(score / max * 100) };
}

// ── Classify AI Risk Tier from inputs ─────────────────────────────────────────
function classifyAIRiskTier(inputs) {
  const riskFactors = {
    uses_biometrics:       EU_AI_ACT_RISK_TIERS.UNACCEPTABLE,
    affects_credit:        EU_AI_ACT_RISK_TIERS.HIGH,
    affects_employment:    EU_AI_ACT_RISK_TIERS.HIGH,
    affects_healthcare:    EU_AI_ACT_RISK_TIERS.HIGH,
    affects_law_enforcement: EU_AI_ACT_RISK_TIERS.HIGH,
    uses_chatbot:          EU_AI_ACT_RISK_TIERS.LIMITED,
    generates_content:     EU_AI_ACT_RISK_TIERS.LIMITED,
  };

  for (const [key, tier] of Object.entries(riskFactors)) {
    if (inputs[key]) return tier;
  }
  return EU_AI_ACT_RISK_TIERS.MINIMAL;
}

// ── Build Governance Roadmap ──────────────────────────────────────────────────
function buildGovernanceRoadmap(nistResults, euResults) {
  const allGaps = [
    ...nistResults.flatMap(fn => fn.controls.map(c => c.finding).filter(Boolean)),
    ...euResults.articles.map(a => a.finding).filter(Boolean),
  ];

  allGaps.sort((a, b) => {
    const so = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return (so[a.severity] ?? 3) - (so[b.severity] ?? 3);
  });

  const phases = [
    { phase: 1, name: 'Foundation',   timeline: '0-60 days',   actions: allGaps.filter(g => g.severity === 'HIGH') },
    { phase: 2, name: 'Core Program', timeline: '60-180 days', actions: allGaps.filter(g => g.severity === 'MEDIUM') },
    { phase: 3, name: 'Maturity',     timeline: '180-365 days',actions: allGaps.filter(g => g.severity === 'LOW') },
  ];

  return phases.filter(p => p.actions.length > 0).map(p => ({
    ...p,
    action_count: p.actions.length,
    top_actions:  p.actions.slice(0, 5).map(a => a.title),
  }));
}

// ═════════════════════════════════════════════════════════════════════════════
export async function runAIGovernanceAssessment(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const org       = inputs.company || inputs.organization || 'Your Organization';

  // Score all frameworks
  const nistResults = scoreNISTAIRMF(inputs);
  const euResults   = scoreEUAIAct(inputs);
  const riskTier    = classifyAIRiskTier(inputs);

  // Collect all findings
  const nistFindings = nistResults.flatMap(fn => fn.controls.map(c => c.finding).filter(Boolean));
  const euFindings   = euResults.articles.map(a => a.finding).filter(Boolean);
  const findings     = [...nistFindings, ...euFindings];

  findings.sort((a, b) => {
    const so = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return (so[a.severity] ?? 3) - (so[b.severity] ?? 3);
  });

  // Add risk tier finding if HIGH/UNACCEPTABLE
  if (['HIGH','UNACCEPTABLE'].includes(riskTier.level)) {
    findings.unshift({
      id:          `AIGOV-RISK-TIER-${riskTier.level}`,
      severity:    riskTier.severity,
      category:    'AI Governance — EU AI Act Risk Classification',
      title:       `AI System Classified as ${riskTier.level} RISK under EU AI Act`,
      description: riskTier.description,
      remediation: riskTier.action,
      cvss:        riskTier.level === 'UNACCEPTABLE' ? 10.0 : 8.5,
      regulation:  'EU AI Act Article 6-9',
    });
  }

  // Score totals
  const nistTotal  = nistResults.reduce((s, fn) => s + fn.score, 0);
  const nistMax    = nistResults.reduce((s, fn) => s + fn.max, 0);
  const nistScore  = Math.round(nistTotal / nistMax * 100);

  const overallScore = Math.round((nistScore + euResults.pct) / 2);
  const riskScore    = 100 - overallScore;
  const grade        = overallScore >= 80 ? 'A' : overallScore >= 65 ? 'B' : overallScore >= 50 ? 'C' : overallScore >= 35 ? 'D' : 'F';

  const governanceRoadmap = buildGovernanceRoadmap(nistResults, euResults);

  const report = {
    meta: {
      service:       'CDB-AIGOV-001',
      service_name:  'AI Governance Consulting',
      version:       '1.0',
      organization:  org,
      generated_at:  startedAt,
      frameworks:    ['NIST AI RMF 1.0', 'EU AI Act (2024)', 'OECD AI Principles'],
      powered_by:    'CYBERDUDEBIVASH AI Security Hub™ | MYTHOS AI Engine',
    },
    executive_summary: {
      overall_score:        overallScore,
      risk_score:           riskScore,
      grade,
      nist_ai_rmf_score:    nistScore,
      eu_ai_act_score:      euResults.pct,
      ai_risk_tier:         riskTier.level,
      ai_risk_tier_action:  riskTier.action,
      total_gaps:           findings.length,
      high_gaps:            findings.filter(f => f.severity === 'HIGH').length,
      medium_gaps:          findings.filter(f => f.severity === 'MEDIUM').length,
      critical_gaps:        findings.filter(f => f.severity === 'CRITICAL').length,
    },
    ai_risk_classification: riskTier,
    nist_ai_rmf: {
      overall_score: nistScore,
      functions:     nistResults.map(fn => ({
        function:    fn.function,
        description: fn.description,
        score:       fn.score,
        max:         fn.max,
        pct:         fn.pct,
        grade:       fn.grade,
      })),
    },
    eu_ai_act: {
      overall_score:  euResults.pct,
      articles:       euResults.articles.map(a => ({
        article: a.article, name: a.name, status: a.status,
      })),
    },
    findings,
    governance_roadmap: governanceRoadmap,
    recommendations: [
      { priority: 1, action: 'Designate AI Risk Executive Owner (CAIO/CTO) with board accountability',  effort: 'Low',  impact: 'Critical' },
      { priority: 2, action: 'Conduct EU AI Act risk classification for all deployed AI systems',        effort: 'Low',  impact: 'Critical' },
      { priority: 3, action: 'Implement human oversight mechanism with kill-switch capability',          effort: 'Medium', impact: 'Critical' },
      { priority: 4, action: 'Establish AI incident response and reporting process per EU AI Act Art 72',effort: 'Medium', impact: 'High' },
      { priority: 5, action: 'Deploy bias/fairness metrics monitoring for all production AI models',     effort: 'High', impact: 'High' },
      { priority: 6, action: 'Create comprehensive AI system technical documentation per Art. 11',       effort: 'Medium', impact: 'High' },
      { priority: 7, action: 'Implement continuous AI performance and drift monitoring',                 effort: 'High', impact: 'Medium' },
    ],
  };

  if (env?.DB && orderId) {
    const assessId = crypto.randomUUID();
    try {
      await env.DB.prepare(
        `INSERT INTO service_assessments
         (id, order_id, service_ref, target, status, risk_score, risk_grade,
          findings_count, critical_count, high_count,
          findings_json, recommendations_json, report_json,
          engine_version, started_at, completed_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        assessId, orderId, 'CDB-AIGOV-001', org, 'complete',
        riskScore, grade,
        findings.length,
        findings.filter(f => f.severity === 'CRITICAL').length,
        findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[AIGovernance-Engine] DB error:', e.message); }
  }

  return report;
}
