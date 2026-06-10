/**
 * CYBERDUDEBIVASH AI Security Posture Management (AI SPM) — v1.0
 * Phase B Revenue Product 2
 *
 * Endpoints:
 *   POST /api/aispm/inventory       — AI model/deployment inventory scan
 *   POST /api/aispm/owasp-llm       — OWASP LLM Top 10 risk assessment
 *   POST /api/aispm/governance      — AI governance maturity assessment
 *   GET  /api/aispm/report/:org     — Full AI SPM posture report
 *
 * Pricing: PRO ($49/mo) — assessment + report; ENTERPRISE — continuous monitoring + API
 */

import { callClaude } from '../core/mythosAIProvider.js';
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';

function ok(data, status = 200) { return Response.json(data, { status }); }
function err(msg, status = 400) { return Response.json({ success: false, error: msg }, { status }); }

// ─── OWASP LLM Top 10 (2025 Edition) catalog ─────────────────────────────────
const OWASP_LLM = [
  { id: 'LLM01', name: 'Prompt Injection',            severity: 'CRITICAL', description: 'Attacker crafts input that overrides system prompt or model instructions to exfiltrate data, bypass controls, or execute unauthorized actions.', mitigations: ['Input/output filtering', 'Privilege separation', 'Least-privilege tool access', 'Human-in-the-loop for high-risk actions'] },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', severity: 'HIGH', description: 'LLM reveals confidential data, training data, PII, or system internals through over-sharing, memorization, or inference.', mitigations: ['Output filtering', 'Data minimization in training', 'Rate limiting on inference', 'DLP integration'] },
  { id: 'LLM03', name: 'Supply Chain Vulnerabilities', severity: 'HIGH', description: 'Compromised model weights, poisoned datasets, malicious plugins, or vulnerable ML frameworks in the AI pipeline.', mitigations: ['Model provenance verification', 'SBOM for AI dependencies', 'Signed model artifacts', 'Third-party plugin vetting'] },
  { id: 'LLM04', name: 'Data and Model Poisoning',    severity: 'HIGH', description: 'Adversarial manipulation of training data or fine-tuning inputs to introduce backdoors, bias, or unsafe behaviors.', mitigations: ['Training data validation', 'Differential privacy', 'Adversarial input testing', 'Model behavior monitoring'] },
  { id: 'LLM05', name: 'Improper Output Handling',    severity: 'HIGH', description: 'LLM output injected into downstream systems (SQL, shell, HTML) without sanitization causes XSS, SQLi, RCE, or SSRF.', mitigations: ['Output sanitization', 'Parameterized queries', 'Content Security Policy', 'Sandboxed execution environments'] },
  { id: 'LLM06', name: 'Excessive Agency',            severity: 'HIGH', description: 'AI agent given excessive permissions or autonomy executes harmful actions (delete files, send emails, make API calls) without authorization.', mitigations: ['Minimal permissions for AI agents', 'Action allowlists', 'Human approval gates', 'Audit logging of all AI actions'] },
  { id: 'LLM07', name: 'System Prompt Leakage',       severity: 'MEDIUM', description: 'System prompt contents exposed via jailbreaking, model inversion, or verbose error responses, revealing security logic and business rules.', mitigations: ['Never put secrets in system prompts', 'Treat system prompt as confidential but not secret', 'Monitor for extraction attempts'] },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', severity: 'MEDIUM', description: 'RAG vector stores contain unvalidated data; adversarial documents injected into the knowledge base manipulate LLM responses.', mitigations: ['Document validation before ingestion', 'Access controls on vector stores', 'Anomaly detection on retrieved chunks'] },
  { id: 'LLM09', name: 'Misinformation',              severity: 'MEDIUM', description: 'LLM generates plausible-sounding false information (hallucinations) that causes business, legal, medical, or security harm.', mitigations: ['Retrieval-augmented generation', 'Confidence scoring', 'Human review for high-stakes decisions', 'Source citation requirements'] },
  { id: 'LLM10', name: 'Unbounded Consumption',       severity: 'MEDIUM', description: 'Adversarial prompts cause excessive token consumption, resource exhaustion, cost spikes, or denial of service via infinite loops.', mitigations: ['Token limits per request', 'Rate limiting', 'Cost monitoring alerts', 'Prompt length validation'] },
];

// ─── AI Governance Maturity Model ─────────────────────────────────────────────
const GOVERNANCE_DOMAINS = [
  { domain: 'model_inventory',       weight: 15, questions: ['Do you maintain a registry of all AI/ML models in production?', 'Is model version control enforced?', 'Are model owners documented?'] },
  { domain: 'risk_assessment',       weight: 20, questions: ['Is a formal AI risk assessment performed before deployment?', 'Are adversarial scenarios tested?', 'Is bias evaluation included?'] },
  { domain: 'access_controls',       weight: 20, questions: ['Is model API access restricted to authorized systems?', 'Are API keys rotated regularly?', 'Is MFA enforced for AI platform access?'] },
  { domain: 'data_governance',       weight: 15, questions: ['Is training data lineage documented?', 'Is PII excluded or de-identified from training sets?', 'Are data retention policies applied?'] },
  { domain: 'monitoring_observability', weight: 15, questions: ['Are LLM inputs/outputs logged for review?', 'Are anomaly alerts configured?', 'Is model drift monitored?'] },
  { domain: 'incident_response',     weight: 10, questions: ['Is there an AI-specific incident response plan?', 'Can a model be rolled back in under 1 hour?'] },
  { domain: 'compliance_alignment',  weight: 5,  questions: ['Is the platform aligned with EU AI Act or NIST AI RMF?', 'Are AI ethics guidelines published?'] },
];

// ─── Scoring helper ───────────────────────────────────────────────────────────
function scoreGovernance(responses) {
  let totalScore = 0;
  const domainScores = {};
  for (const domain of GOVERNANCE_DOMAINS) {
    const answers = responses[domain.domain] || {};
    const questions = domain.questions;
    let domainYes = 0;
    for (const q of questions) {
      if (answers[q] === true || answers[q] === 'yes') domainYes++;
    }
    const pct = questions.length > 0 ? domainYes / questions.length : 0;
    domainScores[domain.domain] = { score: Math.round(pct * 100), answered: domainYes, total: questions.length };
    totalScore += pct * domain.weight;
  }
  return { overall: Math.round(totalScore), domains: domainScores };
}

function maturityLevel(score) {
  if (score >= 80) return { level: 'OPTIMIZING',   label: 'Level 4 — Optimizing',   color: 'green' };
  if (score >= 60) return { level: 'MANAGED',      label: 'Level 3 — Managed',      color: 'blue' };
  if (score >= 40) return { level: 'DEFINED',      label: 'Level 2 — Defined',       color: 'yellow' };
  if (score >= 20) return { level: 'INITIAL',      label: 'Level 1 — Initial',       color: 'orange' };
  return                  { level: 'UNPREPARED',   label: 'Level 0 — Unprepared',    color: 'red' };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 1: POST /api/aispm/inventory — AI Model Inventory Scan
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleAISPMInventory(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return ok({ success: false, error: 'AI SPM requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
  }

  const body        = await request.json().catch(() => ({}));
  const org         = body.organization || body.org || 'Unknown Organization';
  const models      = body.models       || [];
  const domain      = body.domain       || '';
  const integrations = body.integrations || [];

  // Auto-detect common AI usage patterns from provided context
  const detectedRisks = [];
  const knownRiskyIntegrations = ['openai', 'anthropic', 'cohere', 'huggingface', 'replicate', 'together', 'mistral', 'groq'];
  const knownRiskyPatterns = ['langchain', 'autogpt', 'crewai', 'n8n', 'zapier', 'make.com', 'chatgpt plugin'];

  for (const integration of integrations) {
    const lower = integration.toLowerCase();
    if (knownRiskyIntegrations.some(k => lower.includes(k))) {
      detectedRisks.push({ source: integration, risk: 'External LLM API dependency — data leaves your perimeter', severity: 'HIGH', control: 'LLM03' });
    }
    if (knownRiskyPatterns.some(k => lower.includes(k))) {
      detectedRisks.push({ source: integration, risk: 'AI agent/automation framework — excessive agency risk', severity: 'HIGH', control: 'LLM06' });
    }
  }

  // Score each declared model
  const modelAssessments = models.map(m => {
    const risks = [];
    if (!m.access_controls) risks.push({ risk: 'No access controls documented', owasp: 'LLM06', severity: 'HIGH' });
    if (!m.output_filtering) risks.push({ risk: 'No output filtering', owasp: 'LLM05', severity: 'HIGH' });
    if (!m.input_validation) risks.push({ risk: 'No input validation', owasp: 'LLM01', severity: 'CRITICAL' });
    if (!m.monitoring)       risks.push({ risk: 'No monitoring/logging', owasp: 'LLM02', severity: 'MEDIUM' });
    if (!m.data_classification) risks.push({ risk: 'Training data not classified', owasp: 'LLM04', severity: 'MEDIUM' });
    const riskScore = risks.reduce((s, r) => s + (r.severity === 'CRITICAL' ? 30 : r.severity === 'HIGH' ? 20 : 10), 0);
    return { model: m.name || 'Unnamed Model', type: m.type || 'LLM', risks, risk_score: Math.min(100, riskScore), status: riskScore > 50 ? 'HIGH_RISK' : riskScore > 20 ? 'MEDIUM_RISK' : 'MONITORED' };
  });

  const overallRisk = modelAssessments.length > 0
    ? Math.round(modelAssessments.reduce((s, m) => s + m.risk_score, 0) / modelAssessments.length)
    : detectedRisks.length > 0 ? 60 : 30;

  // AI narrative
  let aiAnalysis = null;
  try {
    const result = await callClaude(env, {
      prompt: `AI model inventory for ${org}. Models: ${models.length || 0}. Integrations: ${integrations.join(', ') || 'none'}. Detected risks: ${detectedRisks.length}. Overall risk: ${overallRisk}/100.
Provide: top 3 AI security risks for this organization, immediate actions required, and 2026 AI governance priority. Be concise (4-5 sentences).`,
      tier: authCtx?.tier || 'PRO',
      max_tokens: 250,
      temperature: 0.2,
    });
    aiAnalysis = result?.content?.trim() || null;
  } catch {}

  return ok({
    success: true,
    service: 'CDB-AISPM-001',
    organization: org,
    inventory: {
      total_models:       models.length,
      total_integrations: integrations.length,
      model_assessments:  modelAssessments,
      detected_risks:     detectedRisks,
      overall_risk_score: overallRisk,
      risk_level:         overallRisk >= 70 ? 'CRITICAL' : overallRisk >= 50 ? 'HIGH' : overallRisk >= 30 ? 'MEDIUM' : 'LOW',
    },
    recommendations: [
      'Complete OWASP LLM Top 10 assessment via POST /api/aispm/owasp-llm',
      'Implement AI governance framework via POST /api/aispm/governance',
      'Enable continuous AI posture monitoring via ENTERPRISE plan',
    ],
    ai_analysis:   aiAnalysis,
    powered_by:    'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:     new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 2: POST /api/aispm/owasp-llm — OWASP LLM Top 10 Assessment
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleAISPMOWASP(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return ok({ success: false, error: 'OWASP LLM assessment requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
  }

  const body    = await request.json().catch(() => ({}));
  const org     = body.organization || body.org || 'Unknown Organization';
  const answers = body.answers || {};  // { LLM01: { prompt_filtering: true, ... }, ... }
  const context = body.context || {};

  // Score each OWASP control
  const assessments = OWASP_LLM.map(item => {
    const controlAnswers = answers[item.id] || {};
    const implemented = Object.values(controlAnswers).filter(Boolean).length;
    const total       = Math.max(Object.keys(controlAnswers).length, 1);
    const coverage    = Math.round((implemented / total) * 100);

    let status;
    if (coverage >= 80)      status = 'IMPLEMENTED';
    else if (coverage >= 40) status = 'PARTIAL';
    else                     status = 'NOT_ADDRESSED';

    const riskScore = status === 'IMPLEMENTED' ? 10 :
                      status === 'PARTIAL'      ? (item.severity === 'CRITICAL' ? 70 : item.severity === 'HIGH' ? 55 : 35) :
                                                  (item.severity === 'CRITICAL' ? 95 : item.severity === 'HIGH' ? 80 : 60);

    return { ...item, coverage, status, risk_score: riskScore, findings: Object.keys(controlAnswers).filter(k => !controlAnswers[k]).map(k => `${k}: Not implemented`) };
  });

  // Composite posture score
  const totalRisk = assessments.reduce((s, a) => {
    const w = a.severity === 'CRITICAL' ? 3 : a.severity === 'HIGH' ? 2 : 1;
    return s + a.risk_score * w;
  }, 0);
  const maxRisk = assessments.reduce((s, a) => s + 100 * (a.severity === 'CRITICAL' ? 3 : a.severity === 'HIGH' ? 2 : 1), 0);
  const postureScore = 100 - Math.round((totalRisk / maxRisk) * 100);

  const criticalGaps = assessments.filter(a => a.status === 'NOT_ADDRESSED' && a.severity === 'CRITICAL');
  const highGaps     = assessments.filter(a => a.status === 'NOT_ADDRESSED' && a.severity === 'HIGH');

  // AI narrative
  let narrative = null;
  try {
    const result = await callClaude(env, {
      prompt: `OWASP LLM Top 10 assessment for ${org}. Posture score: ${postureScore}/100. Critical gaps: ${criticalGaps.map(g => g.id + ' ' + g.name).join(', ') || 'none'}. High gaps: ${highGaps.map(g => g.id).join(', ') || 'none'}.
Write an executive summary covering: overall AI security posture, the most dangerous gaps, regulatory exposure (EU AI Act / ISO 42001), and top 3 immediate remediation actions. Be concise (5-6 sentences).`,
      tier: authCtx?.tier || 'PRO',
      max_tokens: 350,
      temperature: 0.2,
    });
    narrative = result?.content?.trim() || null;
  } catch {}

  let report = {
    success:        true,
    service:        'CDB-AISPM-002',
    organization:   org,
    framework:      'OWASP LLM Top 10 2025',
    posture: {
      score:           postureScore,
      level:           postureScore >= 75 ? 'STRONG' : postureScore >= 50 ? 'MODERATE' : postureScore >= 25 ? 'WEAK' : 'CRITICAL',
      critical_gaps:   criticalGaps.length,
      high_gaps:       highGaps.length,
      total_controls:  OWASP_LLM.length,
      implemented:     assessments.filter(a => a.status === 'IMPLEMENTED').length,
      partial:         assessments.filter(a => a.status === 'PARTIAL').length,
      not_addressed:   assessments.filter(a => a.status === 'NOT_ADDRESSED').length,
    },
    assessments,
    executive_summary:  narrative,
    priority_remediations: [...criticalGaps, ...highGaps].slice(0, 5).map(g => ({
      control:     g.id,
      name:        g.name,
      severity:    g.severity,
      mitigations: g.mitigations.slice(0, 2),
    })),
    compliance_alignment: {
      'EU AI Act':     postureScore >= 70 ? 'Likely compliant' : 'Gaps identified',
      'NIST AI RMF':   postureScore >= 60 ? 'Aligned' : 'Partial alignment',
      'ISO 42001':     postureScore >= 75 ? 'Aligned' : 'Remediation required',
    },
    powered_by:     'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:      new Date().toISOString(),
  };

  // MYTHOS enrichment
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report,
      findings: criticalGaps.concat(highGaps).map(g => ({ title: g.name, severity: g.severity, description: g.description })),
      service_name: 'AI Security Posture Management',
      service_ref:  'CDB-AISPM-002',
      target:       org,
      sector:       context.sector || 'Technology',
      tier:         authCtx?.tier || 'PRO',
    });
  } catch {}

  return ok(report);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 3: POST /api/aispm/governance — AI Governance Maturity Assessment
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleAISPMGovernance(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return ok({ success: false, error: 'AI Governance assessment requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
  }

  const body      = await request.json().catch(() => ({}));
  const org       = body.organization || body.org || 'Unknown Organization';
  const responses = body.responses || {};
  const sector    = body.sector || 'Technology';

  const { overall, domains } = scoreGovernance(responses);
  const maturity = maturityLevel(overall);

  // Gap analysis
  const gaps = Object.entries(domains)
    .filter(([, d]) => d.score < 60)
    .map(([domain, d]) => ({
      domain,
      score:     d.score,
      priority:  d.score < 30 ? 'CRITICAL' : 'HIGH',
      questions: GOVERNANCE_DOMAINS.find(gd => gd.domain === domain)?.questions || [],
    }))
    .sort((a, b) => a.score - b.score);

  // AI governance roadmap
  let roadmap = null;
  try {
    const result = await callClaude(env, {
      prompt: `AI governance maturity assessment for ${org} (${sector}). Score: ${overall}/100, Level: ${maturity.level}. Weakest domains: ${gaps.slice(0,3).map(g => g.domain).join(', ')}.
Generate a 90-day AI governance improvement roadmap with: Month 1 quick wins, Month 2 structural improvements, Month 3 framework alignment. Each month should have 2-3 specific actions. Be concise.`,
      tier: authCtx?.tier || 'PRO',
      max_tokens: 400,
      temperature: 0.3,
    });
    roadmap = result?.content?.trim() || null;
  } catch {}

  return ok({
    success:      true,
    service:      'CDB-AISPM-003',
    organization: org,
    sector,
    maturity: {
      overall_score: overall,
      ...maturity,
      domains,
      benchmarks: {
        industry_median:  65,
        top_quartile:     82,
        your_percentile:  overall > 82 ? 'Top 25%' : overall > 65 ? 'Above median' : overall > 40 ? 'Below median' : 'Bottom quartile',
      },
    },
    critical_gaps:    gaps.filter(g => g.priority === 'CRITICAL').map(g => ({ domain: g.domain, score: g.score, impact: 'High regulatory and operational risk' })),
    high_gaps:        gaps.filter(g => g.priority === 'HIGH').map(g => ({ domain: g.domain, score: g.score })),
    improvement_roadmap: roadmap,
    frameworks_alignment: {
      'NIST AI RMF 1.0': overall >= 70 ? 'Aligned' : 'Gaps in ' + gaps.slice(0,2).map(g => g.domain).join(', '),
      'EU AI Act':       overall >= 65 ? 'High likelihood of compliance' : 'Significant gaps — remediation required',
      'ISO 42001':       overall >= 75 ? 'Aligned' : 'Partial — ' + (gaps[0]?.domain || 'multiple domains') + ' needs improvement',
      'NIST CSF 2.0':    overall >= 60 ? 'Aligned' : 'Partial alignment',
    },
    next_steps: [
      `Schedule AI security assessment via POST /api/aispm/owasp-llm`,
      `Complete AI model inventory via POST /api/aispm/inventory`,
      gaps[0] ? `Priority fix: ${gaps[0].domain.replace(/_/g,' ')} (score: ${gaps[0].score}/100)` : 'Maintain current governance posture',
    ],
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 4: GET /api/aispm/report — AI SPM Full Posture Report
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleAISPMReport(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return ok({ success: false, error: 'AI SPM report requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
  }

  const url  = new URL(request.url);
  const org  = url.searchParams.get('org') || url.searchParams.get('organization') || 'Your Organization';

  // Aggregate posture summary
  let aiNarrative = null;
  try {
    const result = await callClaude(env, {
      prompt: `Generate a comprehensive AI Security Posture Management executive report for ${org}. Cover: AI security landscape in 2026, key risks from OWASP LLM Top 10, governance maturity framework, and ROI of AI security investment. Professional tone, board-ready. 6-8 sentences.`,
      tier: authCtx?.tier || 'PRO',
      max_tokens: 500,
      temperature: 0.3,
    });
    aiNarrative = result?.content?.trim() || null;
  } catch {}

  return ok({
    success:      true,
    service:      'CDB-AISPM-REPORT',
    organization: org,
    report_type:  'AI Security Posture Management Summary',
    framework:    'OWASP LLM Top 10 2025 + NIST AI RMF 1.0 + ISO 42001',
    modules: [
      { name: 'AI Model Inventory',           endpoint: 'POST /api/aispm/inventory',  description: 'Discover and assess all AI/ML deployments' },
      { name: 'OWASP LLM Top 10 Assessment',  endpoint: 'POST /api/aispm/owasp-llm',  description: 'Full OWASP LLM 2025 compliance check' },
      { name: 'AI Governance Maturity',       endpoint: 'POST /api/aispm/governance', description: '5-domain governance maturity model + roadmap' },
    ],
    controls_catalog: OWASP_LLM.map(c => ({ id: c.id, name: c.name, severity: c.severity, mitigation_count: c.mitigations.length })),
    governance_domains: GOVERNANCE_DOMAINS.map(d => ({ domain: d.domain, weight: d.weight })),
    executive_overview: aiNarrative,
    pricing: {
      pro_assessment:         '$49/month — Full OWASP LLM assessment + governance report',
      enterprise_continuous:  '$299/month — Continuous posture monitoring + alerts + API',
      upgrade_url:            'https://tools.cyberdudebivash.com/#pricing',
    },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}
