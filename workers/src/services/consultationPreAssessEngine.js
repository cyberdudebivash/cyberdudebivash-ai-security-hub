/**
 * CYBERDUDEBIVASH AI Security Hub — Consultation Pre-Assessment Engine v1.0
 * Services:
 *   CDB-CONSULT-001 (₹999)  — Cybersecurity & AI Security Consultation
 *   CDB-AISEC-001  (₹1,999) — AI Security Consultation (Premium)
 *   CDB-TI-001     (₹2,999) — Threat Intelligence Advisory Call
 *   CDB-SHC-001    (₹999)   — Security Hiring & Career Guidance
 *
 * Generates a comprehensive pre-assessment brief so the human consultant
 * arrives fully prepared with MYTHOS AI intelligence, reducing consultation
 * time and elevating session quality to enterprise-grade precision.
 */

import { enrichAssessmentWithMYTHOS } from './mythosEnrichmentEngine.js';

// ── Domain knowledge bases ────────────────────────────────────────────────────
const SECURITY_CAREER_ROADMAPS = {
  soc_analyst: {
    role:        'SOC Analyst (Tier 1-3)',
    certifications: ['CompTIA Security+', 'CompTIA CySA+', 'CEH', 'GCIA', 'GCIH'],
    skills:         ['SIEM analysis', 'Incident triage', 'Threat hunting', 'Log analysis', 'EDR tools'],
    salary_range:   '₹4L–₹18L (India) / $55K–$95K (US)',
    timeline:       '3–6 months for Tier 1 readiness',
    resources:      ['TryHackMe', 'SANS Blue Team Training', 'Splunk Free Training', 'Security Blue Team courses'],
  },
  penetration_tester: {
    role:        'Penetration Tester',
    certifications: ['OSCP', 'CEH', 'CompTIA PenTest+', 'eJPT', 'GPEN'],
    skills:         ['Kali Linux', 'Web app testing', 'Network pentesting', 'Exploit development', 'Report writing'],
    salary_range:   '₹6L–₹30L (India) / $70K–$130K (US)',
    timeline:       '6–18 months',
    resources:      ['HTB Academy', 'PortSwigger Web Security', 'TCM Security', 'OWASP Testing Guide'],
  },
  cloud_security_engineer: {
    role:        'Cloud Security Engineer',
    certifications: ['AWS Security Specialty', 'GCP PCSE', 'Azure Security AZ-500', 'CCSP', 'CCSK'],
    skills:         ['IAM', 'Cloud-native security', 'IaC security', 'Container security', 'Zero Trust'],
    salary_range:   '₹12L–₹40L (India) / $100K–$180K (US)',
    timeline:       '6–12 months with cloud background',
    resources:      ['AWS Security Training', 'Cloud Security Alliance', 'A Cloud Guru', 'Pluralsight'],
  },
  ciso: {
    role:        'CISO / Security Manager',
    certifications: ['CISSP', 'CISM', 'CISO Executive Program', 'MBA with Security Focus'],
    skills:         ['Risk management', 'Security strategy', 'Board communication', 'Compliance', 'Team leadership'],
    salary_range:   '₹30L–₹1Cr+ (India) / $150K–$350K (US)',
    timeline:       '10–20 years experience pathway',
    resources:      ['ISC2 CISSP Study', 'ISACA CISM', 'SANS CISO Training', 'Executive security programs'],
  },
};

const AI_SECURITY_TOPICS = [
  { topic: 'LLM Security',          priority: 1, coverage: 'Prompt injection, jailbreaking, data poisoning, model extraction' },
  { topic: 'AI Red Teaming',         priority: 2, coverage: 'Adversarial testing, model robustness, attack simulation' },
  { topic: 'EU AI Act Compliance',   priority: 3, coverage: 'Risk classification, conformity assessment, technical documentation' },
  { topic: 'OWASP LLM Top 10',       priority: 4, coverage: 'LLM01-LLM10 2025 — all critical LLM vulnerability categories' },
  { topic: 'AI Supply Chain',        priority: 5, coverage: 'Model provenance, dataset integrity, third-party model risk' },
  { topic: 'Agentic AI Security',    priority: 6, coverage: 'Autonomous agent attack surfaces, tool use risk, privilege escalation' },
  { topic: 'AI Governance Frameworks',priority: 7, coverage: 'NIST AI RMF, ISO 42001, EU AI Act implementation' },
];

const THREAT_INTEL_BRIEFING_TOPICS = [
  { topic: 'Current Threat Landscape',    content: 'Active ransomware groups, APT campaigns, geopolitical threat actors' },
  { topic: 'Industry-Specific Threats',   content: 'Sector-targeted campaigns, supply chain attacks, insider threat trends' },
  { topic: 'Emerging Attack Vectors',     content: 'AI-powered attacks, zero-day exploitation trends, cloud-native threats' },
  { topic: 'Threat Actor Profiles',       content: 'Top 5 APT groups, cybercriminal organizations, state-sponsored actors' },
  { topic: 'IOC Intelligence',            content: 'Malware families, C2 infrastructure, phishing campaigns' },
  { topic: 'Defensive Intelligence',      content: 'Detection signatures, threat hunting pivots, MITRE ATT&CK coverage' },
];

// ── Generate pre-assessment brief for general consultation ────────────────────
function buildConsultationBrief(inputs) {
  const domain     = inputs.domain || inputs.target_domain || '';
  const industry   = inputs.target_industry || inputs.industry || 'Technology';
  const concerns   = inputs.security_concerns || inputs.requirements || 'General security posture assessment';
  const company    = inputs.company || inputs.customer_name || 'Your Organization';
  const org_size   = inputs.company_size || 'SME';

  // Industry risk profile
  const INDUSTRY_RISK = {
    Finance:     { risk: 'HIGH',   top_threats: ['Ransomware', 'Business Email Compromise', 'Card fraud', 'API attacks'] },
    Healthcare:  { risk: 'HIGH',   top_threats: ['Ransomware', 'Patient data theft', 'IoT device attacks', 'Phishing'] },
    Technology:  { risk: 'MEDIUM', top_threats: ['Supply chain attacks', 'Credential theft', 'API abuse', 'Insider threats'] },
    Government:  { risk: 'HIGH',   top_threats: ['Nation-state APTs', 'Ransomware', 'Data exfiltration', 'Phishing'] },
    Retail:      { risk: 'MEDIUM', top_threats: ['Card skimming', 'Account takeover', 'API fraud', 'DDoS'] },
    General:     { risk: 'MEDIUM', top_threats: ['Ransomware', 'Phishing', 'Credential theft', 'Supply chain'] },
  };

  const riskProfile = INDUSTRY_RISK[industry] || INDUSTRY_RISK.General;

  // Generate agenda
  const agenda = [
    { item: 1, topic: 'Organization Security Posture Overview', duration: '5 min' },
    { item: 2, topic: `${industry} Threat Landscape & Current Risks`, duration: '10 min' },
    { item: 3, topic: `Address: ${(concerns || '').slice(0, 80)}`, duration: '10 min' },
    { item: 4, topic: 'Priority Actions & Quick Wins', duration: '8 min' },
    { item: 5, topic: 'Strategic Roadmap & Next Steps', duration: '5 min' },
    { item: 6, topic: 'Q&A', duration: '2 min' },
  ];

  return {
    organization:    company,
    org_size,
    domain,
    industry,
    risk_profile:    riskProfile,
    stated_concerns: concerns,
    recommended_agenda: agenda,
    pre_read_materials: [
      `Current ${industry} threat landscape report`,
      'OWASP Top 10 2024 summary',
      'CISA Known Exploited Vulnerabilities relevant to the industry',
    ],
  };
}

// ── Generate AI security consultation brief ───────────────────────────────────
function buildAISecurityConsultBrief(inputs) {
  const ai_systems    = inputs.ai_systems || inputs.ai_use_cases || 'LLM-based application';
  const domain        = inputs.domain || '';
  const focus_areas   = inputs.focus_areas || AI_SECURITY_TOPICS.slice(0, 5).map(t => t.topic);

  return {
    ai_systems_in_scope: typeof ai_systems === 'string' ? [ai_systems] : ai_systems,
    assessment_agenda: AI_SECURITY_TOPICS.slice(0, 6),
    regulatory_context: {
      eu_ai_act_applicable: !!inputs.eu_operations,
      nist_ai_rmf:          'Applicable to all AI deployments',
      owasp_llm_top10:      'LLM01:2025–LLM10:2025 assessment framework',
    },
    key_questions: [
      'What data is your AI/LLM processing? Does it include PII or sensitive data?',
      'How are prompts sanitized before reaching the model?',
      'What is your model fine-tuning and training data governance process?',
      'Do you have human oversight and kill-switch capability?',
      'What third-party AI APIs or models are integrated?',
      'Have you conducted adversarial testing or red-team exercises?',
    ],
    recommended_tools: [
      'Garak — LLM vulnerability scanner',
      'LLM-Guard — input/output validation',
      'PromptBench — adversarial robustness testing',
      'OWASP AI Security Testing Guide',
    ],
  };
}

// ── Generate threat intel advisory brief ─────────────────────────────────────
function buildThreatIntelBrief(inputs) {
  const industry  = inputs.target_industry || inputs.industry || 'Technology';
  const domain    = inputs.domain || '';

  return {
    briefing_scope: THREAT_INTEL_BRIEFING_TOPICS,
    industry_focus: industry,
    session_structure: [
      { segment: 1, topic: 'Current Active Campaigns',    duration: '10 min', content: 'Live threat actor activity and ongoing campaigns' },
      { segment: 2, topic: 'Industry Threat Deep-Dive',   duration: '15 min', content: `${industry}-specific threat actors and TTPs` },
      { segment: 3, topic: 'IOC Intelligence Review',     duration: '10 min', content: 'Indicators of compromise relevant to your stack' },
      { segment: 4, topic: 'Detection & Hunting Pivots',  duration: '15 min', content: 'Actionable SIEM queries and hunt hypotheses' },
      { segment: 5, topic: 'Strategic Recommendations',   duration: '10 min', content: 'Defensive priorities and threat mitigation' },
    ],
    intel_sources_covered: ['CISA KEV', 'MITRE ATT&CK v15', 'OSINT feeds', 'Dark web monitoring', 'ISACs'],
    deliverables: ['Session summary PDF', 'IOC list (if applicable)', '30-day threat outlook', 'Detection rule recommendations'],
  };
}

// ── Generate career guidance brief ───────────────────────────────────────────
function buildCareerGuidanceBrief(inputs) {
  const target_role = inputs.target_role || inputs.career_goal || 'soc_analyst';
  const experience  = inputs.experience_years || 0;
  const background  = inputs.background || 'IT/Technical';
  const key         = Object.keys(SECURITY_CAREER_ROADMAPS).find(k =>
    target_role.toLowerCase().includes(k.replace('_', ' ').toLowerCase())
  ) || 'soc_analyst';
  const roadmap = SECURITY_CAREER_ROADMAPS[key];

  return {
    target_role:     roadmap.role,
    current_background: background,
    experience_years: experience,
    recommended_roadmap: roadmap,
    session_agenda: [
      { item: 1, topic: 'Skills gap analysis based on your background',  duration: '10 min' },
      { item: 2, topic: 'Certification roadmap and priority order',      duration: '10 min' },
      { item: 3, topic: 'Job market insights and salary benchmarks',     duration: '10 min' },
      { item: 4, topic: 'Learning resources and study plan',             duration: '10 min' },
      { item: 5, topic: 'Resume and LinkedIn review highlights',         duration: '5 min' },
      { item: 6, topic: '30-60-90 day action plan',                      duration: '5 min' },
    ],
    quick_wins: [
      'Start TryHackMe beginner path this week',
      'Apply for CompTIA Security+ exam within 30 days',
      'Build a home lab (VirtualBox + Kali + vulnerable VMs)',
      'Create GitHub with security projects and CTF write-ups',
    ],
  };
}

// ═════════════════════════════════════════════════════════════════════════════
export async function runConsultationPreAssessment(env, inputs, orderId = null, serviceRef = 'CDB-CONSULT-001') {
  const startedAt = new Date().toISOString();
  const customer  = inputs.customer_name || 'Customer';

  // Select brief type based on service
  let serviceBrief;
  let service_name;
  let findings = [];

  switch (serviceRef) {
    case 'CDB-AISEC-001':
      service_name = 'AI Security Consultation (Premium)';
      serviceBrief = buildAISecurityConsultBrief(inputs);
      // Add pre-assessment findings to inform consultant
      if (inputs.domain) {
        findings = AI_SECURITY_TOPICS.slice(0, 3).map((t, i) => ({
          id:          `CONSULT-AISEC-${i + 1}`,
          severity:    i === 0 ? 'HIGH' : 'MEDIUM',
          category:    'AI Security Pre-Assessment',
          title:       `Review Required: ${t.topic}`,
          description: t.coverage,
          remediation: `Address during consultation session`,
          cvss:        i === 0 ? 7.0 : 5.5,
        }));
      }
      break;

    case 'CDB-TI-001':
      service_name = 'Threat Intelligence Advisory Call';
      serviceBrief = buildThreatIntelBrief(inputs);
      break;

    case 'CDB-SHC-001':
      service_name = 'Security Hiring & Career Guidance';
      serviceBrief = buildCareerGuidanceBrief(inputs);
      break;

    default: // CDB-CONSULT-001
      service_name = 'Cybersecurity & AI Security Consultation';
      serviceBrief = buildConsultationBrief(inputs);
      // Quick domain findings if domain provided
      if (inputs.domain) {
        findings = [{
          id:          'CONSULT-DOMAIN-PREP',
          severity:    'MEDIUM',
          category:    'Pre-Assessment',
          title:       `Domain ${inputs.domain} queued for quick-scan briefing`,
          description: `Quick security scan of ${inputs.domain} will be conducted before the consultation session.`,
          remediation: `Full SSL and exposure assessment provided in consultation prep`,
          cvss:        4.0,
        }];
      }
  }

  const report = {
    meta: {
      service:       serviceRef,
      service_name,
      version:       '1.0',
      customer,
      generated_at:  startedAt,
      report_type:   'PRE-ASSESSMENT INTELLIGENCE BRIEF',
      powered_by:    'CYBERDUDEBIVASH AI Security Hub™ | MYTHOS AI Engine',
      note:          'This pre-assessment brief prepares the consultant and customer for a high-value session.',
    },
    executive_summary: {
      status:        'CONSULTATION SCHEDULED',
      brief_type:    service_name,
      customer,
      prepared_at:   startedAt,
      session_ready: true,
    },
    service_brief:   serviceBrief,
    findings:        findings.length > 0 ? findings : [],
    consultation_checklist: [
      'Review pre-assessment brief before session',
      'Prepare specific questions about listed concerns',
      'Have access to your security tools/dashboards during call',
      'Note current pain points and security incidents (last 90 days)',
      'Confirm attendees and decision-makers',
    ],
    deliverables_after_session: [
      'Session summary PDF',
      'Action plan with priority recommendations',
      'Resource list and next steps',
      'Follow-up email within 24 hours',
    ],
    powered_by_mythos: true,
  };

  // Enrich with MYTHOS if findings exist
  let enrichedReport = report;
  if (findings.length > 0) {
    try {
      enrichedReport = await enrichAssessmentWithMYTHOS(env, {
        report,
        findings,
        service_name,
        service_ref: serviceRef,
        target:      inputs.domain || '',
        sector:      inputs.target_industry || 'Technology',
        tier:        'PRO',
      });
    } catch (e) {
      console.error('[ConsultationPreAssess] MYTHOS enrichment error:', e.message);
    }
  }

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
        assessId, orderId, serviceRef, inputs.domain || customer, 'complete',
        0, 'N/A',
        findings.length, 0, 0,
        JSON.stringify(findings),
        JSON.stringify(enrichedReport.consultation_checklist || []),
        JSON.stringify(enrichedReport),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='in_progress', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run(); // remains in_progress for human consultant
    } catch (e) { console.error('[ConsultationPreAssess] DB error:', e.message); }
  }

  return enrichedReport;
}
