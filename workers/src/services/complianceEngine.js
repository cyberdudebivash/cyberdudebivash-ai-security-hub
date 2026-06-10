/**
 * CYBERDUDEBIVASH AI Security Hub — Compliance Readiness Engine v1.0
 * Service: CDB-COMP-001 (₹24,999) — ISO 27001:2022 + NIST CSF 2.0 + GDPR
 * Automated gap analysis with prioritized roadmap and executive report
 */

// ── ISO 27001:2022 Control Domains (4 themes, 93 controls) ───────────────────
const ISO27001_DOMAINS = [
  {
    id: 'A.5', name: 'Organizational Controls', controls: 37,
    questions: [
      { id: 'A.5.1',  text: 'Information security policies documented and approved by management?' },
      { id: 'A.5.2',  text: 'Information security roles and responsibilities defined?' },
      { id: 'A.5.3',  text: 'Segregation of duties implemented for conflicting functions?' },
      { id: 'A.5.7',  text: 'Threat intelligence process to collect and analyze security threats?' },
      { id: 'A.5.9',  text: 'Inventory of information assets maintained?' },
      { id: 'A.5.10', text: 'Acceptable use policy for information assets?' },
      { id: 'A.5.14', text: 'Information transfer agreements for external transfers?' },
      { id: 'A.5.23', text: 'Cloud service information security policies documented?' },
      { id: 'A.5.24', text: 'Incident management process defined and tested?' },
      { id: 'A.5.29', text: 'Business continuity plan documented and tested?' },
      { id: 'A.5.30', text: 'ICT readiness for business continuity addressed?' },
      { id: 'A.5.33', text: 'Protection of records policy and controls in place?' },
      { id: 'A.5.34', text: 'Privacy and data protection requirements met?' },
    ],
  },
  {
    id: 'A.6', name: 'People Controls', controls: 8,
    questions: [
      { id: 'A.6.1', text: 'Background verification checks for staff?' },
      { id: 'A.6.2', text: 'Employment terms include security responsibilities?' },
      { id: 'A.6.3', text: 'Security awareness training program in place?' },
      { id: 'A.6.4', text: 'Disciplinary process for security violations?' },
      { id: 'A.6.5', text: 'Responsibilities on termination/change of employment addressed?' },
      { id: 'A.6.6', text: 'Confidentiality/NDA agreements with staff and contractors?' },
      { id: 'A.6.7', text: 'Remote working security policy?' },
      { id: 'A.6.8', text: 'Incident reporting mechanism for staff?' },
    ],
  },
  {
    id: 'A.7', name: 'Physical Controls', controls: 14,
    questions: [
      { id: 'A.7.1',  text: 'Physical security perimeters defined and controlled?' },
      { id: 'A.7.2',  text: 'Physical entry controls for secure areas?' },
      { id: 'A.7.3',  text: 'Offices, rooms, facilities physically secured?' },
      { id: 'A.7.4',  text: 'Physical security monitoring (CCTV, alarms)?' },
      { id: 'A.7.5',  text: 'Protection against environmental threats (fire, flood)?' },
      { id: 'A.7.7',  text: 'Clear desk and clear screen policy enforced?' },
      { id: 'A.7.8',  text: 'Equipment siting and protection controls?' },
      { id: 'A.7.10', text: 'Storage media management policy?' },
      { id: 'A.7.13', text: 'Equipment maintenance and protection procedures?' },
    ],
  },
  {
    id: 'A.8', name: 'Technological Controls', controls: 34,
    questions: [
      { id: 'A.8.1',  text: 'User endpoint devices managed and secured?' },
      { id: 'A.8.2',  text: 'Privileged access rights managed and reviewed?' },
      { id: 'A.8.3',  text: 'Information access restricted on need-to-know basis?' },
      { id: 'A.8.4',  text: 'Access to source code restricted and controlled?' },
      { id: 'A.8.5',  text: 'Secure authentication controls (MFA) implemented?' },
      { id: 'A.8.6',  text: 'Capacity management to ensure performance?' },
      { id: 'A.8.7',  text: 'Malware protection controls deployed?' },
      { id: 'A.8.8',  text: 'Technical vulnerability management process?' },
      { id: 'A.8.9',  text: 'Configuration management for systems?' },
      { id: 'A.8.10', text: 'Information deletion and sanitization procedures?' },
      { id: 'A.8.11', text: 'Data masking implemented for sensitive data?' },
      { id: 'A.8.12', text: 'Data leakage prevention (DLP) controls?' },
      { id: 'A.8.13', text: 'Information backup procedures and testing?' },
      { id: 'A.8.15', text: 'Logging and monitoring of security events?' },
      { id: 'A.8.16', text: 'Network monitoring for anomalies?' },
      { id: 'A.8.19', text: 'Security of software in operational systems?' },
      { id: 'A.8.20', text: 'Network security management controls?' },
      { id: 'A.8.21', text: 'Security of network services?' },
      { id: 'A.8.22', text: 'Network segregation implemented?' },
      { id: 'A.8.23', text: 'Web filtering controls?' },
      { id: 'A.8.24', text: 'Cryptography key management?' },
      { id: 'A.8.25', text: 'Secure development lifecycle (SDLC) policy?' },
      { id: 'A.8.28', text: 'Secure coding practices?' },
      { id: 'A.8.29', text: 'Security testing in development and acceptance?' },
      { id: 'A.8.30', text: 'Outsourced development security?' },
      { id: 'A.8.31', text: 'Separation of development, testing, production?' },
      { id: 'A.8.34', text: 'Audit controls and information systems security?' },
    ],
  },
];

// ── NIST CSF 2.0 Functions ────────────────────────────────────────────────────
const NIST_CSF_FUNCTIONS = [
  {
    id: 'GV', name: 'GOVERN', description: 'Establish and monitor cybersecurity risk management strategy',
    categories: ['GV.OC', 'GV.RM', 'GV.RR', 'GV.PO', 'GV.OV', 'GV.SC'],
    key_questions: [
      'Is cybersecurity risk embedded in enterprise risk management?',
      'Are cybersecurity roles and responsibilities defined?',
      'Is a cybersecurity policy established and communicated?',
      'Are supply chain cybersecurity risks managed?',
    ],
  },
  {
    id: 'ID', name: 'IDENTIFY', description: 'Understand cybersecurity risks to systems, people, assets, data',
    categories: ['ID.AM', 'ID.RA', 'ID.IM'],
    key_questions: [
      'Is an asset inventory maintained?',
      'Are cybersecurity risks identified and assessed?',
      'Are improvement activities identified from assessments?',
    ],
  },
  {
    id: 'PR', name: 'PROTECT', description: 'Implement safeguards to manage cybersecurity risks',
    categories: ['PR.AA', 'PR.AT', 'PR.DS', 'PR.PS', 'PR.IR'],
    key_questions: [
      'Is access controlled based on least privilege?',
      'Are users trained on security awareness?',
      'Is data protected at rest and in transit?',
      'Are platforms secured and hardened?',
      'Is the technology infrastructure resilient?',
    ],
  },
  {
    id: 'DE', name: 'DETECT', description: 'Find and analyze possible cybersecurity attacks and compromises',
    categories: ['DE.CM', 'DE.AE'],
    key_questions: [
      'Is the environment monitored for anomalies?',
      'Are adverse events analyzed to characterize attacks?',
    ],
  },
  {
    id: 'RS', name: 'RESPOND', description: 'Take action regarding a detected cybersecurity incident',
    categories: ['RS.MA', 'RS.AN', 'RS.CO', 'RS.MI', 'RS.IM'],
    key_questions: [
      'Is incident management process defined?',
      'Are incidents analyzed to determine impact?',
      'Are responses coordinated with stakeholders?',
      'Are incidents mitigated and contained?',
      'Are response plans improved post-incident?',
    ],
  },
  {
    id: 'RC', name: 'RECOVER', description: 'Restore assets and operations affected by cybersecurity incidents',
    categories: ['RC.RP', 'RC.CO'],
    key_questions: [
      'Are recovery plans executed and tested?',
      'Are stakeholders informed during recovery?',
    ],
  },
];

// ── GDPR Key Articles ─────────────────────────────────────────────────────────
const GDPR_ARTICLES = [
  { article: 'Art.5',  title: 'Principles of Processing', risk: 'HIGH' },
  { article: 'Art.6',  title: 'Lawful Basis for Processing', risk: 'HIGH' },
  { article: 'Art.13-14', title: 'Transparency & Privacy Notices', risk: 'MEDIUM' },
  { article: 'Art.17', title: 'Right to Erasure', risk: 'MEDIUM' },
  { article: 'Art.25', title: 'Data Protection by Design', risk: 'HIGH' },
  { article: 'Art.32', title: 'Security of Processing', risk: 'CRITICAL' },
  { article: 'Art.33', title: 'Breach Notification (72hr)', risk: 'HIGH' },
  { article: 'Art.35', title: 'Data Protection Impact Assessment (DPIA)', risk: 'MEDIUM' },
  { article: 'Art.37', title: 'Data Protection Officer (DPO)', risk: 'MEDIUM' },
];

// ── Smart scoring using domain + inputs ───────────────────────────────────────
function scoreOrganization(inputs) {
  const {
    has_policy           = false,
    has_isms             = false,
    has_mfa              = false,
    has_backups          = false,
    has_monitoring       = false,
    has_incident_plan    = false,
    has_training         = false,
    has_asset_inventory  = false,
    has_dlp              = false,
    has_vuln_mgmt        = false,
    company_size         = 'sme',
    industry             = 'General',
  } = inputs;

  const boolScore = (v) => v === true || v === 'true' || v === '1' || v === 1;

  const controls = {
    has_policy:          { pass: boolScore(has_policy),          weight: 10, control: 'A.5.1' },
    has_isms:            { pass: boolScore(has_isms),            weight: 15, control: 'ISMS Core' },
    has_mfa:             { pass: boolScore(has_mfa),             weight: 12, control: 'A.8.5' },
    has_backups:         { pass: boolScore(has_backups),         weight: 10, control: 'A.8.13' },
    has_monitoring:      { pass: boolScore(has_monitoring),      weight: 10, control: 'A.8.15' },
    has_incident_plan:   { pass: boolScore(has_incident_plan),   weight: 10, control: 'A.5.24' },
    has_training:        { pass: boolScore(has_training),        weight: 8,  control: 'A.6.3' },
    has_asset_inventory: { pass: boolScore(has_asset_inventory), weight: 8,  control: 'A.5.9' },
    has_dlp:             { pass: boolScore(has_dlp),             weight: 7,  control: 'A.8.12' },
    has_vuln_mgmt:       { pass: boolScore(has_vuln_mgmt),       weight: 10, control: 'A.8.8' },
  };

  let earnedScore = 0;
  const maxScore  = Object.values(controls).reduce((s, c) => s + c.weight, 0);
  const gaps = [];

  for (const [key, c] of Object.entries(controls)) {
    if (c.pass) {
      earnedScore += c.weight;
    } else {
      gaps.push({
        control:    c.control,
        area:       key.replace(/has_/,'').replace(/_/g,' ').replace(/\b\w/g, l => l.toUpperCase()),
        weight:     c.weight,
        severity:   c.weight >= 12 ? 'CRITICAL' : c.weight >= 9 ? 'HIGH' : 'MEDIUM',
      });
    }
  }

  return { earnedScore, maxScore, percentage: Math.round((earnedScore / maxScore) * 100), gaps };
}

function generateRoadmap(gaps, timeline = '12_months') {
  const sorted = [...gaps].sort((a, b) => b.weight - a.weight);
  const roadmap = [
    { phase: 'Phase 1 (Months 1-2)', priority: 'CRITICAL', description: 'Foundation Controls', actions: [] },
    { phase: 'Phase 2 (Months 3-4)', priority: 'HIGH',     description: 'Core Security Controls', actions: [] },
    { phase: 'Phase 3 (Months 5-8)', priority: 'MEDIUM',   description: 'Advanced Controls', actions: [] },
    { phase: 'Phase 4 (Months 9-12)', priority: 'LOW',     description: 'Optimization & Certification', actions: [] },
  ];

  const phaseMap = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  for (const gap of sorted) {
    const p = phaseMap[gap.severity] ?? 2;
    roadmap[p].actions.push({
      control:  gap.control,
      area:     gap.area,
      action:   `Implement ${gap.area} controls (${gap.control})`,
      effort:   gap.weight >= 12 ? 'High' : gap.weight >= 9 ? 'Medium' : 'Low',
      impact:   gap.severity,
    });
  }

  return roadmap.filter(p => p.actions.length > 0);
}

export async function runComplianceAssessment(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const domain = (inputs.domain || inputs.target_domain || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const industry = inputs.industry || inputs.target_industry || 'General';

  // Score the organization
  const orgScore = scoreOrganization(inputs);
  const compliancePct = orgScore.percentage;
  const isoGap   = 100 - compliancePct;

  // Grade
  const grade = compliancePct >= 85 ? 'COMPLIANT' : compliancePct >= 65 ? 'PARTIALLY_COMPLIANT' : compliancePct >= 40 ? 'NON_COMPLIANT' : 'CRITICAL_GAPS';

  // NIST CSF scoring (domain-based + inputs)
  const nistScores = NIST_CSF_FUNCTIONS.map(fn => {
    let fnScore = 50; // baseline
    if (fn.id === 'GV' && inputs.has_policy) fnScore += 20;
    if (fn.id === 'GV' && inputs.has_isms)   fnScore += 20;
    if (fn.id === 'ID' && inputs.has_asset_inventory) fnScore += 30;
    if (fn.id === 'PR' && inputs.has_mfa)    fnScore += 15;
    if (fn.id === 'PR' && inputs.has_dlp)    fnScore += 10;
    if (fn.id === 'DE' && inputs.has_monitoring) fnScore += 30;
    if (fn.id === 'RS' && inputs.has_incident_plan) fnScore += 30;
    if (fn.id === 'RC' && inputs.has_backups) fnScore += 30;
    return { ...fn, score: Math.min(100, fnScore), tier: fnScore >= 75 ? 'Adaptive' : fnScore >= 50 ? 'Repeatable' : fnScore >= 25 ? 'Developing' : 'Partial' };
  });

  // ISO control gaps mapped to domains
  const isoDomainScores = ISO27001_DOMAINS.map(domain_ => {
    const passedQuestions = domain_.questions.filter(q => {
      // Map questions to inputs for intelligent scoring
      if (q.id.startsWith('A.5') && inputs.has_policy && q.id === 'A.5.1') return true;
      if (q.id === 'A.5.24' && inputs.has_incident_plan) return true;
      if (q.id === 'A.5.9' && inputs.has_asset_inventory) return true;
      if (q.id === 'A.6.3' && inputs.has_training) return true;
      if (q.id === 'A.8.5' && inputs.has_mfa) return true;
      if (q.id === 'A.8.7' && inputs.has_monitoring) return true;
      if (q.id === 'A.8.8' && inputs.has_vuln_mgmt) return true;
      if (q.id === 'A.8.12' && inputs.has_dlp) return true;
      if (q.id === 'A.8.13' && inputs.has_backups) return true;
      if (q.id === 'A.8.15' && inputs.has_monitoring) return true;
      return false;
    });
    const score = Math.round((passedQuestions.length / domain_.questions.length) * 100);
    return { id: domain_.id, name: domain_.name, controls: domain_.controls, score, gap: 100 - score };
  });

  // GDPR readiness (simple assessment)
  const gdprScore = [
    inputs.has_policy ? 15 : 0,
    inputs.has_isms   ? 10 : 0,
    inputs.has_incident_plan ? 20 : 0, // Art.33 breach notification
    inputs.has_dlp    ? 15 : 0,
  ].reduce((a, b) => a + b, 0); // max ~60 base; rest requires manual verification

  // Roadmap
  const roadmap = generateRoadmap(orgScore.gaps);

  // Findings
  const findings = orgScore.gaps.map(g => ({
    id:          `COMP-${g.control.replace(/[^A-Z0-9.]/gi,'-')}`,
    severity:    g.severity,
    category:    'Compliance Gap',
    title:       `Gap: ${g.area} Controls Not Implemented`,
    description: `ISO 27001:2022 control ${g.control} has not been implemented. This represents a compliance gap.`,
    framework:   'ISO 27001:2022',
    control:     g.control,
    remediation: `Implement ${g.area} controls as per ISO 27001:2022 Annex A ${g.control} requirements.`,
  }));

  const riskScore = Math.max(0, 100 - compliancePct);

  const report = {
    meta: {
      service:         'CDB-COMP-001',
      service_name:    'Compliance Readiness Assessment',
      version:         '1.0',
      domain:          domain || 'N/A',
      industry,
      generated_at:    startedAt,
      powered_by:      'CYBERDUDEBIVASH AI Security Hub™',
      classification:  'CONFIDENTIAL — Executive & Board Use',
      frameworks:      ['ISO 27001:2022', 'NIST CSF 2.0', 'GDPR'],
    },
    executive_summary: {
      overall_compliance:      compliancePct,
      compliance_status:       grade,
      iso27001_score:          compliancePct,
      nist_csf_score:          Math.round(nistScores.reduce((s, f) => s + f.score, 0) / nistScores.length),
      gdpr_readiness:          gdprScore,
      critical_gaps:           orgScore.gaps.filter(g => g.severity === 'CRITICAL').length,
      high_gaps:               orgScore.gaps.filter(g => g.severity === 'HIGH').length,
      total_controls_assessed: Object.keys(orgScore.gaps).length + (orgScore.earnedScore / (orgScore.maxScore / 93)),
      estimated_certification_timeline: compliancePct >= 65 ? '6-9 months' : compliancePct >= 40 ? '12-18 months' : '18-24 months',
    },
    iso27001_assessment: {
      overall_score:    compliancePct,
      status:           grade,
      domain_scores:    isoDomainScores,
      total_controls:   93,
      controls_passing: Math.round(93 * compliancePct / 100),
      controls_failing: Math.round(93 * (100 - compliancePct) / 100),
      gaps:             orgScore.gaps,
    },
    nist_csf_assessment: {
      overall_tier:  nistScores.filter(f => f.score >= 75).length >= 4 ? 'Adaptive (Tier 4)' : 'Repeatable (Tier 2)',
      functions:     nistScores,
      weakest_areas: nistScores.filter(f => f.score < 60).map(f => f.name),
    },
    gdpr_assessment: {
      readiness_score:    gdprScore,
      status:             gdprScore >= 80 ? 'COMPLIANT' : gdprScore >= 50 ? 'PARTIAL' : 'NON_COMPLIANT',
      key_articles:       GDPR_ARTICLES,
      breach_notification: inputs.has_incident_plan ? 'PASS' : 'FAIL — No incident plan = breach notification risk',
      data_protection:    inputs.has_dlp ? 'PASS' : 'FAIL — No DLP controls',
    },
    findings,
    certification_roadmap: roadmap,
    recommendations: [
      ...orgScore.gaps.slice(0, 5).map((g, i) => ({
        priority:  i + 1,
        category:  'ISO 27001',
        action:    `Implement ${g.area} (${g.control})`,
        effort:    g.weight >= 12 ? 'High' : 'Medium',
        impact:    g.severity,
        framework: 'ISO 27001:2022',
      })),
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
        assessId, orderId, 'CDB-COMP-001', domain || industry, 'complete',
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
    } catch (e) {
      console.error('[Compliance-Engine] DB error:', e.message);
    }
  }

  return report;
}
