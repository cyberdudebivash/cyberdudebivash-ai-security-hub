/**
 * CYBERDUDEBIVASH AI Security Hub — DPDP Act 2023 Compliance Engine
 * India's Digital Personal Data Protection Act 2023 — AI-powered compliance automation
 *
 * GET  /api/compliance/dpdp                → overview & readiness score
 * POST /api/compliance/dpdp/assess         → full AI-powered DPDP gap assessment
 * GET  /api/compliance/dpdp/sections       → section-by-section gap analysis
 * POST /api/compliance/dpdp/ropa           → generate Record of Processing Activities
 * GET  /api/compliance/dpdp/report/:id     → get saved assessment report
 * GET  /api/compliance/dpdp/reports        → list all assessments for org
 *
 * Requires: PRO or ENTERPRISE tier
 */

import { corsHeaders } from '../middleware/cors.js';

// ─── DPDP Act 2023 Section Map ────────────────────────────────────────────────
const DPDP_SECTIONS = [
  {
    id: 'S4', title: 'Grounds for Processing Personal Data',
    description: 'Personal data may only be processed for lawful purpose with consent or legitimate use.',
    key_obligations: [
      'Obtain free, specific, informed, unconditional consent',
      'Maintain consent artefacts per Clause 6',
      'Provide notice before or at time of collection',
    ],
    evidence_required: ['Consent management system', 'Notice templates', 'Consent logs'],
  },
  {
    id: 'S5', title: 'Notice',
    description: 'Data fiduciary must give notice in clear and plain language.',
    key_obligations: [
      'Notice in English or any 8th Schedule language',
      'Describe purpose of processing',
      'List rights of Data Principal',
      'Contact details of Data Protection Officer',
    ],
    evidence_required: ['Privacy notice', 'Notice version history', 'Translation records'],
  },
  {
    id: 'S6', title: 'Consent',
    description: 'Consent must be free, specific, informed, unconditional and unambiguous.',
    key_obligations: [
      'Separate consent for each processing purpose',
      'Opt-in mechanism (no pre-ticked boxes)',
      'Withdrawal as easy as giving consent',
      'Consent manager registration (if applicable)',
    ],
    evidence_required: ['Consent UI screenshots', 'Withdrawal mechanism proof', 'Consent audit log'],
  },
  {
    id: 'S8', title: 'Obligations of Data Fiduciary',
    description: 'Data fiduciary must ensure data quality, security and purpose limitation.',
    key_obligations: [
      'Process only for stated purpose',
      'Erase data when purpose is fulfilled',
      'Implement reasonable security safeguards',
      'Notify breach to DPBI within 72 hours',
    ],
    evidence_required: ['Data retention policy', 'Security audit report', 'Breach notification SOP'],
  },
  {
    id: 'S9', title: 'Processing Children\'s Personal Data',
    description: 'Special obligations for data of children under 18.',
    key_obligations: [
      'Obtain verifiable parental consent',
      'No tracking or behavioural monitoring of children',
      'No targeted advertising to children',
    ],
    evidence_required: ['Age verification mechanism', 'Parental consent flow', 'Children data inventory'],
  },
  {
    id: 'S10', title: 'Significant Data Fiduciary',
    description: 'Additional obligations for entities processing large-scale sensitive data.',
    key_obligations: [
      'Appoint Data Protection Officer in India',
      'Conduct Data Protection Impact Assessment annually',
      'Appoint independent Data Auditor',
    ],
    evidence_required: ['DPO appointment letter', 'DPIA report', 'Auditor engagement letter'],
  },
  {
    id: 'S11', title: 'Rights of Data Principal',
    description: 'Data subjects have rights to access, correction, erasure and grievance redressal.',
    key_obligations: [
      'Right to access summary of processed data',
      'Right to correction and erasure',
      'Right to grievance redressal within 48 hours',
      'Right to nominate (in case of death/incapacity)',
    ],
    evidence_required: ['DSR portal/process', 'Grievance response SLA', 'Erasure confirmation flow'],
  },
  {
    id: 'S16', title: 'Cross-border Data Transfer',
    description: 'Transfer of personal data outside India subject to government whitelist.',
    key_obligations: [
      'Transfer only to countries on government-approved list',
      'Maintain transfer records',
      'Apply equivalent safeguards',
    ],
    evidence_required: ['Data flow map', 'Transfer agreements', 'Country whitelist compliance check'],
  },
  {
    id: 'S17', title: 'Data Protection Board',
    description: 'Accountability to DPBI — India\'s Data Protection Board of India.',
    key_obligations: [
      'Respond to DPBI inquiries within stipulated time',
      'Report significant data breaches',
      'Cooperate with audits',
    ],
    evidence_required: ['DPBI communication log', 'Breach register', 'Audit response protocol'],
  },
];

// ─── Scoring weights ──────────────────────────────────────────────────────────
const MATURITY_LEVELS = {
  0: { label: 'Non-existent', color: '#ef4444', score_range: [0, 20] },
  1: { label: 'Initial',      color: '#f97316', score_range: [21, 40] },
  2: { label: 'Developing',   color: '#eab308', score_range: [41, 60] },
  3: { label: 'Defined',      color: '#3b82f6', score_range: [61, 80] },
  4: { label: 'Managed',      color: '#8b5cf6', score_range: [81, 90] },
  5: { label: 'Optimised',    color: '#22c55e', score_range: [91, 100] },
};

function maturityFromScore(score) {
  for (const [level, m] of Object.entries(MATURITY_LEVELS)) {
    if (score >= m.score_range[0] && score <= m.score_range[1]) {
      return { level: parseInt(level), ...m };
    }
  }
  return { level: 0, ...MATURITY_LEVELS[0] };
}

function buildGapAnalysis(responses) {
  return DPDP_SECTIONS.map(section => {
    const resp = responses?.[section.id] || {};
    const implemented = resp.implemented || [];
    const gaps        = section.key_obligations.filter(o => !implemented.includes(o));
    const score       = Math.round(((section.key_obligations.length - gaps.length) / section.key_obligations.length) * 100);
    return {
      section_id:    section.id,
      title:         section.title,
      score,
      maturity:      maturityFromScore(score),
      gaps:          gaps.map(g => ({ obligation: g, remediation: `Implement and document: ${g}`, priority: score < 40 ? 'CRITICAL' : score < 70 ? 'HIGH' : 'MEDIUM' })),
      evidence_required: section.evidence_required,
      compliant:     gaps.length === 0,
    };
  });
}

// ─── GET /api/compliance/dpdp — overview ─────────────────────────────────────
export async function handleDPDPOverview(request, env, authCtx) {
  const headers = corsHeaders(request);
  const tier = authCtx?.tier || 'FREE';
  if (!['PRO', 'ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'DPDP Compliance Engine requires PRO or ENTERPRISE tier.', upgrade_url: '/pricing' }, { status: 403 });
  }

  const orgId = authCtx?.org_id || authCtx?.user_id || authCtx?.userId;

  // Load latest assessment from D1
  let latest = null;
  try {
    latest = await env.DB.prepare(
      `SELECT * FROM report_jobs WHERE type = 'dpdp_assessment' AND user_id = ?
       ORDER BY created_at DESC LIMIT 1`
    ).bind(orgId).first();
  } catch (_) {}

  const overview = {
    framework:        'Digital Personal Data Protection Act 2023 (India)',
    act_ref:          'Ministry of Electronics and Information Technology (MeitY)',
    enforcement_date: '2025-Q1 (expected)',
    total_sections:   DPDP_SECTIONS.length,
    sections: DPDP_SECTIONS.map(s => ({ id: s.id, title: s.title, obligations_count: s.key_obligations.length })),
    latest_assessment: latest ? {
      id:         latest.id,
      score:      latest.result_score,
      assessed_at: latest.completed_at,
      status:     latest.status,
    } : null,
    services: [
      { name: 'Full DPDP Gap Assessment',     endpoint: 'POST /api/compliance/dpdp/assess',   price: '₹75,000 one-time or included in ENTERPRISE' },
      { name: 'Record of Processing Activities (RoPA)', endpoint: 'POST /api/compliance/dpdp/ropa', price: 'Included in PRO+' },
      { name: 'Section-by-section Analysis',  endpoint: 'GET /api/compliance/dpdp/sections',  price: 'Included in PRO+' },
      { name: 'Annual Retainer',               endpoint: 'Contact sales',                       price: '₹1,50,000/year' },
    ],
  };

  return Response.json({ success: true, data: overview }, { headers: { ...headers, 'Content-Type': 'application/json' } });
}

// ─── POST /api/compliance/dpdp/assess — run AI-powered DPDP assessment ───────
export async function handleDPDPAssess(request, env, authCtx) {
  const headers = corsHeaders(request);
  const tier = authCtx?.tier || 'FREE';
  if (!['PRO', 'ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'PRO or ENTERPRISE required.', upgrade_url: '/pricing' }, { status: 403 });
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}

  const {
    org_name       = 'Your Organisation',
    industry       = 'Technology',
    employee_count = null,
    data_categories = [],     // e.g. ['email', 'financial', 'health', 'biometric']
    processing_countries = [], // countries where data is processed
    has_children_data = false,
    has_dpo = false,
    has_privacy_notice = false,
    has_consent_mechanism = false,
    has_dsr_process = false,
    has_breach_process = false,
    has_data_retention_policy = false,
    has_security_audit = false,
  } = body;

  const userId = authCtx?.user_id || authCtx?.userId;
  const assessId = 'dpdp_' + Date.now().toString(36) + '_' + crypto.randomUUID().slice(0, 8);

  // Build section scores from questionnaire
  const sectionResponses = {
    S4: { implemented: has_consent_mechanism ? ['Obtain free, specific, informed, unconditional consent', 'Provide notice before or at time of collection'] : [] },
    S5: { implemented: has_privacy_notice ? ['Notice in English or any 8th Schedule language', 'Describe purpose of processing', 'List rights of Data Principal'] : [] },
    S6: { implemented: has_consent_mechanism ? ['Separate consent for each processing purpose', 'Opt-in mechanism (no pre-ticked boxes)', 'Withdrawal as easy as giving consent'] : [] },
    S8: { implemented: [
      ...(has_data_retention_policy ? ['Process only for stated purpose', 'Erase data when purpose is fulfilled'] : []),
      ...(has_security_audit ? ['Implement reasonable security safeguards'] : []),
      ...(has_breach_process ? ['Notify breach to DPBI within 72 hours'] : []),
    ]},
    S9: { implemented: has_children_data ? [] : ['No tracking or behavioural monitoring of children', 'No targeted advertising to children'] },
    S10: { implemented: [
      ...(has_dpo ? ['Appoint Data Protection Officer in India'] : []),
    ]},
    S11: { implemented: has_dsr_process ? ['Right to access summary of processed data', 'Right to correction and erasure', 'Right to grievance redressal within 48 hours'] : [] },
    S16: { implemented: processing_countries.length === 0 || (processing_countries.length === 1 && processing_countries[0] === 'IN') ? ['Transfer only to countries on government-approved list', 'Apply equivalent safeguards'] : [] },
    S17: { implemented: has_breach_process ? ['Respond to DPBI inquiries within stipulated time', 'Report significant data breaches'] : [] },
  };

  const gapAnalysis  = buildGapAnalysis(sectionResponses);
  const totalScore   = Math.round(gapAnalysis.reduce((s, g) => s + g.score, 0) / gapAnalysis.length);
  const maturity     = maturityFromScore(totalScore);
  const criticalGaps = gapAnalysis.filter(g => g.gaps.some(gap => gap.priority === 'CRITICAL'));
  const highGaps     = gapAnalysis.filter(g => g.gaps.some(gap => gap.priority === 'HIGH'));

  // Build AI-powered remediation roadmap
  const remediation_roadmap = [
    {
      phase: 1, timeline: '0-30 days', title: 'Foundation',
      actions: criticalGaps.flatMap(g => g.gaps.slice(0, 2).map(gap => ({
        section: g.section_id,
        action:  gap.obligation,
        effort:  'High',
        impact:  'Critical — required for basic DPDP compliance',
      }))).slice(0, 5),
    },
    {
      phase: 2, timeline: '30-90 days', title: 'Core Controls',
      actions: highGaps.flatMap(g => g.gaps.slice(0, 2).map(gap => ({
        section: g.section_id,
        action:  gap.obligation,
        effort:  'Medium',
        impact:  'High — reduces regulatory exposure',
      }))).slice(0, 5),
    },
    {
      phase: 3, timeline: '90-180 days', title: 'Optimisation',
      actions: [
        { section: 'S10', action: 'Conduct annual Data Protection Impact Assessment', effort: 'High', impact: 'Required for Significant Data Fiduciaries' },
        { section: 'S6',  action: 'Integrate consent management platform', effort: 'Medium', impact: 'Automates consent lifecycle' },
        { section: 'S11', action: 'Launch self-service Data Subject Rights portal', effort: 'Medium', impact: 'Reduces DSR response time' },
      ],
    },
  ];

  const report = {
    id:            assessId,
    org_name,
    industry,
    assessed_at:   new Date().toISOString(),
    overall_score: totalScore,
    maturity,
    ready_for_enforcement: totalScore >= 70,
    summary: {
      compliant_sections: gapAnalysis.filter(g => g.compliant).length,
      non_compliant:      gapAnalysis.filter(g => !g.compliant).length,
      critical_gaps:      criticalGaps.length,
      high_gaps:          highGaps.length,
      total_sections:     DPDP_SECTIONS.length,
    },
    data_categories,
    has_cross_border_transfer: processing_countries.some(c => c !== 'IN'),
    is_significant_fiduciary: data_categories.includes('biometric') || data_categories.includes('health') || (employee_count && employee_count > 500),
    gap_analysis:         gapAnalysis,
    remediation_roadmap,
    estimated_compliance_cost: {
      one_time_audit:   '₹75,000',
      annual_retainer:  '₹1,50,000',
      consent_platform: '₹25,000–₹1,00,000',
      dpo_appointment:  'Internal or ₹5,00,000–₹15,00,000/yr (outsourced)',
    },
    next_steps: [
      { step: 1, action: 'Download this report and share with your Legal + DPO team' },
      { step: 2, action: 'Prioritise Section 8 (security safeguards) and Section 6 (consent) first' },
      { step: 3, action: 'Generate your RoPA via POST /api/compliance/dpdp/ropa' },
      { step: 4, action: 'Schedule annual DPDP retainer — contact bivash@cyberdudebivash.com' },
    ],
    generated_by: 'CYBERDUDEBIVASH AI Security Hub — DPDP Compliance Engine v1.0',
  };

  // Persist to D1
  if (env.DB && userId) {
    await env.DB.prepare(
      `INSERT INTO report_jobs (id, type, user_id, status, result_score, result_json, created_at, completed_at)
       VALUES (?, 'dpdp_assessment', ?, 'completed', ?, ?, datetime('now'), datetime('now'))`
    ).bind(assessId, userId, totalScore, JSON.stringify(report)).run().catch(() => {});
  }

  return Response.json({ success: true, data: report }, {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

// ─── GET /api/compliance/dpdp/sections — section-by-section gap analysis ─────
export async function handleDPDPSections(request, env, authCtx) {
  const headers = corsHeaders(request);
  const tier = authCtx?.tier || 'FREE';
  if (!['PRO', 'ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'PRO or ENTERPRISE required.' }, { status: 403 });
  }

  return Response.json({
    success: true,
    data: {
      framework: 'DPDP Act 2023',
      sections:  DPDP_SECTIONS.map(s => ({
        ...s,
        maturity_levels: Object.values(MATURITY_LEVELS),
      })),
      total_sections:    DPDP_SECTIONS.length,
      total_obligations: DPDP_SECTIONS.reduce((n, s) => n + s.key_obligations.length, 0),
      assessment_url:    'POST /api/compliance/dpdp/assess',
    },
  }, { headers: { ...headers, 'Content-Type': 'application/json' } });
}

// ─── POST /api/compliance/dpdp/ropa — generate Record of Processing Activities ─
export async function handleDPDPRoPA(request, env, authCtx) {
  const headers = corsHeaders(request);
  const tier = authCtx?.tier || 'FREE';
  if (!['PRO', 'ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'PRO or ENTERPRISE required.' }, { status: 403 });
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}

  const {
    org_name         = 'Your Organisation',
    org_gstin        = '',
    dpo_name         = '',
    dpo_email        = '',
    processing_activities = [],
  } = body;

  const ropaId = 'ropa_' + Date.now().toString(36);

  // Generate structured RoPA entries
  const defaultActivities = [
    { activity: 'Customer Account Management', purpose: 'Provide platform access and billing', categories: ['email', 'name', 'company'], legal_basis: 'Consent (S4)', retention: '7 years post-account closure', recipients: ['Internal teams', 'Razorpay (payments)'], cross_border: false },
    { activity: 'Security Scanning & Threat Intel', purpose: 'Deliver contracted security services', categories: ['domain', 'ip_address', 'scan_results'], legal_basis: 'Contract performance (S7)', retention: '3 years', recipients: ['Internal', 'VirusTotal API', 'Shodan'], cross_border: true },
    { activity: 'Email Marketing', purpose: 'Send product updates and security alerts', categories: ['email', 'name'], legal_basis: 'Consent (S4)', retention: 'Until withdrawal of consent', recipients: ['Resend (email service)'], cross_border: true },
    { activity: 'Analytics & Platform Improvement', purpose: 'Monitor platform usage and improve features', categories: ['usage_data', 'ip_address'], legal_basis: 'Legitimate interest (S7)', retention: '12 months', recipients: ['Internal analytics'], cross_border: false },
  ];

  const activities = processing_activities.length > 0 ? processing_activities : defaultActivities;

  const ropaDocument = {
    id:             ropaId,
    document_title: 'Record of Processing Activities (RoPA)',
    prepared_for:   org_name,
    org_gstin,
    dpo: { name: dpo_name, email: dpo_email },
    act_ref:        'DPDP Act 2023, Section 8(5)',
    generated_at:   new Date().toISOString(),
    version:        '1.0',
    review_due:     new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString().slice(0, 10),
    processing_activities: activities.map((a, i) => ({
      sr_no:          i + 1,
      activity_name:  a.activity,
      purpose:        a.purpose,
      data_categories: a.categories,
      data_principals: 'Customers, Employees (as applicable)',
      legal_basis:    a.legal_basis,
      retention:      a.retention,
      recipients:     a.recipients,
      cross_border_transfer: a.cross_border,
      safeguards:    'TLS 1.3 encryption in transit, AES-256 at rest, role-based access control',
      last_reviewed: new Date().toISOString().slice(0, 10),
    })),
    certification: {
      text: `This RoPA has been prepared in accordance with the Digital Personal Data Protection Act 2023 (India) and represents an accurate record of personal data processing activities conducted by ${org_name}.`,
      prepared_by: 'CYBERDUDEBIVASH AI Security Hub — Automated RoPA Engine',
    },
    download_hint: 'This JSON document may be submitted to auditors or DPBI inspectors as evidence of compliance.',
  };

  // Persist
  const userId = authCtx?.user_id || authCtx?.userId;
  if (env.DB && userId) {
    await env.DB.prepare(
      `INSERT INTO report_jobs (id, type, user_id, status, result_score, result_json, created_at, completed_at)
       VALUES (?, 'dpdp_ropa', ?, 'completed', 100, ?, datetime('now'), datetime('now'))`
    ).bind(ropaId, userId, JSON.stringify(ropaDocument)).run().catch(() => {});
  }

  return Response.json({ success: true, data: ropaDocument }, {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

// ─── GET /api/compliance/dpdp/reports — list saved assessments ───────────────
export async function handleDPDPReports(request, env, authCtx) {
  const headers = corsHeaders(request);
  const userId = authCtx?.user_id || authCtx?.userId;
  if (!userId) return Response.json({ error: 'Authentication required.' }, { status: 401 });

  let reports = [];
  try {
    const rows = await env.DB.prepare(
      `SELECT id, type, status, result_score, created_at, completed_at FROM report_jobs
       WHERE user_id = ? AND type LIKE 'dpdp%' ORDER BY created_at DESC LIMIT 20`
    ).bind(userId).all();
    reports = rows?.results || [];
  } catch (_) {}

  return Response.json({ success: true, data: { reports, total: reports.length } }, {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

// ─── GET /api/compliance/dpdp/report/:id — get specific assessment ────────────
export async function handleDPDPReport(request, env, authCtx, reportId) {
  const headers = corsHeaders(request);
  const userId = authCtx?.user_id || authCtx?.userId;
  if (!userId) return Response.json({ error: 'Authentication required.' }, { status: 401 });

  let row = null;
  try {
    row = await env.DB.prepare(
      `SELECT * FROM report_jobs WHERE id = ? AND user_id = ?`
    ).bind(reportId, userId).first();
  } catch (_) {}

  if (!row) return Response.json({ error: 'Report not found.' }, { status: 404 });

  let result = row.result_json;
  try { result = JSON.parse(row.result_json); } catch (_) {}

  return Response.json({ success: true, data: result }, {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}
