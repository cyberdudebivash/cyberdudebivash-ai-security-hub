/**
 * CYBERDUDEBIVASH AI Security Hub — v24 Enterprise Sales OS
 * Full opportunity scoring, enhanced ICP engine, proposal factory
 */

// ─── Enhanced ICP + Opportunity Scoring Engine ────────────────────────────────
// Scores 0-100: weighted across 7 dimensions

const INDUSTRY_SCORES = {
  banking: 15, fintech: 15, insurance: 13, nbfc: 13,
  healthcare: 12, pharma: 10, hospital: 10,
  it_services: 11, saas: 12, software: 10,
  government: 9, defence: 14, psu: 9,
  ecommerce: 10, retail: 7,
  manufacturing: 7, energy: 9, telecom: 10,
  education: 6, logistics: 7,
};

const SIZE_SCORES = {
  '1-10': 1, '11-50': 5, '51-200': 10, '201-500': 13,
  '501-1000': 14, '1000+': 15,
};

const AI_ADOPTION_SCORES = {
  none: 2, exploring: 6, pilot: 10, deployed: 13, scaling: 15,
};

export function scoreEnterpriseOpportunity(lead) {
  let score = 0;
  const factors = {};

  // 1. Industry fit (0-15)
  const industry = (lead.industry || '').toLowerCase().replace(/\s+/g, '_');
  const industryScore = INDUSTRY_SCORES[industry] || 4;
  score += industryScore;
  factors.industry_fit = industryScore;

  // 2. Company size (0-15)
  const sizeScore = SIZE_SCORES[lead.company_size || ''] || 3;
  score += sizeScore;
  factors.size_fit = sizeScore;

  // 3. Security budget signal (0-15)
  const budget = lead.security_budget_inr || 0;
  const budgetScore = budget > 10000000 ? 15 : budget > 5000000 ? 12 : budget > 1000000 ? 9 : budget > 500000 ? 6 : budget > 0 ? 3 : 0;
  score += budgetScore;
  factors.budget_signal = budgetScore;

  // 4. Compliance requirements (0-15)
  const compliance = lead.compliance_needs || [];
  const highValueCompliance = ['iso27001', 'soc2', 'pci_dss', 'hipaa', 'gdpr', 'dpdp'];
  const compCount = Array.isArray(compliance)
    ? compliance.filter(c => highValueCompliance.includes(c.toLowerCase())).length
    : 0;
  const compScore = Math.min(15, compCount * 5);
  score += compScore;
  factors.compliance_needs = compScore;

  // 5. AI adoption level (0-15)
  const aiScore = AI_ADOPTION_SCORES[lead.ai_adoption_level || 'none'] || 2;
  score += aiScore;
  factors.ai_adoption = aiScore;

  // 6. Risk exposure (0-15)
  const riskMap = { critical: 15, high: 12, medium: 8, low: 4, unknown: 3 };
  const riskScore = riskMap[lead.risk_exposure || 'unknown'] || 3;
  score += riskScore;
  factors.risk_exposure = riskScore;

  // 7. MSSP potential (0-10) — could become a partner
  const msspScore = lead.mssp_potential ? Math.min(10, parseInt(lead.mssp_potential) || 0) : 0;
  score += msspScore;
  factors.mssp_potential = msspScore;

  const tier = score >= 75 ? 'A+' : score >= 60 ? 'A' : score >= 45 ? 'B' : score >= 30 ? 'C' : 'D';
  const recommended_plan = score >= 70 ? 'ENTERPRISE' : score >= 50 ? 'PRO' : 'STARTER';
  const estimated_deal_value = estimateDealValue(lead, score);

  return {
    opportunity_score:    score,
    tier,
    factors,
    recommended_plan,
    estimated_deal_inr:   estimated_deal_value,
    priority:             score >= 60 ? 'HOT' : score >= 40 ? 'WARM' : 'COLD',
    recommended_action:   getRecommendedAction(score, tier),
    mssp_candidate:       msspScore >= 7,
  };
}

function estimateDealValue(lead, score) {
  const base = { 'A+': 499900, A: 299900, B: 149900, C: 59900, D: 14900 };
  const tier = score >= 75 ? 'A+' : score >= 60 ? 'A' : score >= 45 ? 'B' : score >= 30 ? 'C' : 'D';
  const sizeMultiplier = { '1-10': 0.5, '11-50': 0.8, '51-200': 1.0, '201-500': 1.5, '501-1000': 2.0, '1000+': 3.0 };
  return Math.round((base[tier] || 59900) * (sizeMultiplier[lead.company_size || ''] || 1.0));
}

function getRecommendedAction(score, tier) {
  if (score >= 75) return 'Schedule executive demo within 24 hours — high-value opportunity';
  if (score >= 60) return 'Send personalized proposal + book demo call this week';
  if (score >= 45) return 'Add to nurture sequence — 14-day email campaign';
  if (score >= 30) return 'Monthly check-in — monitor for trigger events';
  return 'Low priority — add to newsletter list';
}

// ─── Proposal Factory ─────────────────────────────────────────────────────────
// Generates board-ready proposals for all 6 types

const PROPOSAL_TEMPLATES = {
  ai_security: {
    title:    'AI Security Assessment & Protection',
    tagline:  'Securing Your AI Systems Against OWASP LLM Top 10 Threats',
    sections: ['executive_summary','ai_threat_landscape','owasp_assessment','implementation','pricing','roi','timeline'],
    base_price_inr: 149900,
  },
  mssp: {
    title:    'Managed Security Services Partnership',
    tagline:  'Full-Stack Cybersecurity Under Your Brand',
    sections: ['executive_summary','service_overview','client_management','white_label','billing','sla','onboarding'],
    base_price_inr: 999900,
  },
  threat_intelligence: {
    title:    'Threat Intelligence Subscription',
    tagline:  'Real-Time CVE Intelligence Powered by Sentinel APEX',
    sections: ['executive_summary','threat_landscape','intel_feeds','integration','pricing','roi'],
    base_price_inr: 49900,
  },
  compliance: {
    title:    'Compliance & Security Assessment',
    tagline:  'ISO 27001 · DPDP Act 2023 · GDPR · SOC 2 Readiness',
    sections: ['executive_summary','compliance_gaps','remediation_roadmap','deliverables','pricing','timeline'],
    base_price_inr: 99900,
  },
  retainer: {
    title:    'Annual Security Retainer',
    tagline:  'Dedicated Security Partner — 24 Consultations/Year',
    sections: ['executive_summary','retainer_scope','consultation_schedule','deliverables','pricing','sla'],
    base_price_inr: 999900,
  },
  enterprise: {
    title:    'Enterprise Security Platform',
    tagline:  'Full AI-Powered Cybersecurity Intelligence Platform',
    sections: ['executive_summary','business_risk','threat_landscape','platform_overview','implementation','pricing','roi','timeline','success_metrics'],
    base_price_inr: 599900,
  },
};

export function generateProposal(deal, type = 'enterprise', options = {}) {
  const template = PROPOSAL_TEMPLATES[type] || PROPOSAL_TEMPLATES.enterprise;
  const opp = scoreEnterpriseOpportunity(deal);
  const now = new Date();
  const validUntil = new Date(now.getTime() + 30 * 86400000).toISOString().slice(0, 10);
  const proposalId = `PROP-${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${Date.now().toString(36).toUpperCase().slice(-4)}`;

  const priceInr = options.custom_price_inr || template.base_price_inr;
  const gstAmount = Math.round(priceInr * 0.18);
  const totalInr = priceInr + gstAmount;

  const roi = {
    platform_cost_inr:    priceInr,
    avg_breach_cost_inr:  5400000, // ₹54L IBM Cost of Breach India avg
    risk_reduction_pct:   78,
    roi_multiplier:       Math.round(5400000 / priceInr),
    payback_months:       Math.round(priceInr / (5400000 / 12)),
    annual_risk_prevented: Math.round(5400000 * 0.78),
  };

  const sections = {
    executive_summary: buildExecutiveSummary(deal, opp, type),
    business_risk:     buildBusinessRisk(deal),
    threat_landscape:  buildThreatLandscape(),
    platform_overview: buildPlatformOverview(type),
    implementation:    buildImplementationRoadmap(type),
    pricing: {
      plan:           PROPOSAL_TEMPLATES[type]?.title,
      base_inr:       priceInr,
      gst_inr:        gstAmount,
      total_inr:      totalInr,
      billing:        options.billing || 'annual',
      currency_inr:   true,
      currency_usd:   Math.round(totalInr / 83),
      gst_rate:       18,
      payment_options: ['UPI', 'Bank Transfer', 'Razorpay', 'PayPal', 'Crypto'],
    },
    roi,
    timeline: {
      weeks:    template === PROPOSAL_TEMPLATES.compliance ? 3 : 4,
      phases:   buildTimeline(type),
    },
    success_metrics: buildSuccessMetrics(type),
    deliverables:    buildDeliverables(type),
    sla: {
      uptime:           '99.9%',
      critical_response: '2 hours',
      support:           'Mon–Sat 9AM–8PM IST',
      dedicated_csm:     opp.opportunity_score >= 60,
    },
  };

  return {
    proposal_id:      proposalId,
    type,
    template_title:   template.title,
    tagline:          template.tagline,
    company:          deal.company,
    contact_name:     deal.contact_name,
    contact_email:    deal.contact_email,
    contact_title:    deal.contact_title,
    opportunity_score: opp.opportunity_score,
    tier:             opp.tier,
    generated_at:     now.toISOString(),
    valid_until:      validUntil,
    revision:         1,
    sections,
    total_inr:        totalInr,
    html:             renderProposalHTML({ proposalId, deal, type, template, sections, priceInr, gstAmount, totalInr, validUntil }),
    presenter: {
      name:    'Bivash Kumar Nayak',
      title:   'Founder & Principal Security Architect',
      email:   'bivash@cyberdudebivash.com',
      phone:   '+91 8179881447',
      company: 'CYBERDUDEBIVASH PRIVATE LIMITED',
      gst:     '21ARKPN8270G1ZP',
    },
  };
}

function buildExecutiveSummary(deal, opp, type) {
  return `${deal.company || 'Your organization'} faces an evolving cybersecurity landscape with ${
    opp.tier === 'A+' || opp.tier === 'A' ? 'high' : 'growing'
  } exposure across ${(deal.compliance_needs || []).join(', ') || 'regulatory and technical'} domains. CYBERDUDEBIVASH AI Security Hub provides production-grade ${
    PROPOSAL_TEMPLATES[type]?.title?.toLowerCase() || 'security intelligence'
  } powered by Sentinel APEX v5.0 and MYTHOS AI Engine — delivering real-time threat detection, automated response, and board-ready compliance reporting from day one.`;
}

function buildBusinessRisk(deal) {
  return {
    industry_risk:     `${deal.industry || 'Your sector'} is among the top targets for APT groups in 2026`,
    compliance_risk:   (deal.compliance_needs || []).length > 0 ? `${(deal.compliance_needs || []).join(', ')} compliance gaps carry regulatory penalty risk` : 'Multiple compliance frameworks require immediate attention',
    ai_risk:           deal.ai_adoption_level !== 'none' ? 'AI systems deployed without security controls face OWASP LLM Top 10 exposure' : 'AI adoption without security frameworks creates significant future risk',
    financial_risk:    'Average breach cost in India: ₹54L (IBM 2025) — growing 12% YoY',
  };
}

function buildThreatLandscape() {
  return {
    active_apt_groups:    ['APT29 (Russia)', 'Lazarus (DPRK)', 'APT41 (China)', 'SideWinder (India focus)'],
    top_cves_2026:        ['CVE-2026-1340 (Ivanti EPMM RCE)', 'CVE-2026-20131 (Cisco FMC RCE)', 'CVE-2024-3400 (PAN-OS)'],
    attack_vectors:       ['Phishing (+340% YoY)', 'Ransomware-as-a-Service', 'Supply Chain', 'AI-assisted attacks'],
    india_specific:       'India #3 globally for cyberattacks; BFSI and healthcare top targets',
  };
}

function buildPlatformOverview(type) {
  return {
    engine:          'CYBERDUDEBIVASH® Sentinel APEX v5.0 + MYTHOS AI v3.0',
    capabilities:    ['Real-time CVE monitoring (2,400+ CVEs tracked)', 'AI threat analysis (MITRE ATT&CK)', 'SOAR rule generation (Sigma/YARA/KQL/Splunk)', 'SIEM integration (Splunk/Elastic/Sentinel)'],
    compliance_maps: ['ISO 27001:2022', 'SOC 2 Type II', 'GDPR', 'DPDP Act 2023', 'PCI-DSS v4.0', 'HIPAA'],
    deployment:      'Cloudflare Edge — India region — <50ms latency',
  };
}

function buildImplementationRoadmap(type) {
  const phases = {
    enterprise: [
      { week: 1, title: 'Onboarding & Setup', tasks: ['Account provisioning', 'Team access setup', 'SIEM integration config'] },
      { week: 2, title: 'Integration & Testing', tasks: ['API key provisioning', 'Webhook configuration', 'First threat scan'] },
      { week: 3, title: 'Go-Live & Training', tasks: ['Platform training session', 'Alert rule tuning', 'Dashboard customization'] },
      { week: 4, title: 'Optimization', tasks: ['First executive report', 'Compliance gap assessment', 'CSM check-in'] },
    ],
    mssp: [
      { week: 1, title: 'Partner Onboarding', tasks: ['White-label setup', 'Brand customization', 'Client portal creation'] },
      { week: 2, title: 'Client Migration', tasks: ['First 5 clients onboarded', 'Billing configured', 'Reports automated'] },
    ],
  };
  return phases[type] || phases.enterprise;
}

function buildTimeline(type) {
  return buildImplementationRoadmap(type);
}

function buildSuccessMetrics(type) {
  return {
    '30_days':  ['All systems integrated', 'First threat intel report delivered', 'Team trained on platform'],
    '90_days':  ['MTTD reduced by 80%', 'Compliance score > 80/100', '100% of critical CVEs patched'],
    '12_months': ['Full ISO 27001 alignment', 'Zero critical incidents undetected', 'Board-level security reporting automated'],
  };
}

function buildDeliverables(type) {
  const common = ['Platform access (SLA 99.9%)', 'Onboarding support', 'Monthly executive reports'];
  const specific = {
    enterprise:         [...common, 'Unlimited security scans', '20 API keys', 'Custom SIEM integrations', 'Dedicated CSM'],
    mssp:               [...common, 'White-label dashboard', 'Unlimited client accounts', '50% reseller margin', 'Partner Slack'],
    compliance:         [...common, '50-page gap analysis report', 'Remediation roadmap', 'Policy templates (25 docs)', '3 consultation calls'],
    threat_intelligence:[...common, 'Real-time CVE feed', 'APT attribution data', 'Custom SIGMA/YARA rules', 'STIX 2.1 feed'],
    retainer:           [...common, '24 consultation calls/year', 'Monthly threat reports', 'Priority incident response', 'C-suite briefings'],
    ai_security:        [...common, 'OWASP LLM Top 10 assessment', 'AI security policy', 'Prompt injection testing', 'AI hardening guide'],
  };
  return specific[type] || common;
}

// ─── Render full HTML proposal ────────────────────────────────────────────────
function renderProposalHTML(params) {
  const { proposalId, deal, type, template, sections, priceInr, gstAmount, totalInr, validUntil } = params;

  const deliverablesHTML = (sections.deliverables || []).map(d => `<li>✅ ${d}</li>`).join('');
  const timelineHTML = (sections.timeline?.phases || []).map(p => `
    <div style="margin-bottom:16px;padding:14px;background:#f5f3ff;border-radius:8px;border-left:4px solid #7c3aed">
      <strong>Week ${p.week}: ${p.title}</strong>
      <ul style="margin:6px 0 0 16px">${(p.tasks || []).map(t => `<li>${t}</li>`).join('')}</ul>
    </div>`).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${template.title} — ${deal.company}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; color: #1a1a2e; line-height: 1.6; }
  .cover { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: white; padding: 80px 60px; min-height: 300px; }
  .brand { font-size: 14px; color: #a78bfa; font-weight: 600; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 8px; }
  .cover h1 { font-size: 36px; font-weight: 900; margin: 16px 0 8px; }
  .cover .tagline { color: #c4b5fd; font-size: 18px; }
  .cover .meta { margin-top: 40px; font-size: 14px; color: rgba(255,255,255,0.7); }
  .section { padding: 48px 60px; border-bottom: 1px solid #f0f0f0; }
  .section h2 { font-size: 24px; font-weight: 800; color: #7c3aed; margin-bottom: 20px; }
  .highlight-box { background: #f5f3ff; border-radius: 12px; padding: 24px; margin: 20px 0; border-left: 4px solid #7c3aed; }
  .price-table { width: 100%; border-collapse: collapse; }
  .price-table th { background: #7c3aed; color: white; padding: 12px 16px; text-align: left; }
  .price-table td { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; }
  .price-table .total td { font-weight: 800; font-size: 18px; background: #f5f3ff; color: #7c3aed; }
  .cta { background: linear-gradient(135deg, #7c3aed, #6d28d9); color: white; padding: 48px 60px; text-align: center; }
  .cta h2 { font-size: 28px; margin-bottom: 16px; }
  .btn { display: inline-block; background: white; color: #7c3aed; padding: 14px 40px; border-radius: 8px; font-weight: 800; text-decoration: none; font-size: 16px; }
  ul { padding-left: 20px; }
  li { margin-bottom: 6px; }
</style>
</head>
<body>

<div class="cover">
  <div class="brand">CYBERDUDEBIVASH® AI SECURITY HUB</div>
  <h1>${template.title}</h1>
  <div class="tagline">${template.tagline}</div>
  <div class="meta">
    <p>Prepared for: <strong>${deal.company}</strong> · ${deal.contact_name || ''}</p>
    <p>Proposal ID: ${proposalId} · Valid until: ${validUntil}</p>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="highlight-box"><p>${sections.executive_summary}</p></div>
</div>

<div class="section">
  <h2>Business Risk Assessment</h2>
  <ul>
    ${Object.values(sections.business_risk || {}).map(r => `<li>${r}</li>`).join('')}
  </ul>
</div>

<div class="section">
  <h2>Key Deliverables</h2>
  <ul>${deliverablesHTML}</ul>
</div>

<div class="section">
  <h2>Implementation Timeline</h2>
  ${timelineHTML}
</div>

<div class="section">
  <h2>Investment & ROI</h2>
  <table class="price-table">
    <thead><tr><th>Item</th><th>Amount</th></tr></thead>
    <tbody>
      <tr><td>${template.title} — Annual</td><td>₹${priceInr.toLocaleString('en-IN')}</td></tr>
      <tr><td>GST @ 18%</td><td>₹${gstAmount.toLocaleString('en-IN')}</td></tr>
    </tbody>
    <tfoot><tr class="total"><td><strong>Total Investment</strong></td><td><strong>₹${totalInr.toLocaleString('en-IN')}</strong></td></tr></tfoot>
  </table>
  <div class="highlight-box" style="margin-top:20px">
    <strong>ROI: ${sections.roi?.roi_multiplier || 36}× return</strong><br>
    Platform cost vs. ₹54L average breach cost in India.<br>
    Annual risk prevented: ₹${(sections.roi?.annual_risk_prevented || 4200000).toLocaleString('en-IN')}
  </div>
</div>

<div class="cta">
  <h2>Ready to Secure Your Infrastructure?</h2>
  <p style="margin-bottom:24px;opacity:0.9">Contact us to proceed. Access activated within 2–4 hours of payment.</p>
  <a class="btn" href="mailto:bivash@cyberdudebivash.com?subject=Accept Proposal ${proposalId}">Accept Proposal</a>
  <p style="margin-top:16px;font-size:13px;opacity:0.7">bivash@cyberdudebivash.com · +91 8179881447 · CYBERDUDEBIVASH PRIVATE LIMITED · GST: 21ARKPN8270G1ZP</p>
</div>

</body></html>`;
}
