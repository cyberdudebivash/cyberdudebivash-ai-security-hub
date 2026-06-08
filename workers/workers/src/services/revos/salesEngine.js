/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Sales OS v23.0
 * ICP scoring, deal pipeline, automated proposal generation
 *
 * Routes:
 *   POST /api/revos/crm/leads       — capture + score lead
 *   GET  /api/revos/crm/pipeline    — full deal pipeline
 *   POST /api/revos/crm/deal        — create/update deal
 *   POST /api/revos/crm/propose     — generate proposal
 *   GET  /api/revos/crm/proposals   — list proposals
 *   GET  /api/revos/crm/forecast    — revenue forecast
 */

// ─── ICP Industry weights (cybersecurity buyer personas) ─────────────────────
const ICP_INDUSTRY_SCORES = {
  'banking':       25, 'fintech': 25, 'insurance': 20, 'nbfc': 20,
  'healthcare':    22, 'pharma':  18, 'hospital':  18,
  'it_services':   20, 'saas':    20, 'software':  18,
  'government':    15, 'defence': 25, 'psu':       15,
  'ecommerce':     18, 'retail':  12,
  'manufacturing': 12, 'energy':  15, 'telecom':   18,
};

const ICP_SIZE_SCORES = {
  '1-10': 2, '11-50': 8, '51-200': 15, '201-500': 20,
  '501-1000': 22, '1000+': 25,
};

const STAGE_PROBABILITY = {
  lead: 5, qualified: 20, demo: 40, proposal: 60,
  negotiation: 80, closed_won: 100, closed_lost: 0,
};

// ─── Score a lead against ICP ─────────────────────────────────────────────────
export function scoreICP(lead) {
  let score = 0;
  const breakdown = {};

  // Industry fit (0-25)
  const industry = (lead.industry || '').toLowerCase().replace(/\s+/g, '_');
  const industryScore = ICP_INDUSTRY_SCORES[industry] || 5;
  score += industryScore;
  breakdown.industry_fit = industryScore;

  // Company size fit (0-25)
  const sizeScore = ICP_SIZE_SCORES[lead.company_size || ''] || 5;
  score += sizeScore;
  breakdown.size_fit = sizeScore;

  // Tech stack signals (0-20)
  const techSignals = ['cloud', 'aws', 'gcp', 'azure', 'kubernetes', 'docker', 'api', 'saas', 'microservice'];
  const techText = `${lead.notes || ''} ${lead.website || ''} ${lead.message || ''}`.toLowerCase();
  const techScore = Math.min(20, techSignals.filter(t => techText.includes(t)).length * 4);
  score += techScore;
  breakdown.tech_stack_fit = techScore;

  // Pain signal (0-15) — security-related keywords
  const painSignals = ['breach', 'compliance', 'audit', 'security', 'vulnerability', 'gdpr', 'iso', 'dpdp', 'soc', 'pentest', 'cyber'];
  const painScore = Math.min(15, painSignals.filter(p => techText.includes(p)).length * 3);
  score += painScore;
  breakdown.pain_signal = painScore;

  // Budget signal (0-10)
  const budgetSignals = ['enterprise', 'budget', 'investment', 'priority', 'q1', 'q2', 'q3', 'q4'];
  const budgetScore = Math.min(10, budgetSignals.filter(b => techText.includes(b)).length * 3);
  score += budgetScore;
  breakdown.budget_signal = budgetScore;

  // Urgency (0-5)
  const urgencySignals = ['urgent', 'asap', 'immediately', 'critical', 'this week', 'this month'];
  const urgencyScore = Math.min(5, urgencySignals.filter(u => techText.includes(u)).length * 3);
  score += urgencyScore;
  breakdown.urgency_signal = urgencyScore;

  // Tier assignment
  const tier = score >= 70 ? 'A' : score >= 50 ? 'B' : score >= 30 ? 'C' : 'D';

  return { total_score: score, tier, ...breakdown };
}

// ─── Generate enterprise proposal content ────────────────────────────────────
export function generateProposalContent(deal, type = 'enterprise') {
  const plans = {
    ENTERPRISE:  { name: 'Enterprise', price: 4999, annual: 47988 },
    MSSP:        { name: 'MSSP Partner', price: 9999, annual: 99988 },
    ASSESSMENT:  { name: 'Security Assessment', price: 9999, annual: null },
    AI_SECURITY: { name: 'AI Security Bundle', price: 14999, annual: null },
  };

  const plan = type === 'mssp' ? plans.MSSP
    : type === 'security_assessment' ? plans.ASSESSMENT
    : type === 'ai_security' ? plans.AI_SECURITY
    : plans.ENTERPRISE;

  const now = new Date();
  const validUntil = new Date(now.getTime() + 30 * 86400000);
  const period = now.toLocaleString('en-IN', { month: 'long', year: 'numeric' });

  const roi = {
    breach_cost_avg:    5400000, // ₹54L average breach cost in India (IBM report)
    platform_cost_year: plan.annual || plan.price,
    roi_multiplier:     Math.round(5400000 / (plan.annual || plan.price * 12)),
    risk_prevented_pct: 78,
  };

  const deliverables = {
    enterprise: [
      '✅ Unlimited security scans across all 5 modules',
      '✅ Real-time threat intelligence (2,400+ CVEs tracked)',
      '✅ MYTHOS AI Analyst — unlimited queries',
      '✅ SOAR rule generation (Sigma/YARA/KQL/Splunk)',
      '✅ SIEM integration (Splunk/Elastic/Sentinel)',
      '✅ 20 API Keys + 10 user seats',
      '✅ CISO executive dashboard + board reports',
      '✅ SLA: 99.9% uptime + 2hr critical response',
      '✅ Dedicated Customer Success Manager',
      '✅ Quarterly threat landscape briefings',
    ],
    mssp: [
      '✅ Unlimited client accounts (white-label)',
      '✅ Custom domain + branding per client',
      '✅ MSSP billing & invoicing dashboard',
      '✅ 50% reseller margin on all products',
      '✅ Multi-tenant SOC command center',
      '✅ Client health scoring + risk dashboard',
      '✅ Priority support + dedicated Slack',
      '✅ Volume licensing for defense products',
      '✅ Co-branded proposals & sales materials',
      '✅ 24/7 threat intel feed access',
    ],
    security_assessment: [
      '✅ 50-page security assessment report',
      '✅ Top 10 CVEs prioritized for your stack',
      '✅ Executive risk summary (C-suite ready)',
      '✅ Remediation roadmap (90-day plan)',
      '✅ MITRE ATT&CK coverage mapping',
      '✅ Compliance gap analysis (ISO/DPDP/GDPR)',
      '✅ 1-hour consultation call with lead analyst',
      '✅ 3 custom SIGMA/YARA rules for your env',
      '✅ Delivered within 3 business days',
    ],
    ai_security: [
      '✅ OWASP LLM Top 10 full assessment',
      '✅ AI prompt injection testing',
      '✅ LLM pipeline threat modeling',
      '✅ AI system hardening guide',
      '✅ NIST AI RMF compliance mapping',
      '✅ Custom AI security policy templates',
      '✅ 30-day threat intel on AI attack vectors',
      '✅ 1-hour AI security consultation',
    ],
  }[type] || deliverables?.enterprise || [];

  return {
    proposal_id:   `PROP-${Date.now().toString(36).toUpperCase()}`,
    generated_at:  now.toISOString(),
    valid_until:   validUntil.toISOString().slice(0, 10),
    period,
    company:       deal.company,
    contact_name:  deal.contact_name,
    contact_email: deal.contact_email,
    contact_title: deal.contact_title,
    type,
    plan_name:     plan.name,
    price_monthly: plan.price,
    price_annual:  plan.annual,
    gst_rate:      18,
    price_with_gst: Math.round(plan.price * 1.18),
    annual_with_gst: plan.annual ? Math.round(plan.annual * 1.18) : null,
    deliverables,
    roi,
    implementation_timeline: [
      { week: 1, milestone: 'Account setup + team onboarding' },
      { week: 2, milestone: 'SIEM/tool integrations configured' },
      { week: 3, milestone: 'First threat intelligence report' },
      { week: 4, milestone: 'Full platform live + team trained' },
    ],
    compliance_coverage: ['ISO 27001:2022', 'SOC 2 Type II', 'GDPR', 'DPDP Act 2023', 'HIPAA', 'PCI-DSS v4.0'],
    contact: {
      name:    'Bivash Kumar Nayak',
      title:   'Founder & Lead Security Architect',
      email:   'bivash@cyberdudebivash.com',
      phone:   '+91 8179881447',
      company: 'CYBERDUDEBIVASH PRIVATE LIMITED',
      gst:     '21ARKPN8270G1ZP',
      cin:     'U74999OR2024PTC049281',
    },
  };
}

// ─── Pipeline KPIs ────────────────────────────────────────────────────────────
export async function getPipelineMetrics(db) {
  if (!db) return {};
  try {
    const [stages, forecast, recent] = await Promise.all([
      db.prepare(`
        SELECT stage, COUNT(*) as deals,
               COALESCE(SUM(deal_value_inr),0) as value,
               COALESCE(AVG(icp_score),0) as avg_icp
        FROM deal_pipeline GROUP BY stage
      `).all(),
      db.prepare(`
        SELECT
          COALESCE(SUM(deal_value_inr * probability_pct / 100), 0) as weighted_forecast,
          COALESCE(SUM(deal_value_inr), 0) as total_pipeline
        FROM deal_pipeline
        WHERE stage NOT IN ('closed_won','closed_lost')
      `).first(),
      db.prepare(`
        SELECT * FROM deal_pipeline
        ORDER BY updated_at DESC LIMIT 10
      `).all(),
    ]);

    const stageMap = {};
    for (const s of (stages.results || [])) {
      stageMap[s.stage] = { deals: s.deals, value: s.value, avg_icp: Math.round(s.avg_icp) };
    }

    const won = stageMap['closed_won'] || { deals: 0, value: 0 };
    const lost = stageMap['closed_lost'] || { deals: 0, value: 0 };
    const winRate = (won.deals + lost.deals) > 0
      ? Math.round((won.deals / (won.deals + lost.deals)) * 100) : 0;

    return {
      stages:           stageMap,
      win_rate_pct:     winRate,
      weighted_forecast: forecast?.weighted_forecast || 0,
      total_pipeline:   forecast?.total_pipeline || 0,
      recent_activity:  recent.results || [],
    };
  } catch (e) { return { error: e.message }; }
}

// ─── Forecast next 90 days revenue ───────────────────────────────────────────
export async function revenueForecast90d(db, currentMRR) {
  if (!db) return [];
  const forecast = [];
  const today = new Date();

  for (let month = 1; month <= 3; month++) {
    const d = new Date(today);
    d.setMonth(d.getMonth() + month);
    const period = d.toISOString().slice(0, 7);

    // Simple model: current MRR * (1 + expected growth - churn)
    const growthRate = 0.08; // 8% MoM target
    const churnRate = 0.02;  // 2% churn assumption
    const projectedMRR = Math.round(currentMRR * Math.pow(1 + growthRate - churnRate, month));

    // Add weighted pipeline deals expected to close
    let pipelineContrib = 0;
    try {
      const demoDeals = await db.prepare(`
        SELECT COALESCE(SUM(deal_value_inr * probability_pct / 100), 0) as val
        FROM deal_pipeline WHERE stage IN ('demo','proposal','negotiation')
      `).first();
      pipelineContrib = Math.round((demoDeals?.val || 0) / 3); // spread over 3 months
    } catch {}

    forecast.push({
      period,
      projected_mrr: projectedMRR,
      projected_arr: projectedMRR * 12,
      pipeline_contribution: pipelineContrib,
      total_projected: projectedMRR + pipelineContrib,
      confidence: month === 1 ? 'HIGH' : month === 2 ? 'MEDIUM' : 'LOW',
    });
  }

  return forecast;
}
