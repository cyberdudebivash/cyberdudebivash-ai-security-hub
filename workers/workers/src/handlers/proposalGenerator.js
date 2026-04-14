/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Proposal Generator
 * Phase 4: ₹1CR Revenue Engine
 *
 * Auto-generates branded enterprise security proposals with:
 *   - Customized security assessment summary
 *   - ROI calculation (cost of breach vs. platform cost)
 *   - Tiered pricing recommendations
 *   - Implementation timeline
 *   - SLA & support terms
 *   - Digital signature CTA
 *
 * Endpoints:
 *   POST /api/proposals/generate            → generate proposal for a lead
 *   GET  /api/proposals                     → list all proposals (admin)
 *   GET  /api/proposals/:id                 → get proposal detail
 *   POST /api/proposals/:id/send            → mark as sent (update CRM stage)
 *   POST /api/proposals/:id/accept          → record acceptance
 *   GET  /api/proposals/packages            → public: high-ticket package catalog
 */

import { ok, fail } from '../lib/response.js';

const KV_PROPOSALS_INDEX = 'proposals:index';
const KV_PROPOSAL_PREFIX = 'proposals:doc:';

// ── High-ticket package catalog ───────────────────────────────────────────────
export const ENTERPRISE_PACKAGES = {
  STARTER_PLUS: {
    id:          'STARTER_PLUS',
    name:        'Starter Plus',
    price_inr:   49900,
    price_usd:   599,
    billing:     'annual',
    label:       '₹49,900/year',
    tagline:     'For growing startups and SMBs',
    features: [
      'Unlimited domain scans',
      'AI Threat Analyst (50 queries/day)',
      'SOAR Rule Generation (Sigma + Splunk)',
      'Email alert integration',
      'Basic API access (10K calls/month)',
      'Email support (24h SLA)',
    ],
    target:      'Startups, 10–100 employees',
    roi_metric:  '10× ROI vs. cost of a single breach',
  },
  PROFESSIONAL: {
    id:          'PROFESSIONAL',
    name:        'Professional',
    price_inr:   149900,
    price_usd:   1799,
    billing:     'annual',
    label:       '₹1,49,900/year',
    tagline:     'For mid-market security teams',
    popular:     true,
    features: [
      'Everything in Starter Plus',
      'Autonomous SOC Mode (Assisted)',
      'SIEM Integration (Splunk, Elastic, Sentinel)',
      'Organization Memory & Pattern Analysis',
      'API access (100K calls/month)',
      'Priority support (4h SLA)',
      'Monthly executive report',
      'Threat Confidence Scoring',
    ],
    target:      'Mid-market, 100–500 employees',
    roi_metric:  '25× ROI — replaces ½ FTE analyst',
  },
  ENTERPRISE_SHIELD: {
    id:          'ENTERPRISE_SHIELD',
    name:        'Enterprise Shield',
    price_inr:   499900,
    price_usd:   5999,
    billing:     'annual',
    label:       '₹4,99,900/year',
    tagline:     'Full autonomous defense for enterprises',
    features: [
      'Everything in Professional',
      'Autonomous Defense (AGGRESSIVE mode)',
      'Unlimited SIEM integrations',
      'CISO Dashboard + Board-ready reports',
      'Predictive Threat Intelligence',
      'Custom API SLA + 1M calls/month',
      '24×7 dedicated support (1h SLA)',
      'SOC analyst onboarding sessions (4/year)',
      'Custom threat model for your sector',
    ],
    target:      'Enterprises, 500–5000 employees',
    roi_metric:  '50× ROI — prevents ₹2.5CR+ average breach',
  },
  MSSP_COMMAND: {
    id:          'MSSP_COMMAND',
    name:        'MSSP Command Center',
    price_inr:   1499900,
    price_usd:   17999,
    billing:     'annual',
    label:       '₹14,99,900/year',
    tagline:     'White-label platform for MSSPs — manage 50 clients',
    features: [
      'Everything in Enterprise Shield',
      'Up to 50 managed client tenants',
      'White-label branding',
      'MSSP billing module',
      'Per-client threat dashboard',
      'Unlimited API calls',
      'Dedicated success manager',
      'Custom SLA agreements',
      'Revenue share program (up to 20%)',
      'Early access to new AI modules',
    ],
    target:      'MSSPs, system integrators, consultancies',
    roi_metric:  'Charge clients ₹5L–₹20L/yr — 10× platform ROI',
  },
  CUSTOM_ENTERPRISE: {
    id:          'CUSTOM_ENTERPRISE',
    name:        'Custom Enterprise',
    price_inr:   null,
    price_usd:   null,
    billing:     'custom',
    label:       'Custom Pricing',
    tagline:     'Bespoke deployment for large enterprises & government',
    features: [
      'On-premise or private cloud deployment',
      'Air-gapped environment support',
      'Custom threat model integration',
      'Dedicated infrastructure',
      'Custom compliance frameworks (DPDP, ISO 27001, SOC2)',
      'Government security clearance support',
      'Unlimited everything',
      'White-glove onboarding',
      'Quarterly business reviews',
    ],
    target:      'Large enterprises, government, defense, BFSI',
    roi_metric:  'Full custom ROI analysis provided',
  },
};

// ── ROI Calculator ────────────────────────────────────────────────────────────
function calculateROI(lead, packageId) {
  const pkg      = ENTERPRISE_PACKAGES[packageId];
  const pkgPrice = pkg?.price_inr || 499900;

  // Average cost of data breach in India (IBM 2024): ₹19.5CR
  // But for SMBs, realistic impact: ₹20L–₹2CR
  const sectorBreachCosts = {
    FINANCE: 20000000, BANKING: 25000000, HEALTHCARE: 18000000,
    GOVERNMENT: 15000000, ENERGY: 22000000, TECHNOLOGY: 12000000,
    RETAIL: 8000000, DEFAULT: 10000000,
  };
  const breachCost  = sectorBreachCosts[(lead.sector || '').toUpperCase()] || sectorBreachCosts.DEFAULT;
  const probability = 0.27; // 27% annual breach probability (Verizon DBIR 2024)
  const expectedLoss= Math.round(breachCost * probability);
  const roi_multiplier = Math.round(expectedLoss / pkgPrice);
  const payback_months = Math.round((pkgPrice / expectedLoss) * 12);

  return {
    annual_breach_cost_est_inr: breachCost,
    breach_probability_pct:     27,
    expected_annual_loss_inr:   expectedLoss,
    platform_cost_inr:          pkgPrice,
    roi_multiplier,
    payback_months:             Math.max(1, payback_months),
    net_savings_inr:            expectedLoss - pkgPrice,
  };
}

// ── Proposal document builder ─────────────────────────────────────────────────
function buildProposalDocument(lead, packageId, customizations = {}) {
  const pkg = ENTERPRISE_PACKAGES[packageId] || ENTERPRISE_PACKAGES.PROFESSIONAL;
  const roi = calculateROI(lead, packageId);
  const now = new Date();

  const validity_days = 30;
  const valid_until   = new Date(now.getTime() + validity_days * 86400000).toISOString().slice(0, 10);

  return {
    // Header
    proposal_number:   `CDB-${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2,'0')}-${Math.floor(Math.random() * 9000 + 1000)}`,
    generated_at:      now.toISOString(),
    valid_until,
    version:           '1.0',

    // Parties
    vendor: {
      name:     'CYBERDUDEBIVASH Pvt. Ltd.',
      address:  'India',
      email:    'enterprise@cyberdudebivash.com',
      website:  'https://cyberdudebivash.com',
      gstin:    'PENDING_REGISTRATION',
    },
    client: {
      name:     lead.name,
      company:  lead.company,
      email:    lead.email,
      phone:    lead.phone,
      sector:   lead.sector,
      size:     lead.company_size,
      role:     lead.role,
    },

    // Executive Summary
    executive_summary: `This proposal presents a comprehensive AI-powered cybersecurity solution for ${lead.company}. Based on your organization's profile in the ${lead.sector || 'technology'} sector with ${lead.company_size || '50-200'} employees, we recommend the **${pkg.name}** package which delivers ${roi.roi_multiplier}× ROI against your estimated annual breach exposure of ₹${(roi.annual_breach_cost_est_inr / 100000).toFixed(0)} lakhs.`,

    // Security Assessment
    security_assessment: {
      current_risk_level: lead.has_existing_siem ? 'MEDIUM' : 'HIGH',
      key_gaps: [
        !lead.has_existing_siem ? 'No centralized SIEM integration detected' : null,
        lead.has_compliance_need ? 'Compliance requirements need automated reporting' : null,
        'Manual threat response increases MTTR to 240+ minutes',
        'No AI-powered threat correlation active',
        'No autonomous rule deployment capability',
      ].filter(Boolean),
      recommended_improvements: [
        'Deploy AI Threat Analyst for 24×7 automated monitoring',
        'Enable SIEM integration for real-time rule deployment',
        'Activate Autonomous SOC pipeline for sub-5-minute MTTD',
        'Implement Threat Confidence Scoring for alert prioritization',
      ],
    },

    // Package Details
    package: {
      id:         pkg.id,
      name:       pkg.name,
      tagline:    pkg.tagline,
      features:   pkg.features,
      target:     pkg.target,
    },

    // Pricing
    pricing: {
      base_price_inr:       pkg.price_inr,
      billing_cycle:        pkg.billing,
      setup_fee_inr:        customizations.setup_fee || 0,
      discount_pct:         customizations.discount_pct || 0,
      discount_amount_inr:  Math.round((pkg.price_inr || 0) * (customizations.discount_pct || 0) / 100),
      final_price_inr:      pkg.price_inr
        ? Math.round((pkg.price_inr || 0) * (1 - (customizations.discount_pct || 0) / 100))
        : null,
      gst_rate_pct:         18,
      gst_amount_inr:       pkg.price_inr
        ? Math.round(pkg.price_inr * (1 - (customizations.discount_pct || 0) / 100) * 0.18)
        : null,
      total_with_gst_inr:   pkg.price_inr
        ? Math.round(pkg.price_inr * (1 - (customizations.discount_pct || 0) / 100) * 1.18)
        : null,
      payment_terms:        customizations.payment_terms || 'Annual upfront (5% discount) or quarterly',
      currency:             'INR',
    },

    // ROI Analysis
    roi_analysis: roi,

    // Implementation Timeline
    implementation_timeline: [
      { week: '1',   milestone: 'Account provisioning, API key generation, admin onboarding' },
      { week: '2',   milestone: 'SIEM integration setup, alert configuration, baseline scan' },
      { week: '3',   milestone: 'AI model calibration, custom threat model for your sector' },
      { week: '4',   milestone: 'Go-live, team training, first executive report' },
      { week: '4+',  milestone: 'Ongoing: 24×7 autonomous monitoring, monthly reviews' },
    ],

    // SLA Terms
    sla: {
      uptime_guarantee:   '99.9%',
      support_response:   pkg.id === 'ENTERPRISE_SHIELD' ? '1 hour' : pkg.id === 'PROFESSIONAL' ? '4 hours' : '24 hours',
      support_channels:   ['Email', 'Dedicated Slack channel', pkg.id !== 'STARTER_PLUS' ? 'Phone' : null].filter(Boolean),
      data_retention:     '12 months',
      data_residency:     'India (Cloudflare India PoP)',
      security_compliance:['SOC 2 Type II (in progress)', 'ISO 27001 (in progress)', 'DPDP Act compliant'],
    },

    // Terms
    terms: {
      validity_days,
      cancellation_notice: '30 days',
      auto_renewal:        true,
      governing_law:       'Laws of India',
      jurisdiction:        'Courts of Bangalore, Karnataka',
      nda_required:        pkg.id === 'ENTERPRISE_SHIELD' || pkg.id === 'MSSP_COMMAND',
    },

    // CTA
    next_steps: [
      'Review this proposal with your team',
      'Schedule a 30-minute technical deep-dive call',
      'Sign the agreement digitally via DocuSign or equivalent',
      'Complete payment to initiate provisioning',
      'Onboarding begins within 24 hours of payment confirmation',
    ],

    accept_url:  `https://cyberdudebivash.com/proposal/accept?id=PROP_ID`,
    contact_url: 'https://cyberdudebivash.com/contact',
    status:      'DRAFT',
  };
}

function generateProposalId() {
  return 'prop_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
}

// ── POST /api/proposals/generate ─────────────────────────────────────────────
export async function handleGenerateProposal(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let body = {};
  try { body = await request.json(); } catch {}

  const { lead_id, package_id = 'PROFESSIONAL', discount_pct = 0,
          setup_fee = 0, payment_terms, notes = '' } = body;

  if (!lead_id) return fail(request, 'lead_id is required', 400, 'MISSING_LEAD');
  if (!ENTERPRISE_PACKAGES[package_id]) return fail(request, 'Invalid package_id', 400, 'INVALID_PACKAGE');

  // Load lead
  let lead = {};
  if (env?.SECURITY_HUB_KV) {
    try { lead = (await env.SECURITY_HUB_KV.get(`crm:lead:${lead_id}`, { type: 'json' })) || {}; } catch {}
  }
  if (!lead.id) return fail(request, 'Lead not found', 404, 'LEAD_NOT_FOUND');

  const propId   = generateProposalId();
  const doc      = buildProposalDocument(lead, package_id, { discount_pct, setup_fee, payment_terms });
  doc.accept_url = `https://cyberdudebivash.com/proposal/accept?id=${propId}`;
  doc.notes      = notes;
  doc.lead_id    = lead_id;

  const proposal = { id: propId, lead_id, package_id, status: 'DRAFT', ...doc };

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_PROPOSAL_PREFIX}${propId}`, JSON.stringify(proposal), { expirationTtl: 86400 * 365 });
    let index = [];
    try { index = (await env.SECURITY_HUB_KV.get(KV_PROPOSALS_INDEX, { type: 'json' })) || []; } catch {}
    index.unshift({
      id: propId, lead_id, package_id,
      company:        lead.company,
      value_inr:      proposal.pricing?.final_price_inr,
      status:         'DRAFT',
      generated_at:   doc.generated_at,
      valid_until:    doc.valid_until,
    });
    await env.SECURITY_HUB_KV.put(KV_PROPOSALS_INDEX, JSON.stringify(index.slice(0, 500)), { expirationTtl: 86400 * 365 });
  }

  return ok(request, { generated: true, proposal_id: propId, proposal });
}

// ── GET /api/proposals ────────────────────────────────────────────────────────
export async function handleListProposals(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');
  let index = [];
  if (env?.SECURITY_HUB_KV) {
    try { index = (await env.SECURITY_HUB_KV.get(KV_PROPOSALS_INDEX, { type: 'json' })) || []; } catch {}
  }
  const url   = new URL(request.url);
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '20', 10));
  return ok(request, { total: index.length, proposals: index.slice(0, limit) });
}

// ── GET /api/proposals/:id ────────────────────────────────────────────────────
export async function handleGetProposal(request, env, authCtx = {}) {
  const propId = new URL(request.url).pathname.split('/').pop();
  let proposal = null;
  if (env?.SECURITY_HUB_KV) {
    try { proposal = await env.SECURITY_HUB_KV.get(`${KV_PROPOSAL_PREFIX}${propId}`, { type: 'json' }); } catch {}
  }
  if (!proposal) return fail(request, 'Proposal not found', 404, 'NOT_FOUND');
  return ok(request, proposal);
}

// ── POST /api/proposals/:id/send ──────────────────────────────────────────────
export async function handleMarkProposalSent(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');
  const propId = new URL(request.url).pathname.split('/').slice(-2, -1)[0];

  let proposal = null;
  if (env?.SECURITY_HUB_KV) {
    try { proposal = await env.SECURITY_HUB_KV.get(`${KV_PROPOSAL_PREFIX}${propId}`, { type: 'json' }); } catch {}
  }
  if (!proposal) return fail(request, 'Proposal not found', 404, 'NOT_FOUND');

  proposal.status    = 'SENT';
  proposal.sent_at   = new Date().toISOString();

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_PROPOSAL_PREFIX}${propId}`, JSON.stringify(proposal), { expirationTtl: 86400 * 365 });
    // Advance CRM lead stage
    if (proposal.lead_id) {
      try {
        const lead = await env.SECURITY_HUB_KV.get(`crm:lead:${proposal.lead_id}`, { type: 'json' });
        if (lead && !['CLOSED_WON','CLOSED_LOST'].includes(lead.stage)) {
          lead.stage = 'PROPOSAL_SENT';
          lead.proposal_sent_at = proposal.sent_at;
          lead.updated_at = proposal.sent_at;
          lead.timeline.push({ stage: 'PROPOSAL_SENT', ts: proposal.sent_at, actor: authCtx.email || 'admin', note: 'Proposal ' + propId + ' sent' });
          await env.SECURITY_HUB_KV.put(`crm:lead:${proposal.lead_id}`, JSON.stringify(lead), { expirationTtl: 86400 * 365 * 2 });
        }
      } catch {}
    }
  }
  return ok(request, { sent: true, proposal_id: propId });
}

// ── POST /api/proposals/:id/accept ────────────────────────────────────────────
export async function handleAcceptProposal(request, env, authCtx = {}) {
  const propId = new URL(request.url).pathname.split('/').slice(-2, -1)[0];

  let proposal = null;
  if (env?.SECURITY_HUB_KV) {
    try { proposal = await env.SECURITY_HUB_KV.get(`${KV_PROPOSAL_PREFIX}${propId}`, { type: 'json' }); } catch {}
  }
  if (!proposal) return fail(request, 'Proposal not found', 404, 'NOT_FOUND');

  proposal.status      = 'ACCEPTED';
  proposal.accepted_at = new Date().toISOString();

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_PROPOSAL_PREFIX}${propId}`, JSON.stringify(proposal), { expirationTtl: 86400 * 365 });
    if (proposal.lead_id) {
      try {
        const lead = await env.SECURITY_HUB_KV.get(`crm:lead:${proposal.lead_id}`, { type: 'json' });
        if (lead) {
          lead.stage = 'NEGOTIATION';
          lead.timeline.push({ stage: 'NEGOTIATION', ts: proposal.accepted_at, actor: 'client', note: 'Proposal accepted by client' });
          lead.updated_at = proposal.accepted_at;
          await env.SECURITY_HUB_KV.put(`crm:lead:${proposal.lead_id}`, JSON.stringify(lead), { expirationTtl: 86400 * 365 * 2 });
        }
      } catch {}
    }
  }

  return ok(request, { accepted: true, proposal_id: propId, next_step: 'Complete payment to begin onboarding' });
}

// ── GET /api/proposals/packages ──────────────────────────────────────────────
export async function handleGetPackages(request, env) {
  return ok(request, {
    packages: Object.values(ENTERPRISE_PACKAGES),
    note: 'All prices in INR. GST @18% applicable. Annual billing saves 5% vs quarterly.',
    contact: 'enterprise@cyberdudebivash.com',
  });
}
