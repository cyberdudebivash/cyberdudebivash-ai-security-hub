/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Onboarding & Welcome API
 * GET  /api/enterprise/onboarding   → personalized onboarding guide for authenticated enterprise users
 * POST /api/enterprise/onboarding   → submit onboarding profile (org name, use case, team size)
 * GET  /api/enterprise/welcome      → platform capabilities overview for new enterprise customers
 * GET  /api/enterprise/contacts     → dedicated enterprise support contacts + SLA
 */

import { PRICING_CONFIG } from '../config/pricingConfig.js';

const PLATFORM_VERSION = '40.0.0';

const ENTERPRISE_CONTACTS = {
  sales:       { email: 'sales@cyberdudebivash.in',          name: 'Enterprise Sales',          response_sla: '4 business hours' },
  support:     { email: 'support@cyberdudebivash.in',         name: 'Enterprise Support',        response_sla: '4h SLA (ENTERPRISE tier)' },
  billing:     { email: 'billing@cyberdudebivash.in',         name: 'Billing & GST Invoices',    response_sla: '1 business day' },
  mssp:        { email: 'mssp@cyberdudebivash.in',            name: 'MSSP Partner Success',      response_sla: '4 business hours' },
  security:    { email: 'security@cyberdudebivash.in',        name: 'Security Disclosure',       response_sla: '24 hours' },
  escalation:  { email: 'enterprise@cyberdudebivash.in',      name: 'Executive Escalation',      response_sla: '2 business hours' },
  telegram:    { url: 'https://t.me/cyberdudebivashSentinelApex', name: 'Real-time Threat Alerts', response_sla: 'Instant' },
};

const QUICKSTART_STEPS = {
  threat_intel: [
    { step: 1, action: 'Explore live threat intelligence feed',   endpoint: 'GET /api/threat-intel?limit=10&severity=CRITICAL', docs: 'https://cyberdudebivash.in/api-docs.html#threat-intel' },
    { step: 2, action: 'Enrich an IOC (IP/domain/hash)',          endpoint: 'POST /api/hunt/ioc',    body: '{"ioc":"<ip_or_domain>","type":"ip"}' },
    { step: 3, action: 'Export threat data to your SIEM',         endpoint: 'POST /api/export/siem', body: '{"format":"json","severity":["CRITICAL","HIGH"],"limit":500}' },
    { step: 4, action: 'Set up versioned API key integration',    endpoint: 'GET /api/v1/threat-intel', auth: 'x-api-key: your_enterprise_key' },
  ],
  soc_operations: [
    { step: 1, action: 'Start AI Security Copilot session',       endpoint: 'POST /api/copilot/chat',            body: '{"message":"Analyze top threats to our infrastructure","session_id":"soc-001"}' },
    { step: 2, action: 'Run vulnerability threat hunt',           endpoint: 'POST /api/hunt/threat',             body: '{"query":"<your_asset_or_domain>","types":["cve","ioc"]}' },
    { step: 3, action: 'Create SOC case for incident',            endpoint: 'POST /api/soc/cases',               body: '{"title":"Incident","severity":"HIGH","type":"threat_hunt"}' },
    { step: 4, action: 'Export Sigma detection rules',            endpoint: 'POST /api/export/siem',             body: '{"format":"sigma","severity":["CRITICAL"]}' },
  ],
  compliance: [
    { step: 1, action: 'Get DPDP Act 2023 overview',             endpoint: 'GET /api/compliance/dpdp',         note: 'India-specific data protection compliance' },
    { step: 2, action: 'Run DPDP compliance assessment',          endpoint: 'POST /api/compliance/dpdp/assess', body: '{"organization_name":"Your Org","has_privacy_notice":true,...}' },
    { step: 3, action: 'Generate Record of Processing Activities', endpoint: 'POST /api/compliance/dpdp/ropa',  body: '{"organization":"Your Org","processing_activities":[...]}' },
    { step: 4, action: 'Download GST invoice for procurement',    endpoint: 'GET /api/billing/invoices',        note: 'Auto-generated after payment capture' },
  ],
  mssp: [
    { step: 1, action: 'List your managed tenants',               endpoint: 'GET /api/mssp/tenants' },
    { step: 2, action: 'Provision a new client tenant',           endpoint: 'POST /api/mssp/tenants',  body: '{"name":"ClientOrg","plan":"ENTERPRISE","contact_email":"soc@client.com","seats":50}' },
    { step: 3, action: 'Access white-label dashboard',            endpoint: 'GET /api/mssp/overview',  note: 'Per-tenant API key included in provisioning response' },
    { step: 4, action: 'Set up custom SIEM export per tenant',    endpoint: 'POST /api/export/siem',   note: 'Use tenant API key in x-api-key header' },
  ],
};

// ─── GET /api/enterprise/onboarding ─────────────────────────────────────────
export async function handleEnterpriseOnboarding(request, env, authCtx) {
  const tier   = authCtx?.tier || 'FREE';
  const email  = authCtx?.email || '';
  const userId = authCtx?.user_id || authCtx?.id || '';

  // Load saved onboarding profile if exists
  let profile = null;
  if (env.KV && userId) {
    profile = await env.KV.get(`enterprise_onboarding:${userId}`, 'json').catch(() => null);
  }

  const useCase = profile?.use_case || 'threat_intel';
  const steps   = QUICKSTART_STEPS[useCase] || QUICKSTART_STEPS.threat_intel;

  return Response.json({
    success: true,
    data: {
      welcome: `Welcome to CYBERDUDEBIVASH AI Security Hub™ — Enterprise-Grade AI Cyber Defense`,
      tier,
      platform_version: PLATFORM_VERSION,
      account: {
        email,
        tier,
        capabilities: getTierCapabilities(tier),
        upgrade_url:  '/api/subscription/plans',
      },
      quickstart: {
        use_case:        profile?.use_case || 'threat_intel',
        available_flows: Object.keys(QUICKSTART_STEPS),
        steps,
        tip: 'Change use_case via POST /api/enterprise/onboarding to get personalized steps.',
      },
      key_endpoints: {
        health:           'GET  /api/health',
        threat_intel:     'GET  /api/threat-intel',
        ioc_enrichment:   'POST /api/hunt/ioc',
        siem_export:      'POST /api/export/siem',
        ai_copilot:       'POST /api/copilot/chat',
        dpdp_compliance:  'GET  /api/compliance/dpdp',
        mssp_tenants:     'GET  /api/mssp/tenants',
        invoices:         'GET  /api/billing/invoices',
        api_keys:         'GET  /api/keys',
        v1_api:           'GET  /api/v1/threat-intel (x-api-key header)',
      },
      support: ENTERPRISE_CONTACTS,
      sla: {
        ENTERPRISE: '4-hour response SLA, dedicated account manager',
        MSSP:       '4-hour response SLA, white-label support, revenue share',
        PRO:        '24-hour response SLA',
        STARTER:    'Email support, community',
        FREE:       'Community support only',
      }[tier] || 'Contact sales@cyberdudebivash.in',
      docs:            'https://cyberdudebivash.in/api-docs.html',
      status_page:     'GET /api/health',
    },
    meta: { timestamp: new Date().toISOString(), version: PLATFORM_VERSION },
  });
}

// ─── POST /api/enterprise/onboarding ────────────────────────────────────────
export async function handleSaveOnboardingProfile(request, env, authCtx) {
  const userId = authCtx?.user_id || authCtx?.id;
  if (!userId) return Response.json({ error: 'Authentication required.' }, { status: 401 });

  let body = {};
  try { body = await request.json(); } catch (_) {}

  const { use_case, org_name, team_size, primary_goal, industry } = body;

  const VALID_USE_CASES = Object.keys(QUICKSTART_STEPS);
  const resolvedUseCase = VALID_USE_CASES.includes(use_case) ? use_case : 'threat_intel';

  const profile = {
    user_id:      userId,
    email:        authCtx?.email || '',
    org_name:     org_name || '',
    industry:     industry || '',
    team_size:    team_size || '',
    use_case:     resolvedUseCase,
    primary_goal: primary_goal || '',
    completed_at: new Date().toISOString(),
  };

  if (env.KV) {
    await env.KV.put(`enterprise_onboarding:${userId}`, JSON.stringify(profile), { expirationTtl: 365 * 24 * 3600 }).catch(() => {});
  }

  // Also persist to D1 for analytics
  if (env.DB) {
    await env.DB.prepare(
      `INSERT INTO leads (id, email, company, plan_interest, message, source, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'enterprise_onboarding', 'qualified', datetime('now'))
       ON CONFLICT(email) DO UPDATE SET company=excluded.company, plan_interest=excluded.plan_interest, updated_at=datetime('now')`
    ).bind(
      `lead_${Date.now().toString(36)}`,
      profile.email,
      org_name || '',
      use_case || '',
      JSON.stringify({ team_size, primary_goal, industry })
    ).run().catch(() => {});
  }

  return Response.json({
    success:  true,
    message:  'Onboarding profile saved. Your quickstart guide has been personalized.',
    data: {
      profile,
      next_steps: QUICKSTART_STEPS[resolvedUseCase],
      support:    ENTERPRISE_CONTACTS.support,
    },
  }, { status: 200 });
}

// ─── GET /api/enterprise/welcome ────────────────────────────────────────────
export async function handleEnterpriseWelcome(request, env) {
  return Response.json({
    success: true,
    data: {
      platform:   'CYBERDUDEBIVASH AI Security Hub™',
      tagline:    'AI-Native Cyber Defense. Enterprise-Grade Intelligence. Global Security Excellence.',
      version:    PLATFORM_VERSION,
      capabilities: {
        threat_intelligence:  '1,600+ CVEs, EPSS scores, CISA KEV, active exploitation tracking',
        ioc_enrichment:       'VirusTotal v3 + AbuseIPDB + Shodan InternetDB — real-time verdict',
        ai_copilot:           'GROQ llama-3.3-70b (god mode) with tool orchestration — SOC-grade analysis',
        siem_export:          'JSON / CEF / STIX 2.1 / Sigma / CSV — Splunk, QRadar, Elastic compatible',
        dpdp_compliance:      'India DPDP Act 2023 — 9-section gap analysis, RoPA generation, maturity scoring',
        mssp_platform:        'Multi-tenant SOC, white-label dashboard, per-tenant API keys, revenue share',
        gst_invoicing:        'Auto GST invoices — IGST/CGST/SGST, SAC 998313, ITC-eligible',
        api_economy:          'Versioned REST API (v1), x-api-key auth, unlimited ENTERPRISE quota',
      },
      // Sourced from config/pricingConfig.js (the platform's declared "immutable
      // source of truth") instead of a hand-typed copy — all 4 paid figures
      // here had drifted from the real, currently-charged amounts.
      pricing: {
        free:       '₹0 — 3 scans/day, 5 CVEs',
        starter:    `${PRICING_CONFIG.plans.STARTER.label} — 50 scans, AI analysis, PDF reports`,
        pro:        `${PRICING_CONFIG.plans.PRO.label} — Unlimited scans, Full AI Suite, SIEM export, DPDP`,
        enterprise: `${PRICING_CONFIG.plans.ENTERPRISE.label} — dedicated support, unlimited scans, 20 API keys`,
        mssp:       `${PRICING_CONFIG.plans.MSSP.label} — multi-tenant SOC, unlimited scans and API keys`,
        annual:     '20% discount on annual billing for all paid plans',
      },
      compliance: ['DPDP Act 2023 (India)', 'OWASP API Top 10', 'Zero Trust Architecture'],
      integrations: ['Razorpay (live payments)', 'VirusTotal v3', 'CISA KEV', 'EPSS Cyentia', 'NIST NVD'],
      contact: ENTERPRISE_CONTACTS,
      start_url: 'GET /api/enterprise/onboarding',
    },
    meta: { timestamp: new Date().toISOString() },
  });
}

// ─── GET /api/enterprise/contacts ───────────────────────────────────────────
export async function handleEnterpriseContacts(request, env, authCtx) {
  return Response.json({
    success: true,
    data: {
      contacts: ENTERPRISE_CONTACTS,
      escalation_matrix: [
        { level: 'L1 — General Support',     contact: 'support@cyberdudebivash.in',    sla: '4h (ENTERPRISE), 24h (PRO)' },
        { level: 'L2 — Technical Issues',    contact: 'support@cyberdudebivash.in',    sla: '4h with ticket ID' },
        { level: 'L3 — Executive Escalation',contact: 'enterprise@cyberdudebivash.in', sla: '2h for ENTERPRISE/MSSP' },
        { level: 'Billing / GST Queries',    contact: 'billing@cyberdudebivash.in',    sla: '1 business day' },
        { level: 'Security Disclosures',     contact: 'security@cyberdudebivash.in',   sla: '24h acknowledgement' },
        { level: 'MSSP Partner Support',     contact: 'mssp@cyberdudebivash.in',       sla: '4h (MSSP tier)' },
        { level: 'Real-Time Alerts',         contact: 'https://t.me/cyberdudebivashSentinelApex', sla: 'Instant' },
      ],
      support_hours: 'Monday–Friday 09:00–18:00 IST | Emergency: 24/7 for ENTERPRISE/MSSP',
      website:       'https://cyberdudebivash.in',
      gstin:         'Available on request — billing@cyberdudebivash.in',
    },
    meta: { timestamp: new Date().toISOString() },
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function getTierCapabilities(tier) {
  const caps = {
    FREE:       ['3 scans/day', 'Basic threat intel (5 CVEs)', '1 API key'],
    STARTER:    ['25 scans/month', 'AI Threat Analysis', 'PDF Reports', 'CVE feed', '2 API keys'],
    PRO:        ['Unlimited scans', 'Full AI Copilot', 'SIEM Export', 'DPDP Compliance', 'IOC Enrichment', '5 API keys'],
    ENTERPRISE: ['Unlimited scans', 'God Mode AI Copilot', 'MSSP White-label', 'DPDP + RoPA', 'SIEM (all formats)', 'GST Invoicing', '50 API keys', '4h SLA', 'Dedicated AM'],
    MSSP:       ['Everything in ENTERPRISE', 'Unlimited tenants', 'Revenue share 60/40', 'Partner portal', 'Custom branding', 'Reseller API', 'Co-marketing'],
  };
  return caps[tier] || caps.FREE;
}
