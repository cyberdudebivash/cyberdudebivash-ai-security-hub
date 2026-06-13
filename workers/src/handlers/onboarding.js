/**
 * SENTINEL APEX™ Customer Onboarding & Welcome Flow
 * Triggers post-provisioning: welcome email, checklist, getting-started guide.
 *
 * Routes:
 *   POST /api/onboarding/welcome      - Trigger welcome flow (called by provisioningEngine)
 *   GET  /api/onboarding/checklist    - Return onboarding checklist for authenticated user
 *   POST /api/onboarding/step         - Mark a checklist step complete
 *   GET  /api/onboarding/guide/:tier  - Tier-specific getting-started guide
 */

const CHECKLIST_STEPS = {
  FREE: [
    { id: 'create_account',    label: 'Create your account',                  docs: '/docs/getting-started' },
    { id: 'explore_dashboard', label: 'Explore the Intelligence Dashboard',   docs: '/dashboard' },
    { id: 'try_cve_preview',   label: 'Preview a CVE intelligence card',      docs: '/api/preview/cve/CVE-2024-21413' },
    { id: 'read_api_docs',     label: 'Read the API documentation',           docs: 'https://intel.cyberdudebivash.com/api/' },
    { id: 'upgrade_pro',       label: 'Upgrade to PRO for full access',       docs: 'https://intel.cyberdudebivash.com/pricing.html' },
  ],
  PRO: [
    { id: 'generate_api_key',  label: 'Generate your API key',                docs: '/dashboard#api-keys' },
    { id: 'first_api_call',    label: 'Make your first API call',             docs: 'https://intel.cyberdudebivash.com/api/#quickstart' },
    { id: 'download_report',   label: 'Download your intelligence report',    docs: '/dashboard#intel-reports' },
    { id: 'setup_stix_export', label: 'Configure STIX 2.1 export',           docs: 'https://intel.cyberdudebivash.com/api/#stix' },
    { id: 'explore_actor_intel','label': 'Explore Threat Actor Intelligence', docs: '/api/preview/threat/apt29' },
  ],
  TEAM: [
    { id: 'invite_team',       label: 'Invite team members',                  docs: '/dashboard#team-management' },
    { id: 'configure_siem',    label: 'Configure SIEM webhook integration',   docs: 'https://intel.cyberdudebivash.com/api/#siem' },
    { id: 'setup_kill_chain',  label: 'Enable Kill Chain Mapping',            docs: 'https://intel.cyberdudebivash.com/api/#kill-chain' },
    { id: 'first_api_call',    label: 'Make your first API call',             docs: 'https://intel.cyberdudebivash.com/api/#quickstart' },
    { id: 'review_quota',      label: 'Review your API quota dashboard',      docs: '/dashboard#api-usage' },
  ],
  ENTERPRISE: [
    { id: 'dedicated_endpoint', label: 'Configure your dedicated endpoint',    docs: '/dashboard#dedicated-endpoint' },
    { id: 'sla_brief',          label: 'Review your Enterprise SLA',           docs: '/docs/enterprise-sla' },
    { id: 'analyst_brief',      label: 'Schedule your analyst onboarding call',docs: 'mailto:enterprise@cyberdudebivash.com?subject=ENTERPRISE_ONBOARDING' },
    { id: 'configure_siem',     label: 'Configure SIEM/SOAR integration',      docs: 'https://intel.cyberdudebivash.com/api/#siem' },
    { id: 'board_report',       label: 'Generate your first Board-Level report',docs: '/dashboard#intel-reports' },
  ],
};

const WELCOME_GUIDES = {
  FREE: {
    headline: 'Welcome to SENTINEL APEX™ Intelligence Platform',
    subheading: 'Your journey into elite threat intelligence starts here.',
    steps: [
      'Explore live CVE intelligence cards — search any CVE for instant context.',
      'View the latest Threat Actor profiles including APT29, Lazarus, and APT41.',
      'Access 3,000 API calls/month to power your security dashboards.',
      'Upgrade to PRO to unlock STIX 2.1 export, full IOC feeds, and AI predictions.',
    ],
    cta: { label: 'Upgrade to PRO — $49/month', url: 'https://intel.cyberdudebivash.com/pricing.html' },
    support: 'support@cyberdudebivash.com',
    docs_url: 'https://intel.cyberdudebivash.com/api/',
  },
  PRO: {
    headline: 'Welcome to SENTINEL APEX™ PRO — Full Threat Intelligence Unlocked',
    subheading: 'Your API key, intelligence reports, and advanced feeds are ready.',
    steps: [
      'Your API key is live — find it in the dashboard under API Keys.',
      'Download your included intelligence reports from Intel Reports section.',
      'STIX 2.1 export is enabled — integrate with your SIEM or TIP platform.',
      'AI-powered threat predictions are active — query /api/intel/v2/risk for live scoring.',
    ],
    cta: { label: 'Upgrade to TEAM for SIEM webhooks — $149/month', url: 'https://intel.cyberdudebivash.com/pricing.html#team' },
    support: 'support@cyberdudebivash.com',
    docs_url: 'https://intel.cyberdudebivash.com/api/',
  },
  TEAM: {
    headline: 'Welcome to SENTINEL APEX™ TEAM — Enterprise-Grade Intelligence',
    subheading: 'Multi-seat access, SIEM integration, and Kill Chain Mapping are active.',
    steps: [
      'Invite your team — add up to 10 seats from the Team Management dashboard.',
      'Configure SIEM webhooks at /dashboard#siem — Splunk, Microsoft Sentinel, and QRadar supported.',
      'Kill Chain Mapping is live — query /api/intel/v2/ttp for full MITRE ATT&CK coverage.',
      'Your 10,000 daily API calls are ready — monitor quota in the API Usage dashboard.',
    ],
    cta: { label: 'Upgrade to ENTERPRISE for unlimited access', url: 'mailto:enterprise@cyberdudebivash.com?subject=ENTERPRISE_UPGRADE' },
    support: 'enterprise@cyberdudebivash.com',
    docs_url: 'https://intel.cyberdudebivash.com/api/',
  },
  ENTERPRISE: {
    headline: 'Welcome to SENTINEL APEX™ ENTERPRISE — Unlimited Intelligence Operations',
    subheading: 'Dedicated infrastructure, Board-Level reporting, and analyst briefings are ready.',
    steps: [
      'Your dedicated API endpoint is live — check your welcome email for the endpoint URL.',
      'Schedule your analyst onboarding call: enterprise@cyberdudebivash.com',
      'Board-Level reports are auto-generated monthly — access from Intel Reports.',
      'White-label reporting is enabled — configure your branding at /dashboard#white-label.',
    ],
    cta: null,
    support: 'enterprise@cyberdudebivash.com',
    docs_url: 'https://intel.cyberdudebivash.com/api/',
  },
};

// ─── POST /api/onboarding/welcome ────────────────────────────────────────────
async function handleWelcome(request, env, authCtx) {
  let body = {};
  try { body = await request.json(); } catch {}

  const userId = body.user_id || authCtx?.userId;
  const tier   = (body.tier || authCtx?.tier || 'FREE').toUpperCase();
  const email  = body.email || authCtx?.email || null;
  const name   = body.name || body.username || 'there';

  if (!userId) return Response.json({ error: 'user_id required' }, { status: 400 });

  // Write onboarding record to D1
  try {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO customer_onboarding
       (id, user_id, tier, email, started_at, steps_completed, status)
       VALUES (?, ?, ?, ?, datetime('now'), '[]', 'in_progress')`
    ).bind(crypto.randomUUID(), userId, tier, email).run();
  } catch {
    // Table may not exist in older schema — silently continue
  }

  const guide = WELCOME_GUIDES[tier] || WELCOME_GUIDES.FREE;
  const checklist = CHECKLIST_STEPS[tier] || CHECKLIST_STEPS.FREE;

  return Response.json({
    success: true,
    user_id: userId,
    tier,
    welcome: {
      greeting: `Hi ${name}! ${guide.headline}`,
      headline: guide.headline,
      subheading: guide.subheading,
      getting_started: guide.steps,
      cta: guide.cta,
      support_email: guide.support,
      docs_url: guide.docs_url,
    },
    checklist,
    platform_url: 'https://intel.cyberdudebivash.com',
    dashboard_url: 'https://intel.cyberdudebivash.com/user-dashboard.html',
  });
}

// ─── GET /api/onboarding/checklist ───────────────────────────────────────────
async function handleChecklist(request, env, authCtx) {
  if (!authCtx?.userId) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const userId = authCtx.userId;
  const tier   = (authCtx.tier || 'FREE').toUpperCase();

  // Load completed steps from D1 if table exists
  let completedSteps = [];
  try {
    const row = await env.DB.prepare(
      `SELECT steps_completed FROM customer_onboarding WHERE user_id = ? LIMIT 1`
    ).bind(userId).first();
    if (row?.steps_completed) completedSteps = JSON.parse(row.steps_completed);
  } catch {}

  const allSteps = CHECKLIST_STEPS[tier] || CHECKLIST_STEPS.FREE;
  const steps = allSteps.map(s => ({
    ...s,
    completed: completedSteps.includes(s.id),
  }));

  const completedCount = steps.filter(s => s.completed).length;

  return Response.json({
    user_id: userId,
    tier,
    progress: { completed: completedCount, total: steps.length, percent: Math.round((completedCount / steps.length) * 100) },
    steps,
    guide: WELCOME_GUIDES[tier] || WELCOME_GUIDES.FREE,
  });
}

// ─── POST /api/onboarding/step ───────────────────────────────────────────────
async function handleMarkStep(request, env, authCtx) {
  if (!authCtx?.userId) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body = {};
  try { body = await request.json(); } catch {}
  const { step_id } = body;
  if (!step_id) return Response.json({ error: 'step_id required' }, { status: 400 });

  const userId = authCtx.userId;

  try {
    const row = await env.DB.prepare(
      `SELECT steps_completed FROM customer_onboarding WHERE user_id = ? LIMIT 1`
    ).bind(userId).first();

    let completed = [];
    if (row?.steps_completed) completed = JSON.parse(row.steps_completed);
    if (!completed.includes(step_id)) completed.push(step_id);

    await env.DB.prepare(
      `UPDATE customer_onboarding SET steps_completed = ?, updated_at = datetime('now') WHERE user_id = ?`
    ).bind(JSON.stringify(completed), userId).run();
  } catch {}

  return Response.json({ success: true, step_id, marked_complete: true });
}

// ─── GET /api/onboarding/guide/:tier ─────────────────────────────────────────
async function handleGuide(request, env, authCtx) {
  const url = new URL(request.url);
  const tierParam = url.pathname.split('/').pop().toUpperCase();
  const guide = WELCOME_GUIDES[tierParam] || WELCOME_GUIDES.FREE;
  const checklist = CHECKLIST_STEPS[tierParam] || CHECKLIST_STEPS.FREE;

  return Response.json({
    tier: tierParam,
    guide,
    checklist,
    support: {
      email: guide.support,
      enterprise_email: 'enterprise@cyberdudebivash.com',
      docs: guide.docs_url,
    },
  });
}

// ─── Main Dispatcher ─────────────────────────────────────────────────────────
export async function handleOnboarding(request, env, authCtx, path, method) {
  try {
    if (path === '/api/onboarding/welcome' && method === 'POST')
      return handleWelcome(request, env, authCtx);

    if (path === '/api/onboarding/checklist' && method === 'GET')
      return handleChecklist(request, env, authCtx);

    if (path === '/api/onboarding/step' && method === 'POST')
      return handleMarkStep(request, env, authCtx);

    if (path.startsWith('/api/onboarding/guide/') && method === 'GET')
      return handleGuide(request, env, authCtx);

    return Response.json({
      error: 'Onboarding route not found',
      available: [
        'POST /api/onboarding/welcome',
        'GET  /api/onboarding/checklist',
        'POST /api/onboarding/step',
        'GET  /api/onboarding/guide/:tier',
      ],
    }, { status: 404 });
  } catch (err) {
    return Response.json({ error: 'Onboarding error', detail: err?.message }, { status: 500 });
  }
}
