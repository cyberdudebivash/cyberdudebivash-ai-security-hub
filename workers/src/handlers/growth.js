// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Growth API Handler
// GTM Growth Engine Phase 7: All Growth Endpoints
// ═══════════════════════════════════════════════════════════════════════════

import { ok, fail, withErrorBoundary }       from '../lib/response.js';

import {
  captureEmail, getLead, checkUpgradeTriggers,
  recordScanEvent, recordFunnelEvent, getFunnelMetrics,
  getHotLeads, listLeads, upgradeLead, parseScanContext,
  FUNNEL_STAGES, PLAN_LIMITS,
}                                            from '../services/funnelEngine.js';

import {
  enrollInSequence, runDripAutomation, sendWelcomeEmail,
  trackEmailEvent, getDueEmails,
}                                            from '../services/emailEngine.js';

import {
  detectEnterpriseLeads, generateOutreachBundle,
  runSalesPipeline, getOutreachQueue, markOutreachSent,
  scoreEnterpriseLead,
}                                            from '../services/salesEngine.js';

import {
  checkRateLimit, recordApiUsage, getApiUsageSummary,
  provisionApiKey, resolveApiKey, handlePaymentSuccess,
  buildRazorpayPayload, calculateOverage, API_QUOTAS,
}                                            from '../services/apiRevenueEngine.js';

import {
  buildRevenueDashboard, getCachedDashboard,
  computeConversionMetrics, computeGrowthMetrics,
  computeMRR, trackGrowthEvent,
}                                            from '../services/analyticsEngine.js';

import {
  runContentAutomation, getPendingContent,
  generateContentBundle, storeContentQueue,
}                                            from '../services/contentEngine.js';

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL CAPTURE — POST /api/growth/capture
// ─────────────────────────────────────────────────────────────────────────────
export const handleEmailCapture = withErrorBoundary(async (request, env) => {
  const body = await request.json().catch(() => ({}));
  const { email, name, domain, source = 'scan', scan_data } = body;

  if (!email) return fail(request, 'email is required', 400);

  // Capture or upsert lead
  const result = await captureEmail(env, { email, name, domain, source });
  if (!result.success) return fail(request, result.error || 'capture_failed', 400);

  const lead = result.lead;

  // Enroll in welcome drip
  await enrollInSequence(env, email, 'welcome', { scanData: scan_data || {} });

  // Send immediate Day 0 welcome email (async, non-blocking)
  if (scan_data) {
    sendWelcomeEmail(env, email, lead, scan_data).catch(() => {});
  }

  // Score if enterprise
  if (result.isEnterprise) {
    await enrollInSequence(env, email, 'enterprise', { scanData: scan_data || {} }).catch(() => {});
  }

  // Track funnel event
  await trackGrowthEvent(env, 'email_captured', { email, source, is_enterprise: result.isEnterprise });

  return ok(request, {
    success:       true,
    lead_captured: true,
    is_enterprise: result.isEnterprise,
    plan:          lead?.plan || 'free',
    message:       'Welcome! Check your email for your security report.',
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SCAN EVENT — POST /api/growth/scan
// ─────────────────────────────────────────────────────────────────────────────
export const handleScanEvent = withErrorBoundary(async (request, env) => {
  const body = await request.json().catch(() => ({}));
  const { email, domain, severity_counts, total_found, plan = 'free' } = body;

  // Record scan
  await recordScanEvent(env, email, { domain, severity_counts: severity_counts || {}, total_found: total_found || 0 });

  // Check upgrade triggers
  const ctx = parseScanContext({
    domain,
    email,
    scan_count:     body.scan_count,
    critical_found: (severity_counts?.CRITICAL || 0) > 0,
    results_count:  total_found,
  });

  const upgradeCheck = await checkUpgradeTriggers(env, email, plan, ctx);

  // Track
  await trackGrowthEvent(env, 'scan_performed', { email, domain, total_found, plan });

  return ok(request, {
    scan_recorded:   true,
    upgrade_check:   upgradeCheck,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// UPGRADE CHECK — GET /api/growth/upgrade-check
// ─────────────────────────────────────────────────────────────────────────────
export const handleUpgradeCheck = withErrorBoundary(async (request, env) => {
  const url     = new URL(request.url);
  const email   = url.searchParams.get('email');
  const plan    = url.searchParams.get('plan') || 'free';
  const domain  = url.searchParams.get('domain');

  const ctx = parseScanContext({
    email,
    domain,
    scan_count:      parseInt(url.searchParams.get('scan_count') || '0', 10),
    critical_found:  url.searchParams.get('critical_found') === 'true',
    results_count:   parseInt(url.searchParams.get('results_count') || '0', 10),
    api_calls_today: parseInt(url.searchParams.get('api_calls_today') || '0', 10),
  });

  const upgradeData = await checkUpgradeTriggers(env, email, plan, ctx);

  return ok(request, {
    ...upgradeData,
    plan_limits: PLAN_LIMITS,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FUNNEL DASHBOARD — GET /api/growth/funnel
// ─────────────────────────────────────────────────────────────────────────────
export const handleFunnelDashboard = withErrorBoundary(async (request, env) => {
  const url  = new URL(request.url);
  const days = parseInt(url.searchParams.get('days') || '30', 10);

  const [metrics, hotLeads] = await Promise.all([
    getFunnelMetrics(env, days),
    getHotLeads(env, 10),
  ]);

  return ok(request, {
    funnel_metrics: metrics,
    hot_leads:      hotLeads,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// LEADS — GET /api/growth/leads
// ─────────────────────────────────────────────────────────────────────────────
export const handleGetLeads = withErrorBoundary(async (request, env) => {
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const tier   = url.searchParams.get('tier');
  const plan   = url.searchParams.get('plan');

  const leads = await listLeads(env, { limit, offset, tier, plan });

  return ok(request, {
    leads,
    count:  leads.length,
    offset,
    limit,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SALES PIPELINE — POST /api/growth/sales/run
// ─────────────────────────────────────────────────────────────────────────────
export const handleRunSalesPipeline = withErrorBoundary(async (request, env) => {
  const results = await runSalesPipeline(env);
  return ok(request, { pipeline: 'sales', ...results });
});

// ─────────────────────────────────────────────────────────────────────────────
// OUTREACH QUEUE — GET /api/growth/sales/outreach
// ─────────────────────────────────────────────────────────────────────────────
export const handleGetOutreach = withErrorBoundary(async (request, env) => {
  const url    = new URL(request.url);
  const status = url.searchParams.get('status') || 'draft';
  const limit  = parseInt(url.searchParams.get('limit') || '20', 10);

  const outreach = await getOutreachQueue(env, { status, limit });

  // Enrich with full outreach bundles for draft items
  const enriched = outreach.map(item => ({
    ...item,
    body_preview: (item.body || '').slice(0, 200) + '...',
  }));

  return ok(request, { outreach: enriched, count: enriched.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// MARK OUTREACH SENT — POST /api/growth/sales/outreach/:id/send
// ─────────────────────────────────────────────────────────────────────────────
export const handleMarkOutreachSent = withErrorBoundary(async (request, env, ctx, id) => {
  const result = await markOutreachSent(env, id);
  return result.success ? ok(request, { marked: true, id }) : fail(request, result.error, 400);
});

// ─────────────────────────────────────────────────────────────────────────────
// CONTENT AUTOMATION — POST /api/growth/content/run
// ─────────────────────────────────────────────────────────────────────────────
export const handleRunContentAutomation = withErrorBoundary(async (request, env) => {
  // Fetch top CRITICAL entries
  const result = await env.DB.prepare(`
    SELECT * FROM threat_intel
    WHERE severity = 'CRITICAL'
    ORDER BY cvss DESC, published_at DESC
    LIMIT 10
  `).all();

  const entries = result.results || [];
  if (entries.length === 0) return ok(request, { content_generated: 0, message: 'No CRITICAL entries found' });

  const contentResult = await runContentAutomation(env, entries);
  return ok(request, { pipeline: 'content', ...contentResult });
});

// ─────────────────────────────────────────────────────────────────────────────
// CONTENT QUEUE — GET /api/growth/content/queue
// ─────────────────────────────────────────────────────────────────────────────
export const handleGetContentQueue = withErrorBoundary(async (request, env) => {
  const url   = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit') || '20', 10);

  const items = await getPendingContent(env, limit);
  return ok(request, { content_queue: items, count: items.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL DRIP — POST /api/growth/email/run
// ─────────────────────────────────────────────────────────────────────────────
export const handleRunDrip = withErrorBoundary(async (request, env) => {
  const results = await runDripAutomation(env);
  return ok(request, { pipeline: 'drip_email', ...results });
});

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL TRACKING — GET /api/growth/email/track
// ─────────────────────────────────────────────────────────────────────────────
export const handleEmailTrack = withErrorBoundary(async (request, env) => {
  const url        = new URL(request.url);
  const email      = url.searchParams.get('email');
  const event      = url.searchParams.get('event') || 'open';
  const sequenceId = url.searchParams.get('seq') || 'welcome';
  const step       = parseInt(url.searchParams.get('step') || '0', 10);

  if (email) {
    await trackEmailEvent(env, email, event, sequenceId, step);
  }

  // Return 1x1 transparent GIF for open tracking
  if (event === 'open') {
    const gif = new Uint8Array([
      0x47,0x49,0x46,0x38,0x39,0x61,0x01,0x00,0x01,0x00,0x80,0x00,0x00,
      0xFF,0xFF,0xFF,0x00,0x00,0x00,0x21,0xF9,0x04,0x00,0x00,0x00,0x00,0x00,
      0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x02,0x02,0x44,0x01,0x00,0x3B,
    ]);
    return new Response(gif, {
      headers: {
        'Content-Type':  'image/gif',
        'Cache-Control': 'no-store',
      },
    });
  }

  return new Response(null, { status: 302, headers: { Location: 'https://cyberdudebivash.in' } });
});

// ─────────────────────────────────────────────────────────────────────────────
// API KEY PROVISIONING — POST /api/growth/api-key
// ─────────────────────────────────────────────────────────────────────────────
export const handleProvisionApiKey = withErrorBoundary(async (request, env) => {
  const body  = await request.json().catch(() => ({}));
  const { email, plan = 'starter' } = body;

  if (!email) return fail(request, 'email required', 400);

  const lead = await getLead(env, email);
  const effectivePlan = lead?.plan || plan;

  if (effectivePlan === 'free') {
    return fail(request, 'API keys require Starter plan or above', 403);
  }

  const keyResult = await provisionApiKey(env, email, effectivePlan);
  if (!keyResult) return fail(request, 'key_provisioning_failed', 500);

  return ok(request, {
    api_key:  keyResult.api_key,
    plan:     effectivePlan,
    quotas:   API_QUOTAS[effectivePlan],
    docs_url: 'https://cyberdudebivash.in/docs/api',
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// API USAGE — GET /api/growth/api-usage
// ─────────────────────────────────────────────────────────────────────────────
export const handleGetApiUsage = withErrorBoundary(async (request, env) => {
  const url   = new URL(request.url);
  const email = url.searchParams.get('email');
  const plan  = url.searchParams.get('plan') || 'free';

  if (!email) return fail(request, 'email required', 400);

  const summary = await getApiUsageSummary(env, email, plan);
  return ok(request, summary);
});

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT CALLBACK — POST /api/billing/callback
// ─────────────────────────────────────────────────────────────────────────────
export const handleBillingCallback = withErrorBoundary(async (request, env) => {
  const body = await request.json().catch(() => ({}));

  // Validate Razorpay signature in production (simplified here)
  const { email, plan, razorpay_payment_id, razorpay_order_id, event } = body;

  if (event !== 'payment.captured') {
    return ok(request, { received: true, event });
  }

  const result = await handlePaymentSuccess(env, {
    email,
    plan,
    payment_id: razorpay_payment_id,
    order_id:   razorpay_order_id,
  });

  if (result.success) {
    await trackGrowthEvent(env, 'payment_success', { email, plan });
  }

  return ok(request, result);
});

// ─────────────────────────────────────────────────────────────────────────────
// RAZORPAY LINK GENERATOR — POST /api/billing/create-link
// ─────────────────────────────────────────────────────────────────────────────
export const handleCreatePaymentLink = withErrorBoundary(async (request, env) => {
  const body = await request.json().catch(() => ({}));
  const { email, plan, billing_cycle = 'monthly' } = body;

  if (!email || !plan) return fail(request, 'email and plan required', 400);

  const payload = buildRazorpayPayload(email, plan, billing_cycle);
  if (!payload) return fail(request, 'invalid_plan', 400);

  return ok(request, {
    payload,
    razorpay_key: env.RAZORPAY_KEY_ID || 'rzp_live_PLACEHOLDER',
    note: 'Use this payload to create a Razorpay payment link via their API',
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// REVENUE DASHBOARD — GET /api/growth/analytics
// ─────────────────────────────────────────────────────────────────────────────
export const handleRevenueDashboard = withErrorBoundary(async (request, env) => {
  const url     = new URL(request.url);
  const refresh = url.searchParams.get('refresh') === 'true';

  const dashboard = await getCachedDashboard(env, refresh);
  return ok(request, dashboard);
});

// ─────────────────────────────────────────────────────────────────────────────
// UPGRADE LEAD — POST /api/growth/upgrade
// ─────────────────────────────────────────────────────────────────────────────
export const handleUpgradeLead = withErrorBoundary(async (request, env) => {
  const body = await request.json().catch(() => ({}));
  const { email, plan } = body;

  if (!email || !plan) return fail(request, 'email and plan required', 400);

  const result = await upgradeLead(env, email, plan);
  if (!result.success) return fail(request, result.error, 400);

  // Provision API key for paid plans
  if (plan !== 'free') {
    await provisionApiKey(env, email, plan).catch(() => {});
  }

  await trackGrowthEvent(env, 'lead_upgraded', { email, plan });

  return ok(request, { upgraded: true, email, plan });
});
