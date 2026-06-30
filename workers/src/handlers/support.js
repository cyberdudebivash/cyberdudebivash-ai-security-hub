/**
 * SENTINEL APEX™ Support & Help Centre
 * FAQ, platform status, and ticket routing for customer support.
 *
 * Routes:
 *   GET  /api/support/faq            - Frequently Asked Questions
 *   GET  /api/support/status         - Platform operational status
 *   POST /api/support/ticket         - Submit a support ticket
 *   GET  /api/support/sla            - SLA documentation by tier
 *   GET  /api/support/docs           - Documentation index
 */

import { logSystemError } from '../lib/errorLog.js';

const FAQ_DATA = [
  {
    id: 'faq-001',
    category: 'Getting Started',
    question: 'How do I get an API key?',
    answer: 'After subscribing to PRO, TEAM, or ENTERPRISE, your API key is automatically generated and available in your dashboard under "API Keys". Free tier users receive a rate-limited key on registration.',
    tags: ['api-key', 'getting-started', 'setup'],
  },
  {
    id: 'faq-002',
    category: 'Getting Started',
    question: 'How do I make my first API call?',
    answer: 'Use your API key in the Authorization header: `Authorization: Bearer YOUR_API_KEY`. Example: `curl -H "Authorization: Bearer <key>" https://intel.cyberdudebivash.com/api/intel/v2/cve?limit=10`',
    tags: ['api', 'quickstart'],
  },
  {
    id: 'faq-003',
    category: 'Billing',
    question: 'What is included in the PRO plan?',
    answer: 'PRO includes: 500 API calls/day (10,000/month), full IOC feeds, STIX 2.1 export, AI threat predictions, actor attribution, SIEM export, PDF reports, DPDP compliance engine, and 24h email support. Billed at ₹1,499/month.',
    tags: ['billing', 'pro', 'pricing'],
  },
  {
    id: 'faq-004',
    category: 'Billing',
    question: 'How do I cancel my subscription?',
    answer: 'Visit your dashboard → Subscriptions → click Cancel next to the active subscription. Access continues until the end of the current billing period. No refunds for partial months.',
    tags: ['billing', 'cancel', 'subscription'],
  },
  {
    id: 'faq-005',
    category: 'Billing',
    question: 'Do you offer a free trial?',
    answer: 'Yes — PRO has a 14-day free trial, TEAM has a 7-day free trial. No credit card required to start. Trials auto-cancel if not upgraded.',
    tags: ['trial', 'billing', 'free'],
  },
  {
    id: 'faq-006',
    category: 'Technical',
    question: 'What STIX version do you support?',
    answer: 'SENTINEL APEX™ supports STIX 2.1 (structured threat information expression). TAXII 2.1 compatibility is available on ENTERPRISE plans. Export via GET /api/cti/v2/stix/export.',
    tags: ['stix', 'taxii', 'technical', 'export'],
  },
  {
    id: 'faq-007',
    category: 'Technical',
    question: 'How do I integrate with my SIEM?',
    answer: 'TEAM and ENTERPRISE plans support SIEM webhook integration. Configure your webhook URL in Dashboard → SIEM Integration. Supported: Splunk, Microsoft Sentinel, IBM QRadar, Elastic SIEM.',
    tags: ['siem', 'integration', 'webhook', 'splunk'],
  },
  {
    id: 'faq-008',
    category: 'Technical',
    question: 'What is the API rate limit?',
    answer: 'FREE: 5 calls/day (50/month). STARTER: 20 calls/day (600/month). PRO: 500 calls/day (10,000/month). ENTERPRISE/MSSP: Unlimited. Rate limits are enforced per API key per UTC day. Monthly quotas reset on the 1st of each month.',
    tags: ['rate-limit', 'api', 'quota'],
  },
  {
    id: 'faq-009',
    category: 'Reports',
    question: 'How do I download my purchased intelligence reports?',
    answer: 'Go to Dashboard → Intel Reports. Purchased reports appear with a "Download" button. Reports are available for 365 days after purchase. Generates a secure time-limited link.',
    tags: ['reports', 'download', 'intel'],
  },
  {
    id: 'faq-010',
    category: 'Security',
    question: 'Is my data secure?',
    answer: 'Yes. All API traffic is TLS 1.3 encrypted. API keys use SHA-256 hashing. Platform is hosted on Cloudflare infrastructure with DDoS protection. We never store plaintext credentials. See our security policy at https://cyberdudebivash.in/security.',
    tags: ['security', 'privacy', 'data'],
  },
  {
    id: 'faq-011',
    category: 'Enterprise',
    question: 'What is included in the ENTERPRISE plan?',
    answer: 'ENTERPRISE (₹4,999/month) includes everything in PRO plus: unlimited API calls, multi-tenant SOC dashboard, MSSP white-label (unlimited tenants), custom SIEM integrations, 50 API keys, unlimited team seats, dedicated account manager, 4h SLA guarantee, and custom DPDP compliance reports.',
    tags: ['enterprise', 'pricing', 'features'],
  },
  {
    id: 'faq-012',
    category: 'Enterprise',
    question: 'Do you offer MSSP/reseller plans?',
    answer: 'Yes. MSSP plans include white-label capabilities, multi-tenant management, volume pricing, and co-branded reports. Contact enterprise@cyberdudebivash.com for MSSP partnership details.',
    tags: ['mssp', 'reseller', 'enterprise', 'white-label'],
  },
];

const PLATFORM_COMPONENTS = [
  { id: 'api',           name: 'Threat Intelligence API',     status: 'operational' },
  { id: 'dashboard',     name: 'Intelligence Dashboard',      status: 'operational' },
  { id: 'stix_export',   name: 'STIX 2.1 Export Engine',      status: 'operational' },
  { id: 'siem_webhooks', name: 'SIEM Webhook Delivery',        status: 'operational' },
  { id: 'reports',       name: 'Intelligence Report Downloads',status: 'operational' },
  { id: 'auth',          name: 'Authentication Service',       status: 'operational' },
  { id: 'marketplace',   name: 'Marketplace & Billing',        status: 'operational' },
  { id: 'provisioning',  name: 'Auto-Provisioning Engine',     status: 'operational' },
];

const SLA_TIERS = {
  FREE:       { uptime_sla: '99.0%', support_response: '72 hours', support_channel: 'Email', incident_notification: 'Status page only' },
  STARTER:    { uptime_sla: '99.5%', support_response: '48 hours', support_channel: 'Email', incident_notification: 'Email + Status page' },
  PRO:        { uptime_sla: '99.5%', support_response: '24 hours', support_channel: 'Priority Email', incident_notification: 'Email + Status page' },
  ENTERPRISE: { uptime_sla: '99.9%', support_response: '4 hours',  support_channel: 'Dedicated Email + Account Manager', incident_notification: 'Real-time alerts + Status page' },
  MSSP:       { uptime_sla: '99.9%', support_response: '2 hours',  support_channel: 'Dedicated account manager', incident_notification: 'Real-time alerts + PagerDuty' },
};

// ─── GET /api/support/faq ─────────────────────────────────────────────────────
async function handleFAQ(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');
  const q = (url.searchParams.get('q') || '').toLowerCase();

  let faqs = FAQ_DATA;
  if (category) faqs = faqs.filter(f => f.category.toLowerCase() === category.toLowerCase());
  if (q) faqs = faqs.filter(f =>
    f.question.toLowerCase().includes(q) ||
    f.answer.toLowerCase().includes(q) ||
    f.tags.some(t => t.includes(q))
  );

  const categories = [...new Set(FAQ_DATA.map(f => f.category))];

  return Response.json({
    total: faqs.length,
    categories,
    faqs,
    support_email: 'support@cyberdudebivash.com',
    enterprise_email: 'enterprise@cyberdudebivash.com',
    docs_url: 'https://intel.cyberdudebivash.com/api/',
  });
}

// ─── GET /api/support/status ──────────────────────────────────────────────────
async function handleStatus(request, env) {
  // Try to check D1 connectivity as a live health signal
  let dbHealthy = false;
  try {
    await env.DB.prepare('SELECT 1').first();
    dbHealthy = true;
  } catch {}

  const components = PLATFORM_COMPONENTS.map(c => ({
    ...c,
    // Downgrade DB-dependent components if D1 is unhealthy
    status: (!dbHealthy && ['api','stix_export','siem_webhooks','reports','provisioning'].includes(c.id))
      ? 'degraded' : 'operational',
    last_checked: new Date().toISOString(),
  }));

  const allOperational = components.every(c => c.status === 'operational');
  const anyDegraded    = components.some(c => c.status === 'degraded');

  return Response.json({
    status: allOperational ? 'operational' : anyDegraded ? 'degraded' : 'outage',
    message: allOperational
      ? 'All SENTINEL APEX™ systems operational.'
      : 'Some services are experiencing degraded performance. Our team is investigating.',
    components,
    last_updated: new Date().toISOString(),
    incident_url: 'https://intel.cyberdudebivash.com/status',
    support_email: 'support@cyberdudebivash.com',
  });
}

// ─── POST /api/support/ticket ─────────────────────────────────────────────────
async function handleTicket(request, env, authCtx) {
  let body = {};
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { subject, description, category, priority } = body;
  if (!subject || !description)
    return Response.json({ error: 'subject and description are required' }, { status: 400 });

  const userId = authCtx?.userId || 'anonymous';
  const tier   = (authCtx?.tier || 'FREE').toUpperCase();
  const ticketId = `TKT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

  const sla = SLA_TIERS[tier] || SLA_TIERS.FREE;
  const supportEmail = ['ENTERPRISE','MSSP'].includes(tier)
    ? 'enterprise@cyberdudebivash.com'
    : 'support@cyberdudebivash.com';

  try {
    await env.DB.prepare(
      `INSERT INTO support_tickets (id, user_id, tier, subject, description, category, priority, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'open', datetime('now'))`
    ).bind(ticketId, userId, tier, subject, description, category || 'general', priority || 'normal').run();
  } catch (e) {
    await logSystemError(env, { area: 'support.ticket_insert', message: e.message, context: { user_id: userId, tier } });
    return Response.json({ error: 'Ticket could not be recorded — please email support directly', contact: supportEmail }, { status: 500 });
  }

  return Response.json({
    success: true,
    ticket_id: ticketId,
    status: 'open',
    subject,
    tier,
    sla: {
      response_time: sla.support_response,
      support_channel: sla.support_channel,
    },
    next_steps: `You will receive a response at ${supportEmail} within ${sla.support_response}.`,
    support_email: supportEmail,
    created_at: new Date().toISOString(),
  });
}

// ─── GET /api/support/sla ─────────────────────────────────────────────────────
async function handleSLA(request, env, authCtx) {
  const tier = authCtx?.tier?.toUpperCase() || null;

  return Response.json({
    tiers: SLA_TIERS,
    your_sla: tier ? (SLA_TIERS[tier] || SLA_TIERS.FREE) : null,
    your_tier: tier,
    uptime_history_url: 'https://intel.cyberdudebivash.com/status',
    enterprise_custom_sla: 'Contact enterprise@cyberdudebivash.com for custom SLA agreements.',
  });
}

// ─── GET /api/support/docs ────────────────────────────────────────────────────
async function handleDocs(request, env) {
  return Response.json({
    documentation: [
      { title: 'API Reference',           url: 'https://intel.cyberdudebivash.com/api/',        description: 'Full API endpoint documentation with examples' },
      { title: 'Authentication Guide',    url: 'https://intel.cyberdudebivash.com/api/#auth',   description: 'API key setup and JWT authentication' },
      { title: 'STIX 2.1 Export Guide',  url: 'https://intel.cyberdudebivash.com/api/#stix',   description: 'Structured threat information export' },
      { title: 'SIEM Integration Guide', url: 'https://intel.cyberdudebivash.com/api/#siem',   description: 'Webhook integration with Splunk, Sentinel, QRadar' },
      { title: 'Rate Limits',            url: 'https://intel.cyberdudebivash.com/api/#limits', description: 'API quota and rate limiting documentation' },
      { title: 'IOC Feed Format',        url: 'https://intel.cyberdudebivash.com/api/#ioc',    description: 'IOC data schema and feed format specification' },
      { title: 'Enterprise SLA',         url: 'https://intel.cyberdudebivash.com/docs/sla',    description: 'Enterprise uptime and support SLA details' },
      { title: 'Security Policy',        url: 'https://cyberdudebivash.in/security',          description: 'Platform security and data handling policy' },
    ],
    platform_url: 'https://intel.cyberdudebivash.com',
    support_email: 'support@cyberdudebivash.com',
  });
}

// ─── GET /api/support/tickets (admin only) ───────────────────────────────────
async function handleListTickets(request, env, authCtx) {
  const isAdmin = authCtx?.isAdmin || authCtx?.tier === 'ADMIN';
  if (!isAdmin) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const url    = new URL(request.url);
  const status = url.searchParams.get('status') || 'open';
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let tickets = [];
  try {
    const rows = await env.DB?.prepare(
      `SELECT id, user_id, tier, subject, category, priority, status, created_at
         FROM support_tickets WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(status, limit, offset).all().catch(() => ({ results: [] }));
    tickets = rows?.results || [];
  } catch { /* table may not exist */ }

  return Response.json({ total: tickets.length, status_filter: status, tickets });
}

// ─── GET /api/support/errors (admin only) — system_errors log (EBOC-1 / H-3) ─
async function handleListErrors(request, env, authCtx) {
  const isAdmin = authCtx?.isAdmin || authCtx?.tier === 'ADMIN';
  if (!isAdmin) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const url    = new URL(request.url);
  const area   = url.searchParams.get('area');
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);

  let errors = [];
  try {
    const rows = area
      ? await env.DB?.prepare(`SELECT * FROM system_errors WHERE area = ? ORDER BY created_at DESC LIMIT ?`).bind(area, limit).all().catch(() => ({ results: [] }))
      : await env.DB?.prepare(`SELECT * FROM system_errors ORDER BY created_at DESC LIMIT ?`).bind(limit).all().catch(() => ({ results: [] }));
    errors = rows?.results || [];
  } catch { /* table may not exist */ }

  return Response.json({ total: errors.length, area_filter: area || null, errors });
}

// ─── Main Dispatcher ─────────────────────────────────────────────────────────
export async function handleSupport(request, env, authCtx, path, method) {
  try {
    if (path === '/api/support/faq' && method === 'GET')      return handleFAQ(request, env);
    if (path === '/api/support/status' && method === 'GET')   return handleStatus(request, env);
    if (path === '/api/support/ticket' && method === 'POST')  return handleTicket(request, env, authCtx);
    if (path === '/api/support/tickets' && method === 'GET')  return handleListTickets(request, env, authCtx);
    if (path === '/api/support/errors' && method === 'GET')   return handleListErrors(request, env, authCtx);
    if (path === '/api/support/sla' && method === 'GET')      return handleSLA(request, env, authCtx);
    if (path === '/api/support/docs' && method === 'GET')     return handleDocs(request, env);

    return Response.json({
      error: 'Support route not found',
      available: [
        'GET  /api/support/faq',
        'GET  /api/support/status',
        'POST /api/support/ticket',
        'GET  /api/support/tickets (admin)',
        'GET  /api/support/errors (admin)',
        'GET  /api/support/sla',
        'GET  /api/support/docs',
      ],
    }, { status: 404 });
  } catch (err) {
    return Response.json({ error: 'Support handler error', detail: err?.message }, { status: 500 });
  }
}
