/**
 * CYBERDUDEBIVASH AI Security Hub — Support & Help Centre
 * FAQ, platform status, and ticket routing for customer support.
 *
 * Routes:
 *   GET   /api/support/faq                 - Frequently Asked Questions
 *   GET   /api/support/status              - Platform operational status
 *   POST  /api/support/ticket              - Submit a support ticket (login required)
 *   GET   /api/support/tickets/mine        - List the caller's own tickets (org-scoped if org_id given)
 *   GET   /api/support/ticket/:id          - Ticket detail + comment thread
 *   POST  /api/support/ticket/:id/comment  - Add a comment to a ticket
 *   POST  /api/support/ticket/:id/status   - Update ticket status
 *     (POST, not PATCH: workers/src/middleware/cors.js's Access-Control-Allow-Methods
 *      omits PATCH platform-wide — a pre-existing, cross-cutting gap affecting several
 *      other routes already, out of scope to fix here. Using POST keeps this new route
 *      actually reachable from a real browser instead of inheriting that bug.)
 *   GET   /api/support/tickets             - List tickets (admin only)
 *   GET   /api/support/sla                 - SLA documentation by tier
 *   GET   /api/support/docs                - Documentation index
 */

import { logSystemError } from '../lib/errorLog.js';
import { isRealUser } from '../auth/middleware.js';
import { ok, notFound, forbidden, unauthorized, badRequest, paginated } from '../lib/response.js';
import { deliverNotification } from './notificationPlatform.js';

// CAP-PORTAL-004: org scoping reuses the same org_members-based membership
// check as workers/src/handlers/aiMaturityHandler.js (PR #257) — this
// codebase's convention is to inline this per-handler rather than share a
// helper module (confirmed: no shared requireOrgRole() exists anywhere).
async function getOrgMembership(env, orgId, userId) {
  if (!orgId || !userId) return null;
  return env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, userId).first();
}

// A caller may view/comment/manage a ticket if they created it, they're an
// active member of the org it belongs to, or they're platform-staff admin.
async function canAccessTicket(env, ticket, authCtx) {
  if (authCtx?.isAdmin === true) return true;
  const uid = authCtx?.userId || authCtx?.user_id;
  if (uid && ticket.user_id === uid) return true;
  if (ticket.organization_id && uid) {
    const membership = await getOrgMembership(env, ticket.organization_id, uid);
    if (membership) return true;
  }
  return false;
}

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
    answer: 'Use your API key in the Authorization header: `Authorization: Bearer YOUR_API_KEY`. Example: `curl -H "Authorization: Bearer <key>" https://cyberdudebivash.in/api/intel/cve?limit=10`',
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
    docs_url: 'https://cyberdudebivash.in/api-docs.html',
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
      ? 'All CYBERDUDEBIVASH AI Security Hub systems operational.'
      : 'Some services are experiencing degraded performance. Our team is investigating.',
    components,
    last_updated: new Date().toISOString(),
    incident_url: 'https://cyberdudebivash.in/api/status',
    support_email: 'support@cyberdudebivash.com',
  });
}

// ─── POST /api/support/ticket ─────────────────────────────────────────────────
async function handleTicket(request, env, authCtx) {
  // CAP-PORTAL-004: ticket creation now requires a logged-in caller — closes an
  // unauthenticated-spam vector and lets every ticket be reliably tied to a
  // real customer for the "My Tickets" view, comments, and notifications.
  // Logged-out visitors continue to use the existing mailto: support links.
  // Deliberately checks for a real user id rather than authCtx.authenticated:
  // resolveAuthV5's anonymous IP-fallback also sets authenticated:true (see
  // auth/middleware.js), so presence of a real user id is the actual signal —
  // this also keeps the AI-copilot create_support_ticket tool (which forwards
  // its own session authCtx) working unchanged.
  const userId = authCtx?.userId || authCtx?.user_id;
  if (!userId) {
    return Response.json({ error: 'Login required to submit a support ticket', contact: 'support@cyberdudebivash.com' }, { status: 401 });
  }

  let body = {};
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { subject, description, category, priority, org_id } = body;
  if (!subject || !description)
    return Response.json({ error: 'subject and description are required' }, { status: 400 });

  let orgId = null;
  if (org_id) {
    const membership = await getOrgMembership(env, org_id, userId);
    if (!membership) return Response.json({ error: 'Not a member of this organization' }, { status: 403 });
    orgId = org_id;
  }

  const tier   = (authCtx?.tier || 'FREE').toUpperCase();
  const ticketId = `TKT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

  const sla = SLA_TIERS[tier] || SLA_TIERS.FREE;
  const supportEmail = ['ENTERPRISE','MSSP'].includes(tier)
    ? 'enterprise@cyberdudebivash.com'
    : 'support@cyberdudebivash.com';

  try {
    await env.DB.prepare(
      `INSERT INTO support_tickets (id, user_id, tier, subject, description, category, priority, status, organization_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, datetime('now'))`
    ).bind(ticketId, userId, tier, subject, description, category || 'general', priority || 'normal', orgId).run();
  } catch (e) {
    await logSystemError(env, { area: 'support.ticket_insert', message: e.message, context: { user_id: userId, tier } });
    return Response.json({ error: 'Ticket could not be recorded — please email support directly', contact: supportEmail }, { status: 500 });
  }

  // Fire-and-forget bell confirmation — never let a notification failure fail ticket creation.
  deliverNotification({
    userId, orgId,
    eventType: '*',
    subject: `Support ticket ${ticketId} received`,
    body: `We've received your ticket "${subject}". Expected response within ${sla.support_response}.`,
    channels: ['INAPP'],
  }, env).catch(() => {});

  return Response.json({
    success: true,
    ticket_id: ticketId,
    status: 'open',
    subject,
    tier,
    organization_id: orgId,
    sla: {
      response_time: sla.support_response,
      support_channel: sla.support_channel,
    },
    next_steps: `You will receive a response at ${supportEmail} within ${sla.support_response}.`,
    support_email: supportEmail,
    created_at: new Date().toISOString(),
  });
}

// ─── GET /api/support/tickets/mine ────────────────────────────────────────────
async function handleMyTickets(request, env, authCtx) {
  if (!isRealUser(authCtx)) return unauthorized(request);
  const uid = authCtx.userId || authCtx.user_id;

  const url    = new URL(request.url);
  const orgId  = url.searchParams.get('org_id');
  const page   = Math.max(1, parseInt(url.searchParams.get('page'), 10) || 1);
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 20));
  const offset = (page - 1) * limit;

  if (orgId) {
    const membership = await getOrgMembership(env, orgId, uid);
    if (!membership) return forbidden(request, 'Not a member of this organization');

    const [{ results }, countRow] = await Promise.all([
      env.DB.prepare(
        `SELECT id, user_id, tier, subject, category, priority, status, organization_id, created_at, updated_at
           FROM support_tickets WHERE organization_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      ).bind(orgId, limit, offset).all(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM support_tickets WHERE organization_id = ?`).bind(orgId).first(),
    ]);
    return paginated(request, results, countRow?.n || 0, page, limit);
  }

  const [{ results }, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT id, user_id, tier, subject, category, priority, status, organization_id, created_at, updated_at
         FROM support_tickets WHERE user_id = ? AND organization_id IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(uid, limit, offset).all(),
    env.DB.prepare(`SELECT COUNT(*) as n FROM support_tickets WHERE user_id = ? AND organization_id IS NULL`).bind(uid).first(),
  ]);
  return paginated(request, results, countRow?.n || 0, page, limit);
}

// ─── GET /api/support/ticket/:id ──────────────────────────────────────────────
async function handleTicketDetail(request, env, authCtx, id) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  const ticket = await env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(id).first();
  if (!ticket) return notFound(request, 'Ticket');
  if (!(await canAccessTicket(env, ticket, authCtx))) return notFound(request, 'Ticket'); // don't leak cross-org/cross-user existence

  const { results: comments } = await env.DB.prepare(
    `SELECT id, ticket_id, author_user_id, is_staff, body, created_at
       FROM support_ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC`
  ).bind(id).all();

  return ok(request, { ticket, comments: comments || [] });
}

// ─── POST /api/support/ticket/:id/comment ─────────────────────────────────────
async function handleAddComment(request, env, authCtx, id) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  const ticket = await env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(id).first();
  if (!ticket) return notFound(request, 'Ticket');
  if (!(await canAccessTicket(env, ticket, authCtx))) return notFound(request, 'Ticket');

  let body;
  try { body = await request.json(); } catch { return badRequest(request, 'Invalid JSON body'); }
  const text = (body?.body || '').trim();
  if (!text) return badRequest(request, 'body is required');

  const uid = authCtx.userId || authCtx.user_id;
  const isStaff = authCtx.isAdmin === true;
  const commentId = crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO support_ticket_comments (id, ticket_id, author_user_id, is_staff, body) VALUES (?, ?, ?, ?, ?)`
    ).bind(commentId, id, uid, isStaff ? 1 : 0, text),
    env.DB.prepare(`UPDATE support_tickets SET updated_at = datetime('now') WHERE id = ?`).bind(id),
  ]);

  // Only staff replies have a well-defined single recipient (the ticket owner).
  // A customer comment has no fixed "support staff" user id to notify in-app —
  // that side of the loop stays on the existing email-based staff channel.
  if (isStaff && ticket.user_id) {
    deliverNotification({
      userId: ticket.user_id, orgId: ticket.organization_id,
      eventType: '*',
      subject: `New reply on ticket ${id}`,
      body: text.slice(0, 200),
      channels: ['INAPP'],
    }, env).catch(() => {});
  }

  return ok(request, { id: commentId, ticket_id: id, author_user_id: uid, is_staff: isStaff, body: text }, 201);
}

// ─── PATCH /api/support/ticket/:id/status ─────────────────────────────────────
const CUSTOMER_ALLOWED_STATUSES = ['open', 'resolved'];
const ALL_STATUSES = ['open', 'resolved', 'closed'];

async function handleUpdateStatus(request, env, authCtx, id) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  const ticket = await env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(id).first();
  if (!ticket) return notFound(request, 'Ticket');

  const isStaff = authCtx.isAdmin === true;
  if (!isStaff && !(await canAccessTicket(env, ticket, authCtx))) return notFound(request, 'Ticket');

  let body;
  try { body = await request.json(); } catch { return badRequest(request, 'Invalid JSON body'); }
  const status = body?.status;

  const allowed = isStaff ? ALL_STATUSES : CUSTOMER_ALLOWED_STATUSES;
  if (!allowed.includes(status)) {
    return forbidden(request, isStaff
      ? `status must be one of: ${ALL_STATUSES.join(', ')}`
      : `Customers may only set status to: ${CUSTOMER_ALLOWED_STATUSES.join(', ')}`);
  }

  await env.DB.prepare(`UPDATE support_tickets SET status = ?, updated_at = datetime('now') WHERE id = ?`).bind(status, id).run();

  if (isStaff && ticket.user_id) {
    deliverNotification({
      userId: ticket.user_id, orgId: ticket.organization_id,
      eventType: '*',
      subject: `Ticket ${id} status changed to ${status}`,
      body: `Your support ticket "${ticket.subject}" is now ${status}.`,
      channels: ['INAPP'],
    }, env).catch(() => {});
  }

  return ok(request, { id, status });
}

// ─── GET /api/support/sla ─────────────────────────────────────────────────────
async function handleSLA(request, env, authCtx) {
  const tier = authCtx?.tier?.toUpperCase() || null;

  return Response.json({
    tiers: SLA_TIERS,
    your_sla: tier ? (SLA_TIERS[tier] || SLA_TIERS.FREE) : null,
    your_tier: tier,
    uptime_history_url: 'https://cyberdudebivash.in/api/status',
    enterprise_custom_sla: 'Contact enterprise@cyberdudebivash.com for custom SLA agreements.',
  });
}

// ─── GET /api/support/docs ────────────────────────────────────────────────────
async function handleDocs(request, env) {
  return Response.json({
    documentation: [
      { title: 'API Reference',           url: 'https://cyberdudebivash.in/api-docs.html',              description: 'Full API endpoint documentation with examples' },
      { title: 'Authentication Guide',    url: 'https://cyberdudebivash.in/api-docs.html#auth',         description: 'API key setup and JWT authentication' },
      { title: 'STIX 2.1 Export Guide',  url: 'https://cyberdudebivash.in/api-docs.html',               description: 'Structured threat information export' },
      { title: 'SIEM Integration Guide', url: 'https://cyberdudebivash.in/api-docs.html',               description: 'Webhook integration with Splunk, Sentinel, QRadar' },
      { title: 'Rate Limits',            url: 'https://cyberdudebivash.in/api-docs.html#rate-limits',   description: 'API quota and rate limiting documentation' },
      { title: 'IOC Feed Format',        url: 'https://cyberdudebivash.in/api-docs.html',               description: 'IOC data schema and feed format specification' },
      { title: 'Enterprise SLA',         url: 'https://cyberdudebivash.in/trust-center.html#vd-sla',    description: 'Enterprise uptime and support SLA details' },
      { title: 'Security Policy',        url: 'https://cyberdudebivash.in/trust-center.html',          description: 'Platform security and data handling policy' },
    ],
    platform_url: 'https://cyberdudebivash.in',
    support_email: 'support@cyberdudebivash.com',
  });
}

// ─── GET /api/support/tickets (admin only) ───────────────────────────────────
async function handleListTickets(request, env, authCtx) {
  const isAdmin = authCtx?.isAdmin || authCtx?.tier === 'ADMIN';
  if (!isAdmin) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const url    = new URL(request.url);
  const status = url.searchParams.get('status') || 'open';
  const orgId  = url.searchParams.get('org_id');
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let tickets = [];
  try {
    const rows = orgId
      ? await env.DB?.prepare(
          `SELECT id, user_id, tier, subject, category, priority, status, organization_id, created_at
             FROM support_tickets WHERE status = ? AND organization_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).bind(status, orgId, limit, offset).all().catch(() => ({ results: [] }))
      : await env.DB?.prepare(
          `SELECT id, user_id, tier, subject, category, priority, status, organization_id, created_at
             FROM support_tickets WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).bind(status, limit, offset).all().catch(() => ({ results: [] }));
    tickets = rows?.results || [];
  } catch { /* table may not exist */ }

  return Response.json({ total: tickets.length, status_filter: status, org_filter: orgId || null, tickets });
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
    if (path === '/api/support/faq' && method === 'GET')          return handleFAQ(request, env);
    if (path === '/api/support/status' && method === 'GET')       return handleStatus(request, env);
    if (path === '/api/support/ticket' && method === 'POST')      return handleTicket(request, env, authCtx);
    if (path === '/api/support/tickets/mine' && method === 'GET') return handleMyTickets(request, env, authCtx);
    if (path === '/api/support/tickets' && method === 'GET')      return handleListTickets(request, env, authCtx);
    if (path === '/api/support/errors' && method === 'GET')       return handleListErrors(request, env, authCtx);
    if (path === '/api/support/sla' && method === 'GET')          return handleSLA(request, env, authCtx);
    if (path === '/api/support/docs' && method === 'GET')         return handleDocs(request, env);

    const commentMatch = path.match(/^\/api\/support\/ticket\/([^/]+)\/comment$/);
    if (commentMatch && method === 'POST') return handleAddComment(request, env, authCtx, commentMatch[1]);

    const statusMatch = path.match(/^\/api\/support\/ticket\/([^/]+)\/status$/);
    if (statusMatch && method === 'POST') return handleUpdateStatus(request, env, authCtx, statusMatch[1]);

    const detailMatch = path.match(/^\/api\/support\/ticket\/([^/]+)$/);
    if (detailMatch && method === 'GET') return handleTicketDetail(request, env, authCtx, detailMatch[1]);

    return Response.json({
      error: 'Support route not found',
      available: [
        'GET   /api/support/faq',
        'GET   /api/support/status',
        'POST  /api/support/ticket',
        'GET   /api/support/tickets/mine',
        'GET   /api/support/ticket/:id',
        'POST  /api/support/ticket/:id/comment',
        'POST  /api/support/ticket/:id/status',
        'GET   /api/support/tickets (admin)',
        'GET   /api/support/errors (admin)',
        'GET   /api/support/sla',
        'GET   /api/support/docs',
      ],
    }, { status: 404 });
  } catch (err) {
    return Response.json({ error: 'Support handler error', detail: err?.message }, { status: 500 });
  }
}
