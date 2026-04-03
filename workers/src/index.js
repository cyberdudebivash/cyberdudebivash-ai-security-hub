/**
 * CYBERDUDEBIVASH AI Security Hub — Main Router v8.0
 * World-class AI Cybersecurity SaaS: AI Brain, Attack Graphs, Threat Correlation,
 * Continuous Monitoring, Multi-Tenant Orgs, Content Engine, Public API Platform
 *
 * Auth priority: JWT Bearer → API Key (cdb_*) → IP fallback (FREE)
 *
 * New in v8.0:
 *   AI Brain:          GET  /api/insights/:jobId  → AI narrative from scan
 *   Attack Graph:      POST /api/attack-graph      → D3-ready attack graph
 *   Threat Intel:      GET  /api/threat-intel/stats
 *   Monitoring:        CRUD /api/monitors/*        → scheduled scan monitors
 *   Content Engine:    CRUD /api/content/*         → auto-generated posts
 *   Org Management:    CRUD /api/orgs/*            → multi-tenant orgs + teams
 */

// ─── Sync scan handlers (v4 — backward compat) ───────────────────────────────
import { handleDomainScan }        from './handlers/domain.js';
import { handleAIScan }            from './handlers/ai.js';
import { handleRedteamScan }       from './handlers/redteam.js';
import { handleIdentityScan }      from './handlers/identity.js';
import { handleCompliance }        from './handlers/compliance.js';
import { handleLeadCapture }       from './handlers/leads.js';
import { handleEnterpriseContact } from './handlers/enterprise.js';

// ─── New v5.0 handlers ────────────────────────────────────────────────────────
import { handleReportDownload, handleReportGenerate } from './handlers/report.js';
import {
  handleSignup, handleLogin, handleRefresh, handleLogout,
  handleGetProfile, handleUpdateProfile, handleAlertConfig, handleTestAlert,
} from './handlers/auth.js';
import { handleListKeys, handleCreateKey, handleRevokeKey, handleKeyUsage } from './handlers/apikeys.js';
import { handleAsyncScan, handleJobStatus, handleJobResult, handleD1History } from './handlers/jobs.js';

// ─── New v7.0 handlers ────────────────────────────────────────────────────────
import {
  handleCreateOrder, handleVerifyPayment, handlePaymentStatus,
  handleReportDownload as handlePaidReportDownload,
  handleRazorpayWebhook,
} from './handlers/payments.js';
import { handleGetAnalytics, handleScanStats, trackEvent } from './handlers/analytics.js';

// ─── New v8.0 handlers ────────────────────────────────────────────────────────
import {
  handleCreateMonitor, handleListMonitors, handleGetMonitor,
  handleUpdateMonitor, handleDeleteMonitor, handleMonitorHistory,
  handleTriggerMonitor, runMonitoringCron,
} from './handlers/monitoring.js';
import {
  handleGenerateContent, handleListContent, handleGetContent,
  handlePublishContent, handleDeleteContent, handleContentFeed,
} from './handlers/contentEngine.js';
import {
  handleCreateOrg, handleListOrgs, handleGetOrg, handleUpdateOrg, handleDeleteOrg,
  handleOrgDashboard, handleInviteMember,
  handleUpdateMemberRole, handleRemoveMember,
  handleOrgScans,
} from './handlers/orgManagement.js';
import { generateAIInsights } from './lib/aiBrain.js';
import { buildAttackGraph }   from './lib/attackGraph.js';
import { correlateThreatIntel, getThreatIntelStats, purgeExpiredThreatIntel } from './lib/threatCorrelation.js';

// ─── Intelligence + Sentinel ─────────────────────────────────────────────────
import { handleSentinelFeed, handleSentinelStatus, runSentinelCron } from './lib/sentinelApex.js';
import { processQueueBatch }   from './lib/queue.js';

// ─── Middleware ───────────────────────────────────────────────────────────────
import { corsHeaders, withCors }                                       from './middleware/cors.js';
import { resolveAuthV5, unauthorized, enforceQuota, CONTACT_EMAIL }   from './auth/middleware.js';
import { checkRateLimitV2, rateLimitResponse, injectRateLimitHeaders } from './middleware/rateLimit.js';
import { withSecurityHeaders, checkBodySize, inspectForAttacks, logSuspicious } from './middleware/security.js';
import { handlePaymentWebhook }                                        from './middleware/monetization.js';

// ─── Sync scan route map (v4 backward compat) ─────────────────────────────────
const SYNC_ROUTES = {
  'POST /api/scan/domain':         { handler: handleDomainScan,       module: 'domain'     },
  'POST /api/scan/ai':             { handler: handleAIScan,           module: 'ai'         },
  'POST /api/scan/redteam':        { handler: handleRedteamScan,      module: 'redteam'    },
  'POST /api/scan/identity':       { handler: handleIdentityScan,     module: 'identity'   },
  'POST /api/generate/compliance': { handler: handleCompliance,       module: 'compliance' },
  'POST /api/leads/capture':       { handler: handleLeadCapture,      module: 'leads'      },
  'POST /api/contact/enterprise':  { handler: handleEnterpriseContact,module: 'enterprise' },
  'POST /api/report/generate':     { handler: handleReportGenerate,   module: 'report'     },
};

// ─── Full auth+rate-limit pipeline for sync scan routes ──────────────────────
async function runSyncPipeline(request, env, routeKey, route) {
  const sizeErr = checkBodySize(request, 32768);
  if (sizeErr) return sizeErr;

  const authCtx  = await resolveAuthV5(request, env);
  if (!authCtx.authenticated) return unauthorized(authCtx.error || 'invalid');

  // D1-based quota (API keys) or KV-based rate limit (IP/JWT)
  if (authCtx.method === 'api_key') {
    const quota = await enforceQuota(env, authCtx, route.module);
    if (!quota.allowed) return rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, route.module);
  } else {
    const rl = await checkRateLimitV2(env, authCtx, route.module);
    if (!rl.allowed) return rateLimitResponse(rl, route.module);
  }

  const response = await route.handler(request, env, authCtx);
  return injectRateLimitHeaders(response, { tier: authCtx.tier, remaining: '?' });
}

// ─── Health response ──────────────────────────────────────────────────────────
function healthResponse() {
  return Response.json({
    status:  'ok',
    service: 'CYBERDUDEBIVASH AI Security Hub',
    version: '8.0.0',
    company: 'CyberDudeBivash Pvt. Ltd.',
    website: 'https://cyberdudebivash.in',
    tools:   'https://tools.cyberdudebivash.com',
    contact: CONTACT_EMAIL,
    telegram:'https://t.me/cyberdudebivashSentinelApex',
    new_in_v8: [
      'AI Cyber Brain — threat narratives, attack scenarios, executive briefs',
      'Attack Graph Engine — D3-ready force-directed exploit path visualization',
      'Threat Correlation — live CVE/EPSS/KEV matching with dynamic risk boosting',
      'Continuous Monitoring — scheduled scans, drift detection, real-time alerts',
      'Content & Distribution Engine — auto-generate blog posts, Telegram publish',
      'Enterprise Multi-Tenant — organizations, teams, RBAC, org dashboards',
      'Public API Platform — api_keys, quota tracking, API request logging',
      'Razorpay monetization (V7) — pay-per-report + HTML/PDF delivery',
    ],
    modules:   ['domain','ai','redteam','identity','compliance'],
    timestamp: new Date().toISOString(),
  });
}

// ─── API info ─────────────────────────────────────────────────────────────────
function apiInfoResponse() {
  return Response.json({
    name:    'CYBERDUDEBIVASH AI Security Hub API',
    version: '5.0.0',
    auth_methods: {
      jwt:     'Authorization: Bearer <access_token>  (from /api/auth/login)',
      api_key: 'x-api-key: cdb_<key>  (from /api/keys)',
      free:    'No auth required (FREE tier, 5 req/day by IP)',
    },
    endpoints: {
      // Auth
      'POST /api/auth/signup':      'Create account → access + refresh tokens',
      'POST /api/auth/login':       'Authenticate → access + refresh tokens',
      'POST /api/auth/refresh':     'Rotate access token using refresh token',
      'POST /api/auth/logout':      'Revoke session (single or all)',
      'GET  /api/auth/me':          'Current user profile + scan stats',
      'PUT  /api/auth/profile':     'Update name, company, telegram_chat_id',
      'POST /api/auth/alerts':      'Configure Telegram + email alert rules',
      'POST /api/auth/test-alert':  'Fire a test alert to verify config',
      // API Keys
      'GET  /api/keys':             'List your API keys',
      'POST /api/keys':             'Generate new API key (shown once)',
      'DELETE /api/keys/:id':       'Revoke a key',
      'GET  /api/keys/:id/usage':   'Daily/monthly usage for a key',
      // Sync scans (v4 compatible)
      'POST /api/scan/domain':      'Synchronous domain scan (live DNS + DNSBL)',
      'POST /api/scan/ai':          'AI model security assessment',
      'POST /api/scan/redteam':     'Red team attack simulation',
      'POST /api/scan/identity':    'Identity & access security scan',
      'POST /api/generate/compliance': 'Compliance gap report',
      // Async scans (v5)
      'POST /api/scan/async/domain': 'Queue domain scan → job_id (non-blocking)',
      'POST /api/scan/async/ai':     'Queue AI scan → job_id',
      'POST /api/scan/async/redteam':'Queue red team scan → job_id',
      'GET  /api/jobs/:id':          'Poll job status',
      'GET  /api/jobs/:id/result':   'Retrieve completed scan result',
      // Reports + History
      'POST /api/report/generate':   'Generate downloadable report',
      'GET  /api/report/:token':     'Download report (7-day token)',
      'GET  /api/history':           'Scan history (D1 for auth users, KV for IP)',
      // Intelligence
      'GET  /api/sentinel/feed':     'Live CVE + KEV threat feed',
      'GET  /api/sentinel/status':   'Feed metadata + last refresh',
      // Other
      'GET  /api/health':            'Service health',
      'POST /api/webhooks/razorpay': 'Razorpay payment webhook',
    },
    tiers: {
      FREE:       { daily_limit:  5, burst: '2/min',  key_limit: 2, queue_priority: 'low'  },
      PRO:        { daily_limit: 500, burst: '20/min', key_limit: 5, queue_priority: 'normal' },
      ENTERPRISE: { daily_limit: -1, burst: '60/min', key_limit: 20, queue_priority: 'high' },
    },
    contact: CONTACT_EMAIL,
    pricing: 'https://tools.cyberdudebivash.com/#pricing',
  });
}

// ─── Main fetch handler ───────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Block URL-level attacks
    if (inspectForAttacks(url.pathname + url.search)) {
      logSuspicious(env, request, 'url_attack').catch(() => {});
      return withSecurityHeaders(withCors(Response.json({ error: 'Bad request' }, { status: 400 }), request));
    }

    // ── Static / no-auth routes ─────────────────────────────────────────────
    if (path === '/api/health' && method === 'GET') {
      return withSecurityHeaders(withCors(healthResponse(), request));
    }
    if ((path === '/api' || path === '') && method === 'GET') {
      return withSecurityHeaders(withCors(apiInfoResponse(), request));
    }

    // ── Auth routes (no rate limit — have their own brute-force protection) ─
    if (path === '/api/auth/signup' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleSignup(request, env), request));
    }
    if (path === '/api/auth/login' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleLogin(request, env), request));
    }
    if (path === '/api/auth/refresh' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRefresh(request, env), request));
    }
    if (path === '/api/auth/logout' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleLogout(request, env, authCtx), request));
    }
    if (path === '/api/auth/me' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGetProfile(request, env, authCtx), request));
    }
    if (path === '/api/auth/profile' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleUpdateProfile(request, env, authCtx), request));
    }
    if (path === '/api/auth/alerts' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAlertConfig(request, env, authCtx), request));
    }
    if (path === '/api/auth/test-alert' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleTestAlert(request, env, authCtx), request));
    }

    // ── API Key management ──────────────────────────────────────────────────
    if (path === '/api/keys') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (method === 'GET')  return withSecurityHeaders(withCors(await handleListKeys(request, env, authCtx), request));
      if (method === 'POST') return withSecurityHeaders(withCors(await handleCreateKey(request, env, authCtx), request));
    }
    if (path.startsWith('/api/keys/') && path.includes('/usage') && method === 'GET') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleKeyUsage(request, env, authCtx, keyId), request));
    }
    if (path.startsWith('/api/keys/') && method === 'DELETE') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleRevokeKey(request, env, authCtx, keyId), request));
    }

    // ── Async scan (v5) ─────────────────────────────────────────────────────
    if (path.startsWith('/api/scan/async/') && method === 'POST') {
      const module  = path.split('/')[4]; // /api/scan/async/:module
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const quota = await enforceQuota(env, authCtx, module);
      if (!quota.allowed) return withSecurityHeaders(withCors(
        rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, module), request
      ));
      return withSecurityHeaders(withCors(await handleAsyncScan(request, env, authCtx, module), request));
    }

    // ── Job status + result ─────────────────────────────────────────────────
    if (path.startsWith('/api/jobs/')) {
      const parts  = path.split('/');   // ['','api','jobs',jobId,'result'?]
      const jobId  = parts[3];
      const sub    = parts[4] || '';
      const authCtx = await resolveAuthV5(request, env);

      if (method === 'GET' && sub === 'result') {
        return withSecurityHeaders(withCors(await handleJobResult(request, env, authCtx, jobId), request));
      }
      if (method === 'GET') {
        return withSecurityHeaders(withCors(await handleJobStatus(request, env, authCtx, jobId), request));
      }
    }

    // ── Scan history ────────────────────────────────────────────────────────
    if (path === '/api/history' && (method === 'GET' || method === 'DELETE')) {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleD1History(request, env, authCtx), request));
    }

    // ── Report ──────────────────────────────────────────────────────────────
    if (path.startsWith('/api/report/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleReportDownload(request, env, authCtx), request));
    }

    // ── Sentinel APEX (public, cached) ──────────────────────────────────────
    if (path === '/api/sentinel/feed' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }
    if (path === '/api/sentinel/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelStatus(request, env), request));
    }

    // ── V7.0 Payment routes ─────────────────────────────────────────────────
    if (path === '/api/payments/create-order' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateOrder(request, env, authCtx), request));
    }
    if (path === '/api/payments/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleVerifyPayment(request, env, authCtx), request));
    }
    if (path.startsWith('/api/payments/status/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handlePaymentStatus(request, env, authCtx), request));
    }

    // ── V7.0 Token-gated paid report download ────────────────────────────────
    if (path.startsWith('/api/reports/download/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(await handlePaidReportDownload(request, env, authCtx));
    }

    // ── V7.0 Admin analytics ─────────────────────────────────────────────────
    if (path === '/api/admin/analytics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGetAnalytics(request, env, authCtx), request));
    }
    if (path === '/api/admin/analytics/scans' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleScanStats(request, env, authCtx), request));
    }

    // ── Razorpay webhook (V7 replaces monetization middleware stub) ──────────
    if (path === '/api/webhooks/razorpay' && method === 'POST') {
      return withSecurityHeaders(await handleRazorpayWebhook(request, env));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // V8.0 ROUTES — AI Brain, Attack Graph, Threat Intel, Monitoring,
    //               Content Engine, Org Management
    // ══════════════════════════════════════════════════════════════════════════

    // ── AI Cyber Brain: insights from scan result ─────────────────────────────
    if (path === '/api/insights' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { scan_result, module, target } = body;
        if (!scan_result || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'scan_result and module required' }, { status: 400 }), request));
        }
        const insights = await generateAIInsights(scan_result, module, env);
        return withSecurityHeaders(withCors(Response.json({ success: true, module, target, insights }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // ── Attack Graph: D3-ready graph from scan result ─────────────────────────
    if (path === '/api/attack-graph' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { scan_result, module } = body;
        if (!scan_result || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'scan_result and module required' }, { status: 400 }), request));
        }
        const graph = buildAttackGraph(scan_result, module);
        return withSecurityHeaders(withCors(Response.json({ success: true, graph }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // ── Threat Intel: correlate CVEs + stats ──────────────────────────────────
    if (path === '/api/threat-intel/correlate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { findings, scan_result, module } = body;
        if (!findings || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'findings and module required' }, { status: 400 }), request));
        }
        const correlation = await correlateThreatIntel(findings, scan_result || {}, module, env);
        return withSecurityHeaders(withCors(Response.json({ success: true, correlation }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }
    if (path === '/api/threat-intel/stats' && method === 'GET') {
      const stats = await getThreatIntelStats(env);
      return withSecurityHeaders(withCors(Response.json({ success: true, stats }), request));
    }

    // ── Continuous Monitoring ─────────────────────────────────────────────────
    if (path === '/api/monitors' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateMonitor(request, env, authCtx), request));
    }
    if (path === '/api/monitors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListMonitors(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'GET') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'PUT') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleUpdateMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'DELETE') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+\/history$/) && method === 'GET') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleMonitorHistory(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+\/run$/) && method === 'POST') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleTriggerMonitor(request, env, authCtx, monitorId), request));
    }

    // ── Content & Distribution Engine ─────────────────────────────────────────
    if (path === '/api/content' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGenerateContent(request, env, authCtx), request));
    }
    if (path === '/api/content' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListContent(request, env, authCtx), request));
    }
    if (path === '/api/content/feed' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleContentFeed(request, env), request));
    }
    if (path.match(/^\/api\/content\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetContent(request, env, authCtx, postId), request));
    }
    if (path.match(/^\/api\/content\/[^/]+\/publish$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handlePublishContent(request, env, authCtx, postId), request));
    }
    if (path.match(/^\/api\/content\/[^/]+$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteContent(request, env, authCtx, postId), request));
    }

    // ── Enterprise Multi-Tenant Orgs ──────────────────────────────────────────
    if (path === '/api/orgs' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateOrg(request, env, authCtx), request));
    }
    if (path === '/api/orgs' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListOrgs(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgSlug = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetOrg(request, env, authCtx, orgSlug), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleUpdateOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/dashboard$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleOrgDashboard(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleInviteMember(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members\/[^/]+$/) && method === 'PUT') {
      const authCtx    = await resolveAuthV5(request, env);
      const parts      = path.split('/');
      const orgId      = parts[3];
      const targetUser = parts[5];
      return withSecurityHeaders(withCors(await handleUpdateMemberRole(request, env, authCtx, orgId, targetUser), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members\/[^/]+$/) && method === 'DELETE') {
      const authCtx    = await resolveAuthV5(request, env);
      const parts      = path.split('/');
      const orgId      = parts[3];
      const targetUser = parts[5];
      return withSecurityHeaders(withCors(await handleRemoveMember(request, env, authCtx, orgId, targetUser), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/scans$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleOrgScans(request, env, authCtx, orgId), request));
    }

    // ── Sync scan routes (v4 backward compat — full pipeline) ────────────────
    const routeKey = `${method} ${path}`;
    const route    = SYNC_ROUTES[routeKey];
    if (route) {
      try {
        const response = await runSyncPipeline(request, env, routeKey, route);
        return withSecurityHeaders(withCors(response, request));
      } catch (err) {
        console.error(`[${routeKey}]`, err?.message);
        return withSecurityHeaders(withCors(Response.json({
          error:      'Internal server error',
          request_id: crypto.randomUUID?.() || Date.now().toString(36),
          support:    CONTACT_EMAIL,
        }, { status: 500 }), request));
      }
    }

    // ── 404 ─────────────────────────────────────────────────────────────────
    return withSecurityHeaders(withCors(Response.json({
      error:    'Not Found',
      path,
      method,
      api_docs: 'GET /api',
      contact:  CONTACT_EMAIL,
    }, { status: 404 }), request));
  },

  // ── Cloudflare Queue consumer ─────────────────────────────────────────────
  async queue(batch, env) {
    await processQueueBatch(batch, env);
  },

  // ── Cron scheduler ───────────────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    console.log('[CRON]', event.cron, event.scheduledTime);

    // Run Sentinel APEX CVE feed refresh
    ctx.waitUntil(
      runSentinelCron(env)
        .then(r => console.log('[CRON] Sentinel APEX:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Sentinel error:', e?.message))
    );

    // Run continuous monitoring scans
    ctx.waitUntil(
      runMonitoringCron(env)
        .then(r => console.log('[CRON] Monitoring:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Monitoring error:', e?.message))
    );

    // Purge expired threat intel cache
    ctx.waitUntil(
      purgeExpiredThreatIntel(env)
        .then(n => { if (n > 0) console.log(`[CRON] Purged ${n} expired threat intel entries`); })
        .catch(e => console.error('[CRON] Purge error:', e?.message))
    );
  },
};
