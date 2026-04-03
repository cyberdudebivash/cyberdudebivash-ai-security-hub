/**
 * CYBERDUDEBIVASH AI Security Hub — Main Router v4.0
 * Cloudflare Workers edge API gateway
 * Full middleware chain: Security → CORS → Auth → RateLimit → Handler → Response
 * New in v4.0: Real DNS scanning, DNSBL, Reports, History, Sentinel APEX CVE feed
 */

// ─── Scan Handlers ────────────────────────────────────────────────────────────
import { handleDomainScan }       from './handlers/domain.js';
import { handleAIScan }           from './handlers/ai.js';
import { handleRedteamScan }      from './handlers/redteam.js';
import { handleIdentityScan }     from './handlers/identity.js';
import { handleCompliance }       from './handlers/compliance.js';
import { handleLeadCapture }      from './handlers/leads.js';
import { handleEnterpriseContact }from './handlers/enterprise.js';

// ─── New v4 Handlers ─────────────────────────────────────────────────────────
import { handleReportDownload, handleReportGenerate } from './handlers/report.js';
import { handleScanHistory }                          from './handlers/history.js';
import { handleSentinelFeed, handleSentinelStatus, runSentinelCron } from './lib/sentinelApex.js';

// ─── Middleware ───────────────────────────────────────────────────────────────
import { corsHeaders, withCors }                                       from './middleware/cors.js';
import { resolveAuth, authError }                                      from './middleware/auth.js';
import { checkRateLimitV2, rateLimitResponse, injectRateLimitHeaders } from './middleware/rateLimit.js';
import { withSecurityHeaders, checkBodySize, inspectForAttacks, logSuspicious } from './middleware/security.js';
import { handlePaymentWebhook }                                        from './middleware/monetization.js';

// ─── Route Config (POST routes with full middleware pipeline) ─────────────────
const SCAN_ROUTES = {
  'POST /api/scan/domain':         { handler: handleDomainScan,       module: 'domain',     requireAuth: false },
  'POST /api/scan/ai':             { handler: handleAIScan,           module: 'ai',         requireAuth: false },
  'POST /api/scan/redteam':        { handler: handleRedteamScan,      module: 'redteam',    requireAuth: false },
  'POST /api/scan/identity':       { handler: handleIdentityScan,     module: 'identity',   requireAuth: false },
  'POST /api/generate/compliance': { handler: handleCompliance,       module: 'compliance', requireAuth: false },
  'POST /api/leads/capture':       { handler: handleLeadCapture,      module: 'leads',      requireAuth: false },
  'POST /api/contact/enterprise':  { handler: handleEnterpriseContact,module: 'enterprise', requireAuth: false },
  'POST /api/report/generate':     { handler: handleReportGenerate,   module: 'report',     requireAuth: false },
};

// ─── Middleware Pipeline ──────────────────────────────────────────────────────
async function runPipeline(request, env, routeKey, route) {
  const sizeErr = checkBodySize(request, 32768); // 32KB max body
  if (sizeErr) return sizeErr;

  const authCtx = await resolveAuth(request, env);
  if (!authCtx.authenticated) return authError(authCtx.error || 'invalid');

  const rlResult = await checkRateLimitV2(env, authCtx, route.module);
  if (!rlResult.allowed) return rateLimitResponse(rlResult, route.module);

  let response = await route.handler(request, env, authCtx);
  response     = injectRateLimitHeaders(response, rlResult);
  return response;
}

// ─── Health / Info ────────────────────────────────────────────────────────────
function buildHealthResponse() {
  return Response.json({
    status:   'ok',
    service:  'CYBERDUDEBIVASH AI Security Hub',
    version:  '4.0.0',
    company:  'CyberDudeBivash Pvt. Ltd.',
    website:  'https://cyberdudebivash.in',
    tools:    'https://tools.cyberdudebivash.com',
    telegram: 'https://t.me/cyberdudebivashSentinelApex',
    modules:  ['domain','ai','redteam','identity','compliance'],
    new_in_v4: [
      'Real DNS scanning (DoH via Cloudflare)',
      'SPF/DMARC/DKIM live validation',
      'DNSBL threat intel (Spamhaus, SURBL, URIBL, CISA KEV)',
      'DNSSEC validation',
      'TLS/HSTS live probe',
      'KV scan caching (1h TTL)',
      'Report generation + 7-day download tokens',
      'Scan history per identity',
      'Sentinel APEX CVE feed (NVD + CISA, 6h refresh)',
    ],
    timestamp: new Date().toISOString(),
  });
}

function buildApiInfoResponse() {
  return Response.json({
    name:    'CYBERDUDEBIVASH AI Security Hub API',
    version: '4.0.0',
    auth:    'Header: x-api-key (optional for FREE tier)',
    tiers:   { FREE:'5 req/day', PRO:'500 req/day', ENTERPRISE:'unlimited' },
    endpoints: {
      health:           'GET  /api/health',
      api_info:         'GET  /api',
      domain_scan:      'POST /api/scan/domain',
      ai_scan:          'POST /api/scan/ai',
      redteam_scan:     'POST /api/scan/redteam',
      identity_scan:    'POST /api/scan/identity',
      compliance:       'POST /api/generate/compliance',
      report_generate:  'POST /api/report/generate',
      report_download:  'GET  /api/report/:token',
      report_by_id:     'GET  /api/report/id/:report_id',
      scan_history:     'GET  /api/history',
      clear_history:    'DELETE /api/history',
      sentinel_feed:    'GET  /api/sentinel/feed',
      sentinel_status:  'GET  /api/sentinel/status',
      leads:            'POST /api/leads/capture',
      enterprise:       'POST /api/contact/enterprise',
      webhook:          'POST /api/webhooks/razorpay',
    },
    example_domain_scan: {
      method: 'POST',
      url: 'https://cyberdudebivash-security-hub.workers.dev/api/scan/domain',
      body: { domain: 'example.com' },
      note: 'Returns live DNS, HSTS, SPF, DMARC, DKIM, DNSSEC, DNSBL results',
    },
    pricing: 'https://cyberdudebivash.in/#pricing',
    docs:    'https://cyberdudebivash.in/docs',
  });
}

// ─── Main Worker Entry ────────────────────────────────────────────────────────
export default {
  // ── HTTP fetch handler ────────────────────────────────────────────────────
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Block attack patterns in URL
    const fullUrl = url.pathname + url.search;
    if (inspectForAttacks(fullUrl)) {
      logSuspicious(env, request, 'url_attack_pattern').catch(() => {});
      return withSecurityHeaders(withCors(Response.json({ error: 'Bad request' }, { status: 400 }), request));
    }

    // ── Static routes (no middleware) ─────────────────────────────────────
    if (path === '/api/health' && method === 'GET') {
      return withSecurityHeaders(withCors(buildHealthResponse(), request));
    }
    if ((path === '/api' || path === '/api/') && method === 'GET') {
      return withSecurityHeaders(withCors(buildApiInfoResponse(), request));
    }

    // ── Razorpay webhook ──────────────────────────────────────────────────
    if (path === '/api/webhooks/razorpay' && method === 'POST') {
      return withSecurityHeaders(await handlePaymentWebhook(request, env));
    }

    // ── Sentinel APEX (public, cached, rate-limit-free) ───────────────────
    if (path === '/api/sentinel/feed' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }
    if (path === '/api/sentinel/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelStatus(request, env), request));
    }

    // ── Report download (GET, no heavy middleware) ────────────────────────
    if (path.startsWith('/api/report/') && method === 'GET') {
      const authCtx = await resolveAuth(request, env);
      const res     = await handleReportDownload(request, env, authCtx);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── Scan history ──────────────────────────────────────────────────────
    if (path === '/api/history' && (method === 'GET' || method === 'DELETE')) {
      const authCtx = await resolveAuth(request, env);
      if (!authCtx.authenticated) {
        return withSecurityHeaders(withCors(authError(authCtx.error || 'invalid'), request));
      }
      const res = await handleScanHistory(request, env, authCtx);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── POST routes with full pipeline ────────────────────────────────────
    const routeKey = `${method} ${path}`;
    const route    = SCAN_ROUTES[routeKey];

    if (route) {
      try {
        const response = await runPipeline(request, env, routeKey, route);
        return withSecurityHeaders(withCors(response, request));
      } catch (err) {
        console.error(`[${routeKey}] Unhandled error:`, err?.message);
        return withSecurityHeaders(withCors(Response.json({
          error:      'Internal server error',
          module:     routeKey,
          request_id: crypto.randomUUID?.() || Date.now().toString(36),
          support:    'cyberdudebivash@gmail.com',
        }, { status: 500 }), request));
      }
    }

    // ── 404 ───────────────────────────────────────────────────────────────
    return withSecurityHeaders(withCors(Response.json({
      error:    'Not Found',
      path,
      method,
      api_docs: 'GET /api',
      website:  'https://cyberdudebivash.in',
    }, { status: 404 }), request));
  },

  // ── Cron handler — Sentinel APEX feed refresh ─────────────────────────────
  async scheduled(event, env, ctx) {
    console.log('[CRON] Sentinel APEX feed refresh triggered:', event.cron);
    ctx.waitUntil(
      runSentinelCron(env).then(result => {
        console.log('[CRON] Sentinel APEX result:', JSON.stringify(result));
      }).catch(err => {
        console.error('[CRON] Sentinel APEX error:', err?.message);
      })
    );
  },
};
