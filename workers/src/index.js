/**
 * CYBERDUDEBIVASH AI Security Hub — Main Router v3.0
 * Cloudflare Workers edge API gateway
 * Full middleware chain: Security → CORS → Auth → RateLimit → Handler → Response
 */

// ─── Handlers ─────────────────────────────────────────────────────────────────
import { handleDomainScan }    from './handlers/domain.js';
import { handleAIScan }        from './handlers/ai.js';
import { handleRedteamScan }   from './handlers/redteam.js';
import { handleIdentityScan }  from './handlers/identity.js';
import { handleCompliance }    from './handlers/compliance.js';
import { handleLeadCapture }   from './handlers/leads.js';
import { handleEnterpriseContact } from './handlers/enterprise.js';

// ─── Middleware ───────────────────────────────────────────────────────────────
import { corsHeaders, withCors }                   from './middleware/cors.js';
import { resolveAuth }                             from './middleware/auth.js';
import { checkRateLimitV2, rateLimitResponse, injectRateLimitHeaders } from './middleware/rateLimit.js';
import { withSecurityHeaders, checkBodySize, inspectForAttacks, logSuspicious } from './middleware/security.js';
import { handlePaymentWebhook }                    from './middleware/monetization.js';

// ─── Route Config ─────────────────────────────────────────────────────────────
const SCAN_ROUTES = {
  'POST /api/scan/domain':          { handler: handleDomainScan,       module: 'domain',     requireAuth: false },
  'POST /api/scan/ai':              { handler: handleAIScan,           module: 'ai',         requireAuth: false },
  'POST /api/scan/redteam':         { handler: handleRedteamScan,      module: 'redteam',    requireAuth: false },
  'POST /api/scan/identity':        { handler: handleIdentityScan,     module: 'identity',   requireAuth: false },
  'POST /api/generate/compliance':  { handler: handleCompliance,       module: 'compliance', requireAuth: false },
  'POST /api/leads/capture':        { handler: handleLeadCapture,      module: 'leads',      requireAuth: false },
  'POST /api/contact/enterprise':   { handler: handleEnterpriseContact,module: 'enterprise', requireAuth: false },
};

// ─── Middleware Pipeline ──────────────────────────────────────────────────────
async function runPipeline(request, env, routeKey, route) {
  // 1. Body size guard
  const sizeErr = checkBodySize(request, 16384);
  if (sizeErr) return sizeErr;

  // 2. Auth resolution (keyless IP fallback or API key)
  const authCtx = await resolveAuth(request, env);
  if (!authCtx.authenticated) {
    const { authError } = await import('./middleware/auth.js');
    return authError(authCtx.error || 'invalid');
  }

  // 3. Rate limiting
  const rlResult = await checkRateLimitV2(env, authCtx, route.module);
  if (!rlResult.allowed) {
    return rateLimitResponse(rlResult, route.module);
  }

  // 4. Execute handler
  let response = await route.handler(request, env, authCtx);

  // 5. Inject rate limit headers
  response = injectRateLimitHeaders(response, rlResult);

  return response;
}

// ─── Health / Info endpoints ──────────────────────────────────────────────────
function buildHealthResponse() {
  return Response.json({
    status: 'ok',
    service: 'CYBERDUDEBIVASH AI Security Hub',
    version: '3.0.0',
    company: 'CyberDudeBivash Pvt. Ltd.',
    website: 'https://cyberdudebivash.in',
    modules: ['domain','ai','redteam','identity','compliance'],
    new_in_v3: ['API key auth','per-tier rate limiting','DNSSEC scanning','prompt injection detection','lead capture','enterprise contact'],
    timestamp: new Date().toISOString(),
  });
}

function buildApiInfoResponse() {
  return Response.json({
    name: 'CYBERDUDEBIVASH AI Security Hub API',
    version: '3.0.0',
    auth: 'Header: x-api-key (optional for FREE tier)',
    tiers: { FREE:'5 req/day',PRO:'500 req/day',ENTERPRISE:'unlimited' },
    endpoints: {
      health:      'GET  /api/health',
      domain:      'POST /api/scan/domain',
      ai:          'POST /api/scan/ai',
      redteam:     'POST /api/scan/redteam',
      identity:    'POST /api/scan/identity',
      compliance:  'POST /api/generate/compliance',
      leads:       'POST /api/leads/capture',
      enterprise:  'POST /api/contact/enterprise',
      webhook:     'POST /api/webhooks/razorpay',
    },
    pricing: 'https://cyberdudebivash.in/#pricing',
    docs: 'https://cyberdudebivash.in/docs',
  });
}

// ─── Main Worker Entry ────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method.toUpperCase();

    // ── CORS preflight ─────────────────────────────────────────────────────
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // ── Suspend obvious attack patterns on query string ────────────────────
    const fullUrl = url.pathname + url.search;
    if (inspectForAttacks(fullUrl)) {
      logSuspicious(env, request, 'url_attack_pattern').catch(() => {});
      return withSecurityHeaders(withCors(Response.json({ error: 'Bad request' }, { status: 400 }), request));
    }

    // ── Built-in routes ────────────────────────────────────────────────────
    if (path === '/api/health' && method === 'GET') {
      return withSecurityHeaders(withCors(buildHealthResponse(), request));
    }
    if ((path === '/api' || path === '/api/') && method === 'GET') {
      return withSecurityHeaders(withCors(buildApiInfoResponse(), request));
    }

    // ── Razorpay webhook (no auth needed — verified by signature) ──────────
    if (path === '/api/webhooks/razorpay' && method === 'POST') {
      const res = await handlePaymentWebhook(request, env);
      return withSecurityHeaders(res);
    }

    // ── Scan/action routes ─────────────────────────────────────────────────
    const routeKey = `${method} ${path}`;
    const route    = SCAN_ROUTES[routeKey];

    if (route) {
      try {
        const response = await runPipeline(request, env, routeKey, route);
        return withSecurityHeaders(withCors(response, request));
      } catch (err) {
        console.error(`[${routeKey}] Unhandled error:`, err?.message);
        return withSecurityHeaders(withCors(Response.json({
          error: 'Internal server error',
          module: routeKey,
          request_id: crypto.randomUUID?.() || Date.now().toString(36),
          support: 'cyberdudebivash@gmail.com',
        }, { status: 500 }), request));
      }
    }

    // ── 404 ────────────────────────────────────────────────────────────────
    return withSecurityHeaders(withCors(Response.json({
      error: 'Not Found',
      path,
      method,
      api_docs: 'GET /api',
      website: 'https://cyberdudebivash.in',
    }, { status: 404 }), request));
  },
};
