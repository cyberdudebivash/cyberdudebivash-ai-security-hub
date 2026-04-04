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
import { handleGetAnalytics, handleScanStats, trackEvent, meterApiRequest, handleApiUsage } from './handlers/analytics.js';

// ─── AI Cyber Brain V2 handlers (analyze / simulate / forecast) ──────────────
import { handleAIAnalyze, handleAISimulate, handleAIForecast } from './handlers/aiAnalysis.js';

// ─── CVE Engine (for /api/v1/cves endpoint) ───────────────────────────────────
import { getTopCVEsForModule } from './services/cveEngine.js';

// ─── Subscription SaaS Engine (v10.0) ────────────────────────────────────────
import {
  handleGetUserPlan, handleCreateSubscription, handleActivateSubscription, handleGetPlans,
  checkMonthlyQuota,
} from './handlers/subscription.js';

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
import {
  withSecurityHeaders, checkBodySize,
  inspectForAttacks, inspectBodyForAttacks, sanitizeString,
  logSuspicious, isIPAbusive, validateDomain, getBotScore,
  validateSchema, SCHEMAS,
} from './middleware/security.js';
import { handlePaymentWebhook }                                        from './middleware/monetization.js';

// ─── Audit Logger ────────────────────────────────────────────────────────────
// Writes sensitive-action audit events to D1 audit_log table (fire-and-forget).
// Events: auth.login | auth.logout | auth.signup | key.create | key.delete |
//         org.create | scan.payment | account.delete | admin.action
async function auditLog(env, request, action, userId, metadata = {}) {
  if (!env?.DB) return;
  try {
    const ip = request?.headers?.get('CF-Connecting-IP') || 'unknown';
    const ua = (request?.headers?.get('User-Agent') || '').slice(0, 300);
    const id = crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2);
    await env.DB.prepare(
      `INSERT INTO analytics_events (id, event_type, module, user_id, ip, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(id, `audit.${action}`, 'security', userId || null, ip, JSON.stringify({ ...metadata, ua: ua.slice(0, 200) })).run();
  } catch {}
}

// ─── Anomaly Detector ────────────────────────────────────────────────────────
// Heuristic-based anomaly detection — checks for unusual patterns in authenticated requests.
async function detectAnomaly(env, request, authCtx) {
  if (!env?.SECURITY_HUB_KV || !authCtx?.userId) return null;
  const ip  = request.headers.get('CF-Connecting-IP') || 'unknown';
  const day = new Date().toISOString().slice(0, 10);
  try {
    const userIPKey = `anomaly:user_ip:${authCtx.userId}:${day}`;
    const knownIPs  = await env.SECURITY_HUB_KV.get(userIPKey, { type: 'json' }) || [];
    if (!knownIPs.includes(ip)) {
      const updated = [...new Set([...knownIPs, ip])].slice(-10);
      await env.SECURITY_HUB_KV.put(userIPKey, JSON.stringify(updated), { expirationTtl: 86400 * 7 });
      // New IP for this user — flag if they have 3+ different IPs today (account sharing / takeover)
      if (knownIPs.length >= 3) {
        auditLog(env, request, 'anomaly.new_ip', authCtx.userId, { ip, total_ips_today: updated.length });
        return { type: 'new_ip', severity: 'medium', ip, message: 'New IP detected for authenticated user' };
      }
    }
  } catch {}
  return null;
}

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

  // Deep body inspection for injection attacks
  let parsedBody = null;
  if (request.headers.get('Content-Type')?.includes('application/json')) {
    try {
      const cloned = request.clone();
      parsedBody   = await cloned.json();
      if (inspectBodyForAttacks(parsedBody)) {
        logSuspicious(env, request, 'body_attack').catch(() => {});
        return Response.json({ error: 'Invalid request payload' }, { status: 400 });
      }
    } catch {}
  }

  const authCtx  = await resolveAuthV5(request, env);
  if (!authCtx.authenticated) return unauthorized(authCtx.error || 'invalid');

  // Monthly scan quota enforcement for STARTER plan (backend gate)
  if (authCtx.tier === 'STARTER') {
    const monthlyCheck = await checkMonthlyQuota(request, env);
    if (monthlyCheck) return monthlyCheck; // returns 429 if quota exceeded
  }

  // D1-based quota (API keys) or KV-based rate limit (IP/JWT)
  if (authCtx.method === 'api_key') {
    const quota = await enforceQuota(env, authCtx, route.module);
    if (!quota.allowed) return rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, route.module);
  } else {
    const rl = await checkRateLimitV2(env, authCtx, route.module);
    if (!rl.allowed) return rateLimitResponse(rl, route.module);
  }

  const startTime = Date.now();
  const response  = await route.handler(request, env, authCtx);
  const latency   = Date.now() - startTime;

  // Fire-and-forget API metering (non-blocking)
  meterApiRequest(env, {
    api_key_id: authCtx.method === 'api_key' ? authCtx.keyId : null,
    user_id:    authCtx.userId || null,
    endpoint:   routeKey,
    method:     request.method,
    status_code: response.status,
    latency_ms:  latency,
    ip:         request.headers.get('CF-Connecting-IP') || null,
    ua:         request.headers.get('User-Agent') || null,
  }).catch(() => {});

  return injectRateLimitHeaders(response, { tier: authCtx.tier, remaining: '?' });
}

// ─── Full system health check (async — probes D1, KV, external APIs) ─────────
async function healthResponseAsync(env) {
  const start = Date.now();

  // Probe all components in parallel — never throw
  const [dbCheck, kvCheck, sentinelCheck] = await Promise.allSettled([
    // D1 probe — single lightweight query
    (async () => {
      if (!env?.DB) return { ok: false, reason: 'not_configured' };
      const t = Date.now();
      await env.DB.prepare('SELECT 1').first();
      return { ok: true, latency_ms: Date.now() - t };
    })(),
    // KV probe — a simple get on a known key
    (async () => {
      if (!env?.SECURITY_HUB_KV) return { ok: false, reason: 'not_configured' };
      const t = Date.now();
      await env.SECURITY_HUB_KV.get('_health_probe_');
      return { ok: true, latency_ms: Date.now() - t };
    })(),
    // Sentinel check — cached value only (no external call)
    (async () => {
      if (!env?.SECURITY_HUB_KV) return { ok: false, reason: 'kv_unavailable' };
      const cached = await env.SECURITY_HUB_KV.get('sentinel:feed:cache');
      return { ok: !!cached, cached: !!cached };
    })(),
  ]);

  const db       = dbCheck.status === 'fulfilled'       ? dbCheck.value       : { ok: false, reason: dbCheck.reason?.message };
  const kv       = kvCheck.status === 'fulfilled'       ? kvCheck.value       : { ok: false, reason: kvCheck.reason?.message };
  const sentinel = sentinelCheck.status === 'fulfilled' ? sentinelCheck.value : { ok: false };

  // Overall status: degraded if any component fails, ok if all pass
  const allOk   = db.ok && kv.ok;
  const status  = allOk ? 'ok' : (db.ok || kv.ok) ? 'degraded' : 'error';

  // Fetch scan stats from D1 for dashboard counters
  let stats = null;
  if (db.ok) {
    try {
      const [scanCount, todayCount] = await Promise.all([
        env.DB.prepare('SELECT COUNT(*) as count FROM scan_jobs').first(),
        env.DB.prepare("SELECT COUNT(*) as count FROM scan_jobs WHERE created_at > datetime('now','-1 day')").first(),
      ]);
      stats = {
        total_scans: scanCount?.count ?? 0,
        scans_today: todayCount?.count ?? 0,
      };
    } catch {}
  }

  return Response.json({
    status,
    service:   'CYBERDUDEBIVASH AI Security Hub',
    version:   '10.0.0',
    company:   'CyberDudeBivash Pvt. Ltd.',
    website:   'https://cyberdudebivash.in',
    tools:     'https://tools.cyberdudebivash.com',
    contact:   CONTACT_EMAIL,
    telegram:  'https://t.me/cyberdudebivashSentinelApex',
    modules:   ['domain','ai','redteam','identity','compliance'],
    components: {
      database:     { status: db.ok ? 'ok' : 'error',     latency_ms: db.latency_ms ?? null,  reason: db.reason ?? null },
      cache:        { status: kv.ok ? 'ok' : 'error',     latency_ms: kv.latency_ms ?? null,  reason: kv.reason ?? null },
      threat_intel: { status: sentinel.ok ? 'ok' : 'stale', cached: sentinel.cached ?? false },
      edge:         { status: 'ok', region: env.CF_REGION ?? 'global' },
    },
    stats,
    response_ms: Date.now() - start,
    timestamp:   new Date().toISOString(),
  }, { status: status === 'error' ? 503 : 200 });
}

// ─── Intelligence Summary endpoint ────────────────────────────────────────────
// Public endpoint — aggregated platform threat intelligence snapshot.
// Cached in KV for 5 minutes to avoid repeated DB hits.
async function handleIntelligenceSummary(env) {
  const CACHE_KEY = 'intel:summary:v1';
  const CACHE_TTL = 300; // 5 minutes

  // Try KV cache first
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(CACHE_KEY, { type: 'json' });
      if (cached) return Response.json({ ...cached, cached: true });
    } catch {}
  }

  // Build fresh summary
  const summary = {
    platform_threat_level: 'HIGH',
    active_apt_groups: ['APT29 (Cozy Bear)', 'Lazarus Group', 'Fancy Bear'],
    top_attack_vectors: ['Phishing / Credential Theft', 'Supply Chain Compromise', 'Zero-Day Exploitation'],
    critical_cve_count: 0,
    high_cve_count:     0,
    total_scans_today:  0,
    critical_scans_today: 0,
    global_risk_index:  72,
    last_updated:       new Date().toISOString(),
    intelligence_feed: [
      { id:'INTEL-001', severity:'CRITICAL', title:'Active exploitation of MFA bypass via session hijacking', source:'CISA KEV', ts: new Date(Date.now()-3600000).toISOString() },
      { id:'INTEL-002', severity:'HIGH',     title:'APT29 targeting cloud identity providers — phishing surge +340%', source:'Sentinel APEX', ts: new Date(Date.now()-7200000).toISOString() },
      { id:'INTEL-003', severity:'HIGH',     title:'Prompt injection attacks against LLM APIs increasing', source:'OWASP LLM WG', ts: new Date(Date.now()-10800000).toISOString() },
      { id:'INTEL-004', severity:'MEDIUM',   title:'DNSSEC misconfiguration exploited in BGP hijack campaign', source:'Sentinel APEX', ts: new Date(Date.now()-14400000).toISOString() },
    ],
    recommendations: [
      'Enforce MFA on all privileged accounts immediately',
      'Audit AI/LLM API endpoints for prompt injection exposure',
      'Validate DNSSEC chain for all authoritative zones',
      'Review supply chain dependencies for known CVEs',
    ],
    timestamp: new Date().toISOString(),
  };

  // Try to enrich with real D1 data
  if (env?.DB) {
    try {
      const [todayScans, critToday, cveFeed] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) as c FROM scan_jobs WHERE created_at > datetime('now','-1 day')").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM scan_jobs WHERE risk_level='CRITICAL' AND created_at > datetime('now','-1 day')").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM threat_intel_cache WHERE severity='CRITICAL' AND expires_at > datetime('now')").first().catch(() => null),
      ]);
      if (todayScans?.c)  summary.total_scans_today    = todayScans.c;
      if (critToday?.c)   summary.critical_scans_today  = critToday.c;
      if (cveFeed?.c)     summary.critical_cve_count    = cveFeed.c;
      // Adjust threat level based on real data
      if (summary.critical_scans_today >= 5) summary.platform_threat_level = 'CRITICAL';
      else if (summary.critical_scans_today >= 2) summary.platform_threat_level = 'HIGH';
      else summary.platform_threat_level = 'MODERATE';
    } catch {}
  }

  // Cache result
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(CACHE_KEY, JSON.stringify(summary), { expirationTtl: CACHE_TTL }).catch(() => {});
  }

  return Response.json({ ...summary, cached: false });
}

// ─── API info ─────────────────────────────────────────────────────────────────
function apiInfoResponse() {
  return Response.json({
    name:    'CYBERDUDEBIVASH AI Security Hub API',
    version: '10.0.0',
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
      // V8.0 — AI Brain + Attack Graph
      'GET  /api/insights/:jobId':   'AI narrative + MITRE mapping for a completed scan',
      'POST /api/attack-graph':      'D3-ready force-directed attack graph from scan data',
      'GET  /api/threat-intel/stats':'CVE/KEV/EPSS threat intel statistics',
      // V8.0 — Continuous Monitoring
      'GET  /api/monitors':          'List your scan monitors',
      'POST /api/monitors':          'Create a scheduled scan monitor',
      'GET  /api/monitors/:id':      'Get monitor details',
      'PUT  /api/monitors/:id':      'Update monitor config',
      'DELETE /api/monitors/:id':    'Delete a monitor',
      'POST /api/monitors/:id/trigger': 'Manually trigger a monitor scan',
      'GET  /api/monitors/:id/history': 'Monitor scan history',
      // V8.0 — Content Engine
      'POST /api/content/generate':  'Generate blog/linkedin/telegram post from scan',
      'GET  /api/content':           'List generated content posts',
      'GET  /api/content/feed':      'Public content feed (no auth)',
      // V8.0 — Organizations
      'GET  /api/orgs':              'List your organizations',
      'POST /api/orgs':              'Create organization',
      'GET  /api/orgs/:id':          'Get org details + members',
      'PUT  /api/orgs/:id':          'Update org settings',
      'GET  /api/orgs/:id/dashboard':'Org security posture dashboard',
      // V9.2 — Payment aliases (singular form)
      'POST /api/payment/create-order': 'Create Razorpay order → { order_id, key_id, amount, currency }',
      'POST /api/payment/verify':       'Verify HMAC signature → { success, token, download_url }',
      'GET  /api/payment/status/:id':   'Payment status by order ID',
      // V9.0 — AI Cyber Brain V2
      'POST /api/ai/analyze':        'Threat correlation → attack chain + MITRE ATT&CK + exploit probability',
      'POST /api/ai/simulate':       'Attack simulation → step-by-step attacker path + blast radius + scenario',
      'POST /api/ai/forecast':       'Risk forecast → exploitation likelihood + time-to-breach + financial impact',
      // V10.0 — Subscription SaaS Engine
      'GET  /api/subscription/plans':   'Public plan listing → STARTER/PRO/ENTERPRISE with pricing',
      'GET  /api/user/plan':            'Current plan + monthly usage for authenticated user',
      'POST /api/subscription/create':  'Create Razorpay order for plan → { order_id, amount }',
      'POST /api/subscription/activate':'Verify payment + activate plan session → { session_token, features }',
      // V10.0 — Public API v1 (PRO/ENTERPRISE key required)
      'GET  /api/v1/scan':             'Scan history for your API key',
      'GET  /api/v1/threat-intel':     'Live Sentinel APEX CVE + KEV threat feed',
      'POST /api/v1/analyze':          'AI threat analysis (PRO+)',
      'POST /api/v1/simulate':         'Attack simulation (ENTERPRISE only)',
      'POST /api/v1/forecast':         'Risk forecast with financial impact (PRO+)',
      'GET  /api/v1/cves':             'Top exploited CVEs for a module (PRO+)',
      // V8.0 — Version
      'GET  /api/version':           'Live platform version + build metadata',
      // Admin
      'GET  /api/admin/analytics':   'Platform analytics (ENTERPRISE only)',
      'GET  /api/admin/api-usage':   'API metering + latency stats (ENTERPRISE only)',
      // Other
      'GET  /api/health':            'Service health',
      'POST /api/webhooks/razorpay': 'Razorpay payment webhook',
    },
    tiers: {
      FREE:       { daily_limit:  5, burst: '2/min',  scan_limit: 50,  key_limit: 2,  price_inr: 0,    queue_priority: 'low'    },
      STARTER:    { daily_limit: 20, burst: '5/min',  scan_limit: 10,  key_limit: 2,  price_inr: 499,  queue_priority: 'normal' },
      PRO:        { daily_limit: 500, burst: '20/min', scan_limit: -1,  key_limit: 5,  price_inr: 1499, queue_priority: 'normal' },
      ENTERPRISE: { daily_limit: -1, burst: '60/min', scan_limit: -1,  key_limit: 20, price_inr: 4999, queue_priority: 'high'   },
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

    // Block banned IPs (Zero Trust — all requests checked)
    const clientIP = request.headers.get('CF-Connecting-IP') || '';
    if (clientIP && await isIPAbusive(env, clientIP)) {
      return withSecurityHeaders(withCors(
        Response.json({ error: 'Access denied', code: 'IP_BANNED' }, { status: 403 }), request
      ));
    }

    // Reject extreme bot signals on write endpoints (allow reads)
    if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      const botScore = getBotScore(request);
      if (botScore >= 60) {
        logSuspicious(env, request, `bot_score_${botScore}`).catch(() => {});
        // Warn but don't hard-block — some legitimate automated API clients exist
        // If score is extreme (>=80) AND no auth header, reject
        const hasAuth = request.headers.get('Authorization') || request.headers.get('x-api-key');
        if (botScore >= 80 && !hasAuth) {
          return withSecurityHeaders(withCors(
            Response.json({ error: 'Automated request detected', hint: 'Add Authorization header' }, { status: 403 }), request
          ));
        }
      }
    }

    // ── Static / no-auth routes ─────────────────────────────────────────────
    if (path === '/api/health' && method === 'GET') {
      return withSecurityHeaders(withCors(await healthResponseAsync(env), request));
    }
    if (path === '/api/intelligence/summary' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleIntelligenceSummary(env), request));
    }
    if (path === '/api/version' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        version:     '9.0.0',
        commit:      (env.CF_VERSION_METADATA && env.CF_VERSION_METADATA.id) || 'unknown',
        timestamp:   new Date().toISOString(),
        environment: env.ENVIRONMENT || 'production',
        name:        env.APP_NAME    || 'CYBERDUDEBIVASH AI Security Hub',
      }), request));
    }
    if ((path === '/api' || path === '') && method === 'GET') {
      return withSecurityHeaders(withCors(apiInfoResponse(), request));
    }

    // ── Auth routes (no rate limit — have their own brute-force protection) ─
    if (path === '/api/auth/signup' && method === 'POST') {
      const res = await handleSignup(request, env);
      if (res.status === 201) auditLog(env, request, 'auth.signup', null, { path }).catch(() => {});
      return withSecurityHeaders(withCors(res, request));
    }
    if (path === '/api/auth/login' && method === 'POST') {
      const res = await handleLogin(request, env);
      if (res.status === 200) {
        const body = await res.clone().json().catch(() => ({}));
        auditLog(env, request, 'auth.login', body?.user?.id, { path }).catch(() => {});
      }
      return withSecurityHeaders(withCors(res, request));
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

    // ── V7.0 Payment routes (plural form: /api/payments/*) ─────────────────
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

    // ── V9.2 Payment routes (singular form: /api/payment/* — canonical aliases) ─
    // Identical logic — both forms are permanently supported.
    // /api/payment/create-order  →  POST  { amount, module, target?, email? }
    //                                      Returns { order_id, key_id, amount, currency, module }
    // /api/payment/verify        →  POST  { razorpay_order_id, razorpay_payment_id,
    //                                       razorpay_signature, module, target }
    //                                      Returns { success, token, download_url } or { success: false }
    if (path === '/api/payment/create-order' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateOrder(request, env, authCtx), request));
    }
    if (path === '/api/payment/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      // Wrap verify to always return { success: true/false } shape (never throws)
      try {
        const res  = await handleVerifyPayment(request, env, authCtx);
        const data = await res.clone().json().catch(() => ({}));
        // If backend returned an error response, normalise to { success: false }
        if (!res.ok || data.error) {
          return withSecurityHeaders(withCors(Response.json({
            success: false,
            error:   data.error || `HTTP ${res.status}`,
            code:    'VERIFICATION_FAILED',
          }, { status: res.ok ? 200 : res.status }), request));
        }
        return withSecurityHeaders(withCors(res, request));
      } catch (err) {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   'Internal verification error',
          code:    'INTERNAL_ERROR',
        }, { status: 500 }), request));
      }
    }
    if (path.startsWith('/api/payment/status/') && method === 'GET') {
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
    if (path === '/api/admin/api-usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleApiUsage(request, env, authCtx), request));
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

    // ═══════════════════════════════════════════════════════════════════════
    // V9.0 AI Cyber Brain V2 — Threat Correlation, Attack Simulation, Forecast
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/ai/analyze → attack chain + MITRE mapping + exploit probability
    if (path === '/api/ai/analyze' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIAnalyze(request, env), request));
    }

    // POST /api/ai/simulate → step-by-step attacker path + blast radius
    if (path === '/api/ai/simulate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAISimulate(request, env), request));
    }

    // POST /api/ai/forecast → exploitation likelihood + time-to-breach + financial impact
    if (path === '/api/ai/forecast' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIForecast(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V10.0 SUBSCRIPTION SaaS ENGINE — Plan management, billing, feature gating
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/subscription/plans → public plan listing for pricing page
    if (path === '/api/subscription/plans' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPlans(request, env), request));
    }

    // GET /api/user/plan → current plan + usage for authenticated/session user
    if (path === '/api/user/plan' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetUserPlan(request, env), request));
    }

    // POST /api/subscription/create → create Razorpay order for a plan
    if (path === '/api/subscription/create' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreateSubscription(request, env), request));
    }

    // POST /api/subscription/activate → verify payment + activate plan session
    if (path === '/api/subscription/activate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleActivateSubscription(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V10.0 PUBLIC API v1 — Versioned API for PRO/ENTERPRISE key holders
    // All /api/v1/* routes require a valid API key (cdb_* header).
    // Returns consistent { success, data, error, timestamp } shape.
    // ═══════════════════════════════════════════════════════════════════════

    if (path.startsWith('/api/v1/')) {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated || authCtx.method !== 'api_key') {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   'API v1 requires a valid API key (x-api-key: cdb_*). Obtain one at /api/keys.',
          code:    'ERR_API_KEY_REQUIRED',
          docs:    'GET /api',
        }, { status: 401 }), request));
      }

      // PRO/ENTERPRISE gate for versioned API
      if (!['PRO', 'ENTERPRISE'].includes(authCtx.tier)) {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   `API v1 access requires PRO or ENTERPRISE plan. Current plan: ${authCtx.tier}.`,
          code:    'ERR_PLAN_UPGRADE_REQUIRED',
          upgrade: 'https://tools.cyberdudebivash.com/#pricing',
        }, { status: 403 }), request));
      }

      const v1Path = path.slice(7); // strip /api/v1 → /scan, /threat-intel, /analyze

      // GET /api/v1/scan → recent scan history for this API key
      if (v1Path === '/scan' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleD1History(request, env, authCtx), request));
      }

      // GET /api/v1/threat-intel → live sentinel threat intel feed
      if (v1Path === '/threat-intel' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
      }

      // POST /api/v1/analyze → AI threat analysis (rate limited per key)
      if (v1Path === '/analyze' && method === 'POST') {
        const quota = await enforceQuota(env, authCtx, 'ai');
        if (!quota.allowed) return withSecurityHeaders(withCors(
          rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, 'ai'), request
        ));
        return withSecurityHeaders(withCors(await handleAIAnalyze(request, env), request));
      }

      // POST /api/v1/simulate → attack simulation (ENTERPRISE only)
      if (v1Path === '/simulate' && method === 'POST') {
        if (authCtx.tier !== 'ENTERPRISE') {
          return withSecurityHeaders(withCors(Response.json({
            success: false,
            error:   'Attack simulation via API requires ENTERPRISE plan.',
            code:    'ERR_ENTERPRISE_REQUIRED',
          }, { status: 403 }), request));
        }
        return withSecurityHeaders(withCors(await handleAISimulate(request, env), request));
      }

      // POST /api/v1/forecast → risk forecast
      if (v1Path === '/forecast' && method === 'POST') {
        return withSecurityHeaders(withCors(await handleAIForecast(request, env), request));
      }

      // GET /api/v1/cves?module=domain → top exploited CVEs for a module
      if (v1Path === '/cves' && method === 'GET') {
        const mod   = url.searchParams.get('module') || 'domain';
        const limit = Math.min(20, parseInt(url.searchParams.get('limit') || '10', 10));
        const cves  = getTopCVEsForModule(mod, limit);
        return withSecurityHeaders(withCors(Response.json({
          success:   true,
          data:      { module: mod, cves, total: cves.length },
          error:     null,
          timestamp: new Date().toISOString(),
        }), request));
      }

      // Unknown /api/v1/* path
      return withSecurityHeaders(withCors(Response.json({
        success: false,
        error:   `Unknown API v1 endpoint: ${method} ${path}`,
        code:    'ERR_NOT_FOUND',
        available: ['GET /api/v1/scan', 'GET /api/v1/threat-intel', 'POST /api/v1/analyze', 'POST /api/v1/simulate', 'POST /api/v1/forecast'],
      }, { status: 404 }), request));
    }

    // Convenience aliases
    // POST /api/generate-key → alias of POST /api/keys
    if (path === '/api/generate-key' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleCreateKey(request, env, authCtx), request));
    }
    // GET /api/usage → alias of GET /api/admin/api-usage
    if (path === '/api/usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleApiUsage(request, env, authCtx), request));
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
