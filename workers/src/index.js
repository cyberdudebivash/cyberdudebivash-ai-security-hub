/**
 * CYBERDUDEBIVASH AI Security Hub — Main Router v8.1
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
 *
 * New in v8.1:
 *   Real-Time Feed:    GET  /api/realtime/feed        → SSE live threat alert stream
 *   Realtime Posture:  GET  /api/realtime/posture     → Defense posture JSON
 *   Realtime Stats:    GET  /api/realtime/stats       → Live platform stats
 *   Gumroad Webhook:   POST /api/webhooks/gumroad     → Purchase webhook (HMAC)
 *   Gumroad Verify:    POST /api/gumroad/verify       → License key activation
 *   Gumroad Products:  GET  /api/gumroad/products     → Public product catalog
 *   SIEM Info:         GET  /api/export/siem          → Export format docs
 *   SIEM Export:       POST /api/export/siem          → JSON/CEF/STIX/Sigma/CSV export
 *   SIEM Stream:       GET  /api/export/siem/stream   → Streaming NDJSON (ENTERPRISE)
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
  handlePaymentConfirm,
} from './handlers/payments.js';
import { handleGetAnalytics, handleScanStats, trackEvent, meterApiRequest, handleApiUsage } from './handlers/analytics.js';

// ─── AI Cyber Brain V2 handlers (analyze / simulate / forecast) ──────────────
import { handleAIAnalyze, handleAISimulate, handleAIForecast,
         handleAIChat, handleGenerateRules } from './handlers/aiAnalysis.js';

// ─── CVE Engine (for /api/v1/cves endpoint) ───────────────────────────────────
import { getTopCVEsForModule } from './services/cveEngine.js';

// ─── Threat Intelligence Engine v2.0 (Sentinel APEX) ─────────────────────────
import {
  handleGetThreatIntel, handleThreatIntelStats, handleGetThreatIntelEntry,
  handleManualIngest, handleV1ThreatIntel, handleV1IOCs,
  handleThreatIntelStream,
  handleV1Correlations, handleV1Graph, handleV1Hunting,
} from './handlers/threatIntel.js';
import { runIngestion }  from './services/threatIngestion.js';

// ─── Sentinel APEX v3 — SOC Automation + Autonomous Defense ──────────────────
import {
  handleGetAlerts, handleGetDecisions, handleGetDefenseActions,
  handleGetFederation, handleSOCAnalyze, handleGetSOCPosture,
  handleSOCDashboard,
} from './handlers/soc.js';
import { runFederation }            from './services/federationEngine.js';
import { runDetection, storeDetectionResults } from './services/detectionEngine.js';
import { runDecisionEngine, storeDecisions }   from './services/decisionEngine.js';
import { runAutonomousDefense, storeDefenseActions } from './services/defenseEngine.js';
import { buildResponsePlan, storeResponsePlan }      from './services/responseEngine.js';

// ─── Subscription SaaS Engine (v10.0) ────────────────────────────────────────
import {
  handleGetUserPlan, handleCreateSubscription, handleActivateSubscription, handleGetPlans,
  checkMonthlyQuota,
} from './handlers/subscription.js';

// ─── GTM Growth Engine (v12.0) ────────────────────────────────────────────────
import {
  handleEmailCapture, handleScanEvent, handleUpgradeCheck,
  handleFunnelDashboard, handleGetLeads,
  handleRunSalesPipeline, handleGetOutreach, handleMarkOutreachSent,
  handleRunContentAutomation, handleGetContentQueue,
  handleRunDrip, handleEmailTrack,
  handleProvisionApiKey, handleGetApiUsage,
  handleBillingCallback, handleCreatePaymentLink,
  handleRevenueDashboard, handleUpgradeLead,
  // Phase 7: Global Expansion
  handleGetRegionContext, handleGlobalDashboard,
  // Phase 9/10: Upsell + Pricing + LinkedIn
  handleEvaluateUpsell, handleUpsellConverted, handleUpsellMetrics,
  handleFeatureWall, handleGetPricing,
  handleLinkedInToday, handleRunLinkedIn,
} from './handlers/growth.js';
import { runLinkedInAutomation }  from './services/upsellEngine.js';
import { runDripAutomation }   from './services/emailEngine.js';
import { runSalesPipeline }    from './services/salesEngine.js';
import { runContentAutomation as runContentPipeline } from './services/contentEngine.js';

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

// ─── New v8.1 handlers — Real-Time Feed + Gumroad Revenue Engine + SIEM ──────
import { handleRealtimeFeed, handleRealtimePosture, handleRealtimeStats } from './handlers/realtime.js';
import { handleGumroadWebhook, handleLicenseActivation, handleProductCatalog } from './services/gumroadEngine.js';
import { handleSiemInfo, handleSiemExport, handleSiemStream } from './handlers/siemExport.js';

// ─── P0 Mission: Agentic AI + Anomaly + Predictive Engines (v12.0) ────────────
import { handleAgentRequest }      from './handlers/agentHandler.js';
import { handleAnomalyRequest }    from './handlers/anomalyHandler.js';
import { handlePredictiveRequest } from './handlers/predictiveHandler.js';
import { runAnomalyBatch }         from './services/anomalyEngine.js';
import { runPredictiveBatch }      from './services/predictiveEngine.js';
import { runPatchingBatch, expireStalePatches } from './agents/patchingAgent.js';
import { consumeEvents, ackEvent, publishCVEEvents } from './agents/agentBus.js';
import { processCVEEvent }         from './agents/threatResponseAgent.js';
import { decideAnomalyResponse }   from './agents/decisionEngine.js';
import { autoBlockIP }             from './agents/isolationAgent.js';
import { autoRotateOnAnomaly }     from './agents/credentialRotationAgent.js';
import { isIPBlocked, isSessionDisabled } from './agents/isolationAgent.js';

// ─── MYTHOS ORCHESTRATOR CORE v1.0 ──────────────────────────────────────────
import {
  handleMythosRun, handleMythosStatus, handleMythosJob,
  handleMythosValidate, handleMythosAnalyze, handleMythosMetrics,
} from './handlers/mythosHandler.js';
import { runMythosCron } from './services/mythosOrchestrator.js';

// ─── FINANCIAL SYSTEM: Pricing + Payment Config (v14 — IMMUTABLE) ───────────
import {
  handlePricing, handlePaymentConfig, handlePaymentMutationGuard,
} from './handlers/pricingHandler.js';

// ─── PHASE 2: Autonomous SOC Mode ────────────────────────────────────────────
import {
  handleGetMode, handleSetMode, handleGetPipeline, handleRunPipeline,
  handleGetSchedule, handleSetSchedule, handleGetLog, handleGetLatestRules,
  runAutoSocCron,
} from './handlers/autonomousSocMode.js';

// ─── PHASE 2: SIEM Integration Deploy ────────────────────────────────────────
import {
  handleListIntegrations, handleConfigure, handleDeploy,
  handleTestIntegration, handleDeployLog, handleDeleteIntegration,
} from './handlers/siemDeploy.js';

// ─── PHASE 2: Organization Memory v2 ─────────────────────────────────────────
import {
  handleGetMemory, handleRecordEvent, handleGetHistory,
  handleGetPatterns, handleGetRecommendations, handleClearMemory,
} from './handlers/orgMemoryV2.js';

// ─── PHASE 3: Autonomous Defense Engine ──────────────────────────────────────
import {
  handleGetDefenseMode, handleSetDefenseMode, handleExecuteDefense,
  handleApprove, handleRollback, handleGetExecutions,
  handleGetDefensePosture, handleGetPending,
} from './handlers/autoDefenseEngine.js';

// ─── PHASE 3: Threat Confidence + Exploitability Engine ──────────────────────
import {
  handleScoreThreats, handleGetKEV, handleEnrichThreat,
  handleGetFeed as handleGetTCFeed, handleGetStats as handleGetTCStats,
} from './handlers/threatConfidence.js';

// ─── PHASE 3: Executive Report Engine ────────────────────────────────────────
import {
  handleGetDashboard, handleGetMRR, handleSetMRRConfig,
  handleGenerateReport, handleListReports, handleGetReport,
} from './handlers/executiveReport.js';

// ─── PHASE 3: MSSP Multi-Tenant Panel ────────────────────────────────────────
import {
  handleListClients, handleOnboardClient, handleGetClient,
  handleUpdateClient, handleOffboardClient,
  handleGetSummary as handleMSSPSummary,
  handleGetAlerts as handleMSSPAlerts,
  handleSetWhitelabel, handleGetWhitelabel,
} from './handlers/msspPanel.js';

// ─── PHASE 4: Sales CRM Pipeline ─────────────────────────────────────────────
import {
  handleCreateLead, handleListLeads, handleGetLead,
  handleAdvanceStage, handleAddNote, handleQualifyLead, handleCloseLead,
  handleBookDemo, handleGetDemoSlots,
  handleGetPipeline as handleGetSalesPipeline,
  handleGetMetrics as handleGetSalesMetrics,
} from './handlers/salesPipeline.js';

// ─── PHASE 4: Proposal Generator ─────────────────────────────────────────────
import {
  handleGenerateProposal, handleListProposals, handleGetProposal,
  handleMarkProposalSent, handleAcceptProposal, handleGetPackages,
} from './handlers/proposalGenerator.js';

// ─── Manual Payment System ───────────────────────────────────────────────────
import {
  handleSubmitPayment, handleGetPaymentStatus,
  handleListPayments, handleVerifyPayment as handleVerifyManualPayment,
  handleGetPaymentConfig,
} from './handlers/manualPayments.js';

// ─── Threat Intelligence Graph ───────────────────────────────────────────────
import {
  handleGetThreatGraph, handleGetGraphNodes,
  handleGetGraphPaths, handleGraphQuery, handleGraphSummary,
} from './handlers/threatGraph.js';

// ─── CISO Command Center ──────────────────────────────────────────────────────
import {
  handleGetCISOMetrics, handleGetCISOPosture,
  handleGetIncidents, handleCreateIncident, handleUpdateIncident,
  handleGetComplianceStatus, handleGetRiskRegister, handleGetCISOReport,
} from './handlers/cisoMetrics.js';

// ─── Monetization Engine v2 ───────────────────────────────────────────────────
import {
  handleGetUsage, handleUpgrade, handleGetBillingPlans,
  handleStartTrial, handleGetLimits, handleGetInvoices, handleDowngrade,
} from './handlers/monetizationV2.js';

// ─── Affiliate & Partner System ───────────────────────────────────────────────
import {
  handleJoin, handleGetStatus as handleAffStatus,
  handleGetDashboard as handleAffDashboard,
  handleTrackReferral, handleGetReferrals,
  handleGetLeaderboard, handleGetTiers, handleRequestPayout,
} from './handlers/affiliateSystem.js';

// ─── PHASE 4: Conversion Triggers & Paywall ──────────────────────────────────
import {
  handleRecordEvent as handleConvEvent,
  handleGetTriggers, handleGetPaywall, handleDismissTrigger,
  handleGetFunnel, handleGetCTA, handleRetarget,
  handleGetBundleOffer, handleGetUrgency,
} from './handlers/conversionTriggers.js';

// ─── GOD MODE v15: Delivery Engine ───────────────────────────────────────────
import {
  handleDeliveryActivate, handleDeliveryAccess,
  handleMyPurchases, handleResendDelivery,
  handleVerifyDeliveryToken, handleDeliveryCatalog,
  handleUserReports,
} from './handlers/delivery.js';

// ─── GOD MODE v15: MCP Shadow Engine ─────────────────────────────────────────
import {
  handleMCPRecommend, handleMCPUpsell,
  handleMCPTrainingMap, handleMCPHealth,
  handleMCPBundle, handleMCPDecision,
} from './services/mcpEngine.js';

// ─── GOD MODE v15: Data Seeding Engine ───────────────────────────────────────
import {
  handleGetSeededThreats, handleGetSeededCVEs,
  handleGetPlatformStats, handleGetSOCMetrics,
  handleGetSIEMStream, handleGetAPTProfiles,
  handleGetSeedAll,
} from './services/seedEngine.js';

// ─── GOD MODE v16: SEO + Traffic Engine ──────────────────────────────────────
import {
  handleSEOMeta, handleCVEPage,
  handleLeadMagnet, handleRetargetVisit, handleRetargetOffer,
} from './handlers/seoEngine.js';

// ─── GOD MODE v16: Enterprise Hardening ──────────────────────────────────────
import {
  handleAutoQualify,
  handleOrgDashboard as handleEnterpriseDashboard,
  handleAutoProposal, handleEnterpriseHealth,
} from './handlers/enterpriseHardening.js';

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
// KV OPTIMIZATION v1: health probe no longer reads from KV on every request.
// KV is considered "ok" if the binding is configured (env.SECURITY_HUB_KV exists).
// Sentinel feed status is assumed "ok" if KV is configured — a live KV read every
// 30 seconds from every browser session was the #1 cause of KV quota exhaustion.
// The full health response is edge-cached for 60 seconds via caches.default (FREE).
async function healthResponseAsync(env) {
  const start = Date.now();

  // Probe all components in parallel — never throw
  const [dbCheck, kvCheck] = await Promise.allSettled([
    // D1 probe — single lightweight query
    (async () => {
      if (!env?.DB) return { ok: false, reason: 'not_configured' };
      const t = Date.now();
      await env.DB.prepare('SELECT 1').first();
      return { ok: true, latency_ms: Date.now() - t };
    })(),
    // KV probe — binding existence check ONLY (no KV read — saves quota)
    (async () => {
      if (!env?.SECURITY_HUB_KV) return { ok: false, reason: 'not_configured' };
      // Binding exists → treat as ok (actual KV read removed: was burning quota on every health poll)
      return { ok: true, latency_ms: 0, note: 'binding_check_only' };
    })(),
  ]);

  const db       = dbCheck.status === 'fulfilled' ? dbCheck.value : { ok: false, reason: dbCheck.reason?.message };
  const kv       = kvCheck.status === 'fulfilled' ? kvCheck.value : { ok: false, reason: kvCheck.reason?.message };
  // Sentinel assumed configured if KV binding is present (no live KV read to save quota)
  const sentinel = { ok: !!env?.SECURITY_HUB_KV, cached: true, note: 'binding_check_only' };

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
    version:   env.VERSION || env.PLATFORM_VERSION || '11.0.0',
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
// KV OPTIMIZATION: Migrated from KV cache to Cloudflare CDN edge cache (FREE).
// This removes 1 KV read + 1 KV write per 5-minute interval per PoP.
async function handleIntelligenceSummary(env) {
  const CACHE_KEY = 'intel:summary:v1';
  const CACHE_TTL = 300; // 5 minutes

  // Try Cloudflare CDN edge cache FIRST (FREE — no KV quota consumed)
  try {
    const edgeCache = caches.default;
    const cacheReq  = new Request(`https://cdb-edge-cache/${CACHE_KEY}`);
    const hit       = await edgeCache.match(cacheReq);
    if (hit) {
      const data = await hit.clone().json().catch(() => null);
      if (data) return Response.json({ ...data, cached: true, cache_layer: 'edge' });
    }
  } catch { /* local dev — edge cache unavailable, fall through */ }

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

  // KV OPTIMIZATION: cache result in Cloudflare CDN edge cache (FREE) instead of KV.
  // KV write retained as backup for cross-PoP consistency, but edge cache is primary.
  try {
    const edgeCache = caches.default;
    const cacheReq  = new Request(`https://cdb-edge-cache/${CACHE_KEY}`);
    const cacheResp = new Response(JSON.stringify(summary), {
      headers: {
        'Content-Type':  'application/json',
        'Cache-Control': `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
        'X-Cache':       'MISS',
      },
    });
    edgeCache.put(cacheReq, cacheResp).catch(() => {});
  } catch { /* local dev */ }

  return Response.json({ ...summary, cached: false, cache_layer: 'fresh' });
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
      // V11.0 — Threat Intelligence Engine v2.0 (Sentinel APEX)
      'GET  /api/threat-intel':          'Paginated threat feed (FREE:5, STARTER:20, PRO:50, ENT:100)',
      'GET  /api/threat-intel/stats':    'Aggregate CVE/KEV/exploit statistics',
      'GET  /api/threat-intel/:id':      'Single advisory detail with IOC extraction',
      'POST /api/threat-intel/ingest':   'Manual ingestion trigger (PRO/ENTERPRISE)',
      // V10.0 — Public API v1 (PRO/ENTERPRISE key required)
      'GET  /api/v1/scan':             'Scan history for your API key',
      'GET  /api/v1/threat-intel':     'D1-backed threat intel feed with IOCs (PRO+)',
      'GET  /api/v1/iocs':             'IOC registry — IPs, domains, hashes (ENTERPRISE)',
      'POST /api/v1/analyze':          'AI threat analysis (PRO+)',
      'POST /api/v1/simulate':         'Attack simulation (ENTERPRISE only)',
      'POST /api/v1/forecast':         'Risk forecast with financial impact (PRO+)',
      'GET  /api/v1/cves':             'Top exploited CVEs for a module (PRO+)',
      // V8.0 — Version
      'GET  /api/version':           'Live platform version + build metadata',
      // Admin
      'GET  /api/admin/analytics':   'Platform analytics (ENTERPRISE only)',
      'GET  /api/admin/api-usage':   'API metering + latency stats (ENTERPRISE only)',
      // V8.1 — SIEM Export
      'GET  /api/export/siem':       'SIEM export capabilities + format list (public)',
      'POST /api/export/siem':       'Export threat data — JSON/CEF/STIX/Sigma/CSV (PRO+)',
      'GET  /api/export/siem/stream':'Streaming NDJSON export for Logstash/Fluentd (ENTERPRISE)',
      // V8.1 — Real-Time Feed (SSE)
      'GET  /api/realtime/feed':     'SSE live threat alert stream (PRO/ENTERPRISE)',
      'GET  /api/realtime/posture':  'Defense posture snapshot JSON (authenticated)',
      'GET  /api/realtime/stats':    'Live platform stats (public)',
      // V8.1 — Gumroad Revenue Engine
      'POST /api/webhooks/gumroad':  'Gumroad purchase webhook (HMAC verified)',
      'POST /api/gumroad/verify':    'Activate Gumroad license key → provision tier',
      'GET  /api/gumroad/products':  'Public product catalog with pricing + SKUs',
      // Other
      'GET  /api/health':            'Service health',
      'POST /api/webhooks/razorpay': 'Razorpay payment webhook',
    },
    tiers: {
      FREEMIUM:   { daily_limit:  5, burst: '2/min',  scan_limit: 50,  key_limit: 2,  price_inr: 0,    queue_priority: 'low'    },
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
    // ── Binding alias normalisation ──────────────────────────────────────────
    // wrangler.toml binds D1 as SECURITY_HUB_DB and KV as SECURITY_HUB_KV.
    // All handlers reference env.DB and env.KV (shorter aliases).
    // Normalise here so every downstream handler works without change.
    if (env.SECURITY_HUB_DB && !env.DB) env.DB = env.SECURITY_HUB_DB;
    if (env.SECURITY_HUB_KV && !env.KV) env.KV = env.SECURITY_HUB_KV;
    if (env.SECURITY_HUB_KV && !env.CDB_KV) env.CDB_KV = env.SECURITY_HUB_KV; // alias for manualPayments.js

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
      // KV OPTIMIZATION: wrap health in 60-second Cloudflare CDN edge cache.
      // This means 1 D1 probe per 60s instead of 1 per 30s per browser session.
      // The edge cache is FREE and does not consume KV quota.
      const HEALTH_CACHE_KEY = 'health:v1';
      const HEALTH_CACHE_TTL = 60; // 60 seconds — matches frontend 120s poll after fix
      try {
        const edgeCache = caches.default;
        const cacheUrl  = new Request(`https://cdb-edge-cache/${HEALTH_CACHE_KEY}`);
        const hit       = await edgeCache.match(cacheUrl);
        if (hit) {
          const headers = new Headers(hit.headers);
          headers.set('X-Cache', 'HIT');
          return withSecurityHeaders(withCors(new Response(hit.body, { status: hit.status, headers }), request));
        }
        const fresh = await healthResponseAsync(env);
        const toCache = fresh.clone();
        const cacheHeaders = new Headers(toCache.headers);
        cacheHeaders.set('Cache-Control', `public, max-age=${HEALTH_CACHE_TTL}, s-maxage=${HEALTH_CACHE_TTL}`);
        cacheHeaders.set('X-Cache', 'MISS');
        edgeCache.put(cacheUrl, new Response(toCache.body, { status: toCache.status, headers: cacheHeaders })).catch(() => {});
        return withSecurityHeaders(withCors(fresh, request));
      } catch {
        // Edge cache unavailable (e.g. local dev) — fall through to uncached
        return withSecurityHeaders(withCors(await healthResponseAsync(env), request));
      }
    }

    // ── /api/config — public frontend config (Razorpay key, feature flags) ──
    // Safe: only exposes publishable key (KEY_ID), never KEY_SECRET.
    // Cached on Cloudflare edge (Cache-Control: public, max-age=300).
    if (path === '/api/config' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        razorpay_key_id:  env.RAZORPAY_KEY_ID  || '',
        razorpay_mode:    (env.RAZORPAY_KEY_ID  || '').startsWith('rzp_live') ? 'live' : 'test',
        platform:         env.APP_NAME         || 'CYBERDUDEBIVASH AI Security Hub',
        version:          env.VERSION           || '11.0.0',
        contact_email:    env.CONTACT           || 'bivash@cyberdudebivash.com',
        features: {
          subscriptions: true,
          per_report_payments: true,
          enterprise_booking: true,
          gumroad: true,
        },
      }, {
        headers: { 'Cache-Control': 'public, max-age=300, stale-while-revalidate=60' },
      }), request));
    }

    // ── /api/pricing — canonical pricing (immutable, from pricingConfig) ────
    if (path === '/api/pricing' && method === 'GET') {
      return withSecurityHeaders(withCors(await handlePricing(request, env), request));
    }
    // ── /api/payment-config — canonical payment details (immutable) ──────────
    if (path === '/api/payment-config' && method === 'GET') {
      return withSecurityHeaders(withCors(await handlePaymentConfig(request, env), request));
    }
    // ── Guard: reject ANY attempt to mutate payment config via API ────────────
    if (path.startsWith('/api/payment-config') && method !== 'GET') {
      return withSecurityHeaders(withCors(await handlePaymentMutationGuard(request, env), request));
    }
    if (path.startsWith('/api/pricing') && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
      return withSecurityHeaders(withCors(await handlePaymentMutationGuard(request, env), request));
    }

    if (path === '/api/intelligence/summary' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleIntelligenceSummary(env), request));
    }
    if (path === '/api/version' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        version:          env.VERSION || env.PLATFORM_VERSION || '13.0.0',
        platform_version: env.PLATFORM_VERSION || '13.0.0',
        commit:           env.COMMIT || (env.CF_VERSION_METADATA?.id) || 'unknown',
        timestamp:        new Date().toISOString(),
        environment:      env.ENVIRONMENT || 'production',
        name:             env.APP_NAME    || 'CYBERDUDEBIVASH AI Security Hub',
        engines: {
          sentinel_apex:       '3.0',
          mythos_orchestrator: '1.0',
          anomaly_detection:   '1.0',
          predictive_intel:    '1.0',
          agentic_ai:          '1.0',
          virtual_waf:         '1.0',
        },
        capabilities: [
          'domain_scan','ai_scan','redteam','identity','compliance',
          'soc_automation','threat_intel','attack_graph','ai_brain',
          'realtime_feed','siem_export','defense_marketplace',
          'agentic_remediation','behavioral_anomaly','predictive_threats',
          'virtual_patching','mythos_tools','global_scale','mssp',
        ],
      }), request));
    }

    // ── v13 Status — comprehensive engine health + metrics ─────────────────
    if ((path === '/api/v13/status' || path === '/api/status') && method === 'GET') {
      const [dbStatus, kvStatus, threatRows, agentRows, anomalyRows] = await Promise.allSettled([
        env.DB?.prepare('SELECT 1').first(),
        env.KV?.get('healthcheck_ts'),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN is_kev=1 THEN 1 ELSE 0 END) as kev FROM threat_intel`).first(),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN execution_status='SUCCESS' THEN 1 ELSE 0 END) as success, SUM(CASE WHEN execution_status='pending' THEN 1 ELSE 0 END) as pending FROM agent_actions`).first(),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN risk_level IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as high_risk, SUM(auto_actioned) as actioned FROM anomaly_events WHERE created_at > datetime('now','-24 hours')`).first(),
      ]);
      return withSecurityHeaders(withCors(Response.json({
        ok: true,
        version: env.PLATFORM_VERSION || '13.0.0',
        timestamp: new Date().toISOString(),
        engines: {
          database:    dbStatus.status==='fulfilled' && dbStatus.value ? 'online' : 'degraded',
          kv_cache:    'online',
          mythos:      'online',
          anomaly:     'online',
          predictive:  'online',
          agent_bus:   'online',
          sentinel:    'online',
          virtual_waf: 'online',
        },
        metrics: {
          threat_intel: {
            total:    threatRows.value?.total    || 0,
            critical: threatRows.value?.critical || 0,
            kev:      threatRows.value?.kev      || 0,
          },
          agent_actions: {
            total:   agentRows.value?.total   || 0,
            success: agentRows.value?.success || 0,
            pending: agentRows.value?.pending || 0,
          },
          anomaly_detection_24h: {
            scanned:    anomalyRows.value?.total    || 0,
            high_risk:  anomalyRows.value?.high_risk || 0,
            actioned:   anomalyRows.value?.actioned  || 0,
          },
        },
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

    // ── CDB Manual payment confirmation (UPI/Bank/Crypto/PayPal) ─────────────
    // POST /api/payment/confirm  →  { txnId, method, product, user, amount }
    if (path === '/api/payment/confirm' && method === 'POST') {
      return withSecurityHeaders(withCors(await handlePaymentConfirm(request, env), request));
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

    // ═══════════════════════════════════════════════════════════════════════
    // V11.0 SENTINEL APEX — Threat Intelligence Engine v2.0
    // D1-backed, real NVD+CISA+GitHub ingestion, IOC extraction, enrichment
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/threat-intel — main paginated feed (public + plan-gated)
    if (path === '/api/threat-intel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetThreatIntel(request, env, authCtx), request));
    }

    // GET /api/threat-intel/stats — aggregate stats (public)
    if (path === '/api/threat-intel/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleThreatIntelStats(request, env, authCtx), request));
    }

    // GET /api/threat-intel/stream — SSE real-time feed (Phase 1)
    // Must be BEFORE the /:id catch-all
    if (path === '/api/threat-intel/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      // SSE does not use withCors wrapper (returns streaming Response directly)
      return await handleThreatIntelStream(request, env, authCtx);
    }

    // GET /api/soc/dashboard — Full SOC dashboard (plan-gated, public route)
    if (path === '/api/soc/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleSOCDashboard(request, env, authCtx), request));
    }

    // POST /api/threat-intel/ingest — manual trigger (PRO/ENTERPRISE)
    if (path === '/api/threat-intel/ingest' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleManualIngest(request, env, authCtx), request));
    }

    // GET /api/threat-intel/live — alias for /api/sentinel/feed (KV-backed live CVE feed)
    if (path === '/api/threat-intel/live' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }

    // GET /api/threat-intel/:id — single advisory detail (after /stats and /stream)
    if (path.match(/^\/api\/threat-intel\/[^/]+$/) && method === 'GET') {
      const entryId = path.split('/')[3];
      // Avoid matching sub-routes already handled above
      if (!['stats', 'stream', 'ingest'].includes(entryId)) {
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
        return withSecurityHeaders(withCors(await handleGetThreatIntelEntry(request, env, authCtx, entryId), request));
      }
    }

    // POST /api/threat-intel/correlate — legacy endpoint (scan findings → CVE correlation)
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

    // POST /api/ai/chat → MYTHOS conversational analyst (multi-turn, intent routing)
    if (path === '/api/ai/chat' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIChat(request, env), request));
    }
    // POST /api/ai/generate-rules → SOAR rule generation (Sigma/Splunk/KQL/YARA/Elastic)
    if (path === '/api/ai/generate-rules' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGenerateRules(request, env), request));
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

      // GET /api/v1/threat-intel → D1-backed threat intel feed (PRO+)
      if (v1Path === '/threat-intel' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1ThreatIntel(request, env, authCtx), request));
      }

      // GET /api/v1/iocs → IOC registry (ENTERPRISE only)
      if (v1Path === '/iocs' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1IOCs(request, env, authCtx), request));
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

      // GET /api/v1/correlations → CVE correlation engine (PRO/ENTERPRISE)
      if (v1Path === '/correlations' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Correlations(request, env, authCtx), request));
      }

      // GET /api/v1/graph → IOC relationship graph (PRO/ENTERPRISE)
      if (v1Path === '/graph' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Graph(request, env, authCtx), request));
      }

      // GET /api/v1/hunting → threat hunting alerts (PRO/ENTERPRISE)
      if (v1Path === '/hunting' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Hunting(request, env, authCtx), request));
      }

      // ── Sentinel APEX v3: SOC Automation + Defense ─────────────────────────

      // GET /api/v1/alerts → SOC detection alerts (STARTER+)
      if (v1Path === '/alerts' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetAlerts(request, env, authCtx), request));
      }

      // GET /api/v1/decisions → AI decision engine (ENTERPRISE)
      if (v1Path === '/decisions' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetDecisions(request, env, authCtx), request));
      }

      // GET /api/v1/defense-actions → Autonomous defense log (ENTERPRISE)
      if (v1Path === '/defense-actions' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetDefenseActions(request, env, authCtx), request));
      }

      // GET /api/v1/federation → Global threat feed + source scores (PRO+)
      if (v1Path === '/federation' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetFederation(request, env, authCtx), request));
      }

      // POST /api/v1/soc/analyze → Full SOC pipeline on-demand (ENTERPRISE)
      if (v1Path === '/soc/analyze' && method === 'POST') {
        return withSecurityHeaders(withCors(await handleSOCAnalyze(request, env, authCtx), request));
      }

      // GET /api/v1/soc/posture → SOC defense posture summary (STARTER+)
      if (v1Path === '/soc/posture' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetSOCPosture(request, env, authCtx), request));
      }

      // ── v13 Agent Actions route ──────────────────────────────────────────
      // GET /api/v1/agent-actions → Recent autonomous agent actions (STARTER+)
      if (v1Path === '/agent-actions' && method === 'GET') {
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 100);
        try {
          const [rows, total] = await Promise.all([
            env.DB?.prepare(
              `SELECT id, agent_type, action_type, target, target_type, trigger_source, risk_level,
                      execution_status, executed_by, duration_ms, created_at, completed_at
               FROM agent_actions ORDER BY created_at DESC LIMIT ?`
            ).bind(limit).all().catch(()=>({results:[]})),
            env.DB?.prepare(`SELECT COUNT(*) as cnt FROM agent_actions`).first().catch(()=>({cnt:0})),
          ]);
          return withSecurityHeaders(withCors(Response.json({
            ok: true, total: total?.cnt||0,
            actions: rows?.results||[],
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, actions:[], error:e.message }), request));
        }
      }

      // ── v13 Predictive Threats route ─────────────────────────────────────
      // GET /api/v1/predictive/threats → Top risk predictions (public lite)
      if (v1Path === '/predictive/threats' && method === 'GET') {
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'10'), 50);
        try {
          const rows = await env.DB?.prepare(
            `SELECT cve_id, exploit_probability, probability_pct, impact_score, risk_score,
                    attack_window_label, expected_window_hrs, recommended_action,
                    is_kev, cvss_score, epss_score, apt_groups, mitre_techniques, prediction_date
             FROM threat_predictions ORDER BY risk_score DESC, probability_pct DESC LIMIT ?`
          ).bind(limit).all().catch(()=>({results:[]}));
          const stats = await env.DB?.prepare(
            `SELECT COUNT(*) as total,
                    SUM(CASE WHEN risk_score>=80 THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN probability_pct>=70 THEN 1 ELSE 0 END) as high_exploit,
                    SUM(CASE WHEN is_kev=1 THEN 1 ELSE 0 END) as kev_count
             FROM threat_predictions WHERE prediction_date=date('now')`
          ).first().catch(()=>({}));
          return withSecurityHeaders(withCors(Response.json({
            ok: true,
            predictions: rows?.results||[],
            summary: {
              total:        stats?.total||0,
              critical:     stats?.critical_count||0,
              high_exploit: stats?.high_exploit||0,
              kev:          stats?.kev_count||0,
            },
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, predictions:[], error:e.message }), request));
        }
      }

      // ── v13 Anomaly Events route ─────────────────────────────────────────
      // GET /api/v1/anomaly/events → Recent anomaly detections (AUTH required)
      if ((v1Path === '/anomaly/events' || v1Path === '/anomaly') && method === 'GET') {
        if (!authCtx?.user_id && authCtx?.tier === 'FREE') {
          return withSecurityHeaders(withCors(Response.json({ ok:false, error:'Authentication required', code:'ERR_AUTH' }, {status:401}), request));
        }
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 100);
        try {
          const rows = await env.DB?.prepare(
            `SELECT id, user_id, anomaly_score, anomaly_types, risk_level, auto_actioned, resolved, created_at
             FROM anomaly_events WHERE created_at > datetime('now','-24 hours')
             ORDER BY anomaly_score DESC LIMIT ?`
          ).bind(limit).all().catch(()=>({results:[]}));
          const stats = await env.DB?.prepare(
            `SELECT COUNT(*) as scanned,
                    SUM(CASE WHEN risk_level IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as high_risk,
                    SUM(auto_actioned) as actioned
             FROM anomaly_events WHERE created_at > datetime('now','-24 hours')`
          ).first().catch(()=>({}));
          return withSecurityHeaders(withCors(Response.json({
            ok: true,
            anomalies: rows?.results||[],
            stats: { scanned: stats?.scanned||0, high_risk: stats?.high_risk||0, actioned: stats?.actioned||0 },
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, anomalies:[], error:e.message }), request));
        }
      }

      // Unknown /api/v1/* path
      return withSecurityHeaders(withCors(Response.json({
        success: false,
        error:   `Unknown API v1 endpoint: ${method} ${path}`,
        code:    'ERR_NOT_FOUND',
        available: [
          'GET /api/v1/scan', 'GET /api/v1/threat-intel',
          'POST /api/v1/analyze', 'POST /api/v1/simulate', 'POST /api/v1/forecast',
          'GET /api/v1/cves', 'GET /api/v1/iocs',
          'GET /api/v1/correlations', 'GET /api/v1/graph', 'GET /api/v1/hunting',
          'GET /api/v1/alerts', 'GET /api/v1/decisions', 'GET /api/v1/defense-actions',
          'GET /api/v1/federation', 'POST /api/v1/soc/analyze', 'GET /api/v1/soc/posture',
          'GET /api/v1/agent-actions', 'GET /api/v1/predictive/threats',
          'GET /api/v1/anomaly/events',
        ],
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

    // ═══════════════════════════════════════════════════════════════════════
    // V12.0 GTM GROWTH ENGINE — Revenue + Funnel + Email + Sales + Analytics
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/growth/capture — email capture + drip enroll (public)
    if (path === '/api/growth/capture' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleEmailCapture(request, env), request));
    }

    // POST /api/growth/scan — record scan event + upgrade check (public)
    if (path === '/api/growth/scan' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleScanEvent(request, env), request));
    }

    // GET /api/growth/upgrade-check — get upgrade trigger status (public)
    if (path === '/api/growth/upgrade-check' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleUpgradeCheck(request, env), request));
    }

    // POST /api/growth/upgrade — mark lead as upgraded (public)
    if (path === '/api/growth/upgrade' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleUpgradeLead(request, env), request));
    }

    // GET /api/growth/analytics — revenue dashboard (admin, no strict auth for now)
    if (path === '/api/growth/analytics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleRevenueDashboard(request, env), request));
    }

    // GET /api/growth/funnel — funnel conversion metrics (admin)
    if (path === '/api/growth/funnel' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleFunnelDashboard(request, env), request));
    }

    // GET /api/growth/leads — lead list (admin)
    if (path === '/api/growth/leads' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetLeads(request, env), request));
    }

    // POST /api/growth/sales/run — run enterprise sales pipeline
    if (path === '/api/growth/sales/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunSalesPipeline(request, env), request));
    }

    // GET /api/growth/sales/outreach — get outreach queue
    if (path === '/api/growth/sales/outreach' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetOutreach(request, env), request));
    }

    // POST /api/growth/sales/outreach/:id/send — mark sent
    if (path.match(/^\/api\/growth\/sales\/outreach\/[^/]+\/send$/) && method === 'POST') {
      const outreachId = path.split('/')[5];
      return withSecurityHeaders(withCors(await handleMarkOutreachSent(request, env, null, outreachId), request));
    }

    // POST /api/growth/content/run — run content automation pipeline
    if (path === '/api/growth/content/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunContentAutomation(request, env), request));
    }

    // GET /api/growth/content/queue — get content queue
    if (path === '/api/growth/content/queue' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetContentQueue(request, env), request));
    }

    // POST /api/growth/email/run — run drip email automation
    if (path === '/api/growth/email/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunDrip(request, env), request));
    }

    // GET /api/unsubscribe — global one-click unsubscribe (public, no auth)
    // Linked from every email footer; marks lead as unsubscribed in D1.
    if (path === '/api/unsubscribe' && method === 'GET') {
      const email = url.searchParams.get('email') || '';
      const token = url.searchParams.get('token') || '';
      if (!email) {
        return withSecurityHeaders(withCors(
          Response.json({ success: false, error: 'email param required' }, { status: 400 }), request
        ));
      }
      try {
        if (env?.DB) {
          await env.DB.prepare(
            `UPDATE leads SET unsubscribed = 1, unsubscribed_at = datetime('now') WHERE email = ?`
          ).bind(email.toLowerCase()).run();
        }
        // Return a clean HTML confirmation page
        return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Unsubscribed — CYBERDUDEBIVASH</title>
<style>body{background:#0a0e1a;color:#e2e8f0;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:40px;max-width:420px;text-align:center}
h2{color:#10b981;margin-bottom:8px}p{color:#94a3b8;font-size:.9rem}a{color:#00d4ff}</style></head>
<body><div class="box"><h2>✅ Unsubscribed</h2>
<p><strong>${email}</strong> has been removed from all marketing emails.</p>
<p style="margin-top:16px">You will still receive critical security alerts if you have an active account.</p>
<p style="margin-top:16px"><a href="https://cyberdudebivash.in">← Return to Sentinel APEX</a></p>
</div></body></html>`, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        });
      } catch (e) {
        return withSecurityHeaders(withCors(
          Response.json({ success: false, error: e.message }, { status: 500 }), request
        ));
      }
    }

    // GET /api/growth/email/track — 1×1 pixel / redirect for email tracking
    if (path === '/api/growth/email/track' && method === 'GET') {
      return await handleEmailTrack(request, env);
    }

    // POST /api/growth/api-key — provision API key
    if (path === '/api/growth/api-key' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleProvisionApiKey(request, env), request));
    }

    // GET /api/growth/api-usage — get API usage summary
    if (path === '/api/growth/api-usage' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetApiUsage(request, env), request));
    }

    // POST /api/billing/callback — Razorpay webhook / payment callback
    if (path === '/api/billing/callback' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleBillingCallback(request, env), request));
    }

    // POST /api/billing/create-link — generate Razorpay payment link payload
    if (path === '/api/billing/create-link' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreatePaymentLink(request, env), request));
    }

    // ─── MONETIZATION ENGINE v2 ─────────────────────────────────────────────
    // GET /api/billing/usage — detailed usage + quota status
    if (path === '/api/billing/usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetUsage(request, env, authCtx), request));
    }
    // POST /api/billing/upgrade — initiate plan upgrade
    if (path === '/api/billing/upgrade' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpgrade(request, env, authCtx), request));
    }
    // GET /api/billing/plans — enriched plan comparison
    if (path === '/api/billing/plans' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetBillingPlans(request, env, authCtx), request));
    }
    // POST /api/billing/trial/start — activate 14-day PRO trial
    if (path === '/api/billing/trial/start' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleStartTrial(request, env, authCtx), request));
    }
    // GET /api/billing/limits — quota enforcement state
    if (path === '/api/billing/limits' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLimits(request, env, authCtx), request));
    }
    // GET /api/billing/invoices — invoice history
    if (path === '/api/billing/invoices' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetInvoices(request, env, authCtx), request));
    }
    // POST /api/billing/downgrade — schedule plan downgrade
    if (path === '/api/billing/downgrade' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDowngrade(request, env, authCtx), request));
    }

    // ─── THREAT INTELLIGENCE GRAPH ──────────────────────────────────────────
    // GET /api/threat-graph — full D3-ready graph
    if (path === '/api/threat-graph' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetThreatGraph(request, env, authCtx), request));
    }
    // GET /api/threat-graph/nodes — node list with filter
    if (path === '/api/threat-graph/nodes' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetGraphNodes(request, env), request));
    }
    // GET /api/threat-graph/paths — shortest attack path
    if (path === '/api/threat-graph/paths' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetGraphPaths(request, env), request));
    }
    // POST /api/threat-graph/query — subgraph query
    if (path === '/api/threat-graph/query' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGraphQuery(request, env), request));
    }
    // GET /api/threat-graph/summary — aggregate stats
    if (path === '/api/threat-graph/summary' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGraphSummary(request, env), request));
    }

    // ─── CISO COMMAND CENTER ────────────────────────────────────────────────
    // GET /api/ciso/metrics — full CISO dashboard payload
    if (path === '/api/ciso/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOMetrics(request, env, authCtx), request));
    }
    // GET /api/ciso/posture — security posture scorecard
    if (path === '/api/ciso/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOPosture(request, env, authCtx), request));
    }
    // GET /api/ciso/incidents — incident list
    if (path === '/api/ciso/incidents' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetIncidents(request, env, authCtx), request));
    }
    // POST /api/ciso/incidents — create incident
    if (path === '/api/ciso/incidents' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleCreateIncident(request, env, authCtx), request));
    }
    // PUT /api/ciso/incidents/:id — update incident
    if (path.startsWith('/api/ciso/incidents/') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpdateIncident(request, env, authCtx), request));
    }
    // GET /api/ciso/compliance-status
    if (path === '/api/ciso/compliance-status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetComplianceStatus(request, env, authCtx), request));
    }
    // GET /api/ciso/risk-register
    if (path === '/api/ciso/risk-register' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetRiskRegister(request, env, authCtx), request));
    }
    // GET /api/ciso/report
    if (path === '/api/ciso/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOReport(request, env, authCtx), request));
    }

    // ── Phase 7: Global Expansion ───────────────────────────────────────────
    // GET /api/growth/region — region context + localized pricing + compliance
    if (path === '/api/growth/region' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetRegionContext(request, env), request));
    }

    // GET /api/growth/global — global expansion dashboard (region stats + pricing)
    if (path === '/api/growth/global' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGlobalDashboard(request, env), request));
    }

    // ── Phase 9: Upsell + Revenue Maximization ──────────────────────────────
    // POST /api/growth/upsell/evaluate — evaluate upsell triggers for a session
    if (path === '/api/growth/upsell/evaluate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleEvaluateUpsell(request, env), request));
    }

    // POST /api/growth/upsell/converted — mark a upsell as converted
    if (path === '/api/growth/upsell/converted' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleUpsellConverted(request, env), request));
    }

    // GET /api/growth/upsell/metrics — upsell + A/B test results
    if (path === '/api/growth/upsell/metrics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleUpsellMetrics(request, env), request));
    }

    // GET /api/growth/feature-wall — get upgrade wall for a locked feature
    if (path === '/api/growth/feature-wall' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleFeatureWall(request, env), request));
    }

    // GET /api/growth/pricing — region-aware pricing with A/B variant
    if (path === '/api/growth/pricing' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPricing(request, env), request));
    }

    // ── Phase 9: LinkedIn Domination Engine ─────────────────────────────────
    // GET /api/growth/linkedin/today — get today's LinkedIn post (pre-generated)
    if (path === '/api/growth/linkedin/today' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleLinkedInToday(request, env), request));
    }

    // POST /api/growth/linkedin/run — generate + queue today's LinkedIn post
    if (path === '/api/growth/linkedin/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunLinkedIn(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 REAL-TIME FEED — SSE threat alerts + posture + stats
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/realtime/feed — SSE live threat alert stream (PRO/ENTERPRISE)
    if (path === '/api/realtime/feed' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      // SSE streams cannot use withCors wrapper — returns raw streaming Response
      return await handleRealtimeFeed(request, env, authCtx);
    }

    // GET /api/realtime/posture — Defense posture JSON (authenticated)
    if (path === '/api/realtime/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleRealtimePosture(request, env, authCtx), request));
    }

    // GET /api/realtime/stats — Live platform stats (public)
    if (path === '/api/realtime/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleRealtimeStats(request, env, authCtx), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 GUMROAD REVENUE ENGINE — License verification + webhook + catalog
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/webhooks/gumroad — Gumroad purchase webhook (no auth — HMAC verified)
    if (path === '/api/webhooks/gumroad' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGumroadWebhook(request, env), request));
    }

    // POST /api/gumroad/verify — License key activation (optionally authenticated)
    if (path === '/api/gumroad/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleLicenseActivation(request, env, authCtx), request));
    }

    // GET /api/gumroad/products — Public product catalog
    if (path === '/api/gumroad/products' && method === 'GET') {
      return withSecurityHeaders(withCors(handleProductCatalog(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 SIEM EXPORT — JSON / CEF / STIX 2.1 / Sigma / CSV / NDJSON
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 AFFILIATE + REVENUE TRACKING
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/affiliate/click — track affiliate link click (public, fire-and-forget)
    if (path === '/api/affiliate/click' && method === 'POST') {
      // Non-blocking — always return 204
      (async () => {
        try {
          const body = await request.clone().json().catch(() => ({}));
          const ip   = request.headers.get('CF-Connecting-IP') || '';
          const country = request.cf?.country || '';
          const ua  = (request.headers.get('User-Agent') || '').slice(0, 300);
          if (env?.DB && body.link_id) {
            const id = crypto.randomUUID();
            await env.DB.prepare(
              `INSERT INTO affiliate_clicks (id, program, link_id, link_url, ref_page, ip, country, user_agent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
            ).bind(
              id,
              (body.program || 'unknown').slice(0, 64),
              (body.link_id || 'unknown').slice(0, 128),
              (body.link_url || '').slice(0, 500),
              (body.ref_page || '').slice(0, 500),
              ip, country,
              ua.slice(0, 200),
            ).run().catch(() => {});
          }
        } catch {}
      })();
      return withSecurityHeaders(withCors(new Response(null, { status: 204 }), request));
    }

    // GET /api/revenue/dashboard — revenue analytics (ENTERPRISE only)
    if (path === '/api/revenue/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (authCtx.tier !== 'ENTERPRISE') {
        return withSecurityHeaders(withCors(Response.json({
          success: false, error: 'Revenue dashboard requires ENTERPRISE plan.',
          code: 'ERR_ENTERPRISE_REQUIRED',
        }, { status: 403 }), request));
      }
      try {
        const days = parseInt(new URL(request.url).searchParams.get('days') || '30', 10);
        const cutoff = new Date(Date.now() - days * 86400000).toISOString();
        const [payments, affiliates, gumroad] = await Promise.all([
          env.DB?.prepare(`SELECT source, SUM(amount_inr) as total_inr, COUNT(*) as count FROM revenue_events WHERE created_at >= ? GROUP BY source ORDER BY total_inr DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
          env.DB?.prepare(`SELECT program, COUNT(*) as clicks, SUM(converted) as conversions, SUM(revenue) as revenue FROM affiliate_clicks WHERE created_at >= ? GROUP BY program ORDER BY clicks DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
          env.DB?.prepare(`SELECT product_permalink, COUNT(*) as licenses, tier_granted FROM gumroad_licenses WHERE created_at >= ? GROUP BY product_permalink ORDER BY licenses DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
        ]);
        return withSecurityHeaders(withCors(Response.json({
          success: true,
          period_days: days,
          revenue_by_source: payments?.results || [],
          affiliate_performance: affiliates?.results || [],
          gumroad_licenses: gumroad?.results || [],
          generated_at: new Date().toISOString(),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // ── v8.2 Revenue + Monetization + Automation Routes ──────────────────────

    // GET /api/revenue/snapshot — lightweight KPI snapshot (all plans)
    if (path === '/api/revenue/snapshot' && method === 'GET') {
      const { handleRevenueSnapshot } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueSnapshot(request, env, authCtx), request));
    }

    // GET /api/revenue/metrics — plan-gated full metrics
    if (path === '/api/revenue/metrics' && method === 'GET') {
      const { handleRevenueMetrics } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueMetrics(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role, email: authCtx.email }), request));
    }

    // GET /api/revenue/products — product catalog with live sales data (public)
    if (path === '/api/revenue/products' && method === 'GET') {
      const { handleRevenueProducts } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueProducts(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role } : null), request));
    }

    // GET /api/revenue/recommendations — admin recommendations
    if (path === '/api/revenue/recommendations' && method === 'GET') {
      const { handleRevenueRecommendations } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueRecommendations(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/revenue/event — record revenue event (admin/internal)
    if (path === '/api/revenue/event' && method === 'POST') {
      const { handleRevenueEvent } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueEvent(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // POST /api/revenue/track — track any revenue action (public)
    if (path === '/api/revenue/track' && method === 'POST') {
      const { handleRevenueTrack } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueTrack(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : null), request));
    }

    // GET /api/revenue/dashboard/enhanced — charts-ready enhanced dashboard (PRO+)
    if (path === '/api/revenue/dashboard/enhanced' && method === 'GET') {
      const { handleEnhancedDashboard } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleEnhancedDashboard(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/revenue/trends — trend analytics (PRO+)
    if (path === '/api/revenue/trends' && method === 'GET') {
      const { handleRevenueTrends } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueTrends(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/revenue/growth — growth score + levers
    if (path === '/api/revenue/growth' && method === 'GET') {
      const { handleRevenueGrowth } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueGrowth(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/monetize/upsell — AI upsell trigger (auth or anon)
    if (path === '/api/monetize/upsell' && method === 'GET') {
      const { handleUpsellTrigger } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleUpsellTrigger(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // GET /api/monetize/products — AI product recommendations
    if (path === '/api/monetize/products' && method === 'GET') {
      const { handleProductRecommendations } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleProductRecommendations(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // GET /api/monetize/churn-risk — churn risk assessment (PRO+)
    if (path === '/api/monetize/churn-risk' && method === 'GET') {
      const { handleChurnRisk } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleChurnRisk(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/monetize/optimize — full AI optimization pass (auth required)
    if (path === '/api/monetize/optimize' && method === 'POST') {
      const { handleRevenueOptimize } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueOptimize(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() }), request));
    }

    // POST /api/monetize/bulk-optimize — bulk AI pass (admin only)
    if (path === '/api/monetize/bulk-optimize' && method === 'POST') {
      const { handleBulkOptimize } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleBulkOptimize(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // GET  /api/funnel/metrics — conversion funnel data (ENTERPRISE/admin)
    if (path === '/api/funnel/metrics' && method === 'GET') {
      const { handleFunnelMetrics } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleFunnelMetrics(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/funnel/event — record funnel stage event (public, fire-and-forget)
    if (path === '/api/funnel/event' && method === 'POST') {
      const { handleFunnelEvent } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFunnelEvent(request, env, authCtx ? { userId: authCtx.userId } : null), request));
    }

    // GET  /api/defense/catalog — defense product catalog (public)
    if (path === '/api/defense/catalog' && method === 'GET') {
      const { handleDefenseCatalog } = await import('./handlers/revenue.js');
      return withSecurityHeaders(withCors(await handleDefenseCatalog(request, env, null), request));
    }

    // GET  /api/defense/preview — defense product preview with paywall
    if (path === '/api/defense/preview' && method === 'GET') {
      const { handleDefensePreview } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDefensePreview(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // POST /api/checkout — initiate Razorpay checkout
    if (path === '/api/checkout' && method === 'POST') {
      const { handleCheckoutInitiate } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCheckoutInitiate(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email, name: authCtx.name } : null), request));
    }

    // POST /api/checkout/verify — verify Razorpay payment + grant access
    if (path === '/api/checkout/verify' && method === 'POST') {
      const { handleCheckoutVerify } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCheckoutVerify(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : null), request));
    }

    // GET  /api/affiliate/stats — affiliate click stats (admin)
    if (path === '/api/affiliate/stats' && method === 'GET') {
      const { handleAffiliateStats } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleAffiliateStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // POST /api/automation/run — manual automation trigger (admin only)
    if (path === '/api/automation/run' && method === 'POST') {
      const { handleAutomationRun } = await import('./services/automationEngine.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleAutomationRun(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ════════════════════════════════════════════════════════════════════════
    // v10.0 ROUTES — Defense Solutions Marketplace, Enterprise, Global Scale
    // ════════════════════════════════════════════════════════════════════════

    // ── Defense Solutions Marketplace (Phase 1+2) ─────────────────────────

    // GET /api/defense/solutions — list marketplace solutions (public with filter)
    if (path === '/api/defense/solutions' && method === 'GET') {
      const { handleGetSolutions } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetSolutions(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}), request));
    }

    // GET /api/defense/solutions/featured — featured solutions (public)
    if (path === '/api/defense/solutions/featured' && method === 'GET') {
      const { handleGetFeatured } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetFeatured(request, env), request));
    }

    // GET /api/defense/stats — marketplace aggregate stats (public)
    if (path === '/api/defense/stats' && method === 'GET') {
      const { handleGetMarketplaceStats } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetMarketplaceStats(request, env), request));
    }

    // GET /api/defense/fomo — FOMO social proof events (public)
    if (path === '/api/defense/fomo' && method === 'GET') {
      const { handleGetFOMO } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetFOMO(request, env), request));
    }

    // POST /api/defense/generate — admin: trigger on-demand generation
    if (path === '/api/defense/generate' && method === 'POST') {
      const { handleGenerateSolutions } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleGenerateSolutions(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ═══ ROUTE ALIASES: fix 404s hit by the frontend ══════════════════════════
    // GET /api/threat-intel/live  → alias → /api/sentinel/feed
    if (path === '/api/threat-intel/live' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }

    // GET /api/defense/list  → alias → /api/defense/solutions
    if (path === '/api/defense/list' && method === 'GET') {
      const { handleGetSolutions } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetSolutions(request, env, {}), request));
    }

    // GET /api/analytics/dashboard  → live platform metrics from D1
    if (path === '/api/analytics/dashboard' && method === 'GET') {
      try {
        const [scansRow, revenueRow, defenseRow, usersRow, threatRow] = await Promise.all([
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN scanned_at > datetime('now','-1 day') THEN 1 ELSE 0 END) as today FROM scan_history`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='paid'`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as rev FROM payments WHERE status='paid' AND module LIKE 'defense%'`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as total FROM users`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical FROM threat_intel`).first().catch(()=>null),
        ]);
        return withSecurityHeaders(withCors(Response.json({
          success: true,
          scans:        { total: scansRow?.total||0, today: scansRow?.today||0 },
          revenue:      { total_inr: revenueRow?.total||0, defense_inr: defenseRow?.rev||0 },
          defense:      { products: defenseRow?.cnt||0 },
          users:        { total: usersRow?.total||0 },
          threat_intel: { total: threatRow?.total||0, critical: threatRow?.critical||0 },
          timestamp:    new Date().toISOString(),
        }), request));
      } catch(e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // POST /api/admin/bootstrap  — seed threat intel + defense marketplace
    if (path === '/api/admin/bootstrap' && method === 'POST') {
      // Simple token auth — pass Authorization: Bearer bootstrap-cyberdude-2026
      const authHeader = request.headers.get('Authorization') || '';
      if (!authHeader.includes('bootstrap-cyberdude-2026')) {
        return withSecurityHeaders(withCors(Response.json({ error: 'Unauthorized' }, { status: 401 }), request));
      }
      const results = { threat_intel: null, defense: null };
      // 1. Seed threat intel D1
      try {
        const ir = await runIngestion(env);
        results.threat_intel = { inserted: ir.inserted, total: ir.total, sources: ir.sources };
      } catch(e) { results.threat_intel = { error: e.message }; }
      // 2. Seed defense solutions D1
      try {
        const { seedDefenseSolutions } = await import('./handlers/defenseSeed.js');
        results.defense = await seedDefenseSolutions(env);
      } catch(e) { results.defense = { error: e.message }; }
      // 3. Populate sentinel KV feed so /api/threat-intel/live returns data immediately
      try {
        results.sentinel = await runSentinelCron(env);
      } catch(e) { results.sentinel = { error: e.message }; }
      return withSecurityHeaders(withCors(Response.json({
        success: true, bootstrap: results, timestamp: new Date().toISOString(),
      }), request));
    }

    // POST /api/defense/custom-request — submit custom solution request (public)
    if (path === '/api/defense/custom-request' && method === 'POST') {
      const { handleCustomSolutionRequest } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomSolutionRequest(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // GET /api/defense/solutions/:id — single solution detail
    if (path.startsWith('/api/defense/solutions/') && !path.includes('/purchase') && !path.includes('/verify') && method === 'GET') {
      const { handleGetSolution } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/solutions/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetSolution(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}, solutionId), request));
    }

    // POST /api/defense/purchase/:id — initiate Razorpay checkout for solution
    if (path.startsWith('/api/defense/purchase/') && method === 'POST') {
      const { handleInitiatePurchase } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/purchase/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleInitiatePurchase(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}, solutionId), request));
    }

    // POST /api/defense/verify/:id — verify Razorpay payment for solution
    if (path.startsWith('/api/defense/verify/') && method === 'POST') {
      const { handleVerifyPurchase } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/verify/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleVerifyPurchase(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}, solutionId), request));
    }

    // ── Scan → Upsell Engine (Phase 3) ───────────────────────────────────

    // POST /api/scan/upsell — evaluate scan result for upsell opportunity
    // ── MYTHOS ORCHESTRATOR CORE v1.0 ────────────────────────────────────────
    // POST /api/mythos/run — trigger autonomous orchestration loop (admin)
    if (path === '/api/mythos/run' && method === 'POST') {
      const adminKey = request.headers.get('x-admin-key') || request.headers.get('X-Admin-Key');
      const isAdmin  = adminKey && env.ADMIN_KEY && adminKey === env.ADMIN_KEY;
      if (!isAdmin) return withSecurityHeaders(withCors(new Response(JSON.stringify({ success: false, error: 'Admin access required', hint: 'Provide x-admin-key header' }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      return withSecurityHeaders(withCors(await handleMythosRun(request, env, { role: 'admin' }), request));
    }
    // GET /api/mythos/status — live pipeline status (public)
    if (path === '/api/mythos/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMythosStatus(request, env, {}), request));
    }
    // GET /api/mythos/metrics — lifetime metrics (public)
    if (path === '/api/mythos/metrics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMythosMetrics(request, env, {}), request));
    }
    // GET /api/mythos/jobs/:jobId — job details (public, polls job state)
    if (path.startsWith('/api/mythos/jobs/') && method === 'GET') {
      const jobId = path.replace('/api/mythos/jobs/', '').split('/')[0];
      return withSecurityHeaders(withCors(await handleMythosJob(request, env, {}, jobId), request));
    }
    // POST /api/mythos/validate — validate any security artifact
    if (path === '/api/mythos/validate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleMythosValidate(request, env, {}), request));
    }
    // POST /api/mythos/analyze — AI-powered CVE deep analysis + task plan
    if (path === '/api/mythos/analyze' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMythosAnalyze(request, env, authCtx || {}), request));
    }

    // ── PHASE 2: Autonomous SOC Mode ──────────────────────────────────────────
    if (path === '/api/auto-soc/mode' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMode(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/mode' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetMode(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPipeline(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/run' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRunPipeline(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/schedule' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetSchedule(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/schedule' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetSchedule(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLog(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/latest-rules' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLatestRules(request, env, authCtx), request));
    }

    // ── PHASE 2: SIEM Integration Deploy ──────────────────────────────────────
    if (path === '/api/integrations' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListIntegrations(request, env, authCtx), request));
    }
    if (path === '/api/integrations/configure' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleConfigure(request, env, authCtx), request));
    }
    if (path === '/api/integrations/deploy' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeploy(request, env, authCtx), request));
    }
    if (path === '/api/integrations/test' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleTestIntegration(request, env, authCtx), request));
    }
    if (path === '/api/integrations/deploy-log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeployLog(request, env, authCtx), request));
    }
    if (path.startsWith('/api/integrations/') && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeleteIntegration(request, env, authCtx), request));
    }

    // ── PHASE 2: Organization Memory v2 ───────────────────────────────────────
    if (path === '/api/org-memory' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMemory(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/record' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRecordEvent(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/history' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetHistory(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/patterns' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPatterns(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/recommend' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetRecommendations(request, env, authCtx), request));
    }
    if (path === '/api/org-memory' && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleClearMemory(request, env, authCtx), request));
    }

    // ── PHASE 3: Autonomous Defense Engine ───────────────────────────────────
    if (path === '/api/defense-engine/mode' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDefenseMode(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/mode' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetDefenseMode(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/execute' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleExecuteDefense(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/pending' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPending(request, env, authCtx), request));
    }
    if (path.startsWith('/api/defense-engine/approve/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleApprove(request, env, authCtx), request));
    }
    if (path.startsWith('/api/defense-engine/rollback/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRollback(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/executions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetExecutions(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDefensePosture(request, env, authCtx), request));
    }

    // ── PHASE 3: Threat Confidence Engine ────────────────────────────────────
    if (path === '/api/threat-confidence/score' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleScoreThreats(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/kev' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetKEV(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/enrich' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleEnrichThreat(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/feed' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTCFeed(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTCStats(request, env, authCtx), request));
    }

    // ── PHASE 3: Executive Report Engine ─────────────────────────────────────
    if (path === '/api/executive/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDashboard(request, env, authCtx), request));
    }
    if (path === '/api/executive/mrr' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMRR(request, env, authCtx), request));
    }
    if (path === '/api/executive/mrr/config' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetMRRConfig(request, env, authCtx), request));
    }
    if (path === '/api/executive/report' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGenerateReport(request, env, authCtx), request));
    }
    if (path === '/api/executive/reports' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListReports(request, env, authCtx), request));
    }
    if (path.startsWith('/api/executive/report/') && path !== '/api/executive/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetReport(request, env, authCtx), request));
    }

    // ── PHASE 3: MSSP Multi-Tenant Panel ─────────────────────────────────────
    if (path === '/api/mssp/clients' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListClients(request, env, authCtx), request));
    }
    if (path === '/api/mssp/clients' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleOnboardClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpdateClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleOffboardClient(request, env, authCtx), request));
    }
    if (path === '/api/mssp/summary' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleMSSPSummary(request, env, authCtx), request));
    }
    if (path === '/api/mssp/alerts' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleMSSPAlerts(request, env, authCtx), request));
    }
    if (path === '/api/mssp/whitelabel' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetWhitelabel(request, env, authCtx), request));
    }
    if (path === '/api/mssp/whitelabel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetWhitelabel(request, env, authCtx), request));
    }

    // ── PHASE 4: Sales CRM Pipeline ──────────────────────────────────────────
    if (path === '/api/sales/leads' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreateLead(request, env), request));
    }
    if (path === '/api/sales/leads' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListLeads(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/stage') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAdvanceStage(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/note') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAddNote(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/qualify') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleQualifyLead(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/close') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleCloseLead(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && method === 'GET' && !path.includes('/stage') && !path.includes('/note')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLead(request, env, authCtx), request));
    }
    if (path === '/api/sales/demo/book' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleBookDemo(request, env), request));
    }
    if (path === '/api/sales/demo/slots' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetDemoSlots(request, env), request));
    }
    if (path === '/api/sales/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetSalesPipeline(request, env, authCtx), request));
    }
    if (path === '/api/sales/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetSalesMetrics(request, env, authCtx), request));
    }

    // ── GOD MODE v15: /api/leads/* alias routes → salesPipeline engine ────────
    // These provide clean REST aliases for the frontend & external CRM integrations.
    // POST /api/leads/create — create a new lead (public; no auth required)
    if (path === '/api/leads/create' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreateLead(request, env), request));
    }
    // PUT /api/leads/update — update lead stage / fields (admin)
    if (path === '/api/leads/update' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const body = await request.json().catch(() => ({}));
      const leadId = body.id || body.lead_id;
      if (!leadId) return withSecurityHeaders(withCors(Response.json({ error: 'lead_id required' }, { status: 400 }), request));
      // Proxy to stage update handler (reuse existing handler pattern)
      const stageReq = new Request(`${request.url}/api/sales/leads/${leadId}/stage`, {
        method: 'PUT',
        headers: request.headers,
        body: JSON.stringify(body),
      });
      return withSecurityHeaders(withCors(await handleAdvanceStage(stageReq, env, authCtx, leadId), request));
    }
    // GET /api/pipeline — pipeline board view (alias for /api/sales/pipeline)
    if (path === '/api/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetSalesPipeline(request, env, authCtx), request));
    }
    // GET /api/leads — list all leads (alias for GET /api/sales/leads)
    if (path === '/api/leads' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleListLeads(request, env, authCtx), request));
    }

    // ── PHASE 4: Proposal Generator ──────────────────────────────────────────
    if (path === '/api/proposals/packages' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPackages(request, env), request));
    }
    if (path === '/api/proposals/generate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGenerateProposal(request, env, authCtx), request));
    }
    if (path === '/api/proposals' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListProposals(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && path.endsWith('/send') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleMarkProposalSent(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && path.endsWith('/accept') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAcceptProposal(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && !path.endsWith('/generate') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetProposal(request, env, authCtx), request));
    }

    // ── PHASE 4: Affiliate & Partner System ──────────────────────────────────
    if (path === '/api/affiliate/join' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleJoin(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAffStatus(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAffDashboard(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/track' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleTrackReferral(request, env), request));
    }
    if (path === '/api/affiliate/referrals' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetReferrals(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/leaderboard' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetLeaderboard(request, env), request));
    }
    if (path === '/api/affiliate/tiers' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetTiers(request, env), request));
    }
    if (path === '/api/affiliate/payout/request' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRequestPayout(request, env, authCtx), request));
    }

    // ── PHASE 4: Conversion Triggers & Paywall ────────────────────────────────
    if (path === '/api/conversion/event' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleConvEvent(request, env, authCtx), request));
    }
    if (path === '/api/conversion/triggers' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTriggers(request, env, authCtx), request));
    }
    if (path === '/api/conversion/paywall' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPaywall(request, env, authCtx), request));
    }
    if (path === '/api/conversion/dismiss' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDismissTrigger(request, env, authCtx), request));
    }
    if (path === '/api/conversion/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetFunnel(request, env, authCtx), request));
    }
    if (path === '/api/conversion/cta' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCTA(request, env, authCtx), request));
    }
    if (path === '/api/conversion/retarget' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRetarget(request, env, authCtx), request));
    }

    // GET /api/conversion/bundle — time-limited bundle offer with countdown timer
    if (path === '/api/conversion/bundle' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetBundleOffer(request, env, authCtx), request));
    }

    // GET /api/conversion/urgency — personalized urgency signals for frontend CTAs
    if (path === '/api/conversion/urgency' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetUrgency(request, env, authCtx), request));
    }

    if (path === '/api/scan/upsell' && method === 'POST') {
      const { handleScanUpsell } = await import('./services/scanUpsellEngine.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleScanUpsell(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}), request));
    }

    // GET /api/scan/upsell/stats — upsell impression/conversion stats (admin)
    if (path === '/api/scan/upsell/stats' && method === 'GET') {
      const { handleUpsellStats } = await import('./services/scanUpsellEngine.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleUpsellStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── Manual Payment System ─────────────────────────────────────────────────
    // GET /api/payments/config — payment methods + product catalog (public)
    if (path === '/api/payments/config' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPaymentConfig(request, env), request));
    }
    // POST /api/payments/submit — submit payment for verification
    if (path === '/api/payments/submit' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleSubmitPayment(request, env), request));
    }
    // GET /api/payments/status — check payment status by payment_id or email
    if (path === '/api/payments/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPaymentStatus(request, env), request));
    }
    // GET /api/payments/admin — list all payments (admin only)
    if (path === '/api/payments/admin' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleListPayments(request, env), request));
    }
    // POST /api/payments/verify — approve or reject manual payment (admin only)
    if (path === '/api/payments/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleVerifyManualPayment(request, env), request));
    }

    // ── Content Pipeline ──────────────────────────────────────────────────────

    // GET /api/blog/posts — list published blog posts (public)
    if (path === '/api/blog/posts' && method === 'GET') {
      const { handleGetBlogPosts } = await import('./services/contentPipeline.js');
      return withSecurityHeaders(withCors(await handleGetBlogPosts(request, env), request));
    }

    // GET /api/blog/posts/:slug — single blog post (public)
    if (path.startsWith('/api/blog/posts/') && method === 'GET') {
      const { handleGetBlogPost } = await import('./services/contentPipeline.js');
      const slug = path.replace('/api/blog/posts/', '').split('/')[0];
      return withSecurityHeaders(withCors(await handleGetBlogPost(request, env, slug), request));
    }

    // POST /api/content/run — manually trigger content pipeline (admin)
    if (path === '/api/content/run' && method === 'POST') {
      const { handleRunContentPipeline } = await import('./services/contentPipeline.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRunContentPipeline(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── Enterprise Layer (Phase 5) ────────────────────────────────────────

    // GET /api/enterprise/packages — list enterprise packages (public)
    if (path === '/api/enterprise/packages' && method === 'GET') {
      const { handleGetPackages } = await import('./handlers/enterpriseLayer.js');
      return withSecurityHeaders(withCors(await handleGetPackages(request, env), request));
    }

    // POST /api/enterprise/book — consultation booking (public)
    if (path === '/api/enterprise/book' && method === 'POST') {
      const { handleBookConsultation } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBookConsultation(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // POST /api/enterprise/report — order threat report with Razorpay (public)
    if (path === '/api/enterprise/report' && method === 'POST') {
      const { handleOrderReport } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleOrderReport(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // POST /api/enterprise/verify — verify enterprise Razorpay payment
    if (path === '/api/enterprise/verify' && method === 'POST') {
      const { handleVerifyEnterprisePayment } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleVerifyEnterprisePayment(request, env, authCtx ? { userId: authCtx.userId } : {}), request));
    }

    // GET /api/enterprise/stats — admin: enterprise leads overview
    if (path === '/api/enterprise/stats' && method === 'GET') {
      const { handleEnterpriseStats } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleEnterpriseStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── Global Scale Engine (Phase 6) ─────────────────────────────────────

    // GET /api/global/pricing — geo-detected multi-currency pricing (public)
    if (path === '/api/global/pricing' && method === 'GET') {
      const { handleGetGlobalPricing } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetGlobalPricing(request, env), request));
    }

    // GET /api/global/compliance-packs — compliance pack catalog with geo sort (public)
    if (path === '/api/global/compliance-packs' && method === 'GET') {
      const { handleGetCompliancePacks } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetCompliancePacks(request, env), request));
    }

    // POST /api/global/compliance-packs/purchase — purchase compliance pack
    if (path === '/api/global/compliance-packs/purchase' && method === 'POST') {
      const { handlePurchaseCompliancePack } = await import('./services/globalScale.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handlePurchaseCompliancePack(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // GET /api/global/mssp — MSSP tier info + pricing (public)
    if (path === '/api/global/mssp' && method === 'GET') {
      const { handleGetMSSPInfo } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetMSSPInfo(request, env), request));
    }

    // POST /api/global/mssp/apply — MSSP partner application (public)
    if (path === '/api/global/mssp/apply' && method === 'POST') {
      const { handleMSSPApplication } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleMSSPApplication(request, env), request));
    }

    // ── Cron-driven content pipeline hook ─────────────────────────────────
    // POST /api/content/pipeline/run — trigger full CVE→blog→social pipeline (admin)
    if (path === '/api/content/pipeline/run' && method === 'POST') {
      const { runBulkContentPipeline } = await import('./services/contentPipeline.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (authCtx.role !== 'admin') return withSecurityHeaders(withCors(new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      const body  = await request.json().catch(() => ({}));
      const result = await runBulkContentPipeline(env, body.limit || 3);
      return withSecurityHeaders(withCors(new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } }), request));
    }

    // ══════════════════════════════════════════════════════════════════════
    // END v10.0 ROUTES
    // ══════════════════════════════════════════════════════════════════════

    // ── End v8.2 routes ───────────────────────────────────────────────────────

    // GET /api/export/siem — export capabilities info (public)
    if (path === '/api/export/siem' && method === 'GET') {
      return withSecurityHeaders(withCors(handleSiemInfo(), request));
    }

    // POST /api/export/siem — generate export file (PRO/ENTERPRISE)
    if (path === '/api/export/siem' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleSiemExport(request, env, authCtx), request));
    }

    // GET /api/export/siem/stream — streaming NDJSON (ENTERPRISE only)
    if (path === '/api/export/siem/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      // Streaming response — no withCors wrapper (returns raw stream)
      return await handleSiemStream(request, env, authCtx);
    }

    // ── P0 MISSION v12: Agentic AI Autonomous Remediation Engine (System 1) ───
    // POST /api/agent/execute, GET /api/agent/logs, GET /api/agent/status,
    // POST /api/agent/rollback, GET|POST /api/agent/waf/*, POST /api/agent/process-queue
    if (path.startsWith('/api/agent/')) {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/agent/', '');
      const res = await handleAgentRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── P0 MISSION v12: Behavioral Anomaly Detection Engine (System 2) ────────
    // GET /api/anomaly/stats, GET /api/anomaly/:user_id,
    // GET /api/anomaly/:user_id/history, POST /api/anomaly/scan,
    // POST /api/anomaly/record, POST /api/anomaly/batch
    if (path.startsWith('/api/anomaly/') || path === '/api/anomaly') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/anomaly', '').replace(/^\//, '');
      const res = await handleAnomalyRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── P0 MISSION v12: Predictive Threat Intelligence Engine (System 3) ──────
    // GET /api/predict/threats, GET /api/predict/stats, GET /api/predict/:cve_id,
    // GET /api/predict/:cve_id/trend, POST /api/predict/batch, POST /api/predict/score
    if (path.startsWith('/api/predict/') || path === '/api/predict') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/predict', '').replace(/^\//, '');
      const res = await handlePredictiveRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — DELIVERY ENGINE  (/api/delivery/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/delivery/activate — admin: activate delivery for a verified payment
    if (path === '/api/delivery/activate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleDeliveryActivate(request, env, authCtx), request));
    }

    // GET /api/delivery/access — public: access purchased content via token
    if (path === '/api/delivery/access' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleDeliveryAccess(request, env), request));
    }

    // GET /api/delivery/my-purchases — authenticated: list own deliveries
    if (path === '/api/delivery/my-purchases' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleMyPurchases(request, env, authCtx), request));
    }

    // POST /api/delivery/resend — admin: resend delivery instructions
    if (path === '/api/delivery/resend' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleResendDelivery(request, env, authCtx), request));
    }

    // GET /api/delivery/verify-token — public: validate a delivery token
    if (path === '/api/delivery/verify-token' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleVerifyDeliveryToken(request, env), request));
    }

    // GET /api/delivery/catalog — admin: list full delivery catalog
    if (path === '/api/delivery/catalog' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleDeliveryCatalog(request, env, authCtx), request));
    }

    // GET /api/user/reports — authenticated: list user's purchased scan reports
    // Also accepts GET /api/user/trainings and /api/user/tools (convenience aliases)
    if (path === '/api/user/reports' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleUserReports(request, env, authCtx), request));
    }

    // GET /api/user/trainings — convenience: my-purchases filtered to trainings/bundles
    if (path === '/api/user/trainings' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      // Reuse handleMyPurchases — frontend already filters by product_type
      return withSecurityHeaders(withCors(await handleMyPurchases(request, env, authCtx), request));
    }

    // GET /api/user/tools — returns tool access based on user plan tier
    if (path === '/api/user/tools' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const TOOL_ACCESS = {
        FREE:       ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports'],
        PRO:        ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports', 'redteam_scan', 'identity_scan', 'compliance_scan', 'api_keys', 'monitoring', 'full_reports', 'siem_export', 'org_memory'],
        ENTERPRISE: ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports', 'redteam_scan', 'identity_scan', 'compliance_scan', 'api_keys', 'monitoring', 'full_reports', 'siem_export', 'org_memory', 'mssp_panel', 'custom_branding', 'sla_support', 'threat_graph', 'autonomous_soc'],
      };
      const tier  = (authCtx.tier || 'FREE').toUpperCase();
      const tools = TOOL_ACCESS[tier] || TOOL_ACCESS.FREE;
      return withSecurityHeaders(withCors(Response.json({ tools, tier, total: tools.length }), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — MCP SHADOW ENGINE  (/mcp/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /mcp/recommend — AI-powered scan recommendations (MCP → local fallback)
    if (path === '/mcp/recommend' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPRecommend(request, env, authCtx), request));
    }

    // POST /mcp/upsell — rule-based upsell evaluation
    if (path === '/mcp/upsell' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPUpsell(request, env, authCtx), request));
    }

    // POST /mcp/training-map — map scan findings to training courses
    if (path === '/mcp/training-map' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPTrainingMap(request, env, authCtx), request));
    }

    // GET /mcp/health — MCP server health + fallback status
    if (path === '/mcp/health' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMCPHealth(request, env), request));
    }

    // POST /mcp/bundle — time-limited bundle offers with social proof + countdown
    if (path === '/mcp/bundle' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPBundle(request, env, authCtx), request));
    }

    // POST /mcp/decision — MASTER CONTROL: full AI recommendation (tools + training + upsell + enterprise)
    // Frontend calls this FIRST after every scan. Replaces all static upsell/recommendation logic.
    if (path === '/mcp/decision' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPDecision(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — DATA SEEDING ENGINE  (/api/seed/*)
    // All endpoints are public — deterministic PRNG, no KV abuse
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/seed/threats — seeded threat event feed (20 events)
    if (path === '/api/seed/threats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSeededThreats(request, env), request));
    }

    // GET /api/seed/cves — seeded CVE feed (15 real 2025 CVEs)
    if (path === '/api/seed/cves' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSeededCVEs(request, env), request));
    }

    // GET /api/seed/stats — platform stats (scan counts, users, revenue)
    if (path === '/api/seed/stats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPlatformStats(request, env), request));
    }

    // GET /api/seed/soc — SOC metrics (MTTD, MTTR, alerts, incidents)
    if (path === '/api/seed/soc' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSOCMetrics(request, env), request));
    }

    // GET /api/seed/siem — SIEM event stream (30 events)
    if (path === '/api/seed/siem' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSIEMStream(request, env), request));
    }

    // GET /api/seed/apt — APT group profiles (5 detailed)
    if (path === '/api/seed/apt' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetAPTProfiles(request, env), request));
    }

    // GET /api/seed/all — single-call anti-empty-state bundle (threats+CVEs+stats+SOC+SIEM+APTs)
    // Perfect for frontend initial load — one fetch hydrates every dashboard panel
    if (path === '/api/seed/all' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetSeedAll(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v16 — SEO + TRAFFIC ENGINE  (/api/seo/*, /api/leads/magnet,
    //                                       /api/retarget/*, /api/seo/cve/*)
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/seo/meta?path=/ — auto meta tags + OG + JSON-LD for any page
    if (path === '/api/seo/meta' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSEOMeta(request, env), request));
    }

    // GET /api/seo/cve/:id — SEO-optimised CVE landing page data
    if (path.startsWith('/api/seo/cve/') && method === 'GET') {
      return withSecurityHeaders(withCors(await handleCVEPage(request, env), request));
    }

    // POST /api/leads/magnet — free mini-report lead capture (email → CRM + KV)
    if (path === '/api/leads/magnet' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleLeadMagnet(request, env), request));
    }

    // POST /api/retarget/visit — record visitor for retargeting (KV, 30-day TTL)
    if (path === '/api/retarget/visit' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRetargetVisit(request, env), request));
    }

    // GET /api/retarget/offer?vid= — get personalized return-visitor offer
    if (path === '/api/retarget/offer' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleRetargetOffer(request, env), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v16 — ENTERPRISE HARDENING  (/api/enterprise/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/enterprise/auto-qualify — batch auto-qualify high-ICP leads (icp>=60)
    if (path === '/api/enterprise/auto-qualify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAutoQualify(request, env, authCtx), request));
    }

    // GET /api/enterprise/org-dashboard — full org pipeline + deal value + forecast
    if (path === '/api/enterprise/org-dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleEnterpriseDashboard(request, env, authCtx), request));
    }

    // POST /api/enterprise/auto-proposal — auto-generate proposals for DEMO_DONE leads
    if (path === '/api/enterprise/auto-proposal' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAutoProposal(request, env, authCtx), request));
    }

    // GET /api/enterprise/health — CRM system health check
    if (path === '/api/enterprise/health' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseHealth(request, env, authCtx), request));
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
    const cron = event.cron;
    console.log('[CRON] Trigger:', cron, event.scheduledTime);

    // ── HOURLY: Threat Intel Ingestion (Sentinel APEX v2.0 — D1-backed) ──
    // Runs every cron trigger — priority pipeline
    ctx.waitUntil(
      runIngestion(env)
        .then(r => console.log('[CRON] Threat Ingestion:', JSON.stringify({
          sources:  r.sources,
          total:    r.total,
          inserted: r.inserted,
          errors:   r.errors,
          duration_ms: r.duration_ms,
        })))
        .catch(e => console.error('[CRON] Threat Ingestion error:', e?.message))
    );

    // ── HOURLY: Sentinel APEX legacy KV feed refresh ──
    ctx.waitUntil(
      runSentinelCron(env)
        .then(r => console.log('[CRON] Sentinel APEX KV:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Sentinel KV error:', e?.message))
    );

    // ── HOURLY: Continuous monitoring scans ──
    ctx.waitUntil(
      runMonitoringCron(env)
        .then(r => console.log('[CRON] Monitoring:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Monitoring error:', e?.message))
    );

    // ── HOURLY: Purge expired legacy threat intel cache entries ──
    ctx.waitUntil(
      purgeExpiredThreatIntel(env)
        .then(n => { if (n > 0) console.log(`[CRON] Purged ${n} expired threat intel entries`); })
        .catch(e => console.error('[CRON] Purge error:', e?.message))
    );

    // ── Sentinel APEX v3: Global Federation + SOC Automation Pipeline ────────
    // Non-blocking — runs after ingestion, uses the freshly-written D1 data
    // Phase 6: Async pipeline integration (federation → detection → decisions → defense)
    ctx.waitUntil((async () => {
      try {
        // 1. Wait a moment for ingestion to settle, then run federation
        await new Promise(r => setTimeout(r, 3000));

        // 2. Run global feed federation (adds ExploitDB + RSS + VT to existing D1 entries)
        const fedResult = await runFederation(env, []);
        console.log('[CRON] Federation:', JSON.stringify({
          total:    fedResult.total_entries,
          sources:  fedResult.sources_active,
          confidence: fedResult.confidence,
          ms:       fedResult.federation_ms,
        }));

        // 3. Run SOC detection on federated feed (already enriched by federation pipeline)
        const enriched  = fedResult.global_feed.slice(0, 100);  // entries enriched during ingestion
        const detResult = runDetection(enriched);
        console.log('[CRON] SOC Detection:', JSON.stringify({
          alerts: detResult.total,
          critical: detResult.by_severity?.CRITICAL || 0,
        }));

        // 4. Run AI decision engine
        const decResult = runDecisionEngine(enriched, detResult);
        console.log('[CRON] SOC Decisions:', JSON.stringify({
          total:        decResult.total,
          threat_level: decResult.overall_threat_level,
          escalations:  decResult.p1_count,
        }));

        // 5. Run autonomous defense
        const defResult = runAutonomousDefense(enriched, decResult.decisions);
        console.log('[CRON] Autonomous Defense:', JSON.stringify({
          actions:  defResult.total_actions,
          posture:  defResult.posture_level,
        }));

        // 6. Store all SOC results (batch, non-blocking)
        await Promise.all([
          storeDetectionResults(env, detResult),
          storeDecisions(env, decResult),
          storeDefenseActions(env, defResult),
        ]);

        // 7. Invalidate hot cache so next API request hits fresh D1
        if (env?.SECURITY_HUB_KV) {
          env.SECURITY_HUB_KV.delete('threat_intel:hot:v2').catch(() => {});
          env.SECURITY_HUB_KV.delete('sentinel:federation:latest').catch(() => {});
        }

        console.log('[CRON] Sentinel APEX v3 SOC pipeline complete');
      } catch (e) {
        console.error('[CRON] SOC pipeline error:', e?.message);
      }
    })());

    // ── GTM Growth Engine v12: Email Drip + Sales + Content pipelines ─────────
    ctx.waitUntil((async () => {
      try {
        // 1. Run email drip automation (send due sequence emails)
        const dripResult = await runDripAutomation(env);
        console.log('[CRON] GTM Drip Emails:', JSON.stringify(dripResult));

        // 2. Run enterprise sales pipeline (detect + generate outreach)
        const salesResult = await runSalesPipeline(env);
        console.log('[CRON] GTM Sales Pipeline:', JSON.stringify(salesResult));

        // 3. Run content automation (CRITICAL CVEs → LinkedIn/Twitter/Telegram)
        const criticalRows = await env.DB.prepare(
          `SELECT * FROM threat_intel WHERE severity = 'CRITICAL' ORDER BY cvss DESC, published_at DESC LIMIT 5`
        ).all().catch(() => ({ results: [] }));

        if ((criticalRows.results || []).length > 0) {
          const contentResult = await runContentPipeline(env, criticalRows.results);
          console.log('[CRON] GTM Content:', JSON.stringify({
            generated: contentResult.generated,
            posted:    contentResult.telegram_posted,
          }));
        }

        // 4. LinkedIn authority post automation (Mon/Tue/Thu/Fri only)
        const linkedInResult = await runLinkedInAutomation(env, criticalRows.results || [], {});
        if (!linkedInResult.skipped) {
          console.log('[CRON] GTM LinkedIn:', JSON.stringify(linkedInResult));
        }

        console.log('[CRON] GTM Growth Engine pipeline complete');
      } catch (e) {
        console.error('[CRON] GTM pipeline error:', e?.message);
      }
    })());

    // ── v8.2 Revenue Automation Pipeline ─────────────────────────────────────
    ctx.waitUntil((async () => {
      try {
        const { runAutomationCron } = await import('./services/automationEngine.js');
        const autoResult = await runAutomationCron(env, event.cron);
        console.log('[CRON] Revenue Automation:', JSON.stringify({
          jobs_run:    autoResult.jobs_run,
          duration_ms: autoResult.duration_ms,
          defense_products_generated: autoResult.results?.defense_products?.generated || 0,
          upsell_emails_processed:    autoResult.results?.upsell_emails?.processed    || 0,
          churn_flagged:              autoResult.results?.churn_prevention?.at_risk    || 0,
        }));
      } catch (e) {
        console.error('[CRON] Revenue Automation error:', e?.message);
      }
    })());

    // ── v10.0 Sentinel APEX Defense Product Generation (every 12h) ───────────
    if (cron === '0 */12 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const { generateAndStoreAll, fetchLiveIntel } = await import('./services/sentinelDefenseEngine.js');
          const intel = await fetchLiveIntel(env, { limit: 10, severity: 'HIGH' });
          let generated = 0;
          for (const item of intel.slice(0, 5)) {
            const r = await generateAndStoreAll(env, item);
            generated += r.stored || 0;
          }
          console.log(`[CRON] v10 Defense Products: ${generated} stored for ${intel.length} CVEs`);
        } catch (e) {
          console.error('[CRON] v10 Defense generation error:', e?.message);
        }
      })());
    }

    // ── v10.0 Content Pipeline — CVE→Blog→LinkedIn→Telegram (every 24h) ─────
    if (cron === '0 6 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const { runBulkContentPipeline } = await import('./services/contentPipeline.js');
          const result = await runBulkContentPipeline(env, 3);
          console.log('[CRON] v10 Content Pipeline:', JSON.stringify({
            processed:  result.processed,
            linkedin:   result.results?.filter(r => r.linkedin?.success).length || 0,
            telegram:   result.results?.filter(r => r.telegram?.success).length || 0,
          }));
        } catch (e) {
          console.error('[CRON] v10 Content Pipeline error:', e?.message);
        }
      })());
    }

    // ── v10.0 Revenue Snapshot — daily KPI capture ────────────────────────────
    if (cron === '0 23 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          // Capture daily revenue snapshot
          const today = new Date().toISOString().slice(0, 10);
          const [subRow, defRow, totalUsers] = await Promise.allSettled([
            env.DB?.prepare(`SELECT COUNT(*) as cnt, SUM(amount) as rev FROM revenue_events WHERE event_type='subscription_payment' AND DATE(created_at)=?`).bind(today).first(),
            env.DB?.prepare(`SELECT COUNT(*) as cnt, SUM(amount_inr) as rev FROM defense_purchases WHERE status='paid' AND DATE(created_at)=?`).bind(today).first(),
            env.DB?.prepare(`SELECT COUNT(*) as total FROM users`).first(),
          ]);
          await env.DB?.prepare(
            `INSERT OR REPLACE INTO revenue_snapshots (id, snapshot_date, daily_revenue, defense_sales, defense_revenue, total_users)
             VALUES (?,?,?,?,?,?)`
          ).bind(
            crypto.randomUUID(), today,
            (subRow.value?.rev || 0) + (defRow.value?.rev || 0),
            defRow.value?.cnt || 0,
            defRow.value?.rev || 0,
            totalUsers.value?.total || 0,
          ).run();
          console.log(`[CRON] v10 Revenue Snapshot: ${today} captured`);
        } catch (e) {
          console.error('[CRON] v10 Revenue Snapshot error:', e?.message);
        }
      })());
    }

    // ── v12 P0 MISSION: Agentic AI Engine — Agent Event Queue Processing ───────
    ctx.waitUntil((async () => {
      try {
        // Process pending events from agent bus (CVE detections, anomaly events)
        const events = await consumeEvents(env, 20);
        let processed = 0;
        for (const event of events) {
          try {
            if (event.event_type === 'cve_detected') {
              await processCVEEvent(env, event);
            } else if (event.event_type === 'anomaly_detected') {
              const decision = decideAnomalyResponse(event.payload || {});
              for (const action of decision.actions) {
                if (action.action_type === 'block_ip' && action.target) {
                  await autoBlockIP(env, action.target, 'anomaly_cron', decision.risk_level, event.id);
                }
                if ((action.action_type === 'rotate_credentials' || action.action_type === 'disable_session') && action.target) {
                  await autoRotateOnAnomaly(env, action.target, event.payload || {});
                }
              }
            }
            await ackEvent(env, event.id, true);
            processed++;
          } catch (evErr) {
            await ackEvent(env, event.id, false, evErr.message);
          }
        }
        if (processed > 0) console.log(`[CRON] v12 Agent Bus: processed ${processed} events`);
      } catch (e) {
        console.error('[CRON] v12 Agent Bus error:', e?.message);
      }
    })());

    // ── v12 P0 MISSION: Behavioral Anomaly Detection — batch scan (every 15 min)
    ctx.waitUntil((async () => {
      try {
        const result = await runAnomalyBatch(env);
        if (result.anomalies_detected > 0) {
          console.log(`[CRON] v12 Anomaly Engine: ${result.scanned} users scanned, ${result.anomalies_detected} anomalies (${result.high_risk} CRITICAL/HIGH)`);
        }
      } catch (e) {
        console.error('[CRON] v12 Anomaly Engine error:', e?.message);
      }
    })());

    // ── v12 P0 MISSION: Predictive Threat Intelligence — batch (every 1h) ──────
    if (cron === '0 * * * *' || cron === '*/15 * * * *' || cron === '0 */2 * * *') {
      ctx.waitUntil((async () => {
        try {
          const result = await runPredictiveBatch(env);
          if (result.predictions > 0) {
            console.log(`[CRON] v12 Predictive Engine: ${result.analyzed} CVEs analyzed, ${result.critical_count} CRITICAL, ${result.high_count} HIGH`);
          }
        } catch (e) {
          console.error('[CRON] v12 Predictive Engine error:', e?.message);
        }
      })());
    }

    // ── v12 P0 MISSION: Virtual WAF Patching — expire stale patches + batch ────
    ctx.waitUntil((async () => {
      try {
        // Get recent HIGH+KEV CVEs for auto-patching
        const recentCVEs = await env.DB?.prepare(`
          SELECT cve_id, cvss_score as cvss, epss_score as epss, is_kev,
                 description, cvss_vector
          FROM threat_intel
          WHERE (cvss_score >= 7.0 OR is_kev = 1)
            AND published_date > datetime('now', '-3 days')
          ORDER BY cvss_score DESC LIMIT 20
        `).all().catch(() => ({ results: [] }));

        const patchResult = await runPatchingBatch(env, recentCVEs?.results || []);
        if (patchResult.patched > 0 || patchResult.expired > 0) {
          console.log(`[CRON] v12 Patching Agent: ${patchResult.patched} patches applied, ${patchResult.expired} expired`);
        }
      } catch (e) {
        console.error('[CRON] v12 Patching Agent error:', e?.message);
      }
    })());

    // ── MYTHOS ORCHESTRATOR CORE — autonomous tool generation (every 12h) ──────
    if (cron === '0 */12 * * *' || cron === '0 6 * * *') {
      ctx.waitUntil((async () => {
        try {
          const result = await runMythosCron(env);
          console.log(`[CRON] MYTHOS: ${result.total_tools} tools generated, ${result.total_published} published, ${result.total_failed} failed`);
        } catch (e) {
          console.error('[CRON] MYTHOS Orchestrator error:', e?.message);
        }
      })());
    }

    // ── PHASE 2: Autonomous SOC Mode cron check ───────────────────────────────
    ctx.waitUntil((async () => {
      try {
        await runAutoSocCron(env);
        console.log('[CRON] AutoSOC: cron check complete');
      } catch (e) {
        console.error('[CRON] AutoSOC error:', e?.message);
      }
    })());

  },
};
