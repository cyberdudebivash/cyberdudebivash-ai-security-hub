/**
 * CYBERDUDEBIVASH AI Security Hub — P15.0 Commercial Platform & Enterprise Customer Success
 *
 * Endpoints:
 *   GET   /api/customer/onboarding/wizard    — P15.1 first-login wizard state
 *   GET   /api/customer/license              — P15.2 subscription & license center
 *   GET   /api/customer/usage/analytics      — P15.3 usage analytics (API/scans/reports/AI)
 *   GET   /api/customer/success/score        — P15.4 adoption + health + renewal readiness
 *   PATCH /api/keys/:id                      — P15.6 update key metadata (label/expiry/scopes)
 *   GET   /api/keys/:id/history              — P15.6 key rotation history
 *   GET   /api/customer/reports/archive      — P15.7 enterprise report archive
 *   GET   /api/customer/notifications/center — P15.8 notification center (priority/channel filter)
 *   GET   /api/commercial/observability      — P15.9 commercial observability (OWNER/ADMIN)
 *
 * Reuses (NEVER duplicates):
 *   middleware/entitlementCheck.js — FEATURES constant
 *   D1 tables (existing)           — users, api_keys, api_key_usage, ops_usage_events,
 *                                    ops_notifications, customer_profiles, customer_assets,
 *                                    scheduled_reports, scan_jobs, customer_entitlements
 *   KV namespace: SECURITY_HUB_KV (prefix: customer:v1:*, commercial:v1:*, key:meta:*, key:history:*)
 *
 * Performance:
 *   TTL: 300s (license, success), 120s (wizard, usage, reports), live (notifications, observability)
 *   Target: <50ms cache hit  <400ms uncached
 *
 * Security:
 *   P15.9: OWNER/ADMIN only
 *   P15.6: key owner or OWNER/ADMIN
 *   All others: authenticated, data scoped to user_id
 */

import { FEATURES } from '../middleware/entitlementCheck.js';

// ─── Tier gates ───────────────────────────────────────────────────────────────
const ADMIN_TIERS = new Set(['OWNER', 'ADMIN']);

function checkAuth(authCtx) {
  if (!authCtx?.authenticated) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-COMMERCIAL' },
      { status: 401 }
    );
  }
  return null;
}

function checkAdminTier(authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;
  if (!ADMIN_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'Administrative access required', service: 'CDB-COMMERCIAL' },
      { status: 403 }
    );
  }
  return null;
}

// ─── KV helpers ───────────────────────────────────────────────────────────────
async function kvGet(env, key) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function kvSet(env, key, value, ttl = 300) {
  if (!env?.SECURITY_HUB_KV) return;
  try { await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); }
  catch {}
}

// ─── Static lookup tables ─────────────────────────────────────────────────────
const PLAN_NAMES = {
  FREE: 'Freemium', STARTER: 'Starter', PRO: 'Pro',
  ENTERPRISE: 'Enterprise', MSSP: 'MSSP Partner',
  OWNER: 'Platform Owner', ADMIN: 'Administrator',
};
const PLAN_PRICES = { FREE: 0, STARTER: 499, PRO: 1499, ENTERPRISE: 4999, MSSP: 0 };

const TIER_QUOTAS = {
  FREE:       { scans: 50,  api_keys: 2,  seats: 1,  api_calls_day: 5,   storage_gb: 0.1 },
  STARTER:    { scans: 10,  api_keys: 2,  seats: 1,  api_calls_day: 20,  storage_gb: 1   },
  PRO:        { scans: -1,  api_keys: 5,  seats: 5,  api_calls_day: 500, storage_gb: 10  },
  ENTERPRISE: { scans: -1,  api_keys: 20, seats: 10, api_calls_day: -1,  storage_gb: 100 },
  MSSP:       { scans: -1,  api_keys: 50, seats: 50, api_calls_day: -1,  storage_gb: 500 },
  OWNER:      { scans: -1,  api_keys: -1, seats: -1, api_calls_day: -1,  storage_gb: -1  },
  ADMIN:      { scans: -1,  api_keys: -1, seats: -1, api_calls_day: -1,  storage_gb: -1  },
};

const TIER_IMPLICIT_FEATURES = {
  FREE:       ['api_access'],
  STARTER:    ['api_access', 'threat_feed_full', 'dashboard_pro'],
  PRO:        ['api_access', 'threat_feed_full', 'dashboard_pro', 'ai_predictions',
                'actor_attribution', 'report_download', 'pdf_reports', 'stix_21_export'],
  ENTERPRISE: Object.values(FEATURES),
  MSSP:       Object.values(FEATURES),
  OWNER:      Object.values(FEATURES),
  ADMIN:      Object.values(FEATURES),
};

const VALID_SCOPES = ['read:intel', 'write:events', 'read:reports', 'write:scans', 'read:analytics', 'admin:keys'];

function safeParseJSON(str, fallback = []) {
  if (!str) return fallback;
  if (typeof str !== 'string') return Array.isArray(str) ? str : fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}

function resolveUserId(authCtx) {
  return authCtx.userId || authCtx.user_id || 'anon';
}

// ─── P15.1: Enterprise Onboarding Wizard ─────────────────────────────────────
export async function handleOnboardingWizard(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const cacheKey = `customer:v1:wizard:${userId}`;
  const t0       = Date.now();

  const cached = await kvGet(env, cacheKey);
  if (cached) return Response.json({ ...cached, _cache: 'hit', _ms: Date.now() - t0 });

  const db = env.DB;

  const [profileRow, keyRows, assetRows, scanRow] = await Promise.all([
    db ? db.prepare(
      `SELECT id FROM customer_profiles WHERE id = ? LIMIT 1`
    ).bind(userId).first().catch(() => null) : Promise.resolve(null),
    db ? db.prepare(
      `SELECT id FROM api_keys WHERE user_id = ? LIMIT 5`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT id FROM customer_assets WHERE owner_id = ? LIMIT 1`
    ).bind(userId).first().catch(() => null) : Promise.resolve(null),
    db ? db.prepare(
      `SELECT id FROM scan_jobs WHERE user_id = ? LIMIT 1`
    ).bind(userId).first().catch(() => null) : Promise.resolve(null),
  ]);

  const steps = [
    { id: 'profile',       title: 'Organization Profile',  completed: !!profileRow,        description: 'Set your company and industry details' },
    { id: 'api_key',       title: 'API Key Created',       completed: keyRows.length > 0,  description: 'Generate your first API key to integrate' },
    { id: 'first_scan',    title: 'First Security Scan',   completed: !!scanRow,           description: 'Run a domain or asset scan to baseline posture' },
    { id: 'assets',        title: 'Asset Inventory',       completed: !!assetRows,         description: 'Register your critical business assets' },
    { id: 'notifications', title: 'Alert Preferences',     completed: false,               description: 'Configure notification channels (email/webhook)' },
  ];

  const completedCount = steps.filter(s => s.completed).length;
  const completionPct  = Math.round((completedCount / steps.length) * 100);
  const nextStep       = steps.find(s => !s.completed) || null;

  const payload = {
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    onboarding: {
      completion_pct:  completionPct,
      completed_steps: completedCount,
      total_steps:     steps.length,
      status:          completionPct === 100 ? 'COMPLETE' : completionPct >= 60 ? 'IN_PROGRESS' : 'STARTED',
      steps,
      next_step:       nextStep,
      tier:            (authCtx.tier || 'FREE').toUpperCase(),
    },
    _cache: 'miss',
    _ms:    Date.now() - t0,
  };

  await kvSet(env, cacheKey, payload, 120);
  return Response.json(payload);
}

// ─── P15.2: Subscription & License Center ────────────────────────────────────
export async function handleCustomerLicense(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const tier     = (authCtx.tier || 'FREE').toUpperCase();
  const cacheKey = `customer:v1:license:${userId}`;
  const t0       = Date.now();

  const cached = await kvGet(env, cacheKey);
  if (cached) return Response.json({ ...cached, _cache: 'hit', _ms: Date.now() - t0 });

  const db = env.DB;

  const trialRaw = await kvGet(env, `billing:trial:${userId}`);

  const [keyRows, entitlementRows] = await Promise.all([
    db ? db.prepare(
      `SELECT id, tier, created_at FROM api_keys WHERE user_id = ?`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT feature, granted, expires_at FROM customer_entitlements WHERE user_id = ? AND granted = 1`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
  ]);

  const quota       = TIER_QUOTAS[tier] || TIER_QUOTAS.FREE;
  const implicitFt  = TIER_IMPLICIT_FEATURES[tier] || ['api_access'];
  const explicitFt  = entitlementRows.map(e => e.feature);
  const features    = [...new Set([...implicitFt, ...explicitFt])];
  const activeKeys  = keyRows.filter(k => k.tier !== 'REVOKED');

  const payload = {
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    license: {
      tier,
      status:       'ACTIVE',
      plan_name:    PLAN_NAMES[tier] || tier,
      pricing_inr:  PLAN_PRICES[tier] ?? 0,
      quota,
      features,
      api_keys: {
        active: activeKeys.length,
        max:    quota.api_keys,
        keys:   activeKeys.map(k => ({ id: k.id, created_at: k.created_at })),
      },
      trial: trialRaw ? {
        active:     true,
        tier:       trialRaw.tier || 'PRO',
        expires_at: trialRaw.expires_at || null,
      } : null,
      entitlements: entitlementRows.map(e => ({ feature: e.feature, expires_at: e.expires_at })),
    },
    _cache: 'miss',
    _ms:    Date.now() - t0,
  };

  await kvSet(env, cacheKey, payload, 300);
  return Response.json(payload);
}

// ─── P15.3: Usage Analytics ───────────────────────────────────────────────────
export async function handleUsageAnalytics(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const cacheKey = `customer:v1:usage:${userId}`;
  const t0       = Date.now();

  const cached = await kvGet(env, cacheKey);
  if (cached) return Response.json({ ...cached, _cache: 'hit', _ms: Date.now() - t0 });

  const db = env.DB;

  const [usageByKey, usageByEndpoint, scanStats, reportStats, recentEvents] = await Promise.all([
    db ? db.prepare(
      `SELECT k.id as key_id, SUM(u.request_count) as total_calls
       FROM api_keys k LEFT JOIN api_key_usage u ON k.id = u.key_id
       WHERE k.user_id = ? GROUP BY k.id ORDER BY total_calls DESC LIMIT 10`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT u.endpoint, SUM(u.request_count) as call_count
       FROM api_key_usage u JOIN api_keys k ON u.key_id = k.id
       WHERE k.user_id = ? GROUP BY u.endpoint ORDER BY call_count DESC LIMIT 20`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT status, COUNT(*) as cnt FROM scan_jobs WHERE user_id = ? GROUP BY status`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT COUNT(*) as cnt FROM scheduled_reports WHERE org_id = ?`
    ).bind(userId).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
    db ? db.prepare(
      `SELECT event_type, endpoint, latency_ms, cached, ts FROM ops_usage_events
       WHERE user_id = ? ORDER BY ts DESC LIMIT 20`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
  ]);

  const totalApiCalls = usageByKey.reduce((s, r) => s + (r.total_calls || 0), 0);
  const scanMap       = {};
  scanStats.forEach(r => { scanMap[r.status] = r.cnt; });

  const avgLatencyMs = recentEvents.length
    ? Math.round(recentEvents.reduce((s, e) => s + (e.latency_ms || 0), 0) / recentEvents.length)
    : 0;
  const cacheHitRate = recentEvents.length
    ? Math.round((recentEvents.filter(e => e.cached).length / recentEvents.length) * 100)
    : 0;
  const aiRequests = recentEvents.filter(e => (e.endpoint || '').includes('copilot')).length;

  const payload = {
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    usage: {
      api: {
        total_calls:    totalApiCalls,
        by_key:         usageByKey,
        by_endpoint:    usageByEndpoint.slice(0, 10),
        avg_latency_ms: avgLatencyMs,
        cache_hit_rate: cacheHitRate,
      },
      scans: {
        total:     Object.values(scanMap).reduce((s, v) => s + v, 0),
        by_status: scanMap,
        completed: scanMap['completed'] || scanMap['COMPLETED'] || 0,
        pending:   scanMap['pending']   || scanMap['PENDING']   || 0,
      },
      reports: {
        scheduled: reportStats?.cnt || 0,
      },
      ai_requests:   aiRequests,
      recent_events: recentEvents.slice(0, 10),
    },
    _cache: 'miss',
    _ms:    Date.now() - t0,
  };

  await kvSet(env, cacheKey, payload, 120);
  return Response.json(payload);
}

// ─── P15.4: Customer Success Score ────────────────────────────────────────────
export async function handleCustomerSuccessScore(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const tier     = (authCtx.tier || 'FREE').toUpperCase();
  const cacheKey = `customer:v1:success:${userId}`;
  const t0       = Date.now();

  const cached = await kvGet(env, cacheKey);
  if (cached) return Response.json({ ...cached, _cache: 'hit', _ms: Date.now() - t0 });

  const db = env.DB;

  const [profileRow, keyCount, scanCount, usageCount, reportCount] = await Promise.all([
    db ? db.prepare(`SELECT id FROM customer_profiles WHERE id = ? LIMIT 1`).bind(userId).first().catch(() => null) : Promise.resolve(null),
    db ? db.prepare(`SELECT COUNT(*) as cnt FROM api_keys WHERE user_id = ?`).bind(userId).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
    db ? db.prepare(`SELECT COUNT(*) as cnt FROM scan_jobs WHERE user_id = ? AND status IN ('completed', 'COMPLETED')`).bind(userId).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
    db ? db.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE user_id = ? AND ts > datetime('now', '-30 days')`).bind(userId).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
    db ? db.prepare(`SELECT COUNT(*) as cnt FROM scheduled_reports WHERE org_id = ?`).bind(userId).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
  ]);

  const profileScore  = profileRow ? 20 : 0;
  const keyScore      = Math.min((keyCount?.cnt || 0) * 10, 20);
  const scanScore     = Math.min((scanCount?.cnt || 0) * 5, 20);
  const usageScore    = Math.min(Math.floor((usageCount?.cnt || 0) / 10), 20);
  const reportScore   = Math.min((reportCount?.cnt || 0) * 10, 20);
  const adoptionScore = profileScore + keyScore + scanScore + usageScore + reportScore;

  const tierBonus = { FREE: 0, STARTER: 10, PRO: 20, ENTERPRISE: 30, MSSP: 30, OWNER: 40, ADMIN: 40 }[tier] || 0;
  const healthScore = Math.min(Math.round(adoptionScore * 0.7 + tierBonus), 100);

  const renewalReadiness = healthScore >= 70 ? 'HIGH' : healthScore >= 40 ? 'MEDIUM' : 'LOW';

  const upgradeOpps = [];
  if (tier === 'FREE')    upgradeOpps.push({ to: 'STARTER',    reason: 'Unlock continuous monitoring and threat feeds',              price_inr: 499  });
  if (tier === 'STARTER') upgradeOpps.push({ to: 'PRO',        reason: 'Unlock AI predictions, PDF reports, STIX export',           price_inr: 1499 });
  if (tier === 'PRO')     upgradeOpps.push({ to: 'ENTERPRISE', reason: 'Unlock multi-seat, SLA guarantee, custom integrations',     price_inr: 4999 });

  const recommendations = [];
  if (adoptionScore < 40) recommendations.push('Complete your organization profile to personalize threat intelligence');
  if (!scanCount?.cnt)    recommendations.push('Run your first domain scan to establish a security baseline');
  if (!reportCount?.cnt)  recommendations.push('Schedule automated reports to track security posture over time');

  const payload = {
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    success_metrics: {
      adoption_score:        adoptionScore,
      health_score:          healthScore,
      renewal_readiness:     renewalReadiness,
      tier,
      upgrade_opportunities: upgradeOpps,
      score_breakdown: {
        profile_completed:  profileScore,
        api_keys_active:    keyScore,
        scans_completed:    scanScore,
        recent_activity:    usageScore,
        reports_scheduled:  reportScore,
        tier_bonus:         tierBonus,
      },
      recommendations,
    },
    _cache: 'miss',
    _ms:    Date.now() - t0,
  };

  await kvSet(env, cacheKey, payload, 300);
  return Response.json(payload);
}

// ─── P15.6a: Update API Key Metadata (PATCH /api/keys/:id) ───────────────────
export async function handleKeyUpdateMeta(request, env, authCtx, keyId) {
  if (!authCtx?.authenticated) {
    return Response.json({ success: false, error: 'Authentication required', service: 'CDB-COMMERCIAL' }, { status: 401 });
  }
  if (!keyId || !/^[a-zA-Z0-9_-]{1,64}$/.test(keyId)) {
    return Response.json({ success: false, error: 'Invalid key ID format', service: 'CDB-COMMERCIAL' }, { status: 400 });
  }

  const userId = resolveUserId(authCtx);
  const isAdmin = ADMIN_TIERS.has((authCtx.tier || '').toUpperCase());

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ success: false, error: 'Invalid JSON body', service: 'CDB-COMMERCIAL' }, { status: 400 }); }

  const { label, expires_at, scopes } = body || {};

  if (label !== undefined && (typeof label !== 'string' || label.length > 100)) {
    return Response.json({ success: false, error: 'label must be a string ≤100 chars', service: 'CDB-COMMERCIAL' }, { status: 400 });
  }
  if (expires_at !== undefined && expires_at !== null && isNaN(Date.parse(expires_at))) {
    return Response.json({ success: false, error: 'expires_at must be ISO 8601 date or null', service: 'CDB-COMMERCIAL' }, { status: 400 });
  }
  if (scopes !== undefined && !Array.isArray(scopes)) {
    return Response.json({ success: false, error: 'scopes must be an array', service: 'CDB-COMMERCIAL' }, { status: 400 });
  }
  if (scopes) {
    const bad = scopes.find(s => !VALID_SCOPES.includes(s));
    if (bad) {
      return Response.json({ success: false, error: `Invalid scope: ${bad}`, valid_scopes: VALID_SCOPES, service: 'CDB-COMMERCIAL' }, { status: 400 });
    }
  }

  const db = env.DB;
  if (db) {
    const keyRow = await db.prepare(`SELECT id, user_id FROM api_keys WHERE id = ? LIMIT 1`).bind(keyId).first().catch(() => null);
    if (!keyRow) {
      return Response.json({ success: false, error: 'Key not found', service: 'CDB-COMMERCIAL' }, { status: 404 });
    }
    if (!isAdmin && keyRow.user_id !== userId) {
      return Response.json({ success: false, error: 'Access denied', service: 'CDB-COMMERCIAL' }, { status: 403 });
    }
  }

  const metaKey  = `key:meta:${keyId}`;
  const existing = await kvGet(env, metaKey) || {};
  const updated  = {
    ...existing,
    ...(label      !== undefined ? { label }      : {}),
    ...(expires_at !== undefined ? { expires_at } : {}),
    ...(scopes     !== undefined ? { scopes }     : {}),
    updated_at: new Date().toISOString(),
    updated_by: userId,
  };

  await kvSet(env, metaKey, updated, 86400 * 365);

  const histKey = `key:history:${userId}`;
  const history = await kvGet(env, histKey) || [];
  history.unshift({
    key_id:     keyId,
    action:     'META_UPDATE',
    changes:    { label, expires_at, scopes },
    changed_by: userId,
    changed_at: new Date().toISOString(),
  });
  await kvSet(env, histKey, history.slice(0, 50), 86400 * 90);

  return Response.json({
    success:   true,
    service:   'CDB-COMMERCIAL',
    key_id:    keyId,
    meta:      updated,
    timestamp: new Date().toISOString(),
  });
}

// ─── P15.6b: Key Rotation History (GET /api/keys/:id/history) ─────────────────
export async function handleKeyHistory(request, env, authCtx, keyId) {
  if (!authCtx?.authenticated) {
    return Response.json({ success: false, error: 'Authentication required', service: 'CDB-COMMERCIAL' }, { status: 401 });
  }
  if (!keyId || !/^[a-zA-Z0-9_-]{1,64}$/.test(keyId)) {
    return Response.json({ success: false, error: 'Invalid key ID', service: 'CDB-COMMERCIAL' }, { status: 400 });
  }

  const userId  = resolveUserId(authCtx);
  const isAdmin = ADMIN_TIERS.has((authCtx.tier || '').toUpperCase());
  const db      = env.DB;

  if (db) {
    const keyRow = await db.prepare(`SELECT user_id FROM api_keys WHERE id = ? LIMIT 1`).bind(keyId).first().catch(() => null);
    if (!keyRow) {
      return Response.json({ success: false, error: 'Key not found', service: 'CDB-COMMERCIAL' }, { status: 404 });
    }
    if (!isAdmin && keyRow.user_id !== userId) {
      return Response.json({ success: false, error: 'Access denied', service: 'CDB-COMMERCIAL' }, { status: 403 });
    }
  }

  const histKey    = `key:history:${userId}`;
  const allHistory = await kvGet(env, histKey) || [];
  const keyHistory = allHistory.filter(e => e.key_id === keyId);

  const meta = await kvGet(env, `key:meta:${keyId}`) || {};

  return Response.json({
    success:   true,
    service:   'CDB-COMMERCIAL',
    key_id:    keyId,
    meta,
    history:   keyHistory,
    total:     keyHistory.length,
    timestamp: new Date().toISOString(),
  });
}

// ─── P15.7: Enterprise Report Archive ────────────────────────────────────────
export async function handleReportArchive(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const cacheKey = `customer:v1:reports:${userId}`;
  const t0       = Date.now();

  const cached = await kvGet(env, cacheKey);
  if (cached) return Response.json({ ...cached, _cache: 'hit', _ms: Date.now() - t0 });

  const db    = env.DB;
  const url   = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);

  const [scheduledRows, completedScans] = await Promise.all([
    db ? db.prepare(
      `SELECT id, template_type, recipients, frequency, last_run, next_run
       FROM scheduled_reports WHERE org_id = ? ORDER BY last_run DESC LIMIT ?`
    ).bind(userId, limit).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT id, target, risk_level, created_at FROM scan_jobs
       WHERE user_id = ? AND status IN ('completed', 'COMPLETED')
       ORDER BY created_at DESC LIMIT 20`
    ).bind(userId).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
  ]);

  const payload = {
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    archive: {
      scheduled_reports: scheduledRows.map(r => ({
        id:         r.id,
        type:       r.template_type,
        recipients: safeParseJSON(r.recipients, []),
        frequency:  r.frequency,
        last_run:   r.last_run,
        next_run:   r.next_run,
        status:     r.last_run ? 'DELIVERED' : 'PENDING',
      })),
      completed_scans: completedScans.map(s => ({
        id:         s.id,
        target:     s.target,
        risk_level: s.risk_level,
        created_at: s.created_at,
        report_url: `/api/customer/report?scan_id=${s.id}`,
      })),
      total_scheduled: scheduledRows.length,
      total_scans:     completedScans.length,
    },
    _cache: 'miss',
    _ms:    Date.now() - t0,
  };

  await kvSet(env, cacheKey, payload, 120);
  return Response.json(payload);
}

// ─── P15.8: Customer Notification Center ─────────────────────────────────────
export async function handleNotificationCenter(request, env, authCtx) {
  const gate = checkAuth(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const url    = new URL(request.url);
  const t0     = Date.now();

  const priority = url.searchParams.get('priority') || null;
  const channel  = url.searchParams.get('channel')  || null;
  const limit    = Math.min(parseInt(url.searchParams.get('limit') || '30', 10), 100);

  const db = env.DB;

  const binds = [userId];
  let query   = `SELECT id, type, channel, subject, body, delivered, delivery_ts, created_at
                 FROM ops_notifications WHERE user_id = ?`;
  if (priority) { query += ` AND type = ?`;    binds.push(priority.toUpperCase()); }
  if (channel)  { query += ` AND channel = ?`; binds.push(channel.toLowerCase());  }
  query += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const rows = db
    ? await db.prepare(query).bind(...binds).all().then(r => r.results || []).catch(() => [])
    : [];

  const deliveredCount = rows.filter(r => r.delivered).length;

  return Response.json({
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    notifications: {
      items: rows.map(r => ({
        id:          r.id,
        type:        r.type,
        channel:     r.channel,
        subject:     r.subject,
        body:        r.body,
        delivered:   !!r.delivered,
        delivery_ts: r.delivery_ts,
        created_at:  r.created_at,
      })),
      total:     rows.length,
      delivered: deliveredCount,
      pending:   rows.length - deliveredCount,
      filters:   { priority, channel },
      _cache:    'none',
    },
    _ms: Date.now() - t0,
  });
}

// ─── P15.9: Commercial Observability (OWNER/ADMIN only) ───────────────────────
export async function handleCommercialObservability(request, env, authCtx) {
  const gate = checkAdminTier(authCtx);
  if (gate) return gate;

  const t0 = Date.now();
  const db = env.DB;

  const [usersByTier, apiConsumption, featureAdoption, profileCount, reportCount] = await Promise.all([
    db ? db.prepare(
      `SELECT tier, COUNT(*) as cnt FROM users GROUP BY tier`
    ).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT SUM(request_count) as total_calls, COUNT(DISTINCT key_id) as active_keys
       FROM api_key_usage WHERE date_bucket >= date('now', '-30 days')`
    ).first().catch(() => ({ total_calls: 0, active_keys: 0 })) : Promise.resolve({ total_calls: 0, active_keys: 0 }),
    db ? db.prepare(
      `SELECT feature, COUNT(*) as user_count
       FROM customer_entitlements WHERE granted = 1
       GROUP BY feature ORDER BY user_count DESC LIMIT 15`
    ).all().then(r => r.results || []).catch(() => []) : Promise.resolve([]),
    db ? db.prepare(
      `SELECT COUNT(*) as cnt FROM customer_profiles`
    ).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
    db ? db.prepare(
      `SELECT COUNT(*) as cnt FROM scheduled_reports`
    ).first().catch(() => ({ cnt: 0 })) : Promise.resolve({ cnt: 0 }),
  ]);

  const tierMap = {};
  usersByTier.forEach(r => { tierMap[r.tier || 'FREE'] = r.cnt; });
  const totalUsers     = Object.values(tierMap).reduce((s, v) => s + v, 0);
  const paidUsers      = (tierMap['STARTER'] || 0) + (tierMap['PRO'] || 0) + (tierMap['ENTERPRISE'] || 0) + (tierMap['MSSP'] || 0);
  const mrrEstimateINR = (tierMap['STARTER'] || 0) * 499 + (tierMap['PRO'] || 0) * 1499 + (tierMap['ENTERPRISE'] || 0) * 4999;

  return Response.json({
    success:   true,
    service:   'CDB-COMMERCIAL',
    timestamp: new Date().toISOString(),
    commercial_observability: {
      customers: {
        total:                      totalUsers,
        paid:                       paidUsers,
        free:                       tierMap['FREE'] || 0,
        by_tier:                    tierMap,
        with_profile:               profileCount?.cnt || 0,
        onboarding_completion_rate: totalUsers > 0 ? Math.round(((profileCount?.cnt || 0) / totalUsers) * 100) : 0,
      },
      revenue: {
        mrr_estimate_inr:     mrrEstimateINR,
        arr_estimate_inr:     mrrEstimateINR * 12,
        pro_customers:        tierMap['PRO'] || 0,
        enterprise_customers: tierMap['ENTERPRISE'] || 0,
      },
      api_consumption: {
        total_calls_30d: apiConsumption?.total_calls || 0,
        active_keys_30d: apiConsumption?.active_keys || 0,
      },
      feature_adoption: featureAdoption.map(f => ({
        feature:    f.feature,
        users:      f.user_count,
        pct:        totalUsers > 0 ? Math.round((f.user_count / totalUsers) * 100) : 0,
      })),
      content: {
        scheduled_reports: reportCount?.cnt || 0,
      },
      _cache: 'none',
    },
    _ms: Date.now() - t0,
  });
}
