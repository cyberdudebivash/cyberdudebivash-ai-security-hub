import { isRealUser } from '../auth/middleware.js';
/**
 * CYBERDUDEBIVASH® AI Security Hub — Operations Engine v1.0 (P6.0)
 * Enterprise operations: usage analytics, subscription enforcement,
 * audit, notifications, feature flags, admin APIs, observability, lifecycle.
 *
 * P6.0-001  trackUsage()          — usage analytics (fire-and-forget)
 * P6.0-002  checkEntitlements()   — subscription + feature enforcement
 * P6.0-003  writeOpsAudit()       — wraps existing writeAuditEvent
 * P6.0-004  sendNotification()    — customer notification dispatch
 * P6.0-005  getFeatureFlag()      — per-customer feature control
 * P6.0-006  handleAdmin*          — OWNER/ADMIN restricted admin APIs
 * P6.0-007  (frontend/ops-dashboard.html)
 * P6.0-008  handleOpsMetrics()    — observability metrics endpoint
 * P6.0-009  runOpsLifecycleCron() — data retention and cleanup
 */

// ─── Table bootstrap ──────────────────────────────────────────────────────────
let _opsTablesReady = false;

async function ensureOpsTables(db) {
  if (_opsTablesReady) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS ops_usage_events (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT,
        event_type TEXT NOT NULL,
        endpoint TEXT,
        method TEXT,
        latency_ms INTEGER DEFAULT 0,
        cached INTEGER DEFAULT 0,
        ts TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS ops_feature_flags (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        flag_name TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        tier_required TEXT DEFAULT 'FREE',
        note TEXT,
        expires_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, flag_name)
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS ops_notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT,
        type TEXT NOT NULL,
        channel TEXT DEFAULT 'inapp',
        subject TEXT,
        body TEXT,
        delivered INTEGER DEFAULT 0,
        delivery_ts TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
    ]);
    _opsTablesReady = true;
  } catch {}
}

// ─── P6.0-001: Usage Analytics ───────────────────────────────────────────────
export async function trackUsage(env, userId, orgId, eventType, endpoint, method = 'GET', latencyMs = 0, cached = false) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db || !userId) return;
  try {
    await ensureOpsTables(db);
    const id = `use_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    await db.prepare(
      `INSERT INTO ops_usage_events (id,user_id,org_id,event_type,endpoint,method,latency_ms,cached)
       VALUES (?,?,?,?,?,?,?,?)`
    ).bind(id, userId, orgId || null, eventType, endpoint || null, method, latencyMs | 0, cached ? 1 : 0).run();
    // KV counter for fast aggregation
    const kv = env.SECURITY_HUB_KV || env.KV;
    if (kv) {
      const dayKey = `ops:usage:${new Date().toISOString().slice(0,10)}:${eventType}`;
      const cur = parseInt(await kv.get(dayKey) || '0', 10);
      kv.put(dayKey, String(cur + 1), { expirationTtl: 7776000 }).catch(() => {});
    }
  } catch {}
}

// ─── P6.0-002: Subscription Enforcement ──────────────────────────────────────
// Tier hierarchy: FREE < PRO < ENTERPRISE < MSSP < ADMIN < OWNER
const TIER_ORDER = { FREE: 0, PRO: 1, ENTERPRISE: 2, MSSP: 3, ADMIN: 4, OWNER: 5 };

const FEATURE_REQUIREMENTS = {
  customer_radar:   'FREE',
  customer_risk:    'FREE',
  customer_profile: 'FREE',
  customer_assets:  'PRO',
  customer_report:  'PRO',
  enterprise_intel: 'PRO',
  enterprise_risk:  'PRO',
  enterprise_actors:'ENTERPRISE',
  enterprise_campaigns: 'PRO',
  mssp_tenant:      'MSSP',
  admin_panel:      'ADMIN',
  feature_flags:    'ENTERPRISE',
};

const MONTHLY_LIMITS = {
  FREE:       { radar_calls: 20,  report_calls: 2,   asset_count: 5  },
  PRO:        { radar_calls: 500, report_calls: 30,  asset_count: 50 },
  ENTERPRISE: { radar_calls: -1,  report_calls: -1,  asset_count: -1 },
  MSSP:       { radar_calls: -1,  report_calls: -1,  asset_count: -1 },
  ADMIN:      { radar_calls: -1,  report_calls: -1,  asset_count: -1 },
  OWNER:      { radar_calls: -1,  report_calls: -1,  asset_count: -1 },
};

export function checkEntitlements(authCtx, feature) {
  if (!isRealUser(authCtx)) return { allowed: false, reason: 'Authentication required' };
  const tier = (authCtx.tier || 'FREE').toUpperCase();
  const required = (FEATURE_REQUIREMENTS[feature] || 'FREE').toUpperCase();
  if ((TIER_ORDER[tier] ?? 0) < (TIER_ORDER[required] ?? 0)) {
    return { allowed: false, reason: `Feature requires ${required} tier`, upgrade_url: 'https://cyberdudebivash.in/#pricing', tier, required };
  }
  return { allowed: true, tier, limits: MONTHLY_LIMITS[tier] || MONTHLY_LIMITS.FREE };
}

// ─── P6.0-003: Ops Audit ─────────────────────────────────────────────────────
export async function writeOpsAudit(env, { type, actor, actorTier, ip, resource, action, outcome, details, orgId }) {
  const kv = env.SECURITY_HUB_KV || env.KV;
  if (!kv) return;
  const id = `audit_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  const ts = new Date().toISOString();
  const entry = {
    id, type, actor, actor_tier: actorTier, ip, resource, action, outcome,
    details: details || {}, org_id: orgId || null, timestamp: ts,
    integrity: btoa(`${id}|${type}|${actor}|${ts}`).slice(0, 32),
  };
  try {
    await kv.put(`audit:${ts.slice(0, 10)}:${id}`, JSON.stringify(entry), { expirationTtl: 7776000 });
  } catch {}
}

// ─── P6.0-004: Customer Notifications ────────────────────────────────────────
const NOTIFICATION_TYPES = new Set([
  'high_risk_cve', 'campaign_targeting', 'subscription_expiry',
  'product_alert', 'maintenance', 'welcome', 'security_alert',
]);

export async function sendNotification(env, userId, type, subject, body, orgId = null) {
  if (!NOTIFICATION_TYPES.has(type)) return;
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db) return;
  try {
    await ensureOpsTables(db);
    const id = `notif_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    await db.prepare(
      `INSERT INTO ops_notifications (id,user_id,org_id,type,subject,body)
       VALUES (?,?,?,?,?,?)`
    ).bind(id, userId, orgId || null, type, subject || '', body || '').run();
    // In-app KV delivery
    const kv = env.SECURITY_HUB_KV || env.KV;
    if (kv) {
      const notifKey = `notif:user:${userId}:${id}`;
      await kv.put(notifKey, JSON.stringify({ id, type, subject, body, ts: new Date().toISOString() }),
        { expirationTtl: 2592000 }); // 30 days
    }
    // Mark delivered
    await db.prepare(`UPDATE ops_notifications SET delivered=1,delivery_ts=datetime('now') WHERE id=?`).bind(id).run();
  } catch {}
}

// ─── P6.0-005: Feature Flag Engine ───────────────────────────────────────────
export async function getFeatureFlag(env, userId, flagName) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db) return false;
  try {
    await ensureOpsTables(db);
    // Check user-specific flag first, then global flag (user_id IS NULL)
    const row = await db.prepare(
      `SELECT enabled, expires_at FROM ops_feature_flags
       WHERE flag_name=? AND (user_id=? OR user_id IS NULL)
       ORDER BY user_id NULLS LAST LIMIT 1`
    ).bind(flagName, userId).first();
    if (!row) return false;
    if (row.expires_at && new Date(row.expires_at) < new Date()) return false;
    return row.enabled === 1;
  } catch { return false; }
}

async function handleGetFeatureFlags(req, env, authCtx) {
  if (!isRealUser(authCtx)) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const db = env.SECURITY_HUB_DB || env.DB;
  await ensureOpsTables(db);
  try {
    const { results } = await db.prepare(
      `SELECT flag_name, enabled, tier_required, note, expires_at, created_at
       FROM ops_feature_flags WHERE user_id=? OR user_id IS NULL ORDER BY flag_name`
    ).bind(authCtx.userId).all();
    return Response.json({ flags: results || [], user_id: authCtx.userId });
  } catch { return Response.json({ flags: [] }); }
}

async function handleSetFeatureFlag(req, env, authCtx) {
  const tier = (authCtx.tier || '').toUpperCase();
  if (!['ADMIN', 'OWNER'].includes(tier)) return Response.json({ error: 'Admin required' }, { status: 403 });
  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { user_id, flag_name, enabled, tier_required, note, expires_at } = body;
  if (!flag_name) return Response.json({ error: 'flag_name required' }, { status: 400 });
  const db = env.SECURITY_HUB_DB || env.DB;
  await ensureOpsTables(db);
  try {
    await db.prepare(
      `INSERT INTO ops_feature_flags (id,user_id,flag_name,enabled,tier_required,note,expires_at)
       VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(user_id,flag_name) DO UPDATE SET enabled=excluded.enabled,
         tier_required=excluded.tier_required,note=excluded.note,expires_at=excluded.expires_at`
    ).bind(
      `ff_${Date.now().toString(36)}`,
      user_id || null, flag_name, enabled ? 1 : 0,
      tier_required || 'FREE', note || null, expires_at || null
    ).run();
    await writeOpsAudit(env, { type: 'config.changed', actor: authCtx.userId, actorTier: tier,
      resource: 'feature_flags', action: `set:${flag_name}`, outcome: 'success',
      details: { flag_name, user_id, enabled } });
    return Response.json({ ok: true, flag_name, enabled });
  } catch (e) { return Response.json({ error: 'DB error' }, { status: 500 }); }
}

// ─── P6.0-006: Enterprise Administration APIs ─────────────────────────────────
function assertAdmin(authCtx) {
  const tier = (authCtx?.tier || '').toUpperCase();
  if (!authCtx?.isAdmin && !['ADMIN', 'OWNER'].includes(tier))
    return Response.json({ error: 'OWNER or ADMIN required' }, { status: 403 });
  return null;
}

export async function handleAdminCustomers(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const db = env.SECURITY_HUB_DB || env.DB;
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const industry = url.searchParams.get('industry');
  try {
    await ensureOpsTables(db);
    let q = `SELECT id, org_id, org_name, industry, country, org_size,
                     json_array_length(technology_stack) AS tech_count,
                     json_array_length(business_critical_assets) AS bca_count,
                     created_at, updated_at
             FROM customer_profiles`;
    const binds = [];
    if (industry) { q += ` WHERE industry=?`; binds.push(industry); }
    q += ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    binds.push(limit, offset);
    const { results } = await db.prepare(q).bind(...binds).all();
    // Asset counts per customer
    const assetRows = await db.prepare(`SELECT owner_id, COUNT(*) as cnt FROM customer_assets GROUP BY owner_id`).all().catch(() => ({ results: [] }));
    const assetMap = {};
    (assetRows.results || []).forEach(r => { assetMap[r.owner_id] = r.cnt; });
    const customers = (results || []).map(c => ({ ...c, asset_count: assetMap[c.id] || 0 }));
    // Industry distribution
    const distRows = await db.prepare(`SELECT industry, COUNT(*) as cnt FROM customer_profiles GROUP BY industry`).all().catch(() => ({ results: [] }));
    return Response.json({ customers, total: customers.length, offset, limit, industry_distribution: distRows.results || [] });
  } catch (e) { return Response.json({ error: 'DB error', detail: e.message }, { status: 500 }); }
}

export async function handleAdminUsage(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const db = env.SECURITY_HUB_DB || env.DB;
  const url = new URL(req.url);
  const days = Math.min(parseInt(url.searchParams.get('days') || '7', 10), 90);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  try {
    await ensureOpsTables(db);
    const [byEndpoint, byUser, byType, cacheStats, latencyStats] = await Promise.all([
      db.prepare(`SELECT endpoint, method, COUNT(*) as calls, AVG(latency_ms) as avg_latency
                  FROM ops_usage_events WHERE ts>=? GROUP BY endpoint,method ORDER BY calls DESC LIMIT 20`).bind(since).all(),
      db.prepare(`SELECT user_id, COUNT(*) as calls FROM ops_usage_events WHERE ts>=? GROUP BY user_id ORDER BY calls DESC LIMIT 20`).bind(since).all(),
      db.prepare(`SELECT event_type, COUNT(*) as calls FROM ops_usage_events WHERE ts>=? GROUP BY event_type ORDER BY calls DESC`).bind(since).all(),
      db.prepare(`SELECT SUM(cached) as cache_hits, COUNT(*) as total FROM ops_usage_events WHERE ts>=?`).bind(since).first(),
      db.prepare(`SELECT AVG(latency_ms) as p50, MAX(latency_ms) as p99 FROM ops_usage_events WHERE ts>=?`).bind(since).first(),
    ]);
    const total = cacheStats?.total || 0;
    const hits  = cacheStats?.cache_hits || 0;
    return Response.json({
      period_days: days,
      summary: { total_calls: total, cache_hits: hits, cache_hit_ratio: total ? (hits / total).toFixed(3) : 0, avg_latency_ms: Math.round(latencyStats?.p50 || 0), p99_latency_ms: Math.round(latencyStats?.p99 || 0) },
      top_endpoints: byEndpoint.results || [],
      top_users: byUser.results || [],
      by_event_type: byType.results || [],
    });
  } catch (e) { return Response.json({ error: 'DB error', detail: e.message }, { status: 500 }); }
}

export async function handleAdminSubscriptions(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const db = env.SECURITY_HUB_DB || env.DB;
  try {
    // Tier distribution from api_keys
    const tierDist = await db.prepare(
      `SELECT tier, COUNT(*) as count FROM api_keys GROUP BY tier ORDER BY count DESC`
    ).all().catch(() => ({ results: [] }));
    // Active keys in last 30 days
    const activeRow = await db.prepare(
      `SELECT COUNT(DISTINCT user_id) as active_users
       FROM api_keys WHERE last_used_at >= datetime('now','-30 days')`
    ).first().catch(() => null);
    // Expiring soon (keys with expires_at in next 14 days)
    const expiring = await db.prepare(
      `SELECT user_id, tier, expires_at FROM api_keys
       WHERE expires_at IS NOT NULL AND expires_at <= datetime('now','+14 days') AND expires_at > datetime('now')
       ORDER BY expires_at LIMIT 50`
    ).all().catch(() => ({ results: [] }));
    // Usage vs limits from ops_usage_events this month
    const usageRows = await db.prepare(
      `SELECT user_id, event_type, COUNT(*) as calls
       FROM ops_usage_events WHERE ts >= date('now','start of month')
       GROUP BY user_id, event_type ORDER BY calls DESC LIMIT 50`
    ).all().catch(() => ({ results: [] }));
    return Response.json({
      tier_distribution: tierDist.results || [],
      active_users_30d: activeRow?.active_users || 0,
      expiring_soon: expiring.results || [],
      monthly_usage_sample: usageRows.results || [],
      plans: {
        FREE: { limits: MONTHLY_LIMITS.FREE },
        PRO: { limits: MONTHLY_LIMITS.PRO },
        ENTERPRISE: { limits: MONTHLY_LIMITS.ENTERPRISE },
      },
    });
  } catch (e) { return Response.json({ error: 'DB error', detail: e.message }, { status: 500 }); }
}

export async function handleAdminAudit(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const kv = env.SECURITY_HUB_KV || env.KV;
  const url = new URL(req.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const type = url.searchParams.get('type');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return Response.json({ error: 'date must be YYYY-MM-DD' }, { status: 400 });
  const entries = [];
  if (kv) {
    try {
      const list = await kv.list({ prefix: `audit:${date}:` });
      for (const key of (list.keys || []).slice(0, limit * 2)) {
        const raw = await kv.get(key.name);
        if (!raw) continue;
        try {
          const entry = JSON.parse(raw);
          if (type && !entry.type?.startsWith(type)) continue;
          entries.push({ ...entry, source: 'kv' });
        } catch {}
      }
    } catch {}
  }

  // This admin view previously only ever saw events written via
  // writeOpsAudit() (KV). Enterprise SSO logins/config changes
  // (enterpriseSsoHandler.js) and AI copilot sessions (aiSecurityCopilot.js)
  // write straight to the D1 audit_log table instead and were completely
  // invisible here — an admin reviewing "the audit log" would never see an
  // SSO reconfiguration. Merge both trails.
  const db = env.SECURITY_HUB_DB || env.DB;
  if (db) {
    try {
      const { results } = await db.prepare(
        `SELECT id, user_id, action, resource, resource_id, status, metadata, details, created_at
         FROM audit_log WHERE created_at >= ? AND created_at < ? ORDER BY created_at DESC LIMIT ?`
      ).bind(`${date} 00:00:00`, `${date} 23:59:59`, limit * 2).all();
      for (const row of (results || [])) {
        if (type && !row.action?.startsWith(type)) continue;
        let parsedDetails = {};
        try { parsedDetails = JSON.parse(row.metadata || row.details || '{}'); } catch {}
        entries.push({
          id: row.id, type: row.action, actor: row.user_id, resource: row.resource || null,
          action: row.resource_id || row.action, outcome: row.status || 'ok',
          details: parsedDetails, timestamp: row.created_at, source: 'd1',
        });
      }
    } catch {}
  }

  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return Response.json({ date, total: entries.length, entries: entries.slice(0, limit), filter_type: type || null });
}

export async function handleAdminNotifications(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const db = env.SECURITY_HUB_DB || env.DB;
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const type = url.searchParams.get('type');
  const undelivered = url.searchParams.get('undelivered') === 'true';
  try {
    await ensureOpsTables(db);
    let q = `SELECT id,user_id,org_id,type,channel,subject,delivered,delivery_ts,created_at FROM ops_notifications`;
    const binds = [];
    const where = [];
    if (type) { where.push('type=?'); binds.push(type); }
    if (undelivered) { where.push('delivered=0'); }
    if (where.length) q += ` WHERE ${where.join(' AND ')}`;
    q += ` ORDER BY created_at DESC LIMIT ?`;
    binds.push(limit);
    const { results } = await db.prepare(q).bind(...binds).all();
    const stats = await db.prepare(
      `SELECT type, COUNT(*) as total, SUM(delivered) as delivered_count FROM ops_notifications GROUP BY type`
    ).all().catch(() => ({ results: [] }));
    return Response.json({ notifications: results || [], stats: stats.results || [], limit });
  } catch (e) { return Response.json({ error: 'DB error', detail: e.message }, { status: 500 }); }
}

// ─── P6.0-008: Observability Metrics ─────────────────────────────────────────
export async function handleOpsMetrics(req, env, authCtx) {
  const denied = assertAdmin(authCtx); if (denied) return denied;
  const db = env.SECURITY_HUB_DB || env.DB;
  const kv = env.SECURITY_HUB_KV || env.KV;
  const since24h = new Date(Date.now() - 86400000).toISOString();
  const since1h  = new Date(Date.now() - 3600000).toISOString();

  const [latencyRow, cacheRow, endpointRow, d1CountRow] = await Promise.all([
    db?.prepare(`SELECT AVG(latency_ms) as p50, MAX(latency_ms) as p99 FROM ops_usage_events WHERE ts>=?`).bind(since1h).first().catch(() => null),
    db?.prepare(`SELECT SUM(cached) as hits, COUNT(*) as total FROM ops_usage_events WHERE ts>=?`).bind(since1h).first().catch(() => null),
    db?.prepare(`SELECT endpoint, COUNT(*) as calls, AVG(latency_ms) as avg_ms FROM ops_usage_events WHERE ts>=? GROUP BY endpoint ORDER BY calls DESC LIMIT 10`).bind(since24h).all().catch(() => ({ results: [] })),
    db?.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE ts>=?`).bind(since24h).first().catch(() => null),
  ]);

  // KV counters for cron success tracking
  const today = new Date().toISOString().slice(0, 10);
  const [radarHits, ingestHits] = await Promise.all([
    kv?.get(`radar:cache:hits:${today}`).catch(() => null),
    kv?.get(`ops:cron:ingest:success:${today}`).catch(() => null),
  ]);

  const total = cacheRow?.total || 0;
  const hits  = cacheRow?.hits || 0;

  return Response.json({
    ts: new Date().toISOString(),
    api_latency: {
      p50_ms: Math.round(latencyRow?.p50 || 0),
      p99_ms: Math.round(latencyRow?.p99 || 0),
    },
    kv: {
      hit_ratio: total ? parseFloat((hits / total).toFixed(3)) : 0,
      hits_1h: hits,
      total_calls_1h: total,
      radar_cache_hits_today: parseInt(radarHits || '0', 10),
    },
    d1: {
      usage_events_24h: d1CountRow?.cnt || 0,
      top_endpoints: endpointRow?.results || [],
    },
    cron: {
      ingest_success_today: parseInt(ingestHits || '0', 10),
    },
    worker: {
      status: 'healthy',
      platform: 'Cloudflare Workers',
      region: (env.CF_REGION || env.REGION || 'global'),
    },
  });
}

// ─── P6.0-009: Data Lifecycle Cron ────────────────────────────────────────────
export async function runOpsLifecycleCron(env) {
  const db = env.SECURITY_HUB_DB || env.DB;
  const kv = env.SECURITY_HUB_KV || env.KV;
  const report = { deleted_usage_events: 0, deleted_notifications: 0, aggregated_days: 0, errors: [] };
  try {
    await ensureOpsTables(db);
    // Retain 90 days of usage events
    const r1 = await db.prepare(`DELETE FROM ops_usage_events WHERE ts < datetime('now','-90 days')`).run().catch(e => ({ meta: { changes: 0 }, error: e.message }));
    report.deleted_usage_events = r1?.meta?.changes || 0;
    // Retain 30 days of delivered notifications
    const r2 = await db.prepare(`DELETE FROM ops_notifications WHERE delivered=1 AND created_at < datetime('now','-30 days')`).run().catch(e => ({ meta: { changes: 0 }, error: e.message }));
    report.deleted_notifications = r2?.meta?.changes || 0;
    // Aggregate yesterday into KV summary
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const agg = await db.prepare(
      `SELECT event_type, COUNT(*) as calls, AVG(latency_ms) as avg_ms, SUM(cached) as cache_hits
       FROM ops_usage_events WHERE ts >= ? AND ts < ? GROUP BY event_type`
    ).bind(`${yesterday}T00:00:00`, `${yesterday}T23:59:59`).all().catch(() => ({ results: [] }));
    if (kv && agg.results?.length) {
      await kv.put(`ops:daily:summary:${yesterday}`, JSON.stringify({ date: yesterday, breakdown: agg.results, generated_at: new Date().toISOString() }), { expirationTtl: 7776000 });
      report.aggregated_days = 1;
    }
    // Remove expired feature flags
    await db.prepare(`DELETE FROM ops_feature_flags WHERE expires_at IS NOT NULL AND expires_at < datetime('now')`).run().catch(() => {});
    // Track cron success in KV
    const today = new Date().toISOString().slice(0, 10);
    if (kv) await kv.put(`ops:cron:lifecycle:${today}`, 'ok', { expirationTtl: 86400 }).catch(() => {});
  } catch (e) { report.errors.push(e.message); }
  return report;
}

// ─── Public notification endpoint (customer-facing) ───────────────────────────
async function handleGetMyNotifications(req, env, authCtx) {
  if (!isRealUser(authCtx)) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const db = env.SECURITY_HUB_DB || env.DB;
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 100);
  try {
    await ensureOpsTables(db);
    const { results } = await db.prepare(
      `SELECT id,type,subject,body,delivered,created_at FROM ops_notifications WHERE user_id=? ORDER BY created_at DESC LIMIT ?`
    ).bind(authCtx.userId, limit).all();
    return Response.json({ notifications: results || [], user_id: authCtx.userId });
  } catch { return Response.json({ notifications: [] }); }
}

// ─── Main router ──────────────────────────────────────────────────────────────
export async function handleOpsRoute(req, env, authCtx, path, method) {
  // Feature flags
  if (path === '/api/ops/flags' && method === 'GET')  return handleGetFeatureFlags(req, env, authCtx);
  if (path === '/api/ops/flags' && method === 'PUT')  return handleSetFeatureFlag(req, env, authCtx);
  if (path === '/api/ops/metrics' && method === 'GET') return handleOpsMetrics(req, env, authCtx);
  // Customer notifications
  if (path === '/api/ops/notifications' && method === 'GET') return handleGetMyNotifications(req, env, authCtx);
  // Admin
  if (path === '/api/admin/customers' && method === 'GET')     return handleAdminCustomers(req, env, authCtx);
  if (path === '/api/admin/usage' && method === 'GET')         return handleAdminUsage(req, env, authCtx);
  if (path === '/api/admin/subscriptions' && method === 'GET') return handleAdminSubscriptions(req, env, authCtx);
  if (path === '/api/admin/audit' && method === 'GET')         return handleAdminAudit(req, env, authCtx);
  if (path === '/api/admin/notifications' && method === 'GET') return handleAdminNotifications(req, env, authCtx);
  return null;
}
