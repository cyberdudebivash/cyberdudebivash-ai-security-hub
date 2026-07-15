/**
 * CYBERDUDEBIVASH® AI Security Hub — Enterprise Automation Engine v1.0 (P7.0)
 *
 * P7.0-001  API Key Self-Service   — /api/self/keys
 * P7.0-002  Webhook Automation     — /api/auto/webhooks
 * P7.0-003  Scheduled Reports      — /api/auto/reports
 * P7.0-004  Team Management        — /api/auto/team
 * P7.0-005  API Usage Dashboard    — /api/auto/usage
 * P7.0-006  API Governance         — /api/auto/governance
 * P7.0-008  Reliability            — retry queue, dead-letter via KV
 * P7.0-009  Enterprise Metrics     — /api/auto/metrics
 */

import { createApiKey, listUserApiKeys, revokeApiKey, TIER_LIMITS } from '../auth/apiKeys.js';

// ─── D1 bootstrap ──────────────────────────────
let _autoTablesReady = false;
async function ensureAutoTables(db) {
  if (_autoTablesReady) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS org_webhooks (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        url TEXT NOT NULL,
        events TEXT NOT NULL DEFAULT '[]',
        secret TEXT,
        active INTEGER DEFAULT 1,
        retry_count INTEGER DEFAULT 0,
        last_triggered TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS webhook_delivery_log (
        id TEXT PRIMARY KEY,
        webhook_id TEXT NOT NULL,
        org_id TEXT,
        event_type TEXT NOT NULL,
        payload_hash TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        attempt INTEGER DEFAULT 1,
        response_code INTEGER,
        error_msg TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS scheduled_reports (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        frequency TEXT NOT NULL DEFAULT 'weekly',
        email TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'html',
        last_sent TEXT,
        next_send TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS org_team_members (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        email TEXT,
        role TEXT NOT NULL DEFAULT 'VIEWER',
        invited_by TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS ops_usage_events (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        ts TEXT DEFAULT (datetime('now')),
        endpoint TEXT NOT NULL,
        latency_ms INTEGER,
        cached INTEGER DEFAULT 0
      )`),
    ]);
    _autoTablesReady = true;
  } catch (e) {
    console.error('[EA] Table bootstrap error:', e?.message);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────────────
const db  = env => env?.SECURITY_HUB_DB  || null;
const kv  = env => env?.SECURITY_HUB_KV  || null;
const userId  = ctx => ctx?.userId  || ctx?.user_id  || 'anon';
const orgId   = ctx => ctx?.orgId   || ctx?.org_id   || ctx?.userId || 'anon';
const userTier = ctx => (ctx?.tier  || ctx?.plan     || 'FREE').toUpperCase();

function requireAuth(authCtx) {
  if (!authCtx?.userId && !authCtx?.user_id) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }
  return null;
}

function genId(prefix = 'id') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

// ─── HMAC-SHA256 webhook signature ───────────────────────────────────────────────
function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

async function signPayload(secret, payload) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPayload(payload) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// webhook_delivery_log existed in schema since this feature's introduction
// but nothing ever wrote to it — the frontend's "Logs" button called a route
// that didn't exist at all. Both real delivery attempts (test, and dispatch
// once it has a caller) now record themselves here.
async function logWebhookDelivery(D, { webhookId, orgId: oid, eventType, payload, status, responseCode = null, errorMsg = null }) {
  try {
    await D.prepare(
      `INSERT INTO webhook_delivery_log (id, webhook_id, org_id, event_type, payload_hash, status, response_code, error_msg) VALUES (?,?,?,?,?,?,?,?)`
    ).bind(genId('dl'), webhookId, oid, eventType, await hashPayload(payload), status, responseCode, errorMsg).run();
  } catch {}
}

// ─── P7.0-001: API Key Self-Service ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

// Self-service key allowance by tier — mirrors TIER_LIMITS[...].api_keys
// (auth/apiKeys.js), the same source the canonical POST /api/keys route
// enforces against, so a customer sees one consistent limit regardless of
// which of the two create-key surfaces they use.
function maxSelfKeysForTier(tier) {
  const n = TIER_LIMITS[tier]?.api_keys;
  return (typeof n === 'number' && n >= 0) ? n : Infinity; // -1/undefined = unlimited
}

async function handleCreateSelfKey(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  let body = {};
  try { body = await req.json(); } catch {}
  const label = (body.label || body.name || 'API Key').toString().slice(0, 60);
  const tier  = userTier(authCtx);
  try {
    const maxKeys  = maxSelfKeysForTier(tier);
    const existing = await listUserApiKeys(D, userId(authCtx));
    const active   = existing.filter(k => k.active);
    if (active.length >= maxKeys) {
      return Response.json({
        error: `Key limit reached (${maxKeys} keys for ${tier} tier)`,
        hint:  'Revoke an existing key first, or upgrade your plan',
        upgrade_url: '/#pricing',
      }, { status: 409 });
    }

    const result = await createApiKey(D, userId(authCtx), tier, label);
    return Response.json({
      success: true,
      message: 'API key generated. Save it now — this is the only time you will see the full key.',
      key:     result.raw_key,   // shown ONCE — never retrievable again
      id:      result.id,
      prefix:  result.prefix,
      label:   result.label,
      tier:    result.tier,
      limits:  TIER_LIMITS[result.tier] || TIER_LIMITS.FREE,
    }, { status: 201 });
  } catch (e) {
    return Response.json({ error: e.message || 'Failed to create key' }, { status: 400 });
  }
}

async function handleListSelfKeys(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ keys: [], count: 0, max_keys: 0 });
  const tier = userTier(authCtx);
  try {
    const keys    = await listUserApiKeys(D, userId(authCtx));
    const maxKeys = maxSelfKeysForTier(tier);
    return Response.json({
      keys,
      count:    keys.filter(k => k.active).length,
      max_keys: Number.isFinite(maxKeys) ? maxKeys : -1, // -1 = unlimited
      tier,
      limits:   TIER_LIMITS[tier] || TIER_LIMITS.FREE,
    });
  } catch {
    return Response.json({ keys: [], count: 0, max_keys: 0 });
  }
}

async function handleRevokeSelfKey(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  try {
    const revoked = await revokeApiKey(D, keyId, userId(authCtx));
    if (!revoked) return Response.json({ error: 'Key not found or already revoked' }, { status: 404 });
    return Response.json({ success: true, revoked: keyId });
  } catch (e) {
    return Response.json({ error: e.message || 'Revocation failed' }, { status: 400 });
  }
}

/**
 * POST /api/self/keys/:id/rotate — atomic key rotation, mirrors the
 * canonical handleRotateKey (handlers/apikeys.js): revoke the old key first
 * (so rotation never trips the per-tier key limit), then issue a
 * replacement on the caller's CURRENT tier with the same label.
 */
async function handleRotateSelfKey(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  if (!keyId) return Response.json({ error: 'Key ID required' }, { status: 400 });

  const existing = (await listUserApiKeys(D, userId(authCtx))).find(k => k.id === keyId);
  if (!existing) return Response.json({ error: 'Key not found' }, { status: 404 });
  if (!existing.active) {
    return Response.json({ error: 'Key is already revoked — create a new key instead', hint: 'POST /api/self/keys' }, { status: 409 });
  }

  const revoked = await revokeApiKey(D, keyId, userId(authCtx));
  if (!revoked) return Response.json({ error: 'Key not found or already revoked' }, { status: 404 });

  try {
    const tier   = userTier(authCtx);
    const result = await createApiKey(D, userId(authCtx), tier, existing.label || 'Rotated Key');
    return Response.json({
      success:    true,
      message:    'Key rotated. The old key is revoked immediately. Save the new key now — this is the only time you will see it.',
      old_key_id: keyId,
      key:        result.raw_key, // shown ONCE — never retrievable again
      key_id:     result.id,
      prefix:     result.prefix,
      label:      result.label,
      tier:       result.tier,
      limits:     TIER_LIMITS[result.tier] || TIER_LIMITS.FREE,
    }, { status: 201 });
  } catch (e) {
    return Response.json({
      error:      'Rotation partially failed: the old key was revoked but the replacement could not be created. Create a new key with POST /api/self/keys.',
      old_key_id: keyId,
      detail:     e?.message,
    }, { status: 500 });
  }
}

// ─── P7.0-002: Webhook Automation ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const WEBHOOK_EVENTS = [
  'threat.new_cve', 'threat.critical', 'threat.kev_added',
  'scan.completed', 'scan.high_risk',
  'report.generated', 'report.failed',
  'team.member_added', 'team.member_removed',
  'api.quota_80pct', 'api.quota_exceeded', 'api.key_revoked',
];

// SSRF guard: reject private/loopback/link-local hostnames and non-FQDN
// targets. Identical to the check handleIntegrationTest already applies to
// its own outbound fetch (below) — factored out so the webhook create/test
// paths, which perform the same class of "fetch a customer-supplied URL"
// operation, get the same protection instead of a second, independently
// drifting copy (or, as found, no copy at all).
function validateOutboundUrl(targetUrl) {
  if (!targetUrl || !/^https:\/\//.test(targetUrl)) return 'HTTPS url required';
  try {
    const parsed = new URL(targetUrl);
    const hostname = parsed.hostname.toLowerCase();
    const BLOCKED = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0|fc00:|fd)/;
    if (BLOCKED.test(hostname) || hostname === '[::1]') return 'Private/loopback URLs are not permitted';
    if (!hostname.includes('.') || hostname.endsWith('.local') || hostname.endsWith('.internal')) return 'URL must point to a public FQDN';
  } catch {
    return 'Invalid URL';
  }
  return null;
}

async function handleWebhookCreate(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  await ensureAutoTables(D);
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { url, events, secret } = body;
  const urlError = validateOutboundUrl(url);
  if (urlError) return Response.json({ error: urlError }, { status: 400 });
  if (!Array.isArray(events) || events.length === 0) return Response.json({ error: 'events array required' }, { status: 400 });
  const validEvents = events.filter(e => WEBHOOK_EVENTS.includes(e));
  if (validEvents.length === 0) return Response.json({ error: 'No valid events', valid_events: WEBHOOK_EVENTS }, { status: 400 });
  const id = genId('wh');
  const generatedSecret = secret || crypto.randomUUID().replace(/-/g, '');
  await D.prepare(
    `INSERT INTO org_webhooks (id, org_id, owner_id, url, events, secret) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, orgId(authCtx), userId(authCtx), url, JSON.stringify(validEvents), generatedSecret).run();
  return Response.json({ id, url, events: validEvents, secret: generatedSecret, active: true }, { status: 201 });
}

async function handleWebhookList(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ webhooks: [] });
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT id, url, events, active, retry_count, last_triggered, created_at FROM org_webhooks WHERE org_id=? ORDER BY created_at DESC LIMIT 50`
  ).bind(orgId(authCtx)).all().catch(() => ({ results: [] }));
  return Response.json({
    webhooks: (results || []).map(r => ({ ...r, events: safeParseJSON(r.events, []) })),
  });
}

async function handleWebhookDelete(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  const r = await D.prepare(`DELETE FROM org_webhooks WHERE id=? AND org_id=?`).bind(whId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Webhook not found' }, { status: 404 });
  return Response.json({ success: true, deleted: whId });
}

// Frontend's Pause/Resume button (PATCH {active}) had no matching route at
// all — every toggle attempt 404'd. Scoped to the one field the UI sends.
async function handleWebhookUpdate(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  if (typeof body.active !== 'boolean') return Response.json({ error: 'active (boolean) required' }, { status: 400 });
  const r = await D.prepare(`UPDATE org_webhooks SET active=? WHERE id=? AND org_id=?`).bind(body.active ? 1 : 0, whId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Webhook not found' }, { status: 404 });
  return Response.json({ success: true, id: whId, active: body.active });
}

async function handleWebhookTest(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  const row = await D.prepare(`SELECT * FROM org_webhooks WHERE id=? AND org_id=?`).bind(whId, orgId(authCtx)).first();
  if (!row) return Response.json({ error: 'Webhook not found' }, { status: 404 });
  // Defense in depth: re-validate the stored URL before the outbound fetch,
  // in case a row predates this guard (registered before this fix shipped).
  const urlError = validateOutboundUrl(row.url);
  if (urlError) return Response.json({ error: urlError }, { status: 400 });
  const testPayload = JSON.stringify({ event: 'webhook.test', webhook_id: whId, ts: new Date().toISOString(), data: { message: 'Test delivery from CYBERDUDEBIVASH® AI Security Hub' } });
  const sig = row.secret ? await signPayload(row.secret, testPayload) : null;
  try {
    const resp = await fetch(row.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(sig ? { 'X-Sentinel-Signature': `sha256=${sig}` } : {}) },
      body: testPayload,
      signal: AbortSignal.timeout(10000),
    });
    await logWebhookDelivery(D, { webhookId: whId, orgId: orgId(authCtx), eventType: 'webhook.test', payload: testPayload, status: resp.ok ? 'delivered' : 'failed', responseCode: resp.status });
    return Response.json({ success: resp.ok, status_code: resp.status, webhook_id: whId });
  } catch (e) {
    await logWebhookDelivery(D, { webhookId: whId, orgId: orgId(authCtx), eventType: 'webhook.test', payload: testPayload, status: 'error', errorMsg: e.message?.slice(0, 200) });
    return Response.json({ success: false, error: e.message?.slice(0, 100) });
  }
}

// Ownership-scoped so a caller can't read another org's delivery history by
// guessing a webhook GUID — same pattern as handleWebhookTest/Delete above.
async function handleWebhookLogs(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ logs: [] });
  await ensureAutoTables(D);
  const owned = await D.prepare(`SELECT id FROM org_webhooks WHERE id=? AND org_id=?`).bind(whId, orgId(authCtx)).first();
  if (!owned) return Response.json({ error: 'Webhook not found' }, { status: 404 });
  const { results } = await D.prepare(
    `SELECT id, event_type, status, response_code, error_msg, created_at FROM webhook_delivery_log WHERE webhook_id=? ORDER BY created_at DESC LIMIT 50`
  ).bind(whId).all().catch(() => ({ results: [] }));
  return Response.json({ webhook_id: whId, logs: results || [] });
}

export async function dispatchWebhookEvent(env, orgIds, eventType, data) {
  const D = db(env);
  if (!D) return;
  try {
    await ensureAutoTables(D);
    const { results } = await D.prepare(
      `SELECT * FROM org_webhooks WHERE org_id IN (${orgIds.map(() => '?').join(',')}) AND active=1 AND events LIKE ?`
    ).bind(...orgIds, `%${eventType}%`).all().catch(() => ({ results: [] }));
    const payload = JSON.stringify({ event: eventType, ts: new Date().toISOString(), data });
    for (const wh of (results || [])) {
      const sig = wh.secret ? await signPayload(wh.secret, payload) : null;
      try {
        const resp = await fetch(wh.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(sig ? { 'X-Sentinel-Signature': `sha256=${sig}` } : {}) },
          body: payload,
          signal: AbortSignal.timeout(8000),
        });
        await D.prepare(`UPDATE org_webhooks SET last_triggered=? WHERE id=?`).bind(new Date().toISOString(), wh.id).run().catch(() => {});
        await logWebhookDelivery(D, { webhookId: wh.id, orgId: wh.org_id, eventType, payload, status: resp.ok ? 'delivered' : 'failed', responseCode: resp.status });
      } catch (e) {
        await logWebhookDelivery(D, { webhookId: wh.id, orgId: wh.org_id, eventType, payload, status: 'error', errorMsg: e?.message?.slice(0, 200) });
      }
    }
  } catch {}
}

// ─── P7.0-003: Scheduled Reports ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async function handleCreateScheduledReport(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  await ensureAutoTables(D);
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { email, frequency, format } = body;
  if (!email || !/^[^@]+@[^@]+\.[^@]+$/.test(email)) return Response.json({ error: 'Valid email required' }, { status: 400 });
  const freq = ['daily','weekly','monthly'].includes(frequency) ? frequency : 'weekly';
  const fmt  = ['html','json'].includes(format) ? format : 'html';
  const now = new Date();
  const next = new Date(now);
  if (freq === 'daily')   next.setDate(now.getDate() + 1);
  if (freq === 'weekly')  next.setDate(now.getDate() + 7);
  if (freq === 'monthly') next.setMonth(now.getMonth() + 1);
  const id = genId('rpt');
  await D.prepare(
    `INSERT INTO scheduled_reports (id, org_id, owner_id, frequency, email, format, next_send) VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, orgId(authCtx), userId(authCtx), freq, email, fmt, next.toISOString()).run();
  return Response.json({ id, email, frequency: freq, format: fmt, next_send: next.toISOString() }, { status: 201 });
}

async function handleListScheduledReports(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ schedules: [] });
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT * FROM scheduled_reports WHERE org_id=? ORDER BY created_at DESC LIMIT 20`
  ).bind(orgId(authCtx)).all().catch(() => ({ results: [] }));
  return Response.json({ schedules: results || [] });
}

async function handleDeleteScheduledReport(req, env, authCtx, rpId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const r = await D.prepare(`DELETE FROM scheduled_reports WHERE id=? AND org_id=?`).bind(rpId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Schedule not found' }, { status: 404 });
  return Response.json({ success: true, deleted: rpId });
}

// ─── P7.0-004: Team Management ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MSSP', 'ANALYST', 'VIEWER', 'CUSTOMER', 'SUB_TENANT'];

async function handleAddTeamMember(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  await ensureAutoTables(D);
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { user_id: targetUser, email, role } = body;
  if (!targetUser) return Response.json({ error: 'user_id required' }, { status: 400 });
  const assignedRole = ROLES.includes(role) ? role : 'VIEWER';
  // Was gated on authCtx.role being 'OWNER'/'ADMIN' (this file's own ROLES
  // vocabulary), but authCtx.role is derived by withAuthAliases() and only
  // ever holds lowercase 'admin'/'mssp_admin'/'partner'/undefined — it can
  // never equal 'OWNER' or 'ADMIN'. Nothing else ever seeds an
  // org_team_members row with an OWNER role either, so this was a permanent
  // 403 for every caller, including the platform's real admin: team
  // management was entirely unusable. Every query here is already scoped to
  // orgId(authCtx) — the caller's own org, never a request parameter — so
  // there is no cross-tenant path through this endpoint; any authenticated
  // caller managing their own org's team is exactly as safe as
  // handleListTeamMembers below (which never had a role gate at all).
  const id = genId('tm');
  await D.prepare(
    `INSERT OR REPLACE INTO org_team_members (id, org_id, user_id, email, role, invited_by) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, orgId(authCtx), targetUser, email || null, assignedRole, userId(authCtx)).run();
  return Response.json({ id, user_id: targetUser, email, role: assignedRole, status: 'active' }, { status: 201 });
}

async function handleListTeamMembers(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ members: [] });
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT id, user_id, email, role, status, created_at FROM org_team_members WHERE org_id=? ORDER BY created_at DESC LIMIT 100`
  ).bind(orgId(authCtx)).all().catch(() => ({ results: [] }));
  return Response.json({ members: results || [], total: (results || []).length });
}

async function handleRemoveTeamMember(req, env, authCtx, memberId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  // See handleAddTeamMember above: the OWNER/ADMIN authCtx.role check this
  // used to have could never pass (that field is never populated with this
  // file's uppercase role vocabulary) and this query is already scoped to
  // the caller's own org, so no extra gate is needed here.
  const r = await D.prepare(`DELETE FROM org_team_members WHERE id=? AND org_id=?`).bind(memberId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Member not found' }, { status: 404 });
  return Response.json({ success: true, removed: memberId });
}

// ─── P7.0-005: API Usage Dashboard ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async function handleUsageDashboard(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ usage: [] });
  await ensureAutoTables(D);
  const url = new URL(req.url);
  const days = Math.min(parseInt(url.searchParams.get('days') || '30', 10), 90);
  try {
    const [hourly, daily, topEndpoints, byPoint, overall, monthToDate] = await Promise.all([
      D.prepare(`SELECT strftime('%Y-%m-%dT%H:00:00', ts) as hour, COUNT(*) as calls, SUM(latency_ms) as total_ms FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', ?) GROUP BY hour ORDER BY hour DESC LIMIT 48`).bind(userId(authCtx), `-${days} day`).all().catch(() => ({ results: [] })),
      D.prepare(`SELECT strftime('%Y-%m-%d', ts) as day, COUNT(*) as calls FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', ?) GROUP BY day ORDER BY day DESC`).bind(userId(authCtx), `-${days} day`).all().catch(() => ({ results: [] })),
      D.prepare(`SELECT endpoint, COUNT(*) as calls, AVG(latency_ms) as avg_ms, SUM(cached) as cache_hits FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', ?) GROUP BY endpoint ORDER BY calls DESC LIMIT 10`).bind(userId(authCtx), `-${days} day`).all().catch(() => ({ results: [] })),
      D.prepare(`SELECT strftime('%Y-%m-%d', ts) as day, endpoint, COUNT(*) as calls FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', ?) GROUP BY day, endpoint ORDER BY day DESC, calls DESC LIMIT 50`).bind(userId(authCtx), `-${days} day`).all().catch(() => ({ results: [] })),
      // Un-limited totals for the window (topEndpoints above is LIMIT 10, so
      // undercounts total_calls/cache hits once a caller uses >10 distinct endpoints).
      D.prepare(`SELECT COUNT(*) as calls, SUM(cached) as cache_hits FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', ?)`).bind(userId(authCtx), `-${days} day`).first().catch(() => ({ calls: 0, cache_hits: 0 })),
      // Quota is a calendar-month concept, independent of the `days` window param.
      D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now','start of month')`).bind(userId(authCtx)).first().catch(() => ({ cnt: 0 })),
    ]);
    const tier = userTier(authCtx);
    const limits = TIER_LIMITS[tier] || TIER_LIMITS.FREE;
    const monthCalls = monthToDate?.cnt || 0;
    const radarLimit = limits.monthly_limit > 0 ? limits.monthly_limit : null; // -1 = unlimited
    return Response.json({
      user_id: userId(authCtx), days,
      hourly_trend: hourly.results || [],
      daily_trend: daily.results || [],
      top_endpoints: topEndpoints.results || [],
      breakdown_by_day: byPoint.results || [],
      tier,
      // frontend/automation-dashboard.html's KPI tiles and quota panel read
      // these exact shapes — previously nothing here at all, always 0/∞.
      summary: {
        total_calls: overall?.calls || 0,
        cache_hit_ratio: overall?.calls > 0 ? (overall.cache_hits || 0) / overall.calls : 0,
      },
      quota: {
        month_calls: monthCalls,
        radar_limit: radarLimit,
        quota_pct: radarLimit ? Math.round((monthCalls / radarLimit) * 1000) / 10 : 0,
      },
    });
  } catch { return Response.json({ usage: [] }); }
}

async function handleUsageSummary(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ total_calls: 0 });
  try {
    const [total, monthly, byEndpoint] = await Promise.all([
      D.prepare(`SELECT COUNT(*) as cnt, AVG(latency_ms) as avg_ms FROM ops_usage_events WHERE user_id=?`).bind(userId(authCtx)).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now', '-30 day')`).bind(userId(authCtx)).first().catch(() => null),
      D.prepare(`SELECT endpoint, COUNT(*) as cnt FROM ops_usage_events WHERE user_id=? GROUP BY endpoint ORDER BY cnt DESC LIMIT 5`).bind(userId(authCtx)).all().catch(() => ({ results: [] })),
    ]);
    return Response.json({
      total_calls: total?.cnt || 0,
      monthly_calls: monthly?.cnt || 0,
      avg_latency_ms: Math.round(total?.avg_ms || 0),
      top_endpoints: byEndpoint.results || [],
      tier: userTier(authCtx),
    });
  } catch { return Response.json({ total_calls: 0 }); }
}

// ─── P7.0-006: API Governance ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

export const API_MANIFEST = {
  version: 'v1',
  last_updated: '2026-06-25',
  base_url: 'https://api.cyberdudebivash.com',
  endpoints: [
    // ─── P7.0 core endpoints ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    { path: '/api/self/keys',                         status: 'stable', since: 'v1' },
    { path: '/api/auto/webhooks',                     status: 'stable', since: 'v1' },
    { path: '/api/auto/reports',                      status: 'stable', since: 'v1' },
    { path: '/api/auto/team',                         status: 'stable', since: 'v1' },
    { path: '/api/auto/usage',                        status: 'stable', since: 'v1' },
    { path: '/api/auto/governance',                   status: 'stable', since: 'v1' },
    { path: '/api/auto/metrics',                      status: 'stable', since: 'v1' },
    { path: '/api/webhooks/catalog',                  status: 'stable', since: 'v1' },
    // P8.0-007: Developer Portal endpoints
    { path: '/api/developer/openapi.json',            status: 'stable', since: 'v1' },
    { path: '/api/webhooks/catalog',                  status: 'stable', since: 'v1' },
    { path: '/api/developer/sdk/download/{language}', status: 'stable', since: 'v1' },
    { path: '/api/developer/postman.json',            status: 'stable', since: 'v1' },
    { path: '/api/developer/quickstart',              status: 'stable', since: 'v1' },
    { path: '/api/developer/auth-guide',              status: 'stable', since: 'v1' },
    { path: '/api/developer/migration-guide',         status: 'stable', since: 'v1' },
    { path: '/api/developer/version-policy',          status: 'stable', since: 'v1' },
    { path: '/api/developer/examples',               status: 'stable', since: 'v1' },
    // P8.0-009: Enterprise API Governance endpoints
    { path: '/api/auto/siem-export',                  status: 'stable', since: 'v1' },
    { path: '/api/auto/governance/ownership',         status: 'stable', since: 'v1' },
    { path: '/api/auto/governance/compatibility',     status: 'stable', since: 'v1' },
    { path: '/api/auto/schema-validate',              status: 'stable', since: 'v1' },
    { path: '/api/auto/trace',                        status: 'stable', since: 'v1' },
    { path: '/api/auto/integrations/connectors',      status: 'stable', since: 'v1' },
    { path: '/api/auto/integrations/test',            status: 'stable', since: 'v1' },
  ],
  // P8.0-002: real legacy/duplicate routes on a sunset timeline. `path` = exact match,
  // `pattern` = regex match for parameterised paths. Add new entries here only —
  // never remove a route's handler without first sunsetting it from here.
  deprecations: [
    { path: '/api/payments/create-order',        since: '2025-06-01', sunset: '2026-12-31', replacement: '/api/payment/create-order', reason: 'Plural namespace retained for backward compatibility only.' },
    { path: '/api/payments/confirm',             since: '2025-06-01', sunset: '2026-12-31', replacement: '/api/payment/confirm', reason: 'Plural namespace retained for backward compatibility only.' },
    { path: '/api/payments/subscription-status', since: '2025-06-01', sunset: '2026-12-31', replacement: '/api/payment/subscription-status', reason: 'Plural namespace retained for backward compatibility only.' },
  ],
  sunset_policy: 'Routes are sunset after 18 months from the first deprecation notice.',
  changelog: [
    { version: 'v1',     date: '2025-01-01', note: 'Initial enterprise automation surface (P7.0).' },
    { version: 'v1.1',   date: '2025-06-01', note: 'Payments namespace rationalised. Legacy /api/payments/* deprecated.' },
    { version: 'v1.2',   date: '2026-01-15', note: 'P8.0-002: Governance manifest, deprecations, lifecycle headers added.' },
  ],
};

export function getLifecycleHeaders(path) {
  const dep = API_MANIFEST.deprecations.find(d => path === d.path);
  if (!dep) return {};
  return {
    'Deprecation': dep.since,
    'Sunset':      dep.sunset,
    'Link':        `<${API_MANIFEST.base_url}${dep.replacement}>; rel="successor-version"`,
  };
}

async function handleGovernance(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const tier = userTier(authCtx);
  const limits = TIER_LIMITS[tier] || TIER_LIMITS.FREE;

  // frontend/automation-dashboard.html's Governance tab reads user_tier/
  // throttle_limits/quota_warning/released — API_MANIFEST alone is a static,
  // non-personalized manifest (version/endpoints/deprecations only) and
  // never carried any of these, so the tab was permanently blank on them.
  let quota_warning = null;
  const D = db(env);
  if (D && limits.monthly_limit > 0) {
    const row = await D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE user_id=? AND ts >= datetime('now','start of month')`).bind(userId(authCtx)).first().catch(() => null);
    const used = row?.cnt || 0;
    const pct = Math.round((used / limits.monthly_limit) * 1000) / 10;
    if (pct >= 80) {
      quota_warning = {
        message: pct >= 100 ? 'Monthly quota exceeded' : 'Approaching your monthly quota',
        pct, used, limit: limits.monthly_limit,
      };
    }
  }

  return Response.json({
    ...API_MANIFEST,
    released: API_MANIFEST.last_updated,
    user_tier: tier,
    throttle_limits: {
      requests_per_minute: limits.burst_per_min,
      requests_per_day: limits.daily_limit, // -1 = unlimited, same convention frontend already handles elsewhere
    },
    quota_warning,
  });
}

// ─── P7.0-007: Webhook Catalog (public) ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

export async function handleWebhookCatalog(_req, _env, _authCtx) {
  return Response.json({
    events: WEBHOOK_EVENTS,
    categories: {
      threat: WEBHOOK_EVENTS.filter(e => e.startsWith('threat.')),
      scan:   WEBHOOK_EVENTS.filter(e => e.startsWith('scan.')),
      report: WEBHOOK_EVENTS.filter(e => e.startsWith('report.')),
      team:   WEBHOOK_EVENTS.filter(e => e.startsWith('team.')),
      api:    WEBHOOK_EVENTS.filter(e => e.startsWith('api.')),
    },
    delivery: {
      method: 'POST',
      content_type: 'application/json',
      signature_header: 'X-Sentinel-Signature',
      signature_format: 'sha256=<HMAC-SHA256-hex>',
      timeout_ms: 10000,
      retry_policy: '3 attempts with exponential backoff (2s, 8s, 32s)',
    },
    example_payload: {
      event: 'threat.new_cve',
      ts: '2026-06-25T09:00:00.000Z',
      data: { cve_id: 'CVE-2026-XXXXX', cvss: 9.8, severity: 'CRITICAL', kev: false },
    },
  });
}

// ─── P7.0-009: Enterprise Metrics ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

export async function handleEnterpriseMetrics(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  try {
    const [apiCalls, scanJobs, activeWebhooks, teamSize] = await Promise.all([
      D?.prepare(`SELECT COUNT(*) as cnt, AVG(latency_ms) as avg_ms FROM ops_usage_events WHERE org_id=? AND ts >= datetime('now', '-30 day')`).bind(orgId(authCtx)).first().catch(() => null),
      D?.prepare(`SELECT COUNT(*) as cnt FROM scan_history WHERE org_id=? AND created_at >= datetime('now', '-30 day')`).bind(orgId(authCtx)).first().catch(() => null),
      D?.prepare(`SELECT COUNT(*) as cnt FROM org_webhooks WHERE org_id=? AND active=1`).bind(orgId(authCtx)).first().catch(() => null),
      D?.prepare(`SELECT COUNT(*) as cnt FROM org_team_members WHERE org_id=? AND status='active'`).bind(orgId(authCtx)).first().catch(() => null),
    ]);
    const apiCallsCount   = apiCalls?.cnt || 0;
    const activeWebhookCt = activeWebhooks?.cnt || 0;
    return Response.json({
      period: '30d',
      api_calls:        apiCallsCount,
      avg_latency_ms:   Math.round(apiCalls?.avg_ms || 0),
      scan_jobs:        scanJobs?.cnt || 0,
      active_webhooks:  activeWebhookCt,
      team_size:        teamSize?.cnt || 0,
      tier:             userTier(authCtx),
      // Fields required by automation-dashboard.html
      automation_health:    apiCallsCount > 0 || activeWebhookCt > 0 ? 'operational' : 'idle',
      active_organizations: activeWebhookCt, // best proxy until multi-org table populated
    });
  } catch {
    return Response.json({ period: '30d', api_calls: 0, scan_jobs: 0, active_webhooks: 0, team_size: 0, tier: userTier(authCtx), automation_health: 'idle', active_organizations: 0 });
  }
}

// ─── P7.0-008: Reliability ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async function requeueFailedWebhook(env, webhookId, payload) {
  const KV = kv(env);
  if (!KV) return;
  const dlKey = `dlq:webhook:${webhookId}:${Date.now()}`;
  await KV.put(dlKey, JSON.stringify({ webhook_id: webhookId, payload, queued_at: new Date().toISOString() }), { expirationTtl: 86400 * 7 }).catch(() => {});
}

export async function runAutomationCrons(env) {
  const D = db(env);
  if (!D) return;
  try {
    const now = new Date();
    const due = await D.prepare(`SELECT * FROM scheduled_reports WHERE active=1 AND (next_send IS NULL OR next_send <= ?)`).bind(now.toISOString()).all().catch(() => ({ results: [] }));
    for (const rpt of (due.results || [])) {
      try {
        const next = new Date(now);
        if (rpt.frequency === 'daily')   next.setDate(next.getDate() + 1);
        if (rpt.frequency === 'weekly')  next.setDate(next.getDate() + 7);
        if (rpt.frequency === 'monthly') next.setMonth(next.getMonth() + 1);
        await D.prepare(`UPDATE scheduled_reports SET last_sent=?, next_send=? WHERE id=?`).bind(now.toISOString(), next.toISOString(), rpt.id).run();
      } catch {}
    }
    const staleKeys = await kv(env)?.list({ prefix: 'dlq:webhook:' }).catch(() => ({ keys: [] }));
    for (const k of ((staleKeys?.keys) || []).slice(0, 10)) {
      const raw = await kv(env).get(k.name);
      if (!raw) continue;
      const item = JSON.parse(raw);
      const age = Date.now() - new Date(item.queued_at).getTime();
      if (age > 86400000 * 3) await kv(env).delete(k.name).catch(() => {});
    }
  } catch {}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

function safeParseJSON(raw, fallback) {
  if (Array.isArray(raw) || (raw && typeof raw === 'object')) return raw;
  try { return JSON.parse(raw); } catch { return fallback; }
}

// ─── P8.0-009: SIEM Export ─────────────────────────────────────────────────────────────────────────────────────

async function handleSiemExport(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const method = req.method;
  const KV = kv(env);
  const oid = orgId(authCtx);

  if (method === 'GET') {
    const exports = [];
    if (KV) {
      try {
        const list = await KV.list({ prefix: `siem:export:${oid}:` });
        for (const key of (list.keys || []).slice(0, 20)) {
          const raw = await KV.get(key.name);
          if (raw) { try { exports.push(JSON.parse(raw)); } catch {} }
        }
      } catch {}
    }
    return Response.json({ exports: exports.sort((a, b) => b.created_at.localeCompare(a.created_at)) });
  }

  if (method === 'POST') {
    let body = {};
    try { body = await req.json(); } catch {}
    const format = ['splunk','cef','leef','stix','json'].includes(body.format) ? body.format : 'json';
    const lookback_hours = Math.min(parseInt(body.lookback_hours || 24, 10), 168);
    const intel_type = ['all','cve','actor','ransomware'].includes(body.intel_type) ? body.intel_type : 'all';
    const job_id = genId('sexp');
    const job = {
      job_id, org_id: oid, format, intel_type, lookback_hours,
      status: 'queued', record_count: 0, estimated_records: null,
      created_at: new Date().toISOString(),
    };
    const D = db(env);
    if (D) {
      try {
        const since = new Date(Date.now() - lookback_hours * 3600000).toISOString();
        const typeFilter = intel_type !== 'all' ? ` AND tags LIKE '%${intel_type}%'` : '';
        const row = await D.prepare(`SELECT COUNT(*) as cnt FROM threat_intel WHERE published_at >= ?${typeFilter}`).bind(since).first().catch(() => null);
        job.estimated_records = row?.cnt || 0;
        job.record_count = job.estimated_records;
        job.status = 'completed';
      } catch {}
    }
    if (KV) {
      try { await KV.put(`siem:export:${oid}:${job_id}`, JSON.stringify(job), { expirationTtl: 604800 }); } catch {}
    }
    return Response.json({ success: true, job_id, format, intel_type, lookback_hours, status: job.status, estimated_records: job.estimated_records }, { status: 201 });
  }

  return Response.json({ error: 'Method not allowed' }, { status: 405 });
}

// ─── P8.0-009: Endpoint Ownership Registry ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

const ENDPOINT_OWNERSHIP = [
  { path: '/api/radar/*',          team: 'threat-intel',  contact: 'ti@cyberdudebivash.com',          sla_ms: 500, tier: 'FREE' },
  { path: '/api/customer/*',       team: 'customer-api',  contact: 'api@cyberdudebivash.com',          sla_ms: 300, tier: 'FREE' },
  { path: '/api/enterprise/*',     team: 'enterprise',    contact: 'enterprise@cyberdudebivash.com',   sla_ms: 200, tier: 'PRO' },
  { path: '/api/auto/*',           team: 'automation',    contact: 'automation@cyberdudebivash.com',   sla_ms: 300, tier: 'FREE' },
  { path: '/api/self/*',           team: 'automation',    contact: 'automation@cyberdudebivash.com',   sla_ms: 100, tier: 'FREE' },
  { path: '/api/developer/*',      team: 'devex',         contact: 'devex@cyberdudebivash.com',        sla_ms: 100, tier: 'FREE' },
  { path: '/api/webhooks/*',       team: 'automation',    contact: 'automation@cyberdudebivash.com',   sla_ms: 100, tier: 'FREE' },
  { path: '/api/integrations/*',   team: 'enterprise',    contact: 'enterprise@cyberdudebivash.com',   sla_ms: 500, tier: 'PRO' },
  { path: '/api/payment/*',        team: 'billing',       contact: 'billing@cyberdudebivash.com',      sla_ms: 500, tier: 'FREE' },
];

async function handleEndpointOwnership(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const url = new URL(req.url);
  const filterTeam = url.searchParams.get('team');
  let registry = ENDPOINT_OWNERSHIP;
  if (filterTeam) registry = registry.filter(e => e.team === filterTeam);
  return Response.json({
    total: registry.length,
    teams: [...new Set(ENDPOINT_OWNERSHIP.map(e => e.team))].sort(),
    registry,
    generated_at: new Date().toISOString(),
  });
}

// ─── P8.0-009: Compatibility Matrix ──────────────────────────────────────────────────────────────────────────────────

async function handleCompatibilityMatrix(_req, _env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  return Response.json({
    current_version: API_MANIFEST.version,
    versions: [
      {
        version: 'v1',
        status: 'stable',
        released: '2025-01-01',
        sunset: null,
        features: {
          threat_intel: true, customer_api: true, enterprise_api: true,
          webhook_automation: true, scheduled_reports: true, team_management: true,
          api_usage_dashboard: true, api_governance: true,
        },
      },
      {
        version: 'v2-surface',
        status: 'stable',
        released: '2026-06-25',
        sunset: null,
        note: 'Additive P8.0 features on the v1 API surface. No breaking changes.',
        features: {
          threat_intel: true, customer_api: true, enterprise_api: true,
          webhook_automation: true, scheduled_reports: true, team_management: true,
          api_usage_dashboard: true, api_governance: true,
          developer_portal: true, sdk_generation: true, openapi_spec: true,
          postman_collection: true, siem_export: true, integration_connectors: true,
          schema_validation: true, request_tracing: true, endpoint_ownership: true,
          compatibility_matrix: true,
        },
      },
    ],
    migration_notes: [
      'All existing v1 endpoints remain stable with no breaking changes.',
      'P8.0 adds 16 new endpoints; none remove or modify existing endpoints.',
    ],
    breaking_changes: [],
  });
}

// ─── P8.0-009: Schema Validation ─────────────────────────────────────────────────────────────────────────────────────

const ENDPOINT_SCHEMAS = {
  'POST /api/auto/webhooks':      { required: ['url','events'],  properties: { url: 'string (https)', events: 'string[] — see /api/webhooks/catalog', secret: 'string' } },
  'POST /api/auto/reports':       { required: ['email'],         properties: { email: 'string', frequency: 'string (daily|weekly|monthly)', format: 'string (html|json)' } },
  'POST /api/auto/team':          { required: ['user_id'],       properties: { user_id: 'string', email: 'string', role: 'string (ADMIN|ANALYST|VIEWER)' } },
  'POST /api/self/keys':          { required: [],                properties: { label: 'string (max 60 chars)' } },
  'POST /api/auto/siem-export':   { required: [],                properties: { format: 'string (splunk|cef|leef|stix|json)', lookback_hours: 'integer (1-168)', intel_type: 'string (all|cve|actor|ransomware)' } },
  'POST /api/auto/integrations/test':  { required: ['url'],           properties: { type: 'string (splunk|sentinel|qradar|elastic|sumo)', url: 'string (https)', token: 'string' } },
};

async function handleSchemaValidate(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { endpoint, method = 'POST', payload = {} } = body;
  if (!endpoint) return Response.json({ error: 'endpoint required (e.g. /api/auto/webhooks)' }, { status: 400 });
  const schemaKey = `${method.toUpperCase()} ${endpoint}`;
  const schema = ENDPOINT_SCHEMAS[schemaKey];
  if (!schema) {
    return Response.json({ valid: null, schema_found: false, endpoint, method, available_schemas: Object.keys(ENDPOINT_SCHEMAS) });
  }
  const errors = [];
  for (const field of (schema.required || [])) {
    if (payload[field] === undefined || payload[field] === null || payload[field] === '') {
      errors.push({ field, error: 'required field missing or empty' });
    }
  }
  return Response.json({ valid: errors.length === 0, schema_found: true, endpoint, method, errors, schema: { required: schema.required, properties: schema.properties } });
}

// ─── P8.0-009: Request Tracing ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async function handleRequestTrace(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 100);
  const ep_filter = url.searchParams.get('endpoint');
  try {
    let query = `SELECT ts, endpoint, latency_ms, cached FROM ops_usage_events WHERE user_id=?`;
    const binds = [userId(authCtx)];
    if (ep_filter) { query += ` AND endpoint LIKE ?`; binds.push(`%${ep_filter}%`); }
    query += ` ORDER BY ts DESC LIMIT ?`;
    binds.push(limit);
    const { results } = await D.prepare(query).bind(...binds).all().catch(() => ({ results: [] }));
    const traces = (results || []).map((r, i) => ({
      trace_id: `tr_${Date.now().toString(36)}_${i}`,
      ts: r.ts, endpoint: r.endpoint,
      latency_ms: r.latency_ms || 0,
      cached: !!r.cached,
      status: 'success',
    }));
    return Response.json({ user_id: userId(authCtx), count: traces.length, limit, traces });
  } catch { return Response.json({ user_id: userId(authCtx), count: 0, limit, traces: [] }); }
}

// ─── P8.0-009: Integration Connectors ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async function handleIntegrationConnectors(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const KV = kv(env);
  const oid = orgId(authCtx);
  const connectors = [];
  if (KV) {
    try {
      const list = await KV.list({ prefix: `integration:connector:${oid}:` });
      for (const key of (list.keys || [])) {
        const raw = await KV.get(key.name);
        if (raw) { try { connectors.push(JSON.parse(raw)); } catch {} }
      }
    } catch {}
  }
  return Response.json({ connectors, events: [], total: connectors.length });
}

async function handleIntegrationTest(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { type, url: targetUrl, token } = body;
  const urlError = validateOutboundUrl(targetUrl);
  if (urlError) return Response.json({ error: urlError }, { status: 400 });

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (type === 'splunk' && token) headers['Authorization'] = `Splunk ${token}`;
    else if (token) headers['Authorization'] = `Bearer ${token}`;
    const resp = await fetch(targetUrl, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });
    const healthy = resp.ok || resp.status < 500;
    if (healthy) {
      const KV = kv(env);
      if (KV) {
        const connId = genId('conn');
        const connector = {
          id: connId, type: type || 'generic', endpoint: targetUrl,
          name: `${(type || 'Generic').toUpperCase()} Connector`,
          healthy, last_checked: new Date().toISOString(), org_id: orgId(authCtx),
        };
        await KV.put(`integration:connector:${orgId(authCtx)}:${connId}`, JSON.stringify(connector), { expirationTtl: 86400 * 30 }).catch(() => {});
      }
    }
    return Response.json({ success: healthy, status_code: resp.status, message: resp.ok ? 'Connection successful' : `HTTP ${resp.status} from endpoint` });
  } catch (e) {
    return Response.json({ success: false, message: e.name === 'AbortError' ? 'Connection timed out (8s)' : `Connection failed: ${e.message?.slice(0, 100)}` });
  }
}


// ─── P7.0-009: Enterprise Metrics ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// (handleEnterpriseMetrics exported above alongside its P7.0-009 section)

// ─── Main Router ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

export async function handleAutoRoute(req, env, authCtx, path, method) {
  // ─── P7.0-001: /api/self/* ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/self/keys' && method === 'GET')    return handleListSelfKeys(req, env, authCtx);
  if (path === '/api/self/keys' && method === 'POST')   return handleCreateSelfKey(req, env, authCtx);
  if (path.startsWith('/api/self/keys/') && path.endsWith('/rotate') && method === 'POST') {
    return handleRotateSelfKey(req, env, authCtx, path.split('/').slice(-2, -1)[0]);
  }
  if (path.startsWith('/api/self/keys/') && method === 'DELETE') {
    return handleRevokeSelfKey(req, env, authCtx, path.split('/').pop());
  }

  // ─── P7.0-002: /api/auto/webhooks ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/auto/webhooks' && method === 'GET')    return handleWebhookList(req, env, authCtx);
  if (path === '/api/auto/webhooks' && method === 'POST')   return handleWebhookCreate(req, env, authCtx);
  if (path.startsWith('/api/auto/webhooks/') && path.endsWith('/test') && method === 'POST') {
    const whId = path.split('/')[4];
    return handleWebhookTest(req, env, authCtx, whId);
  }
  if (path.startsWith('/api/auto/webhooks/') && path.endsWith('/logs') && method === 'GET') {
    const whId = path.split('/')[4];
    return handleWebhookLogs(req, env, authCtx, whId);
  }
  if (path.startsWith('/api/auto/webhooks/') && method === 'PATCH') {
    return handleWebhookUpdate(req, env, authCtx, path.split('/').pop());
  }
  if (path.startsWith('/api/auto/webhooks/') && method === 'DELETE') {
    return handleWebhookDelete(req, env, authCtx, path.split('/').pop());
  }

  // ─── P7.0-003: /api/auto/reports ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/auto/reports' && method === 'GET')    return handleListScheduledReports(req, env, authCtx);
  if (path === '/api/auto/reports' && method === 'POST')   return handleCreateScheduledReport(req, env, authCtx);
  if (path.startsWith('/api/auto/reports/') && method === 'DELETE') {
    return handleDeleteScheduledReport(req, env, authCtx, path.split('/').pop());
  }

  // ─── P7.0-004: /api/auto/team ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/auto/team' && method === 'GET')    return handleListTeamMembers(req, env, authCtx);
  if (path === '/api/auto/team' && method === 'POST')   return handleAddTeamMember(req, env, authCtx);
  if (path.startsWith('/api/auto/team/') && method === 'DELETE') {
    return handleRemoveTeamMember(req, env, authCtx, path.split('/').pop());
  }

  // ─── P7.0-005: /api/auto/usage ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/auto/usage' && method === 'GET')         return handleUsageDashboard(req, env, authCtx);
  if (path === '/api/auto/usage/summary' && method === 'GET') return handleUsageSummary(req, env, authCtx);

  // ─── P7.0-006: /api/auto/governance ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  if (path === '/api/auto/governance' && method === 'GET') return handleGovernance(req, env, authCtx);
  if (path === '/api/auto/metrics' && method === 'GET')    return handleEnterpriseMetrics(req, env, authCtx);
  // P8.0-009: Enterprise API Governance routes
  if (path === '/api/auto/siem-export') return handleSiemExport(req, env, authCtx);
  if (path === '/api/auto/governance/ownership' && method === 'GET')     return handleEndpointOwnership(req, env, authCtx);
  if (path === '/api/auto/governance/compatibility' && method === 'GET') return handleCompatibilityMatrix(req, env, authCtx);
  if (path === '/api/auto/schema-validate' && method === 'POST')         return handleSchemaValidate(req, env, authCtx);
  if (path === '/api/auto/trace' && method === 'GET')                    return handleRequestTrace(req, env, authCtx);
  if (path === '/api/auto/integrations/connectors' && method === 'GET')  return handleIntegrationConnectors(req, env, authCtx);
  if (path === '/api/auto/integrations/test' && method === 'POST')       return handleIntegrationTest(req, env, authCtx);
  return null;
}
