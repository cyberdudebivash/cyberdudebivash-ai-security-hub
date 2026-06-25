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

import { createApiKey, listUserApiKeys, revokeApiKey, getKeyUsageSummary, TIER_LIMITS } from '../auth/apiKeys.js';

// ─── D1 bootstrap ──────────────────────────────────────────────────────────────
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
        active INTEGER DEFAULT 1,
        last_sent TEXT,
        next_send TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS org_teams (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        email TEXT,
        role TEXT NOT NULL DEFAULT 'VIEWER',
        invited_by TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, user_id)
      )`),
    ]);
    _autoTablesReady = true;
  } catch {}
}

function genId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}
function db(env) { return env.SECURITY_HUB_DB || env.DB; }
function kv(env)  { return env.SECURITY_HUB_KV || env.KV; }

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function userId(authCtx) { return authCtx?.userId || authCtx?.user_id; }
function orgId(authCtx)  { return authCtx?.orgId  || userId(authCtx); }
function tier(authCtx)   { return (authCtx?.tier || 'FREE').toUpperCase(); }
function isAdmin(authCtx){ return ['ADMIN','OWNER'].includes(tier(authCtx)); }

function requireAuth(authCtx) {
  if (!authCtx?.authenticated) return Response.json({ error: 'Authentication required' }, { status: 401 });
  return null;
}

// ─── P7.0-001: API Key Self-Service ──────────────────────────────────────────

async function handleListSelfKeys(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  const keys = await listUserApiKeys(D, userId(authCtx));
  const maxKeys = tier(authCtx) === 'ENTERPRISE' ? 20 : tier(authCtx) === 'PRO' ? 5 : 2;
  return Response.json({ keys, count: keys.length, max_keys: maxKeys, tier: tier(authCtx), limits: TIER_LIMITS[tier(authCtx)] || TIER_LIMITS.FREE });
}

async function handleCreateSelfKey(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  let body = {};
  try { body = await req.json(); } catch {}
  const label = (body.label || body.name || 'API Key').toString().slice(0, 60);
  const maxKeys = tier(authCtx) === 'ENTERPRISE' ? 20 : tier(authCtx) === 'PRO' ? 5 : 2;
  const existing = await listUserApiKeys(D, userId(authCtx));
  if (existing.filter(k => k.active).length >= maxKeys)
    return Response.json({ error: `Key limit reached (${maxKeys} for ${tier(authCtx)})`, upgrade_url: '/#pricing' }, { status: 409 });
  const result = await createApiKey(D, userId(authCtx), tier(authCtx), label);
  return Response.json({ success: true, key: result.raw_key, prefix: result.prefix, label: result.label, tier: result.tier, warning: 'Store this key securely — shown only once.' }, { status: 201 });
}

async function handleRevokeSelfKey(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  const revoked = await revokeApiKey(D, keyId, userId(authCtx));
  if (!revoked) return Response.json({ error: 'Key not found or already revoked' }, { status: 404 });
  return Response.json({ success: true, key_id: keyId });
}

async function handleRotateSelfKey(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  // Get existing key label before revoking
  const existing = await listUserApiKeys(D, userId(authCtx));
  const target = existing.find(k => k.id === keyId);
  if (!target) return Response.json({ error: 'Key not found' }, { status: 404 });
  await revokeApiKey(D, keyId, userId(authCtx));
  const result = await createApiKey(D, userId(authCtx), tier(authCtx), target.label || 'Rotated Key');
  return Response.json({ success: true, rotated: keyId, new_key: result.raw_key, prefix: result.prefix, label: result.label, warning: 'Old key revoked. Store new key securely — shown only once.' }, { status: 201 });
}

async function handleUpdateKeyLabel(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  let body = {};
  try { body = await req.json(); } catch {}
  const label = (body.label || '').toString().slice(0, 60);
  if (!label) return Response.json({ error: 'label required' }, { status: 400 });
  try {
    await D.prepare(`UPDATE api_keys SET label=? WHERE id=? AND user_id=?`).bind(label, keyId, userId(authCtx)).run();
    return Response.json({ success: true, key_id: keyId, label });
  } catch { return Response.json({ error: 'Update failed' }, { status: 500 }); }
}

async function handleKeyUsageSelf(req, env, authCtx, keyId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env); if (!D) return Response.json({ error: 'DB unavailable' }, { status: 503 });
  const usage = await getKeyUsageSummary(D, keyId, userId(authCtx));
  return Response.json({ key_id: keyId, ...usage });
}

// ─── P7.0-002: Webhook Automation ────────────────────────────────────────────

const WEBHOOK_EVENTS = ['cve.critical','kev.added','ransomware.campaign','actor.update','org.risk_change'];

async function handleListWebhooks(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const oid = orgId(authCtx);
  const { results } = await D.prepare(
    `SELECT id,url,events,active,retry_count,last_triggered,created_at FROM org_webhooks WHERE org_id=? ORDER BY created_at DESC`
  ).bind(oid).all().catch(() => ({ results: [] }));
  return Response.json({ webhooks: results || [], supported_events: WEBHOOK_EVENTS });
}

async function handleCreateWebhook(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { url, events = [], secret } = body;
  if (!url || !/^https:\/\//.test(url)) return Response.json({ error: 'HTTPS url required' }, { status: 400 });
  const validEvents = (Array.isArray(events) ? events : []).filter(e => WEBHOOK_EVENTS.includes(e));
  if (!validEvents.length) return Response.json({ error: `events must include one of: ${WEBHOOK_EVENTS.join(', ')}` }, { status: 400 });
  const D = db(env);
  await ensureAutoTables(D);
  const id = genId('wh');
  await D.prepare(
    `INSERT INTO org_webhooks (id,org_id,owner_id,url,events,secret) VALUES (?,?,?,?,?,?)`
  ).bind(id, orgId(authCtx), userId(authCtx), url, JSON.stringify(validEvents), secret || null).run();
  return Response.json({ success: true, id, url, events: validEvents }, { status: 201 });
}

async function handleDeleteWebhook(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const r = await D.prepare(`DELETE FROM org_webhooks WHERE id=? AND org_id=?`).bind(whId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Webhook not found' }, { status: 404 });
  return Response.json({ success: true, id: whId });
}

async function handleUpdateWebhook(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch {}
  const D = db(env);
  await ensureAutoTables(D);
  const sets = []; const binds = [];
  if (typeof body.active === 'boolean') { sets.push('active=?'); binds.push(body.active ? 1 : 0); }
  if (body.url && /^https:\/\//.test(body.url)) { sets.push('url=?'); binds.push(body.url); }
  if (Array.isArray(body.events)) {
    const valid = body.events.filter(e => WEBHOOK_EVENTS.includes(e));
    sets.push('events=?'); binds.push(JSON.stringify(valid));
  }
  if (!sets.length) return Response.json({ error: 'No valid fields to update' }, { status: 400 });
  binds.push(whId, orgId(authCtx));
  await D.prepare(`UPDATE org_webhooks SET ${sets.join(',')} WHERE id=? AND org_id=?`).bind(...binds).run();
  return Response.json({ success: true, id: whId });
}

async function handleWebhookLogs(req, env, authCtx, whId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT id,event_type,status,attempt,response_code,error_msg,created_at FROM webhook_delivery_log
     WHERE webhook_id=? ORDER BY created_at DESC LIMIT 50`
  ).bind(whId).all().catch(() => ({ results: [] }));
  return Response.json({ webhook_id: whId, logs: results || [] });
}

// Dispatch webhooks for an event — called from cron
export async function dispatchWebhookEvent(env, eventType, payload) {
  const D = db(env); if (!D) return;
  try {
    await ensureAutoTables(D);
    const { results } = await D.prepare(
      `SELECT id,org_id,url,secret FROM org_webhooks WHERE active=1 AND events LIKE ?`
    ).bind(`%${eventType}%`).all();
    for (const wh of (results || [])) {
      const body = JSON.stringify({ event: eventType, payload, ts: new Date().toISOString() });
      const headers = { 'Content-Type': 'application/json', 'X-SBHUB-Event': eventType };
      if (wh.secret) {
        // HMAC-SHA256 signature
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey('raw', enc.encode(wh.secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', key, enc.encode(body));
        headers['X-SBHUB-Signature'] = `sha256=${Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('')}`;
      }
      const logId = genId('wdl');
      const payloadHash = `${eventType}:${Date.now()}`;
      let status = 'failed'; let code = 0; let errMsg = null;
      try {
        const resp = await fetch(wh.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10000) });
        code = resp.status; status = resp.ok ? 'delivered' : 'failed';
        if (!resp.ok) errMsg = `HTTP ${code}`;
      } catch (e) {
        errMsg = e.message?.slice(0, 100); status = 'failed';
        // Push to retry queue in KV
        const kvStore = kv(env);
        if (kvStore) {
          const retryKey = `webhook:retry:${wh.id}:${Date.now()}`;
          await kvStore.put(retryKey, JSON.stringify({ webhook_id: wh.id, url: wh.url, eventType, payload, secret: wh.secret, attempt: 1 }),
            { expirationTtl: 3600 }).catch(() => {});
        }
      }
      await D.prepare(
        `INSERT INTO webhook_delivery_log (id,webhook_id,org_id,event_type,payload_hash,status,response_code,error_msg) VALUES (?,?,?,?,?,?,?,?)`
      ).bind(logId, wh.id, wh.org_id, eventType, payloadHash, status, code, errMsg).run().catch(() => {});
      if (status === 'delivered') {
        await D.prepare(`UPDATE org_webhooks SET last_triggered=datetime('now') WHERE id=?`).bind(wh.id).run().catch(() => {});
      }
    }
  } catch {}
}

// Retry failed webhooks from KV queue
async function processWebhookRetryQueue(env) {
  const kvStore = kv(env); if (!kvStore) return { retried: 0, dead_lettered: 0 };
  const D = db(env);
  let retried = 0; let deadLettered = 0;
  try {
    const list = await kvStore.list({ prefix: 'webhook:retry:' });
    for (const key of (list.keys || []).slice(0, 20)) {
      const raw = await kvStore.get(key.name);
      if (!raw) continue;
      let job;
      try { job = JSON.parse(raw); } catch { await kvStore.delete(key.name); continue; }
      if (job.attempt >= 5) {
        // Dead-letter
        await kvStore.put(`webhook:dead:${job.webhook_id}:${Date.now()}`, raw, { expirationTtl: 604800 }).catch(() => {});
        await kvStore.delete(key.name);
        deadLettered++;
        // Mark in D1
        if (D) await ensureAutoTables(D).then(() =>
          D.prepare(`INSERT INTO webhook_delivery_log (id,webhook_id,event_type,status,attempt,error_msg) VALUES (?,?,?,?,?,?)`)
           .bind(genId('wdl'), job.webhook_id, job.eventType, 'dead_lettered', job.attempt, 'Max retries exceeded').run()
        ).catch(() => {});
        continue;
      }
      // Retry with exponential backoff check (backoff stored in KV key name doesn't matter here — just attempt)
      try {
        const body = JSON.stringify({ event: job.eventType, payload: job.payload, ts: new Date().toISOString(), retry: job.attempt });
        const headers = { 'Content-Type': 'application/json', 'X-SBHUB-Event': job.eventType };
        const resp = await fetch(job.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10000) });
        if (resp.ok) {
          await kvStore.delete(key.name);
          retried++;
        } else {
          job.attempt++;
          await kvStore.put(key.name, JSON.stringify(job), { expirationTtl: 3600 * Math.pow(2, job.attempt) }).catch(() => {});
        }
      } catch {
        job.attempt++;
        await kvStore.put(key.name, JSON.stringify(job), { expirationTtl: 3600 * Math.pow(2, job.attempt) }).catch(() => {});
      }
    }
  } catch {}
  return { retried, dead_lettered: deadLettered };
}

// ─── P7.0-003: Scheduled Reports ─────────────────────────────────────────────

const VALID_FREQUENCIES = ['daily','weekly','monthly'];

async function handleListScheduledReports(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT id,frequency,email,format,active,last_sent,next_send,created_at FROM scheduled_reports WHERE org_id=? ORDER BY created_at DESC`
  ).bind(orgId(authCtx)).all().catch(() => ({ results: [] }));
  return Response.json({ schedules: results || [], supported_frequencies: VALID_FREQUENCIES });
}

async function handleCreateScheduledReport(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { frequency = 'weekly', email, format = 'html' } = body;
  if (!email || !/@/.test(email)) return Response.json({ error: 'Valid email required' }, { status: 400 });
  if (!VALID_FREQUENCIES.includes(frequency)) return Response.json({ error: `frequency must be: ${VALID_FREQUENCIES.join('|')}` }, { status: 400 });
  const D = db(env);
  await ensureAutoTables(D);
  const next = nextSendDate(frequency);
  const id = genId('sr');
  await D.prepare(
    `INSERT INTO scheduled_reports (id,org_id,owner_id,frequency,email,format,next_send) VALUES (?,?,?,?,?,?,?)`
  ).bind(id, orgId(authCtx), userId(authCtx), frequency, email, format === 'json' ? 'json' : 'html', next.toISOString()).run();
  return Response.json({ success: true, id, frequency, email, format, next_send: next.toISOString() }, { status: 201 });
}

async function handleDeleteScheduledReport(req, env, authCtx, rpId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const r = await D.prepare(`DELETE FROM scheduled_reports WHERE id=? AND org_id=?`).bind(rpId, orgId(authCtx)).run();
  if (!r?.meta?.changes) return Response.json({ error: 'Schedule not found' }, { status: 404 });
  return Response.json({ success: true, id: rpId });
}

async function handleUpdateScheduledReport(req, env, authCtx, rpId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch {}
  const D = db(env);
  await ensureAutoTables(D);
  const sets = []; const binds = [];
  if (typeof body.active === 'boolean') { sets.push('active=?'); binds.push(body.active ? 1 : 0); }
  if (body.email && /@/.test(body.email)) { sets.push('email=?'); binds.push(body.email); }
  if (VALID_FREQUENCIES.includes(body.frequency)) {
    sets.push('frequency=?'); binds.push(body.frequency);
    sets.push('next_send=?'); binds.push(nextSendDate(body.frequency).toISOString());
  }
  if (!sets.length) return Response.json({ error: 'No valid fields' }, { status: 400 });
  binds.push(rpId, orgId(authCtx));
  await D.prepare(`UPDATE scheduled_reports SET ${sets.join(',')} WHERE id=? AND org_id=?`).bind(...binds).run();
  return Response.json({ success: true, id: rpId });
}

function nextSendDate(frequency) {
  const now = new Date();
  if (frequency === 'daily')   { now.setDate(now.getDate() + 1); now.setHours(6,0,0,0); }
  if (frequency === 'weekly')  { now.setDate(now.getDate() + 7); now.setHours(6,0,0,0); }
  if (frequency === 'monthly') { now.setMonth(now.getMonth() + 1); now.setDate(1); now.setHours(6,0,0,0); }
  return now;
}

// Cron: deliver due scheduled reports
export async function runScheduledReportsCron(env) {
  const D = db(env); if (!D) return { sent: 0 };
  let sent = 0;
  try {
    await ensureAutoTables(D);
    const { results } = await D.prepare(
      `SELECT id,org_id,owner_id,email,frequency,format FROM scheduled_reports
       WHERE active=1 AND next_send <= datetime('now') ORDER BY next_send LIMIT 20`
    ).all();
    for (const sched of (results || [])) {
      try {
        // Build minimal report JSON from D1 data
        const riskRow = await D.prepare(
          `SELECT COUNT(*) as total_signals FROM threat_intel WHERE published_date >= datetime('now','-7 days')`
        ).first().catch(() => null);
        const kevRow = await D.prepare(
          `SELECT COUNT(*) as kev_count FROM threat_intel WHERE is_kev=1 AND published_date >= datetime('now','-7 days')`
        ).first().catch(() => null);
        const reportData = {
          org_id: sched.org_id, frequency: sched.frequency,
          generated_at: new Date().toISOString(),
          summary: { signals_period: riskRow?.total_signals || 0, kev_additions: kevRow?.kev_count || 0 },
        };
        const { sendEmail } = await import('../services/emailEngine.js');
        const subject = `CYBERDUDEBIVASH® Sentinel APEX — ${capitalize(sched.frequency)} Security Report`;
        const html = buildReportEmail(reportData, sched.frequency);
        await sendEmail(env, { to: sched.email, subject, html });
        const next = nextSendDate(sched.frequency);
        await D.prepare(`UPDATE scheduled_reports SET last_sent=datetime('now'),next_send=? WHERE id=?`)
          .bind(next.toISOString(), sched.id).run();
        sent++;
      } catch {}
    }
  } catch {}
  return { sent };
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

function buildReportEmail(data, frequency) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
    body{background:#0a0d11;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:24px}
    .card{background:#161d2a;border:1px solid #1e2a3a;border-radius:10px;padding:20px;margin-bottom:16px}
    h1{color:#00c2ff;font-size:20px}h2{font-size:15px;color:#94a3b8;margin-bottom:8px}
    .num{font-size:32px;font-weight:800;color:#00c2ff}.label{font-size:12px;color:#64748b}
    .footer{color:#64748b;font-size:12px;margin-top:24px}
  </style></head><body>
  <h1>CYBERDUDEBIVASH® Sentinel APEX</h1>
  <p style="color:#64748b">${capitalize(frequency)} Security Report — ${data.generated_at.slice(0,10)}</p>
  <div class="card"><h2>Threat Summary</h2>
    <div class="num">${data.summary.signals_period}</div><div class="label">New signals this period</div>
  </div>
  <div class="card"><h2>KEV Additions</h2>
    <div class="num" style="color:#ef4444">${data.summary.kev_additions}</div><div class="label">Known Exploited Vulnerabilities</div>
  </div>
  <div class="footer">CYBERDUDEBIVASH® AI Security Hub · intel.cyberdudebivash.com</div>
  </body></html>`;
}

// ─── P7.0-004: Team Management ────────────────────────────────────────────────

const TEAM_ROLES = ['OWNER','ADMIN','ANALYST','VIEWER'];

async function handleListTeam(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  const { results } = await D.prepare(
    `SELECT id,user_id,email,role,invited_by,created_at FROM org_teams WHERE org_id=? ORDER BY created_at`
  ).bind(orgId(authCtx)).all().catch(() => ({ results: [] }));
  return Response.json({ members: results || [], roles: TEAM_ROLES, org_id: orgId(authCtx) });
}

async function handleInviteTeamMember(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  if (!['ADMIN','OWNER'].includes(tier(authCtx)) && !['OWNER','ADMIN'].includes(authCtx?.role?.toUpperCase())) {
    // Allow if user has org admin role in teams table
    const D2 = db(env);
    await ensureAutoTables(D2);
    const self = await D2.prepare(`SELECT role FROM org_teams WHERE org_id=? AND user_id=?`).bind(orgId(authCtx), userId(authCtx)).first().catch(() => null);
    if (!self || !['OWNER','ADMIN'].includes(self.role)) return Response.json({ error: 'OWNER or ADMIN required' }, { status: 403 });
  }
  let body = {};
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  const { user_id, email, role = 'VIEWER' } = body;
  if (!user_id) return Response.json({ error: 'user_id required' }, { status: 400 });
  if (!TEAM_ROLES.includes(role.toUpperCase())) return Response.json({ error: `role must be: ${TEAM_ROLES.join('|')}` }, { status: 400 });
  if (role.toUpperCase() === 'OWNER') return Response.json({ error: 'Cannot assign OWNER role via API' }, { status: 403 });
  const D = db(env);
  await ensureAutoTables(D);
  const id = genId('tm');
  try {
    await D.prepare(
      `INSERT INTO org_teams (id,org_id,user_id,email,role,invited_by) VALUES (?,?,?,?,?,?)
       ON CONFLICT(org_id,user_id) DO UPDATE SET role=excluded.role,email=excluded.email`
    ).bind(id, orgId(authCtx), user_id, email || null, role.toUpperCase(), userId(authCtx)).run();
    return Response.json({ success: true, id, org_id: orgId(authCtx), user_id, role: role.toUpperCase() }, { status: 201 });
  } catch { return Response.json({ error: 'DB error' }, { status: 500 }); }
}

async function handleRemoveTeamMember(req, env, authCtx, memberId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  await ensureAutoTables(D);
  // Prevent removing OWNER
  const target = await D.prepare(`SELECT role FROM org_teams WHERE id=? AND org_id=?`).bind(memberId, orgId(authCtx)).first().catch(() => null);
  if (!target) return Response.json({ error: 'Member not found' }, { status: 404 });
  if (target.role === 'OWNER') return Response.json({ error: 'Cannot remove OWNER' }, { status: 403 });
  await D.prepare(`DELETE FROM org_teams WHERE id=? AND org_id=?`).bind(memberId, orgId(authCtx)).run();
  return Response.json({ success: true, id: memberId });
}

async function handleUpdateTeamRole(req, env, authCtx, memberId) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  let body = {};
  try { body = await req.json(); } catch {}
  const role = (body.role || '').toUpperCase();
  if (!TEAM_ROLES.includes(role) || role === 'OWNER') return Response.json({ error: `role must be: ADMIN|ANALYST|VIEWER` }, { status: 400 });
  const D = db(env);
  await ensureAutoTables(D);
  const target = await D.prepare(`SELECT role FROM org_teams WHERE id=? AND org_id=?`).bind(memberId, orgId(authCtx)).first().catch(() => null);
  if (!target) return Response.json({ error: 'Member not found' }, { status: 404 });
  if (target.role === 'OWNER') return Response.json({ error: 'Cannot change OWNER role' }, { status: 403 });
  await D.prepare(`UPDATE org_teams SET role=? WHERE id=? AND org_id=?`).bind(role, memberId, orgId(authCtx)).run();
  return Response.json({ success: true, id: memberId, role });
}

// ─── P7.0-005: API Usage Dashboard ───────────────────────────────────────────
// Reuses ops_usage_events from P6.0

async function handleApiUsageDashboard(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  const url = new URL(req.url);
  const days = Math.min(parseInt(url.searchParams.get('days') || '7', 10), 30);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const uid = userId(authCtx);
  try {
    const [byEndpoint, byDay, cacheRow, latencyRow, quotaRow] = await Promise.all([
      D.prepare(`SELECT endpoint, COUNT(*) as calls, AVG(latency_ms) as avg_ms FROM ops_usage_events WHERE user_id=? AND ts>=? GROUP BY endpoint ORDER BY calls DESC LIMIT 15`).bind(uid, since).all(),
      D.prepare(`SELECT date(ts) as day, COUNT(*) as calls, SUM(cached) as cache_hits FROM ops_usage_events WHERE user_id=? AND ts>=? GROUP BY date(ts) ORDER BY day`).bind(uid, since).all(),
      D.prepare(`SELECT SUM(cached) as hits, COUNT(*) as total FROM ops_usage_events WHERE user_id=? AND ts>=?`).bind(uid, since).first(),
      D.prepare(`SELECT AVG(latency_ms) as p50, MAX(latency_ms) as p99 FROM ops_usage_events WHERE user_id=? AND ts>=?`).bind(uid, since).first(),
      D.prepare(`SELECT COUNT(*) as month_calls FROM ops_usage_events WHERE user_id=? AND ts>=date('now','start of month')`).bind(uid).first(),
    ]);
    const monthCalls = quotaRow?.month_calls || 0;
    const tierLimits = TIER_LIMITS[tier(authCtx)] || TIER_LIMITS.FREE;
    const radarLimit = tierLimits?.scans === -1 ? null : (tierLimits?.scans || 20);
    const total = cacheRow?.total || 0;
    const hits  = cacheRow?.hits  || 0;
    return Response.json({
      period_days: days, user_id: uid, tier: tier(authCtx),
      summary: { total_calls: total, cache_hits: hits, cache_hit_ratio: total ? parseFloat((hits/total).toFixed(3)) : 0, avg_latency_ms: Math.round(latencyRow?.p50 || 0), p99_latency_ms: Math.round(latencyRow?.p99 || 0) },
      quota: { month_calls: monthCalls, radar_limit: radarLimit, quota_pct: radarLimit ? parseFloat(((monthCalls/radarLimit)*100).toFixed(1)) : 0 },
      by_endpoint: byEndpoint?.results || [],
      daily_trend: byDay?.results || [],
    });
  } catch { return Response.json({ error: 'Usage data unavailable' }, { status: 500 }); }
}

// ─── P7.0-006: API Governance ────────────────────────────────────────────────

const API_MANIFEST = {
  version: 'v1',
  released: '2025-01-01',
  endpoints: [
    { path: '/api/radar/signals',       status: 'stable',     since: 'v1' },
    { path: '/api/radar/threat-actors', status: 'stable',     since: 'v1' },
    { path: '/api/radar/campaigns',     status: 'stable',     since: 'v1' },
    { path: '/api/radar/sectors',       status: 'stable',     since: 'v1' },
    { path: '/api/customer/profile',    status: 'stable',     since: 'v1' },
    { path: '/api/customer/radar',      status: 'stable',     since: 'v1' },
    { path: '/api/customer/risk',       status: 'stable',     since: 'v1' },
    { path: '/api/customer/assets',     status: 'stable',     since: 'v1' },
    { path: '/api/customer/report',     status: 'stable',     since: 'v1' },
    { path: '/api/enterprise/intelligence', status: 'stable', since: 'v1', min_tier: 'PRO' },
    { path: '/api/enterprise/risk',     status: 'stable',     since: 'v1', min_tier: 'PRO' },
    { path: '/api/enterprise/actors',   status: 'stable',     since: 'v1', min_tier: 'ENTERPRISE' },
    { path: '/api/enterprise/campaigns',status: 'stable',     since: 'v1', min_tier: 'PRO' },
    { path: '/api/auto/webhooks',       status: 'stable',     since: 'v1' },
    { path: '/api/auto/reports',        status: 'stable',     since: 'v1' },
    { path: '/api/auto/team',           status: 'stable',     since: 'v1' },
    { path: '/api/auto/usage',          status: 'stable',     since: 'v1' },
    { path: '/api/self/keys',           status: 'stable',     since: 'v1' },
  ],
  deprecations: [],
  throttling: {
    FREE:       { requests_per_minute: 10,  requests_per_day: 100 },
    PRO:        { requests_per_minute: 60,  requests_per_day: 5000 },
    ENTERPRISE: { requests_per_minute: 300, requests_per_day: -1 },
    MSSP:       { requests_per_minute: 600, requests_per_day: -1 },
  },
};

async function handleGovernance(req, env, authCtx) {
  const deny = requireAuth(authCtx); if (deny) return deny;
  const D = db(env);
  let quotaWarning = null;
  try {
    const monthCalls = await D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE user_id=? AND ts>=date('now','start of month')`).bind(userId(authCtx)).first().catch(() => null);
    const tierLimits = TIER_LIMITS[tier(authCtx)] || TIER_LIMITS.FREE;
    const limit = tierLimits?.scans;
    if (limit && limit !== -1 && monthCalls?.cnt) {
      const pct = (monthCalls.cnt / limit) * 100;
      if (pct >= 80) quotaWarning = { pct: parseFloat(pct.toFixed(1)), used: monthCalls.cnt, limit, message: pct >= 100 ? 'Quota exceeded' : 'Approaching quota limit' };
    }
  } catch {}
  return Response.json({ ...API_MANIFEST, user_tier: tier(authCtx), throttle_limits: API_MANIFEST.throttling[tier(authCtx)] || API_MANIFEST.throttling.FREE, quota_warning: quotaWarning });
}

// ─── P7.0-009: Enterprise Metrics ────────────────────────────────────────────

export async function handleEnterpriseMetrics(req, env, authCtx) {
  if (!isAdmin(authCtx)) return Response.json({ error: 'OWNER or ADMIN required' }, { status: 403 });
  const D = db(env); const KV = kv(env);
  try {
    await ensureAutoTables(D);
    const [orgs, keys, whTotal, whDelivered, rpTotal, rpSent, apiSuccess, apiTotal] = await Promise.all([
      D.prepare(`SELECT COUNT(*) as cnt FROM customer_profiles`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM api_keys WHERE active=1`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM webhook_delivery_log WHERE created_at>=datetime('now','-24 hours')`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM webhook_delivery_log WHERE status='delivered' AND created_at>=datetime('now','-24 hours')`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM scheduled_reports WHERE active=1`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM scheduled_reports WHERE last_sent>=datetime('now','-7 days')`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE ts>=datetime('now','-24 hours') AND latency_ms < 5000`).first().catch(() => null),
      D.prepare(`SELECT COUNT(*) as cnt FROM ops_usage_events WHERE ts>=datetime('now','-24 hours')`).first().catch(() => null),
    ]);
    const whSuccessRate = whTotal?.cnt ? parseFloat(((whDelivered?.cnt || 0) / whTotal.cnt * 100).toFixed(1)) : 100;
    const apiSuccessRate = apiTotal?.cnt ? parseFloat(((apiSuccess?.cnt || 0) / apiTotal.cnt * 100).toFixed(1)) : 100;
    return Response.json({
      ts: new Date().toISOString(),
      active_organizations: orgs?.cnt || 0,
      active_api_keys: keys?.cnt || 0,
      webhooks: { deliveries_24h: whTotal?.cnt || 0, delivered: whDelivered?.cnt || 0, success_rate_pct: whSuccessRate },
      scheduled_reports: { active_schedules: rpTotal?.cnt || 0, sent_7d: rpSent?.cnt || 0 },
      api_health: { calls_24h: apiTotal?.cnt || 0, success_rate_pct: apiSuccessRate },
      automation_health: 'operational',
    });
  } catch (e) { return Response.json({ error: 'Metrics unavailable', detail: e.message }, { status: 500 }); }
}

// ─── Cron: retry webhooks + deliver scheduled reports ────────────────────────
export async function runAutomationCrons(env) {
  const [retry, reports] = await Promise.all([
    processWebhookRetryQueue(env),
    runScheduledReportsCron(env),
  ]);
  return { webhook_retries: retry, scheduled_reports: reports };
}

// ─── Main router ──────────────────────────────────────────────────────────────
export async function handleAutoRoute(req, env, authCtx, path, method) {
  // API key self-service
  if (path === '/api/self/keys') {
    if (method === 'GET')  return handleListSelfKeys(req, env, authCtx);
    if (method === 'POST') return handleCreateSelfKey(req, env, authCtx);
  }
  if (path.startsWith('/api/self/keys/')) {
    const parts = path.slice('/api/self/keys/'.length).split('/');
    const keyId = parts[0];
    if (method === 'DELETE') return handleRevokeSelfKey(req, env, authCtx, keyId);
    if (method === 'PATCH')  return handleUpdateKeyLabel(req, env, authCtx, keyId);
    if (method === 'GET' && parts[1] === 'usage') return handleKeyUsageSelf(req, env, authCtx, keyId);
    if (method === 'POST' && parts[1] === 'rotate') return handleRotateSelfKey(req, env, authCtx, keyId);
  }
  // Webhooks
  if (path === '/api/auto/webhooks') {
    if (method === 'GET')  return handleListWebhooks(req, env, authCtx);
    if (method === 'POST') return handleCreateWebhook(req, env, authCtx);
  }
  if (path.startsWith('/api/auto/webhooks/')) {
    const parts = path.slice('/api/auto/webhooks/'.length).split('/');
    const whId = parts[0];
    if (method === 'DELETE') return handleDeleteWebhook(req, env, authCtx, whId);
    if (method === 'PATCH')  return handleUpdateWebhook(req, env, authCtx, whId);
    if (method === 'GET' && parts[1] === 'logs') return handleWebhookLogs(req, env, authCtx, whId);
  }
  // Scheduled reports
  if (path === '/api/auto/reports') {
    if (method === 'GET')  return handleListScheduledReports(req, env, authCtx);
    if (method === 'POST') return handleCreateScheduledReport(req, env, authCtx);
  }
  if (path.startsWith('/api/auto/reports/')) {
    const rpId = path.slice('/api/auto/reports/'.length).split('/')[0];
    if (method === 'DELETE') return handleDeleteScheduledReport(req, env, authCtx, rpId);
    if (method === 'PATCH')  return handleUpdateScheduledReport(req, env, authCtx, rpId);
  }
  // Team management
  if (path === '/api/auto/team') {
    if (method === 'GET')  return handleListTeam(req, env, authCtx);
    if (method === 'POST') return handleInviteTeamMember(req, env, authCtx);
  }
  if (path.startsWith('/api/auto/team/')) {
    const mid = path.slice('/api/auto/team/'.length).split('/')[0];
    if (method === 'DELETE') return handleRemoveTeamMember(req, env, authCtx, mid);
    if (method === 'PATCH')  return handleUpdateTeamRole(req, env, authCtx, mid);
  }
  // Usage dashboard + governance + metrics
  if (path === '/api/auto/usage' && method === 'GET')      return handleApiUsageDashboard(req, env, authCtx);
  if (path === '/api/auto/governance' && method === 'GET') return handleGovernance(req, env, authCtx);
  if (path === '/api/auto/metrics' && method === 'GET')    return handleEnterpriseMetrics(req, env, authCtx);
  return null;
}
