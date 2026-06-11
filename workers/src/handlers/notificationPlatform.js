/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * notificationPlatform.js — Enterprise Unified Notification Center
 *
 * APIs:
 *   GET  /api/notifications/preferences    get own preferences
 *   PUT  /api/notifications/preferences    update preferences
 *   GET  /api/notifications/log            delivery history (own user)
 *   POST /api/notifications/test           send test notification
 *   POST /api/notifications/send           internal send (admin)
 */

const DEFAULT_PREFS = {
  email_enabled: 1,
  inapp_enabled: 1,
  slack_webhook: null,
  teams_webhook: null,
  custom_webhook: null,
  event_subscriptions: ['scan.critical','case.created','case.escalated','health.churn'],
  escalation_delay_min: 30,
  quiet_hours_json: {},
};

function genId() { return 'notif_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

const URL_RE = /^https:\/\/[^\s<>"]+$/;

function sanitizePrefs(input) {
  const out = {};
  if (typeof input.email_enabled === 'boolean') out.email_enabled = input.email_enabled ? 1 : 0;
  if (typeof input.inapp_enabled === 'boolean') out.inapp_enabled = input.inapp_enabled ? 1 : 0;
  if (input.slack_webhook === null || (typeof input.slack_webhook === 'string' && URL_RE.test(input.slack_webhook))) {
    out.slack_webhook = input.slack_webhook;
  }
  if (input.teams_webhook === null || (typeof input.teams_webhook === 'string' && URL_RE.test(input.teams_webhook))) {
    out.teams_webhook = input.teams_webhook;
  }
  if (input.custom_webhook === null || (typeof input.custom_webhook === 'string' && URL_RE.test(input.custom_webhook))) {
    out.custom_webhook = input.custom_webhook;
  }
  if (Array.isArray(input.event_subscriptions)) {
    out.event_subscriptions = JSON.stringify(input.event_subscriptions.slice(0, 20));
  }
  if (typeof input.escalation_delay_min === 'number') {
    out.escalation_delay_min = Math.max(0, Math.min(1440, input.escalation_delay_min));
  }
  if (input.quiet_hours_json && typeof input.quiet_hours_json === 'object') {
    out.quiet_hours_json = JSON.stringify(input.quiet_hours_json);
  }
  return out;
}

/**
 * Deliver a notification to all configured channels for a user.
 * Returns delivery log entries.
 */
async function deliverNotification({ userId, orgId, eventType, subject, body, channels }, env) {
  const prefs = await env.DB.prepare(
    `SELECT * FROM notification_preferences WHERE user_id = ?`
  ).bind(userId).first().catch(() => null);

  const cfg = prefs ? { ...DEFAULT_PREFS, ...prefs } : { ...DEFAULT_PREFS };
  const subs = typeof cfg.event_subscriptions === 'string'
    ? JSON.parse(cfg.event_subscriptions)
    : (cfg.event_subscriptions || []);

  // Check subscription
  if (!subs.includes(eventType) && !subs.includes('*')) return [];

  const deliveredChannels = [];
  const reqChannels = channels || ['INAPP'];

  for (const ch of reqChannels) {
    const logId = genId();
    let status = 'SKIPPED', error = null;

    if (ch === 'INAPP' && cfg.inapp_enabled) {
      // In-app: logged to notification_log; picked up by frontend SSE or polling
      status = 'SENT';
    }

    if (ch === 'SLACK' && cfg.slack_webhook && URL_RE.test(cfg.slack_webhook)) {
      try {
        const resp = await fetch(cfg.slack_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: `*${subject}*\n${body || ''}` }),
          signal: AbortSignal.timeout(5000),
        });
        status = resp.ok ? 'SENT' : 'FAILED';
        if (!resp.ok) error = `HTTP ${resp.status}`;
      } catch (e) { status = 'FAILED'; error = e.message; }
    }

    if (ch === 'TEAMS' && cfg.teams_webhook && URL_RE.test(cfg.teams_webhook)) {
      try {
        const resp = await fetch(cfg.teams_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ '@type': 'MessageCard', '@context': 'http://schema.org/extensions', summary: subject, themeColor: '6366f1', title: subject, text: body || '' }),
          signal: AbortSignal.timeout(5000),
        });
        status = resp.ok ? 'SENT' : 'FAILED';
        if (!resp.ok) error = `HTTP ${resp.status}`;
      } catch (e) { status = 'FAILED'; error = e.message; }
    }

    if (ch === 'WEBHOOK' && cfg.custom_webhook && URL_RE.test(cfg.custom_webhook)) {
      try {
        const payload = JSON.stringify({ event_type: eventType, subject, body, ts: new Date().toISOString() });
        const resp = await fetch(cfg.custom_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          signal: AbortSignal.timeout(5000),
        });
        status = resp.ok ? 'SENT' : 'FAILED';
        if (!resp.ok) error = `HTTP ${resp.status}`;
      } catch (e) { status = 'FAILED'; error = e.message; }
    }

    // Log delivery attempt
    await env.DB.prepare(
      `INSERT INTO notification_log (id, recipient_id, org_id, channel, event_type, subject, body_preview, status, error_message, sent_at, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,CASE WHEN ? = 'SENT' THEN datetime('now') ELSE NULL END,datetime('now'))`
    ).bind(logId, userId, orgId, ch, eventType, subject, (body || '').slice(0, 200), status, error, status).run().catch(() => null);

    deliveredChannels.push({ channel: ch, status, log_id: logId });
  }

  return deliveredChannels;
}

export async function handleGetPreferences(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const userId = req.user.id || 'unknown';
  const row = await env.DB.prepare(
    `SELECT * FROM notification_preferences WHERE user_id = ?`
  ).bind(userId).first().catch(() => null);

  const prefs = row ? {
    ...row,
    event_subscriptions: typeof row.event_subscriptions === 'string' ? JSON.parse(row.event_subscriptions) : row.event_subscriptions,
    quiet_hours_json: typeof row.quiet_hours_json === 'string' ? JSON.parse(row.quiet_hours_json) : (row.quiet_hours_json || {}),
  } : { ...DEFAULT_PREFS, user_id: userId };

  return Response.json({ preferences: prefs });
}

export async function handleUpdatePreferences(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const safe = sanitizePrefs(body);
  if (!Object.keys(safe).length) return Response.json({ error: 'No valid fields' }, { status: 400 });

  const userId = req.user.id || 'unknown';
  const orgId  = req.user.org_id || 'default';

  const cols = ['user_id', 'org_id', ...Object.keys(safe), 'updated_at'];
  const vals = [userId, orgId, ...Object.values(safe), new Date().toISOString()];
  const ph = vals.map(() => '?').join(',');
  const upd = Object.keys(safe).map(k => `${k}=excluded.${k}`).join(', ') + ', updated_at=excluded.updated_at';

  await env.DB.prepare(
    `INSERT INTO notification_preferences (${cols.join(',')}) VALUES (${ph})
     ON CONFLICT(user_id) DO UPDATE SET ${upd}`
  ).bind(...vals).run();

  return Response.json({ success: true, updated: safe });
}

export async function handleNotificationLog(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '25'), 100);
  const userId = req.user.id || 'unknown';

  const rows = await env.DB.prepare(
    `SELECT id, channel, event_type, subject, status, sent_at, created_at
     FROM notification_log WHERE recipient_id = ?
     ORDER BY created_at DESC LIMIT ?`
  ).bind(userId, limit).all().catch(() => ({ results: [] }));

  return Response.json({ log: rows.results || [], total: (rows.results || []).length });
}

export async function handleTestNotification(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const channels = Array.isArray(body.channels) ? body.channels : ['INAPP'];
  const userId = req.user.id || 'unknown';
  const orgId  = req.user.org_id || 'default';

  const delivered = await deliverNotification({
    userId, orgId,
    eventType: '*',
    subject: '✓ Test Notification — CYBERDUDEBIVASH® AI Security Hub',
    body: 'This is a test notification from the Enterprise Notification Platform.',
    channels,
  }, env);

  return Response.json({ success: true, delivered });
}

export async function handleAdminSendNotification(req, env) {
  if (!req.user || !['admin', 'mssp_admin'].includes(req.user.role)) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { user_id, org_id, event_type, subject, message, channels } = body;
  if (!user_id || !event_type || !subject) {
    return Response.json({ error: 'user_id, event_type, subject required' }, { status: 400 });
  }

  const delivered = await deliverNotification({
    userId: user_id, orgId: org_id || req.user.org_id || 'default',
    eventType: event_type, subject, body: message || '',
    channels: channels || ['INAPP'],
  }, env);

  return Response.json({ success: true, delivered });
}

export { deliverNotification };
