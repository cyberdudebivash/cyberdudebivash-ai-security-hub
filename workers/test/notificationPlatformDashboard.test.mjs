// CAP-NOTIF-001 — Multi-Channel Notification Preferences & Delivery Log.
// The backend (workers/src/handlers/notificationPlatform.js) was real and
// wired to real events, but had zero frontend callers, AND — discovered while
// investigating this exact gap — every customer-facing handler read
// `req.user.id`, a field that was never populated anywhere in the auth layer
// (only user_id/userId existed). Every real, authenticated request silently
// computed `userId = undefined || 'unknown'`, so every customer's Slack/Teams
// webhook config and delivery history collided onto one shared 'unknown' D1
// row — and the `if (!req.user)` auth gate was permanently dead code, since
// the router always sets req.user to a truthy object (real principal or
// anonymous IP-fallback) before the handler ever runs.
//
// Fixed in two places:
//  1. workers/src/auth/middleware.js's withAuthAliases() now also aliases
//     .id from .user_id (same fix shape as the pre-existing .role fix in the
//     same function) — this transparently repairs notificationPlatform.js
//     AND 4 sibling handlers (reportingEngine.js, workflowAutomation.js,
//     globalSearch.js, productAnalytics.js) that had the identical bug.
//  2. notificationPlatform.js's 4 customer-facing handlers now gate on the
//     real isRealUser(authCtx) helper (workers/src/auth/middleware.js)
//     instead of the always-true `!req.user` check.
//
// Runs the real handlers against a real SQL engine (node:sqlite), same
// convention as workers/test/userSessionManagement.test.mjs.
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  handleGetPreferences, handleUpdatePreferences, handleNotificationLog, handleTestNotification,
  deliverNotification,
} from '../src/handlers/notificationPlatform.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function realUser(userId, overrides = {}) {
  // Shape produced by resolveAuthV5 + withAuthAliases for a genuine JWT session.
  return { authenticated: true, method: 'jwt', user_id: userId, userId, id: userId,
    tier: 'PRO', email: `${userId}@example.com`, org_id: `u:${userId}`, ...overrides };
}
const anonymousUser = { authenticated: true, method: 'ip_fallback', user_id: null, userId: null, id: null, tier: 'FREE' };

function req(url, opts) { const r = new Request(`https://x${url}`, opts); return r; }
function withUser(r, user) { r.user = user; return r; }

describe('CAP-NOTIF-001 — auth gate is now real (was dead code)', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    env.DB._sqlite.exec(`CREATE TABLE notification_preferences (
      user_id TEXT PRIMARY KEY, org_id TEXT DEFAULT 'default', email_enabled INTEGER DEFAULT 1,
      inapp_enabled INTEGER DEFAULT 1, slack_webhook TEXT, teams_webhook TEXT, custom_webhook TEXT,
      webhook_secret TEXT, event_subscriptions TEXT DEFAULT '[]', escalation_delay_min INTEGER DEFAULT 30,
      quiet_hours_json TEXT DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    env.DB._sqlite.exec(`CREATE TABLE notification_log (
      id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, org_id TEXT DEFAULT 'default',
      channel TEXT NOT NULL, event_type TEXT NOT NULL, subject TEXT, body_preview TEXT,
      status TEXT DEFAULT 'PENDING', delivery_attempts INTEGER DEFAULT 0, error_message TEXT,
      sent_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  });

  it('an anonymous (IP-fallback) caller is genuinely rejected with 401 on all 4 endpoints', async () => {
    const g = await handleGetPreferences(withUser(req('/api/notifications/preferences'), anonymousUser), env);
    expect(g.status).toBe(401);
    const u = await handleUpdatePreferences(withUser(req('/api/notifications/preferences', { method: 'PUT', body: '{}' }), anonymousUser), env);
    expect(u.status).toBe(401);
    const l = await handleNotificationLog(withUser(req('/api/notifications/log'), anonymousUser), env);
    expect(l.status).toBe(401);
    const t = await handleTestNotification(withUser(req('/api/notifications/test', { method: 'POST', body: '{}' }), anonymousUser), env);
    expect(t.status).toBe(401);
  });

  it('a real authenticated user passes the gate', async () => {
    const res = await handleGetPreferences(withUser(req('/api/notifications/preferences'), realUser('alice')), env);
    expect(res.status).toBe(200);
  });
});

describe('CAP-NOTIF-001 — real per-user isolation (was: everyone collided on \'unknown\')', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    env.DB._sqlite.exec(`CREATE TABLE notification_preferences (
      user_id TEXT PRIMARY KEY, org_id TEXT DEFAULT 'default', email_enabled INTEGER DEFAULT 1,
      inapp_enabled INTEGER DEFAULT 1, slack_webhook TEXT, teams_webhook TEXT, custom_webhook TEXT,
      webhook_secret TEXT, event_subscriptions TEXT DEFAULT '[]', escalation_delay_min INTEGER DEFAULT 30,
      quiet_hours_json TEXT DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    env.DB._sqlite.exec(`CREATE TABLE notification_log (
      id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, org_id TEXT DEFAULT 'default',
      channel TEXT NOT NULL, event_type TEXT NOT NULL, subject TEXT, body_preview TEXT,
      status TEXT DEFAULT 'PENDING', delivery_attempts INTEGER DEFAULT 0, error_message TEXT,
      sent_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  });

  it('two different real users saving different Slack webhooks do not overwrite each other', async () => {
    await handleUpdatePreferences(withUser(req('/api/notifications/preferences', {
      method: 'PUT', body: JSON.stringify({ slack_webhook: 'https://hooks.slack.com/alice' }),
    }), realUser('alice')), env);
    await handleUpdatePreferences(withUser(req('/api/notifications/preferences', {
      method: 'PUT', body: JSON.stringify({ slack_webhook: 'https://hooks.slack.com/bob' }),
    }), realUser('bob')), env);

    const aliceRes = await handleGetPreferences(withUser(req('/api/notifications/preferences'), realUser('alice')), env);
    const bobRes   = await handleGetPreferences(withUser(req('/api/notifications/preferences'), realUser('bob')), env);
    const alice = (await aliceRes.json()).preferences;
    const bob   = (await bobRes.json()).preferences;
    expect(alice.slack_webhook).toBe('https://hooks.slack.com/alice');
    expect(bob.slack_webhook).toBe('https://hooks.slack.com/bob');
    expect(alice.user_id).toBe('alice');
    expect(bob.user_id).toBe('bob');

    // Confirms this isn't just two rows that both happen to read back their own
    // value — proves they are not the same underlying row.
    const row = env.DB._sqlite.prepare('SELECT COUNT(*) AS c FROM notification_preferences').get();
    expect(row.c).toBe(2);
  });

  it('a PUT then GET round-trips real field changes for the same user', async () => {
    await handleUpdatePreferences(withUser(req('/api/notifications/preferences', {
      method: 'PUT',
      body: JSON.stringify({ teams_webhook: 'https://outlook.office.com/webhook/x', event_subscriptions: ['scan.critical', 'health.churn'] }),
    }), realUser('carol')), env);
    const res = await handleGetPreferences(withUser(req('/api/notifications/preferences'), realUser('carol')), env);
    const { preferences } = await res.json();
    expect(preferences.teams_webhook).toBe('https://outlook.office.com/webhook/x');
    expect(preferences.event_subscriptions).toEqual(['scan.critical', 'health.churn']);
  });

  it('the delivery log is scoped to the calling user only', async () => {
    env.DB._sqlite.prepare(`INSERT INTO notification_log (id, recipient_id, channel, event_type, status) VALUES (?,?,?,?,?)`)
      .run('n1', 'alice', 'INAPP', 'scan.critical', 'SENT');
    env.DB._sqlite.prepare(`INSERT INTO notification_log (id, recipient_id, channel, event_type, status) VALUES (?,?,?,?,?)`)
      .run('n2', 'bob', 'INAPP', 'scan.critical', 'SENT');

    const aliceLog = await (await handleNotificationLog(withUser(req('/api/notifications/log'), realUser('alice')), env)).json();
    expect(aliceLog.log.length).toBe(1);
    expect(aliceLog.log[0].id).toBe('n1');
  });

  it('a test notification is logged under the real caller, not \'unknown\'', async () => {
    await handleTestNotification(withUser(req('/api/notifications/test', { method: 'POST', body: JSON.stringify({ channels: ['INAPP'] }) }), realUser('dave')), env);
    const row = env.DB._sqlite.prepare('SELECT recipient_id FROM notification_log').get();
    expect(row.recipient_id).toBe('dave');
  });
});

describe('CAP-NOTIF-001 — eventType \'*\' is a real wildcard bypass (was: dead comparison)', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    env.DB._sqlite.exec(`CREATE TABLE notification_preferences (
      user_id TEXT PRIMARY KEY, org_id TEXT DEFAULT 'default', email_enabled INTEGER DEFAULT 1,
      inapp_enabled INTEGER DEFAULT 1, slack_webhook TEXT, teams_webhook TEXT, custom_webhook TEXT,
      webhook_secret TEXT, event_subscriptions TEXT DEFAULT '[]', escalation_delay_min INTEGER DEFAULT 30,
      quiet_hours_json TEXT DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    env.DB._sqlite.exec(`CREATE TABLE notification_log (
      id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, org_id TEXT DEFAULT 'default',
      channel TEXT NOT NULL, event_type TEXT NOT NULL, subject TEXT, body_preview TEXT,
      status TEXT DEFAULT 'PENDING', delivery_attempts INTEGER DEFAULT 0, error_message TEXT,
      sent_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  });

  it('delivers to a brand-new user with zero saved preferences (default subs never contain literal \'*\')', async () => {
    // Reproduces developerOnboardingHandler.js's welcome-email call shape: a
    // user with no notification_preferences row yet (falls back to
    // DEFAULT_PREFS, whose event_subscriptions never include '*').
    const delivered = await deliverNotification({
      userId: 'brand-new-signup', orgId: 'brand-new-signup', eventType: '*',
      subject: 'Welcome', body: 'hi', channels: ['INAPP'],
    }, env);
    expect(delivered.length).toBe(1);
    expect(delivered[0].status).toBe('SENT');
    const row = env.DB._sqlite.prepare('SELECT * FROM notification_log').get();
    expect(row.recipient_id).toBe('brand-new-signup');
  });

  it('a user who has actively unsubscribed from everything still receives wildcard broadcasts', async () => {
    await deliverNotification({ userId: 'picky', orgId: 'picky', eventType: 'health.churn', subject: 'x', body: 'x', channels: ['INAPP'] }, env);
    await env.DB.prepare(
      `INSERT INTO notification_preferences (user_id, event_subscriptions) VALUES (?,?)
       ON CONFLICT(user_id) DO UPDATE SET event_subscriptions=excluded.event_subscriptions`
    ).bind('picky', '[]').run();
    const delivered = await deliverNotification({ userId: 'picky', orgId: 'picky', eventType: '*', subject: 'Recovery', body: 'x', channels: ['INAPP'] }, env);
    expect(delivered.length).toBe(1);
    expect(delivered[0].status).toBe('SENT');
  });

  it('a real (non-wildcard) event not in the subscriber list is still correctly suppressed', async () => {
    await env.DB.prepare(
      `INSERT INTO notification_preferences (user_id, event_subscriptions) VALUES (?,?)`
    ).bind('narrow', '["scan.critical"]').run();
    const delivered = await deliverNotification({ userId: 'narrow', orgId: 'narrow', eventType: 'health.churn', subject: 'x', body: 'x', channels: ['INAPP'] }, env);
    expect(delivered.length).toBe(0);
  });
});

describe('CAP-CHURN — churn-risk alerts use the canonical \'health.churn\' event name', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    env.DB._sqlite.exec(`CREATE TABLE notification_preferences (
      user_id TEXT PRIMARY KEY, org_id TEXT DEFAULT 'default', email_enabled INTEGER DEFAULT 1,
      inapp_enabled INTEGER DEFAULT 1, slack_webhook TEXT, teams_webhook TEXT, custom_webhook TEXT,
      webhook_secret TEXT, event_subscriptions TEXT DEFAULT '[]', escalation_delay_min INTEGER DEFAULT 30,
      quiet_hours_json TEXT DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    env.DB._sqlite.exec(`CREATE TABLE notification_log (
      id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, org_id TEXT DEFAULT 'default',
      channel TEXT NOT NULL, event_type TEXT NOT NULL, subject TEXT, body_preview TEXT,
      status TEXT DEFAULT 'PENDING', delivery_attempts INTEGER DEFAULT 0, error_message TEXT,
      sent_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  });

  it('a default (never-customized) customer is subscribed to health.churn out of the box', async () => {
    // No notification_preferences row exists — falls back to DEFAULT_PREFS,
    // which is the shape every real customer starts with.
    const delivered = await deliverNotification({
      userId: 'at-risk-customer', orgId: 'acme-corp', eventType: 'health.churn',
      subject: 'Action Required', body: 'health score dropping', channels: ['INAPP'],
    }, env);
    expect(delivered.length).toBe(1);
    expect(delivered[0].status).toBe('SENT');
  });

  it('the old, mismatched CHURN_RISK_ALERT string would have silently delivered to nobody (regression guard)', async () => {
    const delivered = await deliverNotification({
      userId: 'at-risk-customer', orgId: 'acme-corp', eventType: 'CHURN_RISK_ALERT',
      subject: 'Action Required', body: 'health score dropping', channels: ['INAPP'],
    }, env);
    expect(delivered.length).toBe(0);
  });
});
