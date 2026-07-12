/* P2 — user-dashboard.html's Settings > "Alert Notifications" card could save
 * preferences (POST /api/auth/alerts, wired via saveAlerts()) but had no way
 * to load them back. There was no GET counterpart at all, and the frontend
 * never called one, so the form always rendered its blank default state on
 * every page visit regardless of what a user had actually saved previously —
 * a returning user had no way to tell whether their alert config had taken
 * effect.
 *
 * ROOT CAUSE: handleGetAlertConfig (backend) and loadAlerts() (frontend)
 * simply didn't exist. This is an additive fix: a new GET /api/auth/alerts
 * route reading the same `alert_configs` table the existing POST writes to,
 * plus a new loadAlerts() called from showPage()'s settings branch,
 * reverse-mapping the saved row back onto the #alert-email dropdown and
 * #alert-tg input the same way saveAlerts() maps them forward.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { handleGetAlertConfig, handleAlertConfig } from '../src/handlers/auth.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

const authCtx = { user_id: 'u1' };
const getReq = () => new Request('https://x/api/auth/alerts');
const postReq = (body) => new Request('https://x/api/auth/alerts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

describe('GET /api/auth/alerts (P2 — notification preferences never loaded back)', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE alert_configs (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      user_id TEXT NOT NULL UNIQUE,
      telegram_enabled INTEGER NOT NULL DEFAULT 0,
      telegram_chat_id TEXT,
      email_enabled INTEGER NOT NULL DEFAULT 0,
      alert_email TEXT,
      min_risk_score INTEGER NOT NULL DEFAULT 70,
      alert_on_blacklist INTEGER NOT NULL DEFAULT 1,
      alert_on_critical_cve INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
  });

  it('requires auth', async () => {
    const res = await handleGetAlertConfig(getReq(), env, {});
    expect(res.status).toBe(401);
  });

  it('requires a DB', async () => {
    const res = await handleGetAlertConfig(getReq(), { DB: null }, authCtx);
    expect(res.status).toBe(503);
  });

  it('a user with no saved row yet gets the form\'s blank-state defaults, not a 404 or an empty object', async () => {
    const res = await handleGetAlertConfig(getReq(), env, authCtx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.config).toEqual({
      telegram_enabled: false, telegram_chat_id: null,
      email_enabled: true, alert_email: null, min_risk_score: 0,
      alert_on_blacklist: true, alert_on_critical_cve: true,
      updated_at: null,
    });
  });

  it('a real save via the existing POST is then visible through the new GET — the actual round trip the bug broke', async () => {
    const saveRes = await handleAlertConfig(postReq({
      email_enabled: false,
      min_risk_score: 90,
      telegram_enabled: true,
      telegram_chat_id: '@my_channel',
    }), env, authCtx);
    expect(saveRes.status).toBe(200);

    const res = await handleGetAlertConfig(getReq(), env, authCtx);
    const body = await res.json();
    expect(body.config.email_enabled).toBe(false);
    expect(body.config.min_risk_score).toBe(90);
    expect(body.config.telegram_enabled).toBe(true);
    expect(body.config.telegram_chat_id).toBe('@my_channel');
  });

  it('booleans come back as real booleans, not raw SQLite 0/1 integers', async () => {
    await handleAlertConfig(postReq({ email_enabled: true, alert_on_blacklist: false, alert_on_critical_cve: false }), env, authCtx);
    const body = await (await handleGetAlertConfig(getReq(), env, authCtx)).json();
    expect(body.config.email_enabled).toBe(true);
    expect(body.config.alert_on_blacklist).toBe(false);
    expect(body.config.alert_on_critical_cve).toBe(false);
  });

  it('a second save overwrites rather than duplicating (ON CONFLICT upsert) and GET reflects only the latest', async () => {
    await handleAlertConfig(postReq({ email_enabled: true, min_risk_score: 0 }), env, authCtx);
    await handleAlertConfig(postReq({ email_enabled: false, min_risk_score: 90 }), env, authCtx);
    expect(db.prepare(`SELECT COUNT(*) AS n FROM alert_configs WHERE user_id = ?`).get('u1').n).toBe(1);
    const body = await (await handleGetAlertConfig(getReq(), env, authCtx)).json();
    expect(body.config.email_enabled).toBe(false);
    expect(body.config.min_risk_score).toBe(90);
  });
});

describe('frontend wiring — user-dashboard.html calls the new GET and reverse-maps it onto the form (static parse)', () => {
  const html = readFileSync(new URL('../../frontend/user-dashboard.html', import.meta.url), 'utf8');

  function fnBody(name) {
    const marker = `function ${name}(`;
    const start = html.indexOf(marker);
    expect(start, `${name} should be defined`).toBeGreaterThan(-1);
    const bodyStart = html.indexOf('{', start);
    let depth = 0, i = bodyStart;
    for (; i < html.length; i++) {
      if (html[i] === '{') depth++;
      else if (html[i] === '}') { depth--; if (depth === 0) break; }
    }
    return html.slice(start, i + 1);
  }

  it('defines loadAlerts()', () => {
    const body = fnBody('loadAlerts');
    expect(body).toContain("apiFetch('/api/auth/alerts')");
  });

  it('loadAlerts() is called when the settings page is shown, alongside the other settings loaders', () => {
    const showPage = fnBody('showPage');
    expect(showPage).toMatch(/id === 'settings'[^\n]*loadAlerts/);
  });

  it('loadAlerts() reverse-maps the saved config onto #alert-email and #alert-tg — the same two fields saveAlerts() reads', () => {
    const body = fnBody('loadAlerts');
    expect(body).toContain("getElementById('alert-email')");
    expect(body).toContain("getElementById('alert-tg')");
  });

  it('#alert-email and #alert-tg really exist in the Settings markup (no orphan id references)', () => {
    expect(html).toMatch(/id="alert-email"/);
    expect(html).toMatch(/id="alert-tg"/);
  });
});
