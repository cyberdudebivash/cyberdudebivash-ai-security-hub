/* Regression tests — CAP-NOTIF-003 immediate fix (webhook UI on
 * frontend/automation-dashboard.html was substantially non-functional,
 * independent of any later decision about consolidating the two parallel
 * webhook implementations):
 *
 * 1. Event vocabulary mismatch: the frontend hardcoded a 5-event checklist
 *    (cve.critical, kev.added, ransomware.campaign, actor.update,
 *    org.risk_change) that shares zero names with the real backend
 *    WEBHOOK_EVENTS in enterpriseAutomation.js (threat.*, scan.*, report.*,
 *    team.*, api.*) — every webhook creation attempt through this UI failed
 *    with "No valid events", unconditionally, regardless of which boxes a
 *    customer checked. Fixed by loading the checklist from the real,
 *    already-existing, public GET /api/webhooks/catalog endpoint instead of
 *    a hardcoded list, so the two can never drift apart again.
 * 2. Pause/Resume (PATCH /api/auto/webhooks/:id) had no matching route at
 *    all anywhere in the codebase — every toggle attempt hit the router's
 *    404 fallback. Added handleWebhookUpdate, scoped to the one field the
 *    UI sends.
 * 3. Logs (GET /api/auto/webhooks/:id/logs) had no matching route either,
 *    despite webhook_delivery_log existing in schema since this feature's
 *    introduction — nothing ever wrote to or read from it. Added
 *    handleWebhookLogs, and made both real delivery-attempt code paths
 *    (handleWebhookTest, and dispatchWebhookEvent for whenever it gains a
 *    caller) record themselves there.
 *
 * Of the 4 webhook-tab actions, only Delete worked before this fix. */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { handleAutoRoute, dispatchWebhookEvent, handleWebhookCatalog } from '../src/handlers/enterpriseAutomation.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE IF NOT EXISTS org_webhooks (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, owner_id TEXT NOT NULL,
    url TEXT NOT NULL, events TEXT NOT NULL DEFAULT '[]', secret TEXT,
    active INTEGER DEFAULT 1, retry_count INTEGER DEFAULT 0,
    last_triggered TEXT, created_at TEXT DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE IF NOT EXISTS webhook_delivery_log (
    id TEXT PRIMARY KEY, webhook_id TEXT NOT NULL, org_id TEXT,
    event_type TEXT NOT NULL, payload_hash TEXT, status TEXT NOT NULL DEFAULT 'pending',
    attempt INTEGER DEFAULT 1, response_code INTEGER, error_msg TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap, async batch(stmts) { return Promise.all(stmts.map(s => s.run())); } };
}

const USER = { authenticated: true, userId: 'u1', tier: 'ENTERPRISE' };
const OTHER_USER = { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' };

async function seedWebhook(env, { id = 'wh1', orgId = 'u1', url = 'https://hooks.example.com/inbound', events = ['scan.completed'], secret = null } = {}) {
  await env.SECURITY_HUB_DB.prepare(
    `INSERT INTO org_webhooks (id, org_id, owner_id, url, events, secret) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, orgId, orgId, url, JSON.stringify(events), secret).run();
}

describe('Frontend event vocabulary now matches the real backend (was: 0% overlap, every creation failed)', () => {
  const html = readFileSync(new URL('../../frontend/automation-dashboard.html', import.meta.url), 'utf8');
  const backendSrc = readFileSync(new URL('../src/handlers/enterpriseAutomation.js', import.meta.url), 'utf8');

  it('no longer hardcodes the old, wrong 5-event list', () => {
    expect(html).not.toContain("cve.critical','kev.added','ransomware.campaign','actor.update','org.risk_change");
  });

  it('loads the checkbox list from the real, public webhook catalog endpoint', () => {
    expect(html).toContain("apiFetch('/api/webhooks/catalog')");
    expect(html).toContain('renderEventCheckboxes(d.events)');
  });

  it("the fallback list (used only if the catalog fetch fails) matches the backend's real WEBHOOK_EVENTS exactly", () => {
    const m = backendSrc.match(/const WEBHOOK_EVENTS = \[([\s\S]*?)\];/);
    expect(m).not.toBeNull();
    const realEvents = m[1].match(/'([\w.]+)'/g).map(s => s.replace(/'/g, ''));
    const fallbackMatch = html.match(/const FALLBACK_EVENTS=\[([\s\S]*?)\];/);
    expect(fallbackMatch).not.toBeNull();
    const fallbackEvents = fallbackMatch[1].match(/'([\w.]+)'/g).map(s => s.replace(/'/g, ''));
    expect(fallbackEvents).toEqual(realEvents);
  });

  it('GET /api/webhooks/catalog really returns WEBHOOK_EVENTS (the exact list the frontend now consumes) — routed directly in index.js, not through handleAutoRoute', async () => {
    const req = new Request('https://x/api/webhooks/catalog');
    const res = await handleWebhookCatalog(req, {}, USER);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.events).toContain('scan.completed');
    expect(body.events).toContain('threat.critical');
  });

  it('index.js really routes GET /api/webhooks/catalog to handleWebhookCatalog', () => {
    const indexSrc = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
    expect(indexSrc).toMatch(/path === '\/api\/webhooks\/catalog' && method === 'GET'/);
    expect(indexSrc).toContain('handleWebhookCatalog');
  });
});

describe('PATCH /api/auto/webhooks/:id — Pause/Resume (was: no route at all, 404 on every attempt)', () => {
  let env;
  beforeEach(async () => { env = { SECURITY_HUB_DB: makeRealD1() }; await seedWebhook(env); });

  it('pauses an active webhook', async () => {
    const req = new Request('https://x/api/auto/webhooks/wh1', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: false }),
    });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/wh1', 'PATCH');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    const row = await env.SECURITY_HUB_DB.prepare('SELECT active FROM org_webhooks WHERE id=?').bind('wh1').first();
    expect(row.active).toBe(0);
  });

  it('resumes a paused webhook', async () => {
    await env.SECURITY_HUB_DB.prepare('UPDATE org_webhooks SET active=0 WHERE id=?').bind('wh1').run();
    const req = new Request('https://x/api/auto/webhooks/wh1', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: true }),
    });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/wh1', 'PATCH');
    expect(res.status).toBe(200);
    const row = await env.SECURITY_HUB_DB.prepare('SELECT active FROM org_webhooks WHERE id=?').bind('wh1').first();
    expect(row.active).toBe(1);
  });

  it('rejects a missing/non-boolean active field', async () => {
    const req = new Request('https://x/api/auto/webhooks/wh1', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/wh1', 'PATCH');
    expect(res.status).toBe(400);
  });

  it("user B cannot toggle user A's webhook by GUID (IDOR closed)", async () => {
    const req = new Request('https://x/api/auto/webhooks/wh1', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: false }),
    });
    const res = await handleAutoRoute(req, env, OTHER_USER, '/api/auto/webhooks/wh1', 'PATCH');
    expect(res.status).toBe(404);
    const row = await env.SECURITY_HUB_DB.prepare('SELECT active FROM org_webhooks WHERE id=?').bind('wh1').first();
    expect(row.active).toBe(1); // unchanged
  });
});

describe('GET /api/auto/webhooks/:id/logs — delivery history (was: no route, 404 on every attempt)', () => {
  let env;
  beforeEach(async () => { env = { SECURITY_HUB_DB: makeRealD1() }; await seedWebhook(env); });

  it('returns an empty, real (not fabricated) log list for a webhook with no delivery attempts yet', async () => {
    const req = new Request('https://x/api/auto/webhooks/wh1/logs');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/wh1/logs', 'GET');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.webhook_id).toBe('wh1');
    expect(body.logs).toEqual([]);
  });

  it('404s for a nonexistent webhook id', async () => {
    const req = new Request('https://x/api/auto/webhooks/does-not-exist/logs');
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/does-not-exist/logs', 'GET');
    expect(res.status).toBe(404);
  });

  it("user B cannot read user A's delivery logs by GUID (IDOR closed)", async () => {
    const req = new Request('https://x/api/auto/webhooks/wh1/logs');
    const res = await handleAutoRoute(req, env, OTHER_USER, '/api/auto/webhooks/wh1/logs', 'GET');
    expect(res.status).toBe(404);
  });
});

describe('Delivery attempts now actually write to webhook_delivery_log (was: table existed, nothing ever wrote to it)', () => {
  let env;
  beforeEach(async () => { env = { SECURITY_HUB_DB: makeRealD1() }; await seedWebhook(env, { secret: 'topsecret' }); });
  afterEach(() => vi.unstubAllGlobals());

  it('POST /test logs a "delivered" entry visible via GET /logs on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    const testReq = new Request('https://x/api/auto/webhooks/wh1/test', { method: 'POST' });
    const testRes = await handleAutoRoute(testReq, env, USER, '/api/auto/webhooks/wh1/test', 'POST');
    expect(testRes.status).toBe(200);
    expect((await testRes.json()).success).toBe(true);

    const logsReq = new Request('https://x/api/auto/webhooks/wh1/logs');
    const logsRes = await handleAutoRoute(logsReq, env, USER, '/api/auto/webhooks/wh1/logs', 'GET');
    const body = await logsRes.json();
    expect(body.logs.length).toBe(1);
    expect(body.logs[0].status).toBe('delivered');
    expect(body.logs[0].response_code).toBe(200);
    expect(body.logs[0].event_type).toBe('webhook.test');
  });

  it('logs a "failed" entry (not "delivered") when the receiving endpoint returns a non-2xx status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const testReq = new Request('https://x/api/auto/webhooks/wh1/test', { method: 'POST' });
    await handleAutoRoute(testReq, env, USER, '/api/auto/webhooks/wh1/test', 'POST');

    const logsRes = await handleAutoRoute(new Request('https://x/api/auto/webhooks/wh1/logs'), env, USER, '/api/auto/webhooks/wh1/logs', 'GET');
    const body = await logsRes.json();
    expect(body.logs[0].status).toBe('failed');
    expect(body.logs[0].response_code).toBe(500);
  });

  it('logs an "error" entry (not a crash) when the outbound fetch itself throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connect ETIMEDOUT')));
    const testReq = new Request('https://x/api/auto/webhooks/wh1/test', { method: 'POST' });
    const testRes = await handleAutoRoute(testReq, env, USER, '/api/auto/webhooks/wh1/test', 'POST');
    expect(testRes.status).toBe(200); // handler itself doesn't throw
    expect((await testRes.json()).success).toBe(false);

    const logsRes = await handleAutoRoute(new Request('https://x/api/auto/webhooks/wh1/logs'), env, USER, '/api/auto/webhooks/wh1/logs', 'GET');
    const body = await logsRes.json();
    expect(body.logs[0].status).toBe('error');
    expect(body.logs[0].error_msg).toMatch(/ETIMEDOUT/);
  });

  it('dispatchWebhookEvent (the real, currently-uncalled event-fan-out path) logs delivery attempts too, ready for whenever it gains a caller', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 204 }));
    await dispatchWebhookEvent(env, ['u1'], 'scan.completed', { scan_id: 's1' });

    const logsRes = await handleAutoRoute(new Request('https://x/api/auto/webhooks/wh1/logs'), env, USER, '/api/auto/webhooks/wh1/logs', 'GET');
    const body = await logsRes.json();
    expect(body.logs.length).toBe(1);
    expect(body.logs[0].event_type).toBe('scan.completed');
    expect(body.logs[0].status).toBe('delivered');
  });
});

describe('Frontend "Test" button — was completely absent despite the backend route already existing', () => {
  const html = readFileSync(new URL('../../frontend/automation-dashboard.html', import.meta.url), 'utf8');

  it('each webhook row now has a Test button calling the real, already-SSRF-guarded test endpoint', () => {
    expect(html).toContain("onclick=\"testWebhookRow('${escHtml(w.id)}')\"");
    expect(html).toContain("apiPost(`/api/auto/webhooks/${id}/test`");
  });
});
