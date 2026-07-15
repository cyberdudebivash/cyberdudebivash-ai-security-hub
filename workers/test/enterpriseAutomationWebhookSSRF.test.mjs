/* Regression test — enterpriseAutomation.js's webhook create/test paths had
 * no SSRF guard, unlike this same file's own handleIntegrationTest (which
 * already blocked private/loopback/link-local targets) and unlike the
 * unused sibling implementation in developerPortal.js. Since
 * frontend/automation-dashboard.html calls THIS file's /api/auto/webhooks*
 * routes (the developerPortal.js implementation has zero frontend callers),
 * this was a live, exploitable SSRF oracle: register a webhook pointing at
 * an internal/cloud-metadata address, then hit /test to get its
 * status/error read back.
 *
 * Fixed by factoring the existing handleIntegrationTest guard into a shared
 * validateOutboundUrl() and applying it at webhook creation (reject before
 * anything is stored) and again at test-fire time (defense in depth for any
 * row that predates this fix). handleIntegrationTest itself now calls the
 * same shared function — same behavior, one copy instead of a second drift
 * risk. */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAutoRoute } from '../src/handlers/enterpriseAutomation.js';

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
const VALID_EVENTS = ['scan.completed'];

async function createReq(body) {
  return new Request('https://x/api/auto/webhooks', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('POST /api/auto/webhooks — SSRF guard on creation', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_DB: makeRealD1() }; });

  it('rejects a cloud-metadata target (169.254.169.254) — the live SSRF finding', async () => {
    const req = await createReq({ url: 'https://169.254.169.254/latest/meta-data/', events: VALID_EVENTS });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks', 'POST');
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/private|loopback/i);
    const { results } = await env.SECURITY_HUB_DB.prepare('SELECT * FROM org_webhooks').all();
    expect(results.length).toBe(0);
  });

  it('rejects localhost and private RFC1918 ranges', async () => {
    for (const url of ['https://localhost/x', 'https://127.0.0.1/x', 'https://10.0.0.5/x', 'https://192.168.1.1/x']) {
      const req = await createReq({ url, events: VALID_EVENTS });
      const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks', 'POST');
      expect(res.status, url).toBe(400);
    }
  });

  it('rejects a non-FQDN / .internal target', async () => {
    const req = await createReq({ url: 'https://payment-svc.internal/x', events: VALID_EVENTS });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks', 'POST');
    expect(res.status).toBe(400);
  });

  it('still accepts a legitimate public HTTPS webhook (no regression)', async () => {
    const req = await createReq({ url: 'https://hooks.example.com/inbound', events: VALID_EVENTS });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks', 'POST');
    expect(res.status).toBe(201);
    const { results } = await env.SECURITY_HUB_DB.prepare('SELECT * FROM org_webhooks').all();
    expect(results.length).toBe(1);
  });
});

describe('POST /api/auto/webhooks/:id/test — defense-in-depth guard on stored URLs', () => {
  it('rejects test-firing a row whose URL predates this fix (already stored, e.g. via direct DB write)', async () => {
    const env = { SECURITY_HUB_DB: makeRealD1() };
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO org_webhooks (id, org_id, owner_id, url, events) VALUES (?, ?, ?, ?, ?)`
    ).bind('wh1', 'u1', 'u1', 'https://169.254.169.254/latest/meta-data/', '["scan.completed"]').run();

    const req = new Request('https://x/api/auto/webhooks/wh1/test', { method: 'POST' });
    const res = await handleAutoRoute(req, env, USER, '/api/auto/webhooks/wh1/test', 'POST');
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/private|loopback/i);
  });
});

describe('POST /api/auto/integrations/test — refactor preserves existing behavior', () => {
  it('still rejects private/loopback targets (same guard, now shared)', async () => {
    const req = new Request('https://x/api/auto/integrations/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'generic', url: 'https://127.0.0.1/x' }),
    });
    const env = { SECURITY_HUB_DB: makeRealD1() };
    const res = await handleAutoRoute(req, env, USER, '/api/auto/integrations/test', 'POST');
    expect(res.status).toBe(400);
  });
});
