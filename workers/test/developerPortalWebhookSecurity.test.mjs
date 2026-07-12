// CAP-SEC-AUDIT (Enterprise Production Certification Program, 2026-07-12) —
// workers/src/handlers/developerPortal.js's webhook routes. Zero prior test
// coverage. A manual OWASP-style sweep found: the dispatcher explicitly
// gates key-management routes with isRealUser(authCtx) but the 4 webhook
// CRUD routes registered just above had no such check at all.
// registerWebhook took an arbitrary body.url with no validation and
// body.org_id||'default' with no auth; testWebhook then did a server-side
// fetch(webhook.url) — a fully unauthenticated SSRF oracle (register a
// webhook pointing at an internal address, then hit /test to get
// status/latency/error back). deleteWebhook had no ownership check at all.
//
// Fixed: all 4 routes now require isRealUser(authCtx); org_id is derived
// from the authenticated session, never the client; registerWebhook and
// testWebhook both validate the URL is a public HTTPS FQDN (rejecting
// localhost/private/link-local ranges and non-FQDN/.local/.internal hosts),
// mirroring the existing, already-shipped SSRF guard in
// handlers/enterpriseAutomation.js's handleIntegrationTest; deleteWebhook
// and testWebhook both scope their lookup by org_id.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handleDeveloperPortal } from '../src/handlers/developerPortal.js';

function makeDB() {
  const webhooks = new Map();
  return {
    _webhooks: webhooks,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() {
              if (sql.startsWith('INSERT INTO developer_webhooks')) {
                const [id, org_id, url, events, secret, status, created_at, updated_at] = args;
                webhooks.set(id, { id, org_id, url, events, secret, status, created_at, updated_at });
              } else if (sql.startsWith('UPDATE developer_webhooks SET status')) {
                const [status, id, org_id] = args;
                const w = webhooks.get(id);
                if (w && w.org_id === org_id) w.status = status;
              } else if (sql.startsWith('UPDATE developer_webhooks SET last_tested_at')) {
                // no-op for this test
              }
              return { success: true };
            },
            async first() {
              if (sql.includes('WHERE id=? AND org_id=?')) {
                const [id, org_id] = args;
                const w = webhooks.get(id);
                return (w && w.org_id === org_id) ? w : null;
              }
              return null;
            },
            async all() {
              const [org_id] = args;
              return { results: [...webhooks.values()].filter(w => w.org_id === org_id) };
            },
          };
        },
      };
    },
  };
}

function req(url, { method = 'GET', body } = {}) {
  return { url, method, json: async () => body ?? {} };
}

const userA = { authenticated: true, userId: 'user-A', user_id: 'user-A', org_id: 'org-A' };
const userB = { authenticated: true, userId: 'user-B', user_id: 'user-B', org_id: 'org-B' };
const anon = { authenticated: false };

describe('developerPortal webhook routes — auth, tenant isolation, and SSRF guard', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeDB() };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
  });

  it('anonymous cannot register a webhook', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'] },
    }), env, anon);
    expect(res.status).toBe(401);
  });

  it('anonymous cannot list webhooks', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks'), env, anon);
    expect(res.status).toBe(401);
  });

  it('anonymous cannot delete a webhook', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/some-id', { method: 'DELETE' }), env, anon);
    expect(res.status).toBe(401);
  });

  it('anonymous cannot trigger a test delivery (closes the SSRF oracle for anonymous callers)', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/some-id/test', { method: 'POST' }), env, anon);
    expect(res.status).toBe(401);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('the public webhook event catalog stays unauthenticated (static reference data)', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/events'), env, anon);
    expect(res.status).toBe(200);
  });

  it('a real user registering a webhook has org_id taken from their session, not the request body', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'], org_id: 'org-SPOOFED' },
    }), env, userA);
    expect(res.status).toBe(201);
    const stored = [...env.DB._webhooks.values()][0];
    expect(stored.org_id).toBe('org-A');
  });

  it('rejects registering a webhook pointing at a private/internal address', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://169.254.169.254/latest/meta-data', events: ['scan.completed'] },
    }), env, userA);
    expect(res.status).toBe(400);
    expect(env.DB._webhooks.size).toBe(0);
  });

  it('rejects registering a webhook with a plain HTTP (non-HTTPS) URL', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'http://example.com/hook', events: ['scan.completed'] },
    }), env, userA);
    expect(res.status).toBe(400);
  });

  it('user B cannot list user A\'s webhooks by supplying org_id=org-A', async () => {
    await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'] },
    }), env, userA);
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks?org_id=org-A'), env, userB);
    const body = await res.json();
    expect(body.webhooks).toEqual([]);
  });

  it('user B cannot delete user A\'s webhook by GUID (IDOR closed)', async () => {
    const createRes = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'] },
    }), env, userA);
    const { id } = await createRes.json();
    const res = await handleDeveloperPortal(req(`https://x/api/developer/webhooks/${id}`, { method: 'DELETE' }), env, userB);
    expect(res.status).toBe(404);
    expect(env.DB._webhooks.get(id).status).toBe('ACTIVE');
  });

  it('user B cannot use /test as an SSRF oracle against user A\'s webhook (IDOR closed on the fetch path)', async () => {
    const createRes = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'] },
    }), env, userA);
    const { id } = await createRes.json();
    const res = await handleDeveloperPortal(req(`https://x/api/developer/webhooks/${id}/test`, { method: 'POST' }), env, userB);
    expect(res.status).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('the real owner can register, list, test, and delete their own webhook end to end', async () => {
    const createRes = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', {
      method: 'POST', body: { url: 'https://example.com/hook', events: ['scan.completed'] },
    }), env, userA);
    expect(createRes.status).toBe(201);
    const { id } = await createRes.json();

    const listRes = await handleDeveloperPortal(req('https://x/api/developer/webhooks'), env, userA);
    const listBody = await listRes.json();
    expect(listBody.total).toBe(1);

    const testRes = await handleDeveloperPortal(req(`https://x/api/developer/webhooks/${id}/test`, { method: 'POST' }), env, userA);
    expect(testRes.status).toBe(200);
    expect(fetch).toHaveBeenCalledWith('https://example.com/hook', expect.any(Object));

    const delRes = await handleDeveloperPortal(req(`https://x/api/developer/webhooks/${id}`, { method: 'DELETE' }), env, userA);
    expect(delRes.status).toBe(200);
    expect(env.DB._webhooks.get(id).status).toBe('DELETED');
  });
});
