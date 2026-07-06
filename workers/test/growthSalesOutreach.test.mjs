/* Regression tests — GTM sales-pipeline outreach send, and the auth gate that
 * had to ship alongside it.
 *
 * FOUND during the 2026-07-06 revenue-mechanisms audit: runSalesPipeline()
 * detects leads and drafts cold-outreach email/LinkedIn/proposal content, but
 * markOutreachSent() — the only thing the (former) POST .../send endpoint did
 * — just flipped a DB status column. No email was ever actually sent, so
 * "sent" in the outreach queue was not evidence anything reached a real inbox.
 *
 * Fixing that surfaced a second, more serious problem: /api/growth/sales/run,
 * GET /api/growth/sales/outreach (real lead PII + drafted content), and the
 * send endpoint had ZERO authentication — the neighboring
 * /api/growth/analytics route's own code comment admitted as much ("admin,
 * no strict auth for now"). Wiring in a real send without first closing that
 * gate would have turned a harmless no-op into an unauthenticated mass-email
 * relay on the platform's own domain. Both fixes ship together; this file
 * locks both, mirroring the router-wiring rigor already established in
 * paymentAdminPanel.test.mjs for the exact same class of problem.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { markOutreachSent } from '../src/services/salesEngine.js';
import worker from '../src/index.js';

afterEach(() => { vi.unstubAllGlobals(); });

function makeKV() {
  const store = new Map();
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, v); } };
}

// Resend responds first; sendEmail() only falls through to MailChannels if
// Resend's status isn't exactly 200/201, so a realistic mock must set
// `status` (not just `ok`) and provide `.text()` for the non-success path.
function resendResponse(status, body = {}) {
  return { ok: status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}
function mailchannelsResponse(status) {
  return { ok: status < 300, status, text: async () => '' };
}

function makeOutreachDb(seed) {
  let row = seed ? { ...seed } : null;
  return {
    prepare(sql) {
      const isSelect = /^\s*SELECT/i.test(sql);
      const isUpdate = /^\s*UPDATE/i.test(sql);
      return {
        bind(id) {
          return {
            async first() {
              if (!isSelect || !row || row.id !== id) return null;
              return { email: row.email, subject: row.subject, body: row.body, status: row.status };
            },
            async run() {
              if (isUpdate && row && row.id === id) row.status = 'sent';
              return { success: true };
            },
          };
        },
      };
    },
    _row: () => row,
  };
}

describe('markOutreachSent — approve + actually send (was a status-only no-op)', () => {
  it('calls the real sendEmail path (Resend) and only marks sent on success', async () => {
    let captured;
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      captured = { url, body: JSON.parse(opts.body) };
      return resendResponse(200, { id: 'resend_1' });
    }));
    const db = makeOutreachDb({ id: 'o1', email: 'lead@acme.com', subject: 'Hi', body: 'line one\nline two', status: 'draft' });
    const env = { DB: db, RESEND_API_KEY: 'rk_test' };

    const result = await markOutreachSent(env, 'o1');

    expect(result).toEqual({ success: true, sent: true, provider: 'resend' });
    expect(captured.url).toBe('https://api.resend.com/emails');
    expect(captured.body.to).toEqual(['lead@acme.com']);
    expect(captured.body.subject).toBe('Hi');
    expect(captured.body.html).toContain('line one<br>line two');
    expect(db._row().status).toBe('sent');
  });

  it('does NOT mark sent if the send actually fails on every provider (never lies about delivery)', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) =>
      url.includes('resend.com') ? resendResponse(422, { message: 'invalid domain' }) : mailchannelsResponse(500)
    ));
    const db = makeOutreachDb({ id: 'o2', email: 'lead@acme.com', subject: 'Hi', body: 'text', status: 'draft' });
    const env = { DB: db, RESEND_API_KEY: 'rk_test' };

    const result = await markOutreachSent(env, 'o2');

    expect(result.success).toBe(false);
    expect(db._row().status).toBe('draft');
  });

  it('falls back to MailChannels and still marks sent if only Resend fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) =>
      url.includes('resend.com') ? resendResponse(401, { message: 'bad key' }) : mailchannelsResponse(202)
    ));
    const db = makeOutreachDb({ id: 'o2b', email: 'lead@acme.com', subject: 'Hi', body: 'text', status: 'draft' });
    const env = { DB: db, RESEND_API_KEY: 'rk_test' };

    const result = await markOutreachSent(env, 'o2b');

    expect(result).toEqual({ success: true, sent: true, provider: 'mailchannels' });
    expect(db._row().status).toBe('sent');
  });

  it('is idempotent — re-sending an already-sent item is a no-op, not a duplicate send', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const db = makeOutreachDb({ id: 'o3', email: 'lead@acme.com', subject: 'Hi', body: 'text', status: 'sent' });
    const env = { DB: db, RESEND_API_KEY: 'rk_test' };

    const result = await markOutreachSent(env, 'o3');

    expect(result).toEqual({ success: true, already_sent: true });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('errors clearly on an unknown outreach id instead of silently succeeding', async () => {
    const env = { DB: makeOutreachDb(null), RESEND_API_KEY: 'rk_test' };
    const result = await markOutreachSent(env, 'does-not-exist');
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not found/i);
  });
});

describe('router wiring — /api/growth/sales/* is owner-gated end-to-end', () => {
  const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

  it('POST /api/growth/sales/run 403s an anonymous caller', async () => {
    const env = { DB: makeOutreachDb(null), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/growth/sales/run', { method: 'POST' }), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('GET /api/growth/sales/outreach 403s an anonymous caller (would otherwise leak lead PII)', async () => {
    const env = { DB: makeOutreachDb(null), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/growth/sales/outreach'), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('POST /api/growth/sales/outreach/:id/send 403s an anonymous caller (would otherwise send arbitrary email)', async () => {
    const env = { DB: makeOutreachDb({ id: 'o9', email: 'x@y.com', subject: 's', body: 'b', status: 'draft' }), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/growth/sales/outreach/o9/send', { method: 'POST' }), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('POST /api/growth/sales/outreach/:id/send actually sends for the admin secret, through the real router', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resendResponse(200, { id: 'resend_ok' })));
    const db = makeOutreachDb({ id: 'o10', email: 'lead@acme.com', subject: 'Hi', body: 'text', status: 'draft' });
    const env = { DB: db, RESEND_API_KEY: 'rk_test', ADMIN_KEY: 'SECRET', SECURITY_HUB_KV: makeKV() };
    const req = new Request('https://x/api/growth/sales/outreach/o10/send', {
      method: 'POST', headers: { 'x-admin-secret': 'SECRET' },
    });
    const res = await worker.fetch(req, env, ctxStub);
    expect(res.status).toBe(200);
    expect(db._row().status).toBe('sent');
  });
});
