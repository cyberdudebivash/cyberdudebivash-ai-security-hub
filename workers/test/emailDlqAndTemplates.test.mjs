/* Task 3 Phase 1 — Email & Notification Template Engine hardening.
 *
 * Context: workers/src/services/emailEngine.js already had a mature drip
 * system (9 sequences, 20+ templates, Resend->MailChannels cascade) before
 * this work. The real gaps closed here: (1) a failed send on every provider
 * was previously only console.error'd with the content gone forever — now
 * it lands in email_dlq for a cron-driven retry; (2) sendPurchaseConfirmation
 * (fired on every real purchase) now goes through that same DLQ-backed path
 * instead of a bare sendEmail() call; (3) three previously-silent event
 * types (payment failed, coupon redeemed, suspicious login) now have real
 * templates.
 *
 * Runs against the REAL emailEngine.js with global.fetch mocked (Resend +
 * MailChannels are both outbound HTTP calls) and a real in-memory D1 via
 * node:sqlite for the DLQ table.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  renderEmailLayout, sendEmailWithRetry, runEmailDlqRetry, handleAdminListEmailDlq,
  sendPaymentFailedEmail, sendCouponRedeemedEmail, sendSuspiciousLoginEmail,
} from '../src/services/emailEngine.js';

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

function okResendResponse() {
  return new Response(JSON.stringify({ id: 'resend_123' }), { status: 200 });
}
function failedResendResponse() {
  return new Response(JSON.stringify({ error: 'invalid_api_key' }), { status: 401 });
}
function failedMailChannelsResponse() {
  return new Response('bad request', { status: 400 });
}
function okMailChannelsResponse() {
  return new Response(null, { status: 202 });
}

describe('renderEmailLayout — shared HTML shell (Task 3 Phase 1)', () => {
  it('embeds title, subtitle, and body into the standard dark-theme wrapper', () => {
    const html = renderEmailLayout({ headerTitle: 'Hello', headerSubtitle: 'World', bodyHtml: '<p>content</p>' });
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Hello');
    expect(html).toContain('World');
    expect(html).toContain('<p>content</p>');
    expect(html).toContain('#0a0e1a'); // matches existing template background
  });

  it('omits the subtitle block entirely when none is given', () => {
    const html = renderEmailLayout({ headerTitle: 'Solo Title', bodyHtml: '<p>x</p>' });
    expect(html).toContain('Solo Title');
    expect(html.match(/margin-top:6px/g) || []).toHaveLength(0);
  });
});

describe('sendEmailWithRetry — DLQ persistence on total failure', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('does not touch the DLQ when Resend succeeds', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okResendResponse()));
    const result = await sendEmailWithRetry(env, {
      to: 'a@x.com', subject: 'Hi', html: '<p>hi</p>', text: 'hi', eventType: 'test',
    });
    expect(result.success).toBe(true);
    const { results } = await env.DB.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='email_dlq'`).all();
    expect(results.length).toBe(0); // table never created — nothing to persist
  });

  it('persists to email_dlq when every provider fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('resend.com')) return failedResendResponse();
      return failedMailChannelsResponse();
    }));
    const result = await sendEmailWithRetry(env, {
      to: 'fail@x.com', subject: 'Will Fail', html: '<p>x</p>', text: 'x', eventType: 'payment_failed',
    });
    expect(result.success).toBe(false);

    const { results } = await env.DB.prepare(`SELECT * FROM email_dlq WHERE to_email = ?`).bind('fail@x.com').all();
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pending_retry');
    expect(results[0].event_type).toBe('payment_failed');
    expect(results[0].attempts).toBe(1);
    expect(results[0].subject).toBe('Will Fail');
  });

  it('does nothing (no throw) when env.DB is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    const result = await sendEmailWithRetry({}, { to: 'x@x.com', subject: 's', html: 'h', text: 't' });
    expect(result.success).toBe(false); // still reports the real send failure
  });
});

describe('runEmailDlqRetry — cron sweep', () => {
  let env;
  beforeEach(async () => {
    env = { DB: makeRealD1() };
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    await sendEmailWithRetry(env, { to: 'retry@x.com', subject: 'S1', html: 'h', text: 't', eventType: 'test' });
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('marks a row recovered when a retry succeeds', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okMailChannelsResponse()));
    const out = await runEmailDlqRetry(env);
    expect(out).toEqual({ retried: 1, recovered: 1, permanentlyFailed: 0 });
    const row = await env.DB.prepare(`SELECT status, resolved_at FROM email_dlq WHERE to_email = ?`).bind('retry@x.com').first();
    expect(row.status).toBe('recovered');
    expect(row.resolved_at).toBeTruthy();
  });

  it('increments attempts and stays pending_retry below the max', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    const out = await runEmailDlqRetry(env);
    expect(out.permanentlyFailed).toBe(0);
    const row = await env.DB.prepare(`SELECT status, attempts FROM email_dlq WHERE to_email = ?`).bind('retry@x.com').first();
    expect(row.status).toBe('pending_retry');
    expect(row.attempts).toBe(2);
  });

  it('marks failed_permanent once attempts reach the cap', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    // Already at attempts=1 from beforeEach; drive it to the cap (5).
    await runEmailDlqRetry(env); // 2
    await runEmailDlqRetry(env); // 3
    await runEmailDlqRetry(env); // 4
    const out = await runEmailDlqRetry(env); // 5 -> permanent
    expect(out.permanentlyFailed).toBe(1);
    const row = await env.DB.prepare(`SELECT status, attempts FROM email_dlq WHERE to_email = ?`).bind('retry@x.com').first();
    expect(row.status).toBe('failed_permanent');
    expect(row.attempts).toBe(5);
  });

  it('is a no-op with a clean summary when the queue is empty', async () => {
    const emptyEnv = { DB: makeRealD1() };
    const out = await runEmailDlqRetry(emptyEnv);
    expect(out).toEqual({ retried: 0, recovered: 0, permanentlyFailed: 0 });
  });
});

describe('GET /api/admin/email-dlq — handleAdminListEmailDlq', () => {
  let env;
  beforeEach(async () => {
    env = { DB: makeRealD1() };
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    await sendEmailWithRetry(env, { to: 'a@x.com', subject: 'A', html: 'h', text: 't', eventType: 'payment_failed' });
    await sendEmailWithRetry(env, { to: 'b@x.com', subject: 'B', html: 'h', text: 't', eventType: 'coupon_redeemed' });
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('rejects a non-admin caller', async () => {
    const res = await handleAdminListEmailDlq(new Request('https://x/api/admin/email-dlq'), env, { isAdmin: false });
    expect(res.status).toBe(403);
  });

  it('lists DLQ rows for an admin caller, newest first, without full html/text bodies', async () => {
    const res = await handleAdminListEmailDlq(new Request('https://x/api/admin/email-dlq'), env, { isAdmin: true });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.count).toBe(2);
    expect(body.data.rows).toHaveLength(2);
    expect(body.data.rows[0].html).toBeUndefined();
  });

  it('filters by status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okMailChannelsResponse()));
    await runEmailDlqRetry(env); // both recover now
    const res = await handleAdminListEmailDlq(new Request('https://x/api/admin/email-dlq?status=recovered'), env, { isAdmin: true });
    const body = await res.json();
    expect(body.data.count).toBe(2);
    expect(body.data.rows.every(r => r.status === 'recovered')).toBe(true);
  });
});

describe('New Task 3 templates — payment failed / coupon redeemed / suspicious login', () => {
  let env;
  beforeEach(() => {
    // RESEND_API_KEY set so sendEmail() takes the Resend branch — these
    // assertions check the Resend JSON payload shape ({subject, html, text}
    // top-level), not MailChannels' ({content:[{type,value}]}) shape.
    env = { DB: makeRealD1(), RESEND_API_KEY: 'test_resend_key' };
    vi.stubGlobal('fetch', vi.fn(async () => okResendResponse()));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('sendPaymentFailedEmail sends with a clear subject and no charge language', async () => {
    const result = await sendPaymentFailedEmail(env, { to: 'c@x.com', productName: 'PRO Plan', amountInr: 1499, reason: 'Card declined' });
    expect(result.success).toBe(true);
    const [, init] = global.fetch.mock.calls[0];
    const payload = JSON.parse(init.body);
    expect(payload.subject).toMatch(/Payment Failed/);
    expect(payload.html).toContain('PRO Plan');
    expect(payload.html).toContain('Card declined');
    expect(payload.text).toMatch(/No charge was made/);
  });

  it('sendPaymentFailedEmail requires a destination email', async () => {
    const result = await sendPaymentFailedEmail(env, { productName: 'PRO Plan' });
    expect(result.success).toBe(false);
    expect(result.reason).toBe('missing_params');
  });

  it('sendCouponRedeemedEmail includes the code and discount label', async () => {
    const result = await sendCouponRedeemedEmail(env, {
      to: 'd@x.com', code: 'LAUNCH25', discountLabel: '25% off', productName: 'Pro Plan', finalAmountInr: 1124,
    });
    expect(result.success).toBe(true);
    const [, init] = global.fetch.mock.calls[0];
    const payload = JSON.parse(init.body);
    expect(payload.subject).toContain('LAUNCH25');
    expect(payload.html).toContain('25% off');
    expect(payload.html).toContain('1,124');
  });

  it('sendSuspiciousLoginEmail surfaces IP/location/device and a change-password nudge', async () => {
    const result = await sendSuspiciousLoginEmail(env, {
      to: 'e@x.com', ip: '203.0.113.5', country: 'US', userAgent: 'Mozilla/5.0 Test', previousIp: '198.51.100.1',
    });
    expect(result.success).toBe(true);
    const [, init] = global.fetch.mock.calls[0];
    const payload = JSON.parse(init.body);
    expect(payload.html).toContain('203.0.113.5');
    expect(payload.html).toContain('US');
    expect(payload.text).toMatch(/change your password/i);
  });

  it('a failed new-template send still lands in the DLQ (they route through sendEmailWithRetry)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => failedMailChannelsResponse()));
    await sendPaymentFailedEmail(env, { to: 'f@x.com', productName: 'PRO' });
    const row = await env.DB.prepare(`SELECT event_type FROM email_dlq WHERE to_email = ?`).bind('f@x.com').first();
    expect(row.event_type).toBe('payment_failed');
  });
});
