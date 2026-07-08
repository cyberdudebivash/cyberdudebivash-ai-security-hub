/* Task 3 Phase 1 — call-site wiring for the 3 previously-silent event types.
 *
 * These are "does the right handler call the right email function with the
 * right arguments" tests, with emailEngine.js fully mocked (the actual send
 * behavior — DLQ, retry, template content — is covered by
 * emailDlqAndTemplates.test.mjs against the real module).
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/services/emailEngine.js', () => ({
  sendEmail: vi.fn(async () => ({ success: true, provider: 'mock' })),
  sendSuspiciousLoginEmail: vi.fn(async () => ({ success: true, provider: 'mock' })),
  sendPaymentFailedEmail: vi.fn(async () => ({ success: true, provider: 'mock' })),
  sendPurchaseConfirmation: vi.fn(async () => ({ success: true, provider: 'mock' })),
}));
vi.mock('../src/lib/htmlReport.js', () => ({ generateHTMLReport: vi.fn() }));
vi.mock('../src/lib/reportEngine.js', () => ({ buildReport: vi.fn() }));
vi.mock('../src/handlers/analytics.js', () => ({ trackEvent: vi.fn(async () => {}) }));
vi.mock('../src/services/v24/billingEngine.js', () => ({ createInvoice: vi.fn(async () => {}) }));
vi.mock('../src/services/lifecycleEngine.js', () => ({ triggerPostPurchase: vi.fn(async () => {}), normalizeRevenueSource: vi.fn(s => s) }));
vi.mock('../src/handlers/msspRevenue.js', () => ({ resolvePartnerIdForEmail: vi.fn(async () => null), recordRevenueShare: vi.fn(async () => {}) }));

import { handleLogin } from '../src/handlers/auth.js';
import { handleRazorpayWebhook } from '../src/handlers/payments.js';
import { hashPassword } from '../src/auth/password.js';
import { sendSuspiciousLoginEmail, sendPaymentFailedEmail } from '../src/services/emailEngine.js';

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

function loginRequest(ip = '203.0.113.5') {
  return new Request('https://x/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip, 'CF-IPCountry': 'US' },
    body: JSON.stringify({ email: 'alice@acme.com', password: 'CorrectPassw0rd!x' }),
  });
}

describe('handleLogin — suspicious-login alert via refresh_tokens IP-change detection', () => {
  let env, db;
  beforeEach(async () => {
    vi.mocked(sendSuspiciousLoginEmail).mockClear();
    env = { DB: makeRealD1(), JWT_SECRET: 'test-secret' };
    db = env.DB._sqlite;
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, password_salt TEXT, tier TEXT DEFAULT 'FREE', status TEXT DEFAULT 'active', full_name TEXT, last_login_at TEXT, login_count INTEGER DEFAULT 0)`);
    db.exec(`CREATE TABLE refresh_tokens (id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), user_id TEXT, token_hash TEXT, expires_at TEXT, created_at TEXT, revoked INTEGER DEFAULT 0, ip_address TEXT, user_agent TEXT)`);
    db.exec(`CREATE TABLE login_attempts (email TEXT, ip_address TEXT, success INTEGER, attempted_at TEXT DEFAULT (datetime('now')))`);
    const { hash, salt } = await hashPassword('CorrectPassw0rd!x');
    db.prepare(`INSERT INTO users (id, email, password_hash, password_salt) VALUES ('u1','alice@acme.com',?,?)`).run(hash, salt);
  });

  it('does NOT alert on a user\'s very first login (no prior session to compare against)', async () => {
    const res = await handleLogin(loginRequest('203.0.113.5'), env);
    expect(res.status).toBe(200);
    expect(sendSuspiciousLoginEmail).not.toHaveBeenCalled();
  });

  it('does NOT alert when the login IP matches the most recent known IP', async () => {
    db.prepare(`INSERT INTO refresh_tokens (user_id, ip_address, created_at) VALUES ('u1', '203.0.113.5', '2020-01-01T00:00:00.000Z')`).run();
    const res = await handleLogin(loginRequest('203.0.113.5'), env);
    expect(res.status).toBe(200);
    expect(sendSuspiciousLoginEmail).not.toHaveBeenCalled();
  });

  it('alerts when the login IP differs from the most recent known IP, with correct args', async () => {
    db.prepare(`INSERT INTO refresh_tokens (user_id, ip_address, created_at) VALUES ('u1', '198.51.100.1', '2020-01-01T00:00:00.000Z')`).run();
    const res = await handleLogin(loginRequest('203.0.113.5'), env);
    expect(res.status).toBe(200);
    expect(sendSuspiciousLoginEmail).toHaveBeenCalledTimes(1);
    const [, args] = sendSuspiciousLoginEmail.mock.calls[0];
    expect(args.to).toBe('alice@acme.com');
    expect(args.ip).toBe('203.0.113.5');
    expect(args.previousIp).toBe('198.51.100.1');
    expect(args.country).toBe('US');
  });

  it('never blocks login even if the alert send throws', async () => {
    db.prepare(`INSERT INTO refresh_tokens (user_id, ip_address, created_at) VALUES ('u1', '198.51.100.1', '2020-01-01T00:00:00.000Z')`).run();
    vi.mocked(sendSuspiciousLoginEmail).mockRejectedValueOnce(new Error('provider down'));
    const res = await handleLogin(loginRequest('203.0.113.5'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });
});

describe('handleRazorpayWebhook — payment.failed notifies the customer', () => {
  const WEBHOOK_SECRET = 'whsec_test_12345';

  async function sign(secret, body) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const buf = await crypto.subtle.sign('HMAC', key, enc.encode(body));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function memDB({ paymentRow = null, recoveryInserts = [] } = {}) {
    return {
      recoveryInserts,
      prepare(sql) {
        return {
          _sql: sql, _b: [],
          bind(...a) { this._b = a; return this; },
          async first() {
            if (/FROM payments WHERE razorpay_order_id/i.test(this._sql)) return paymentRow;
            return null;
          },
          async run() {
            if (/UPDATE payments SET status = 'failed'/i.test(this._sql)) return { success: true };
            if (/INSERT OR IGNORE INTO payment_recovery/i.test(this._sql)) {
              recoveryInserts.push(this._b);
            }
            return { success: true };
          },
        };
      },
    };
  }

  beforeEach(() => {
    vi.mocked(sendPaymentFailedEmail).mockClear();
  });

  it('seeds payment_recovery AND emails the customer with the resolved product name + amount', async () => {
    const paymentRow = { id: 'p1', email: 'bob@acme.com', amount: 149900, module: 'subscription' };
    const db = memDB({ paymentRow });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const eventObj = { id: 'evt_x', event: 'payment.failed', payload: { payment: { entity: { order_id: 'order_1', error: { description: 'Card declined by issuer' } } } } };
    const rawBody = JSON.stringify(eventObj);
    const req = new Request('https://x/api/webhooks/razorpay', {
      method: 'POST', headers: { 'x-razorpay-signature': await sign(WEBHOOK_SECRET, rawBody) }, body: rawBody,
    });

    const res = await handleRazorpayWebhook(req, env);
    expect(res.status).toBe(200);

    expect(db.recoveryInserts).toHaveLength(1);
    expect(sendPaymentFailedEmail).toHaveBeenCalledTimes(1);
    const [, args] = sendPaymentFailedEmail.mock.calls[0];
    expect(args.to).toBe('bob@acme.com');
    expect(args.amountInr).toBe(1499);
    expect(args.reason).toBe('Card declined by issuer');
  });

  it('does not attempt to email when the payment row has no email on file', async () => {
    const paymentRow = { id: 'p2', email: '', amount: 49900, module: 'domain' };
    const db = memDB({ paymentRow });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const eventObj = { id: 'evt_y', event: 'payment.failed', payload: { payment: { entity: { order_id: 'order_2' } } } };
    const rawBody = JSON.stringify(eventObj);
    const req = new Request('https://x/api/webhooks/razorpay', {
      method: 'POST', headers: { 'x-razorpay-signature': await sign(WEBHOOK_SECRET, rawBody) }, body: rawBody,
    });

    const res = await handleRazorpayWebhook(req, env);
    expect(res.status).toBe(200);
    expect(sendPaymentFailedEmail).not.toHaveBeenCalled();
  });
});
