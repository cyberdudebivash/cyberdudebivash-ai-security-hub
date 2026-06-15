// Monetization paywall + webhook auth (billing-sensitive + security failure paths).
import { describe, it, expect } from 'vitest';
import {
  addMonetizationFlags,
  buildPaymentUrl,
  verifyRazorpayWebhook,
  MODULE_CONFIG,
} from '../src/middleware/monetization.js';

const sampleResult = () => ({
  findings: [
    { id: 'f1', title: 'Open port', severity: 'high', description: 'desc one', is_premium: false },
    { id: 'f2', title: 'Weak TLS', severity: 'medium', description: 'desc two', is_premium: true },
    { id: 'f3', title: 'No DNSSEC', severity: 'low', description: 'desc three', is_premium: true },
  ],
});

describe('addMonetizationFlags — tier gating', () => {
  it('PRO/ENTERPRISE receive full, unlocked access', () => {
    for (const tier of ['PRO', 'ENTERPRISE']) {
      const out = addMonetizationFlags(sampleResult(), 'domain', { tier });
      expect(out.is_premium_locked).toBe(false);
      expect(out.unlock_required).toBe(false);
      expect(out.access_level).toBe('full');
      // Full access must NOT strip findings.
      expect(out.findings.length).toBe(3);
    }
  });

  it('FREE receives a locked preview with a payment URL', () => {
    const out = addMonetizationFlags(sampleResult(), 'domain', { tier: 'FREE' }, 'scan123', 'lead@acme.com');
    expect(out.access_level).toBe('preview');
    expect(out.is_premium_locked).toBe(true);
    expect(out.locked_findings_count).toBeGreaterThan(0);
    // Premium findings must not leak full detail into the free preview.
    const freeIds = out.findings.map(f => f.id);
    expect(freeIds).not.toContain('f2');
    expect(out.monetization.payment_url).toContain('rzp.io');
    expect(out.monetization.unlock_price).toBe(MODULE_CONFIG.domain.price);
  });

  it('defaults unknown modules to the domain config rather than crashing', () => {
    const out = addMonetizationFlags(sampleResult(), 'no_such_module', { tier: 'FREE' });
    expect(out).toBeTruthy();
    expect(out.access_level).toBe('preview');
  });
});

describe('buildPaymentUrl', () => {
  it('builds a base url without params', () => {
    expect(buildPaymentUrl('redteam')).toBe('https://rzp.io/l/cyberdudebivash-redteam');
  });
  it('appends ref and prefilled email when provided', () => {
    const url = buildPaymentUrl('ai', 'scan9', 'a@b.com');
    expect(url).toContain('ref=scan9');
    expect(url).toContain('prefill');
    expect(url).toContain('a%40b.com');
  });
});

describe('verifyRazorpayWebhook — HMAC-SHA256 signature auth', () => {
  const secret = 'whsec_test_secret';

  async function sign(body, key) {
    const enc = new TextEncoder();
    const ck = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const buf = await crypto.subtle.sign('HMAC', ck, enc.encode(body));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  it('accepts a correctly signed payload', async () => {
    const body = JSON.stringify({ event: 'payment.captured', amount: 149900 });
    const sig = await sign(body, secret);
    expect(await verifyRazorpayWebhook(body, sig, secret)).toBe(true);
  });

  it('rejects a tampered payload', async () => {
    const sig = await sign(JSON.stringify({ amount: 100 }), secret);
    expect(await verifyRazorpayWebhook(JSON.stringify({ amount: 999999 }), sig, secret)).toBe(false);
  });

  it('rejects a signature made with the wrong secret', async () => {
    const body = JSON.stringify({ event: 'payment.captured' });
    const sig = await sign(body, 'attacker_secret');
    expect(await verifyRazorpayWebhook(body, sig, secret)).toBe(false);
  });

  it('rejects missing inputs (fail closed)', async () => {
    expect(await verifyRazorpayWebhook('', 'sig', secret)).toBe(false);
    expect(await verifyRazorpayWebhook('body', '', secret)).toBe(false);
    expect(await verifyRazorpayWebhook('body', 'sig', '')).toBe(false);
  });
});
