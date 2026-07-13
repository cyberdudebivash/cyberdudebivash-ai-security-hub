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

// Regression — v40 MYTHOS enrichment (mythosEnrichmentEngine.js's
// enrichAssessmentWithMYTHOS) is merged into the scan result by
// domain.js/ai.js/redteam.js/identity.js/compliance.js BEFORE this function
// runs. Its full premium value (AI executive narrative, attack-path
// prediction, MITRE mapping, autonomous remediation plan) previously spread
// through `...result` completely untouched for FREE-tier callers — the
// findings array was truncated but mythos_intelligence was not, so the full
// block shipped in the plain JSON response to every free/unauthenticated
// scan. Caught during a post-deploy production audit (called
// handleDomainScan directly against a real resolvable domain with tier:
// undefined and confirmed the full mythos_intelligence block was present in
// the response). Fixed to mirror how mythosRevenueEngine.js's own (separate)
// paywall-aware routes already lock this exact field for their callers.
describe('addMonetizationFlags — mythos_intelligence is locked for FREE, not spread through', () => {
  const withMythos = () => ({
    findings: [{ id: 'f1', title: 'Open port', severity: 'high', description: 'd1', is_premium: false }],
    mythos_intelligence: {
      engine: 'CYBERDUDEBIVASH MYTHOS AI™',
      version: 'v4.0-SOVEREIGN',
      mythos_confidence: 87,
      cyber_brain: {
        risk_score: 76, risk_level: 'HIGH',
        risk_signals: [{ type: 'critical_finding', detail: 'Open port', weight: 30 }],
        attack_paths: [{ id: 'x', name: 'Web Exploitation' }],
      },
      mitre_attack: { tactics_identified: 1, mappings: [{ tactic: 'TA0001', name: 'Initial Access' }] },
      autonomous_remediation_plan: [{ phase: 1, label: 'IMMEDIATE', timeline: '0-7 days', item_count: 1, items: [] }],
      ai_executive_brief: { generated: true, narrative: 'Full paid executive narrative text.' },
      threat_actor_overlay: { active: true, actors: [{ name: 'APT99' }] },
      authority: { platform: 'CYBERDUDEBIVASH® SENTINEL APEX' },
    },
  });

  it('PRO/ENTERPRISE receive the complete mythos_intelligence block unmodified', () => {
    for (const tier of ['PRO', 'ENTERPRISE']) {
      const out = addMonetizationFlags(withMythos(), 'domain', { tier });
      expect(out.mythos_intelligence.ai_executive_brief.narrative).toBe('Full paid executive narrative text.');
      expect(out.mythos_intelligence.autonomous_remediation_plan).toHaveLength(1);
      expect(out.mythos_intelligence._paywall_locked).toBeUndefined();
    }
  });

  it('FREE never receives the AI narrative, attack paths, MITRE mapping, or remediation plan', () => {
    const out = addMonetizationFlags(withMythos(), 'domain', { tier: 'FREE' });
    expect(out.mythos_intelligence._paywall_locked).toBe(true);
    expect(out.mythos_intelligence.ai_executive_brief).toBeUndefined();
    expect(out.mythos_intelligence.autonomous_remediation_plan).toBeUndefined();
    expect(out.mythos_intelligence.mitre_attack).toBeUndefined();
    expect(out.mythos_intelligence.threat_actor_overlay).toBeUndefined();
    // Only a teaser survives: engine/version/confidence and a risk-level summary.
    expect(out.mythos_intelligence.mythos_confidence).toBe(87);
    expect(out.mythos_intelligence.cyber_brain).toEqual({ risk_score: 76, risk_level: 'HIGH' });
  });

  it('unauthenticated callers (no authCtx.tier at all) are treated as FREE and also get the locked teaser', () => {
    const out = addMonetizationFlags(withMythos(), 'domain', {});
    expect(out.mythos_intelligence._paywall_locked).toBe(true);
    expect(out.mythos_intelligence.ai_executive_brief).toBeUndefined();
  });

  it('locks mythos_intelligence even when there are zero locked findings (a clean scan)', () => {
    // is_premium_locked is computed from findings alone and can be false on a
    // clean/low-finding scan — mythos_intelligence must still be locked,
    // independent of that flag, since it's independently valuable content.
    const clean = { findings: [], mythos_intelligence: withMythos().mythos_intelligence };
    const out = addMonetizationFlags(clean, 'domain', { tier: 'FREE' });
    expect(out.is_premium_locked).toBe(false);
    expect(out.mythos_intelligence._paywall_locked).toBe(true);
    expect(out.mythos_intelligence.ai_executive_brief).toBeUndefined();
  });

  it('does not add a mythos_intelligence field where none existed', () => {
    const out = addMonetizationFlags(sampleResult(), 'domain', { tier: 'FREE' });
    expect(out.mythos_intelligence).toBeUndefined();
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
