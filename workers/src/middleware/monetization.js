/**
 * CYBERDUDEBIVASH AI Security Hub — Premium Paywall Engine v3.1
 * Free preview → locked findings → Razorpay unlock flow
 * Full per-module pricing + production HMAC-SHA256 webhook verification
 * SECURITY FIX: Replaced stub webhook verification with real crypto (v3.1)
 */

import { UPGRADE_URL } from './auth.js';

// ─── Module Pricing ───────────────────────────────────────────────────────────
// Kept in sync with lib/razorpay.js's MODULE_PRICES (the "v32 repriced per
// customer escalation audit / P0-1 remediation" values) -- this table had
// drifted to the pre-repricing numbers (domain was still showing ₹199 here
// against a real ₹999, etc.), so a customer could see one price in the free
// preview and be charged a different one at Razorpay checkout. Found and
// fixed 2026-07-24. USD figures are illustrative display text only, not a
// real conversion rate or a currency Razorpay actually charges in here.
//
// NOT verified from this environment: what each rzp.io/l/cyberdudebivash-*
// static Payment Link is actually configured to charge in the Razorpay
// dashboard -- that's the true source of truth for the amount collected,
// independent of this constant, and needs the account owner to confirm it
// matches these prices directly in Razorpay's settings.
export const MODULE_CONFIG = {
  domain:     { price:'₹999',        usd:'$12', name:'Domain Vulnerability Report',  free_findings:2 },
  ai:         { price:'₹2,499',      usd:'$30', name:'AI Security Assessment',       free_findings:2 },
  redteam:    { price:'₹4,999',      usd:'$60', name:'Red Team Simulation Report',   free_findings:2 },
  identity:   { price:'₹799',        usd:'$10', name:'Identity Security Report',     free_findings:2 },
  compliance: { price:'₹499',        usd:'$7',  name:'Compliance Gap Report',        free_findings:1 },
};

// ─── Razorpay Payment Link Builder ───────────────────────────────────────────
export function buildPaymentUrl(module, scanId = '', leadEmail = '') {
  const base = `https://rzp.io/l/cyberdudebivash-${module}`;
  const params = new URLSearchParams();
  if (scanId)    params.set('ref', scanId);
  if (leadEmail) params.set('prefill[email]', leadEmail);
  const qs = params.toString();
  return qs ? `${base}?${qs}` : base;
}

// ─── Razorpay Webhook Verification (production HMAC-SHA256) ──────────────────
// Uses Web Crypto API natively in Cloudflare Workers — no external SDK needed
// SECURITY: Uses constant-time comparison to prevent timing attacks
export async function verifyRazorpayWebhook(body, signature, secret) {
  if (!body || !signature || !secret) return false;
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const computedBuf = await crypto.subtle.sign('HMAC', key, enc.encode(body));
    const computed    = Array.from(new Uint8Array(computedBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    // Constant-time comparison to prevent timing-based signature oracle attacks
    if (computed.length !== signature.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return diff === 0;
  } catch {
    return false;
  }
}

// ─── Lock Premium Findings ───────────────────────────────────────────────────
function lockFindings(findings, freeCount) {
  if (!findings || !Array.isArray(findings)) return { free: [], locked: [] };
  const all    = findings.flat();
  const free   = all.filter(f => !f.is_premium).slice(0, freeCount);
  const locked = all.filter(f => f.is_premium || all.indexOf(f) >= freeCount).map(f => ({
    id:       f.id,
    title:    f.title,
    severity: f.severity,
    preview:  (f.description || '').slice(0, 45) + '...',
    locked:   true,
    unlock_cta: 'Unlock full details',
  }));
  return { free, locked };
}

// ─── Main Monetization Wrapper ────────────────────────────────────────────────
export function addMonetizationFlags(result, module, authCtx = {}, scanId = '', leadEmail = '') {
  const cfg      = MODULE_CONFIG[module] || MODULE_CONFIG.domain;
  const tier     = authCtx?.tier || 'FREE';
  const isPro    = tier === 'PRO' || tier === 'ENTERPRISE';

  // PRO/ENTERPRISE gets full results
  if (isPro) {
    return {
      ...result,
      is_premium_locked: false,
      unlock_required: false,
      tier,
      access_level: 'full',
    };
  }

  // FREE → lock premium findings
  const { free, locked } = lockFindings(result.findings, cfg.free_findings);
  const payUrl = buildPaymentUrl(module, scanId, leadEmail);

  // v40 MYTHOS enrichment (merged into `result` by the calling handler before
  // addMonetizationFlags runs — see domain.js/ai.js/redteam.js/identity.js/
  // compliance.js) carries real premium value: an AI executive narrative,
  // attack-path prediction, MITRE mapping, and an autonomous remediation
  // plan. Previously this spread through `...result` untouched regardless of
  // tier, so the full block shipped in the plain JSON response to every
  // FREE-tier and unauthenticated caller — discoverable via the network tab
  // even though the UI only ever rendered it when unlocked. Truncated here
  // the same way mythosRevenueEngine.js's own (separate) paywall-aware
  // routes already lock it for their callers, independent of whether this
  // particular scan happened to have enough findings to lock any of them.
  let mythosPreview = result.mythos_intelligence;
  if (mythosPreview) {
    mythosPreview = {
      engine:            mythosPreview.engine,
      version:            mythosPreview.version,
      mythos_confidence: mythosPreview.mythos_confidence,
      cyber_brain: mythosPreview.cyber_brain
        ? { risk_score: mythosPreview.cyber_brain.risk_score, risk_level: mythosPreview.cyber_brain.risk_level }
        : undefined,
      _paywall_locked: true,
      _paywall_notice: 'Full AI executive brief, attack-path prediction, MITRE ATT&CK mapping and autonomous remediation plan unlock with the full report.',
    };
  }

  return {
    ...result,
    findings: free,
    locked_findings: locked,
    locked_findings_count: locked.length,
    is_premium_locked: locked.length > 0,
    unlock_required: locked.length > 0,
    tier: 'FREE',
    access_level: 'preview',
    ...(mythosPreview ? { mythos_intelligence: mythosPreview } : {}),
    monetization: {
      unlock_price: cfg.price,
      unlock_price_usd: cfg.usd,
      report_name: cfg.name,
      payment_url: payUrl,
      upgrade_url: UPGRADE_URL,
      upgrade_cta: `Unlock ${locked.length} additional findings & full ${cfg.name} for ${cfg.price}`,
      plan_benefits: {
        PRO: ['500 scans/day','Full findings on all modules','Priority support','Export PDF/JSON reports','API access'],
        ENTERPRISE: ['Unlimited scans','White-label reports','SLA guarantee','Dedicated security analyst','Custom integrations'],
      },
    },
    contact: {
      company: 'CyberDudeBivash Pvt. Ltd.',
      email:   'contact@cyberdudebivash.in',
      website: 'https://cyberdudebivash.in',
      enterprise: 'bivashnayak.ai007@gmail.com',
    },
  };
}

// ─── Webhook Handler (Razorpay payment confirmation) ─────────────────────────
export async function handlePaymentWebhook(request, env) {
  const signature = request.headers.get('x-razorpay-signature') || '';
  const bodyText  = await request.text();
  const secret    = env?.RAZORPAY_WEBHOOK_SECRET || '';

  if (!verifyRazorpayWebhook(bodyText, signature, secret)) {
    return Response.json({ error: 'Invalid webhook signature' }, { status: 401 });
  }

  let payload;
  try { payload = JSON.parse(bodyText); } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const event = payload?.event;
  if (event === 'payment.captured') {
    const paymentId = payload?.payload?.payment?.entity?.id;
    const email     = payload?.payload?.payment?.entity?.email;
    const ref       = payload?.payload?.payment?.entity?.description || '';

    // Store unlock token in KV (24h access to full report)
    if (env?.SECURITY_HUB_KV && paymentId) {
      await env.SECURITY_HUB_KV.put(
        `unlock:${paymentId}`,
        JSON.stringify({ email, ref, unlocked_at: Date.now(), valid_until: Date.now() + 86400000 }),
        { expirationTtl: 86400 }
      );
    }
    return Response.json({ status: 'ok', message: 'Payment captured and access granted', payment_id: paymentId });
  }

  return Response.json({ status: 'ok', event_ignored: event });
}
