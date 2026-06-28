// =============================================================================
// P23.0 — MSSP Public Onboarding & Pricing Flow
// CYBERDUDEBIVASH AI Security Hub | handlers/msspOnboardingHandler.js
//
// Self-serve MSSP partner onboarding with Razorpay subscription checkout.
// Additive only — reuses MSSP_TIERS from globalScale.js, createRazorpayOrder +
// verifyPaymentSignature from lib/razorpay.js, deliverNotification from
// notificationPlatform.js, and normalizeTier from subscriptionPaywallEngine.js.
//
// IMPORTANT — table naming: this file owns `mssp_onboarding_partners`, a
// dedicated table. It does NOT use `mssp_partners` — that table belongs to
// the P9.0 MSSP Tenant Platform (msspOps.js / revenueKPI.js / index.js
// funnel dashboard) and has an incompatible schema (company, contact_email,
// tier, client_count, ...). Writing this flow's rows into mssp_partners
// previously caused every trial/checkout/verify call to fail in production
// with "D1_ERROR: table mssp_partners has no column named email" — found
// and fixed 2026-06-29. Do not rename back to mssp_partners without first
// reconciling the two schemas.
//
// Routes:
//   GET  /api/mssp/onboarding/tiers         → public tier catalog with Razorpay amounts
//   POST /api/mssp/onboarding/checkout      → create Razorpay order for MSSP tier
//   POST /api/mssp/onboarding/verify        → verify payment + provision MSSP account
//   GET  /api/mssp/onboarding/status        → onboarding status by partner_id or email
//   POST /api/mssp/onboarding/trial         → start 14-day free MSSP trial (no payment)
//   GET  /api/mssp/onboarding/observability → health + metrics
// =============================================================================

import { MSSP_TIERS } from '../services/globalScale.js';
import { createRazorpayOrder, verifyPaymentSignature, generateReceiptId, generateAccessToken } from '../lib/razorpay.js';
import { deliverNotification } from './notificationPlatform.js';

const TRIAL_DAYS        = 14;
const TRIAL_KV_TTL      = 86400 * TRIAL_DAYS;
const ONBOARDING_KV_TTL = 86400 * 90;   // 90-day onboarding state retention
const MAX_TRIALS_PER_IP = 2;
const MAX_TRIALS_PER_EMAIL = 1;

// MSSP plan amounts in paise (server-side only — NEVER from client)
// Derived from MSSP_TIERS canonical source in globalScale.js
function getTierAmountPaise(tierId) {
  const tier = MSSP_TIERS[tierId];
  if (!tier) return null;
  return tier.price_inr * 100; // paise
}

// ── GET /api/mssp/onboarding/tiers ────────────────────────────────────────
export async function handleMsspTiers(request, env) {
  const tiers = Object.values(MSSP_TIERS).map(t => ({
    id:          t.id,
    name:        t.name,
    price_inr:   t.price_inr,
    price_display: `₹${t.price_inr.toLocaleString('en-IN')}/month`,
    billing:     t.billing,
    clients:     t.clients === -1 ? 'Unlimited' : t.clients,
    margin:      t.margin,
    features:    t.features,
    amount_paise: getTierAmountPaise(t.id),
    popular:     t.id === 'silver',
  }));

  // Fetch live partner count from D1 for social proof
  let partnerCount = null;
  try {
    const row = await env.DB.prepare(
      'SELECT COUNT(*) AS cnt FROM mssp_onboarding_partners WHERE status=?'
    ).bind('active').first();
    partnerCount = row?.cnt ?? null;
  } catch { /* D1 table may not exist yet — graceful */ }

  return jsonResponse({
    tiers,
    trial_available: true,
    trial_days: TRIAL_DAYS,
    partner_count: partnerCount,
    support_email: 'mssp@cyberdudebivash.com',
    sla: '99.9% uptime SLA for Silver and Gold',
  });
}

// ── POST /api/mssp/onboarding/checkout ────────────────────────────────────
// Body: { tier_id, company_name, email, contact_name, phone?, clients_estimate?, website? }
export async function handleMsspCheckout(request, env) {
  try {
    const body = await request.json();
    const { tier_id, company_name, email, contact_name, phone, clients_estimate, website } = body;

    // Validate required fields
    if (!tier_id || !MSSP_TIERS[tier_id]) {
      return jsonResponse({ error: 'Invalid tier_id. Valid options: reseller, silver, gold' }, 400);
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: 'Valid email required' }, 400);
    }
    if (!company_name || company_name.trim().length < 2) {
      return jsonResponse({ error: 'Company name required (min 2 chars)' }, 400);
    }
    if (!contact_name || contact_name.trim().length < 2) {
      return jsonResponse({ error: 'Contact name required' }, 400);
    }

    const tier       = MSSP_TIERS[tier_id];
    const amountPaise = getTierAmountPaise(tier_id);
    const receipt    = generateReceiptId(`mssp-${tier_id}`);
    const currency   = 'INR';

    // Check for existing pending MSSP checkout (prevent double-orders)
    const dedupKey = `mssp:checkout:${email}:${tier_id}`;
    const existing = await env.KV.get(dedupKey);
    if (existing) {
      const ex = JSON.parse(existing);
      return jsonResponse({
        already_pending: true,
        order_id:    ex.order_id,
        razorpay_key: env.RAZORPAY_KEY_ID,
        tier_id,
        amount_paise: amountPaise,
        currency,
        company_name: company_name.trim(),
        contact_name: contact_name.trim(),
        email,
        message: 'Existing pending order returned.',
      });
    }

    // Create Razorpay order (server-side — amount from canonical MSSP_TIERS)
    const order = await createRazorpayOrder(env, {
      amount:   amountPaise,
      currency,
      receipt,
      notes: {
        tier_id,
        tier_name:       tier.name,
        company_name:    company_name.trim(),
        contact_name:    contact_name.trim(),
        email,
        clients_estimate: String(clients_estimate || ''),
        source:          'mssp_onboarding_v23',
      },
    });

    // Store pending checkout in D1
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS mssp_onboarding_checkouts (
        id TEXT PRIMARY KEY, order_id TEXT, tier_id TEXT, email TEXT,
        company_name TEXT, contact_name TEXT, phone TEXT, website TEXT,
        clients_estimate INTEGER, amount_paise INTEGER, currency TEXT,
        status TEXT DEFAULT 'pending', partner_id TEXT,
        created_at TEXT, paid_at TEXT
      )`
    ).run();

    const checkoutId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO mssp_onboarding_checkouts
        (id, order_id, tier_id, email, company_name, contact_name, phone, website, clients_estimate, amount_paise, currency, status, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      checkoutId, order.id, tier_id, email.toLowerCase().trim(),
      company_name.trim(), contact_name.trim(), phone || null, website || null,
      parseInt(clients_estimate) || 0, amountPaise, currency, 'pending',
      new Date().toISOString()
    ).run();

    // KV dedup with 1-hour TTL
    await env.KV.put(dedupKey, JSON.stringify({ order_id: order.id, checkout_id: checkoutId }), { expirationTtl: 3600 });

    return jsonResponse({
      success:      true,
      checkout_id:  checkoutId,
      order_id:     order.id,
      razorpay_key: env.RAZORPAY_KEY_ID,
      tier_id,
      tier_name:    tier.name,
      amount_paise: amountPaise,
      currency,
      company_name: company_name.trim(),
      contact_name: contact_name.trim(),
      email,
      features:     tier.features,
      clients:      tier.clients === -1 ? 'Unlimited' : tier.clients,
      margin:       tier.margin,
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/mssp/onboarding/verify ──────────────────────────────────────
// Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature, checkout_id }
export async function handleMsspVerify(request, env) {
  try {
    const body = await request.json();
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, checkout_id } = body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return jsonResponse({ error: 'Missing payment verification fields' }, 400);
    }

    // HMAC verify (canonical — never re-implemented)
    const valid = await verifyPaymentSignature(env, razorpay_order_id, razorpay_payment_id, razorpay_signature);
    if (!valid) {
      return jsonResponse({ error: 'Payment signature verification failed' }, 400);
    }

    // Look up checkout record
    const checkout = await env.DB.prepare(
      'SELECT * FROM mssp_onboarding_checkouts WHERE order_id=?'
    ).bind(razorpay_order_id).first();

    if (!checkout) {
      return jsonResponse({ error: 'Checkout record not found for this order' }, 404);
    }
    if (checkout.status === 'paid') {
      return jsonResponse({ already_verified: true, partner_id: checkout.partner_id });
    }

    const tier       = MSSP_TIERS[checkout.tier_id] || {};
    const partnerId  = `mssp-${Date.now()}-${crypto.randomUUID().slice(0,8)}`;
    const accessToken = generateAccessToken();
    const now        = new Date().toISOString();

    // Provision MSSP partner account in D1
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS mssp_onboarding_partners (
        id TEXT PRIMARY KEY, email TEXT UNIQUE, company_name TEXT, contact_name TEXT,
        phone TEXT, website TEXT, tier_id TEXT, clients_limit INTEGER,
        margin_pct TEXT, status TEXT DEFAULT 'active', access_token TEXT,
        razorpay_order_id TEXT, razorpay_payment_id TEXT,
        trial_ends_at TEXT, activated_at TEXT, created_at TEXT
      )`
    ).run();

    await env.DB.prepare(
      `INSERT INTO mssp_onboarding_partners
        (id, email, company_name, contact_name, phone, website, tier_id, clients_limit,
         margin_pct, status, access_token, razorpay_order_id, razorpay_payment_id, activated_at, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(email) DO UPDATE SET
          tier_id=excluded.tier_id, clients_limit=excluded.clients_limit,
          razorpay_order_id=excluded.razorpay_order_id, razorpay_payment_id=excluded.razorpay_payment_id,
          activated_at=excluded.activated_at, status='active'`
    ).bind(
      partnerId, checkout.email, checkout.company_name, checkout.contact_name,
      checkout.phone, checkout.website, checkout.tier_id,
      tier.clients ?? 10, tier.margin ?? '30%',
      'active', accessToken, razorpay_order_id, razorpay_payment_id, now, now
    ).run();

    // Update checkout status
    await env.DB.prepare(
      'UPDATE mssp_onboarding_checkouts SET status=?, partner_id=?, paid_at=? WHERE order_id=?'
    ).bind('paid', partnerId, now, razorpay_order_id).run();

    // Store KV onboarding state (90-day)
    await env.KV.put(
      `mssp:partner:${partnerId}`,
      JSON.stringify({ partnerId, email: checkout.email, company: checkout.company_name, tier_id: checkout.tier_id, activatedAt: now }),
      { expirationTtl: ONBOARDING_KV_TTL }
    );

    // Store access token for API auth
    await env.KV.put(
      `mssp:token:${accessToken}`,
      JSON.stringify({ partnerId, tier_id: checkout.tier_id, company: checkout.company_name }),
      { expirationTtl: 86400 * 30 }  // 30-day token, renewable
    );

    // Send welcome notification
    try {
      await deliverNotification({
        eventType: 'MSSP_PARTNER_ACTIVATED',
        channels: ['INAPP'],
        metadata: { partner_id: partnerId, tier: checkout.tier_id, company: checkout.company_name },
      }, env);
    } catch { /* notification failure non-fatal */ }

    // Also insert CRM lead as converted
    await env.DB.prepare(
      `INSERT INTO crm_leads (id, company_name, email, status, source, created_at)
       VALUES (?,?,?,'converted','mssp_onboarding_v23',?)
       ON CONFLICT(email) DO UPDATE SET status='converted'`
    ).bind(crypto.randomUUID(), checkout.company_name, checkout.email, now).run().catch(() => {});

    return jsonResponse({
      success:      true,
      partner_id:   partnerId,
      access_token: accessToken,
      company_name: checkout.company_name,
      tier_id:      checkout.tier_id,
      tier_name:    tier.name,
      clients_limit: tier.clients === -1 ? 'Unlimited' : tier.clients,
      margin:       tier.margin,
      dashboard_url: '/mssp-dashboard.html',
      api_docs_url:  '/developer-onboarding.html',
      support_email: 'mssp@cyberdudebivash.com',
      activated_at:  now,
      next_steps: [
        'Log in to your MSSP dashboard',
        'Configure white-label branding (Silver/Gold)',
        'Add your first client account',
        'Generate API keys for your integration',
        'Book your onboarding call with your account manager',
      ],
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── POST /api/mssp/onboarding/trial ───────────────────────────────────────
// Body: { company_name, email, contact_name, clients_estimate? }
export async function handleMsspTrial(request, env) {
  try {
    const ip   = request.headers.get('CF-Connecting-IP') || 'unknown';
    const today = new Date().toISOString().slice(0, 10);
    const body  = await request.json();
    const { company_name, email, contact_name, clients_estimate } = body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: 'Valid email required' }, 400);
    }
    if (!company_name || company_name.trim().length < 2) {
      return jsonResponse({ error: 'Company name required' }, 400);
    }
    if (!contact_name || contact_name.trim().length < 2) {
      return jsonResponse({ error: 'Contact name required' }, 400);
    }

    // Rate limit: per IP per day
    const ipKey = `mssp:trial:ratelimit:${ip}:${today}`;
    const ipCount = parseInt(await env.KV.get(ipKey) || '0');
    if (ipCount >= MAX_TRIALS_PER_IP) {
      return jsonResponse({ error: 'Trial limit reached from this IP. Contact mssp@cyberdudebivash.com to proceed.' }, 429);
    }

    // Rate limit: per email (lifetime)
    const emailKey = `mssp:trial:email:${email.toLowerCase()}`;
    const emailExists = await env.KV.get(emailKey);
    if (emailExists) {
      return jsonResponse({ error: 'A trial already exists for this email. Check your inbox or contact support.', hint: 'trial_exists' }, 409);
    }

    const partnerId   = `mssp-trial-${Date.now()}-${crypto.randomUUID().slice(0,8)}`;
    const accessToken = generateAccessToken();
    const now         = new Date();
    const trialEndsAt = new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString();

    // Provision trial in D1 (dedicated table — see header note on mssp_onboarding_partners)
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS mssp_onboarding_partners (
        id TEXT PRIMARY KEY, email TEXT UNIQUE, company_name TEXT, contact_name TEXT,
        phone TEXT, website TEXT, tier_id TEXT, clients_limit INTEGER,
        margin_pct TEXT, status TEXT DEFAULT 'active', access_token TEXT,
        razorpay_order_id TEXT, razorpay_payment_id TEXT,
        trial_ends_at TEXT, activated_at TEXT, created_at TEXT
      )`
    ).run();

    await env.DB.prepare(
      `INSERT INTO mssp_onboarding_partners
        (id, email, company_name, contact_name, tier_id, clients_limit, margin_pct,
         status, access_token, trial_ends_at, activated_at, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(email) DO NOTHING`
    ).bind(
      partnerId, email.toLowerCase().trim(), company_name.trim(), contact_name.trim(),
      'reseller', 3, '0%',
      'trial', accessToken, trialEndsAt, now.toISOString(), now.toISOString()
    ).run();

    // KV rate limit + email dedup
    await env.KV.put(ipKey, String(ipCount + 1), { expirationTtl: 86400 });
    await env.KV.put(emailKey, partnerId, { expirationTtl: TRIAL_KV_TTL });

    // KV onboarding state
    await env.KV.put(
      `mssp:partner:${partnerId}`,
      JSON.stringify({ partnerId, email: email.toLowerCase().trim(), company: company_name.trim(), tier_id: 'trial', trialEndsAt }),
      { expirationTtl: TRIAL_KV_TTL }
    );

    // CRM lead capture
    await env.DB.prepare(
      `INSERT INTO crm_leads (id, company_name, email, status, source, created_at)
       VALUES (?,?,?,'trial','mssp_trial_v23',?)
       ON CONFLICT(email) DO UPDATE SET status='trial', source='mssp_trial_v23'`
    ).bind(crypto.randomUUID(), company_name.trim(), email.toLowerCase().trim(), now.toISOString()).run().catch(() => {});

    // Welcome notification
    try {
      await deliverNotification({
        eventType: 'MSSP_TRIAL_STARTED',
        channels: ['INAPP'],
        metadata: { partner_id: partnerId, company: company_name.trim(), trial_ends_at: trialEndsAt },
      }, env);
    } catch { /* notification failure non-fatal */ }

    return jsonResponse({
      success:      true,
      partner_id:   partnerId,
      access_token: accessToken,
      trial_ends_at: trialEndsAt,
      trial_days:   TRIAL_DAYS,
      company_name: company_name.trim(),
      tier_id:      'trial',
      clients_limit: 3,
      dashboard_url: '/mssp-dashboard.html',
      upgrade_url:   '/mssp-onboarding.html#pricing',
      message:       `${TRIAL_DAYS}-day MSSP trial activated. No credit card required. Upgrade anytime.`,
      next_steps: [
        'Access your MSSP dashboard',
        'Add up to 3 client accounts',
        'Generate white-label reports',
        'Upgrade before trial ends to keep your data',
      ],
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── GET /api/mssp/onboarding/status ───────────────────────────────────────
// Query: ?partner_id= OR ?email=
export async function handleMsspOnboardingStatus(request, env) {
  try {
    const url       = new URL(request.url);
    const partnerId = url.searchParams.get('partner_id');
    const email     = url.searchParams.get('email');

    if (!partnerId && !email) {
      return jsonResponse({ error: 'Provide partner_id or email query param' }, 400);
    }

    let partner = null;
    if (partnerId) {
      partner = await env.DB.prepare(
        'SELECT id,email,company_name,contact_name,tier_id,clients_limit,margin_pct,status,trial_ends_at,activated_at FROM mssp_onboarding_partners WHERE id=?'
      ).bind(partnerId).first().catch(() => null);
    } else {
      partner = await env.DB.prepare(
        'SELECT id,email,company_name,contact_name,tier_id,clients_limit,margin_pct,status,trial_ends_at,activated_at FROM mssp_onboarding_partners WHERE email=?'
      ).bind(email.toLowerCase().trim()).first().catch(() => null);
    }

    if (!partner) return jsonResponse({ exists: false }, 404);

    const tier = MSSP_TIERS[partner.tier_id] || {};
    const trialDaysLeft = partner.trial_ends_at
      ? Math.max(0, Math.ceil((new Date(partner.trial_ends_at) - Date.now()) / 86400000))
      : null;

    // Count active clients
    let clientCount = 0;
    try {
      const row = await env.DB.prepare(
        'SELECT COUNT(*) AS cnt FROM mssp_clients WHERE partner_id=? AND status=?'
      ).bind(partner.id, 'active').first();
      clientCount = row?.cnt ?? 0;
    } catch { /* mssp_clients table may not exist */ }

    return jsonResponse({
      exists:       true,
      partner_id:   partner.id,
      company_name: partner.company_name,
      tier_id:      partner.tier_id,
      tier_name:    tier.name || partner.tier_id,
      status:       partner.status,
      clients_limit: partner.clients_limit === -1 ? 'Unlimited' : partner.clients_limit,
      active_clients: clientCount,
      margin:       partner.margin_pct,
      trial_ends_at: partner.trial_ends_at,
      trial_days_remaining: trialDaysLeft,
      activated_at: partner.activated_at,
      checklist: [
        { step: 'Account activated',     done: partner.status === 'active' || partner.status === 'trial' },
        { step: 'First client added',    done: clientCount > 0 },
        { step: 'White-label configured', done: false },  // checked against KV config
        { step: 'API key generated',     done: false },   // checked against api_keys table
        { step: 'Onboarding call booked', done: false },
      ],
      upgrade_available: partner.status === 'trial' || partner.tier_id === 'reseller',
      upgrade_url:  '/mssp-onboarding.html#pricing',
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ── GET /api/mssp/onboarding/observability ────────────────────────────────
export async function handleMsspOnboardingObservability(request, env) {
  let partnerCount = null, trialCount = null;
  try {
    const r1 = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM mssp_onboarding_partners WHERE status=?').bind('active').first();
    const r2 = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM mssp_onboarding_partners WHERE status=?').bind('trial').first();
    partnerCount = r1?.cnt ?? 0;
    trialCount   = r2?.cnt ?? 0;
  } catch { /* table may not exist yet */ }

  return jsonResponse({
    component:   'P23.0-MSSP-Public-Onboarding',
    version:     '23.0.0',
    status:      'OPERATIONAL',
    tiers:       Object.keys(MSSP_TIERS),
    trial_days:  TRIAL_DAYS,
    metrics: {
      active_partners: partnerCount,
      trial_partners:  trialCount,
    },
    routes: [
      'GET  /api/mssp/onboarding/tiers',
      'POST /api/mssp/onboarding/checkout',
      'POST /api/mssp/onboarding/verify',
      'POST /api/mssp/onboarding/trial',
      'GET  /api/mssp/onboarding/status',
      'GET  /api/mssp/onboarding/observability',
    ],
    timestamp: new Date().toISOString(),
  });
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}
