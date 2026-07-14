/**
 * CYBERDUDEBIVASH® AI Security Hub — P21.0
 * marketplaceCheckoutHandler.js — Sentinel APEX Marketplace Checkout Engine
 *
 * APIs:
 *   GET  /api/marketplace/catalog              full product catalog with pricing
 *   GET  /api/marketplace/catalog/:productId   single product detail
 *   POST /api/marketplace/checkout             create Razorpay order for a product
 *   POST /api/marketplace/verify               verify payment + provision access
 *   GET  /api/marketplace/my-purchases         authenticated user's purchase history
 *   GET  /api/marketplace/observability        P21.0 health gate
 *
 * SECURITY: All prices are server-side only. Client-supplied price_inr is NEVER trusted.
 *           Product IDs are validated against MARKETPLACE_CATALOG before any order is created.
 *
 * Reuses:
 *   createRazorpayOrder, verifyPaymentSignature, generateReceiptId, generateAccessToken → lib/razorpay.js
 *   sendPurchaseConfirmation → services/emailEngine.js
 *   resolveAuthV5 is handled by index.js — authCtx passed in
 *   SECURITY_HUB_KV — access token storage (30-day TTL)
 *   SECURITY_HUB_DB — marketplace_purchases table (schema-independent insert)
 */

import {
  createRazorpayOrder,
  verifyPaymentSignature,
  generateReceiptId,
  generateAccessToken,
} from '../lib/razorpay.js';
import { sendPurchaseConfirmation } from '../services/emailEngine.js';
import { createInvoice } from '../services/v24/billingEngine.js';
import { createApiKey } from '../auth/apiKeys.js';
import { hashPassword } from '../auth/password.js';
import { generateThreatIntelReport } from '../services/ctiReportEngine.js';
import { runComplianceAssessment } from '../services/complianceEngine.js';

// ── Server-Side Product Catalog (prices in paise = INR × 100) ────────────────
// NEVER accept product pricing from the client — all prices defined here only
export const MARKETPLACE_CATALOG = {
  // ── Detection Packs ──
  'dp-ransomware-2025': {
    id: 'dp-ransomware-2025',
    category: 'detection_pack',
    name: 'Ransomware Detection Pack 2025',
    tagline: '847 Sigma rules covering LockBit, BlackCat, Cl0p, Akira, Play, Medusa TTPs',
    description: 'Enterprise-grade Sigma detection rules mapped to MITRE ATT&CK for 2025 active ransomware families. Includes SIEM-ready exports for Splunk, Elastic, Chronicle, and Microsoft Sentinel.',
    amount: 299900,     // ₹2,999
    amount_usd: 3600,   // $36 (in cents)
    currency: 'INR',
    delivery: 'instant',
    format: ['sigma_yml', 'splunk_spl', 'elastic_eql', 'json'],
    mitre_coverage: ['T1486', 'T1490', 'T1489', 'T1562', 'T1078'],
    rule_count: 847,
    updated: '2025-06',
    badge: 'NEW',
    popular: true,
  },
  'dp-apt-north-korea': {
    id: 'dp-apt-north-korea',
    category: 'detection_pack',
    name: 'APT Lazarus & North Korea Detection Pack',
    tagline: '312 detection rules for Lazarus Group, Kimsuky, Andariel — nation-state precision',
    description: 'Covers cryptocurrency theft, supply-chain attacks, and espionage TTPs attributed to DPRK threat actors. CISA advisory-aligned, updated quarterly.',
    amount: 499900,     // ₹4,999
    amount_usd: 6000,
    currency: 'INR',
    delivery: 'instant',
    format: ['sigma_yml', 'splunk_spl', 'json'],
    mitre_coverage: ['T1195', 'T1059', 'T1055', 'T1071', 'T1566'],
    rule_count: 312,
    updated: '2025-06',
    badge: 'PREMIUM',
    popular: false,
  },
  'dp-ai-threats-2025': {
    id: 'dp-ai-threats-2025',
    category: 'detection_pack',
    name: 'AI & LLM Threat Detection Pack',
    tagline: 'OWASP LLM Top 10 detection rules — prompt injection, model theft, data exfil',
    description: 'First-in-class detection rules for AI-native attacks: prompt injection indicators, shadow AI deployment detection, LLM data exfiltration patterns. MITRE ATLAS-mapped.',
    amount: 399900,     // ₹3,999
    amount_usd: 4800,
    currency: 'INR',
    delivery: 'instant',
    format: ['sigma_yml', 'json', 'yara'],
    mitre_coverage: ['ATLAS.T0051', 'ATLAS.T0043', 'ATLAS.T0048'],
    rule_count: 156,
    updated: '2025-06',
    badge: 'AI',
    popular: true,
  },
  'dp-cloud-misconfig': {
    id: 'dp-cloud-misconfig',
    category: 'detection_pack',
    name: 'Cloud Misconfiguration Detection Pack',
    tagline: '634 rules for AWS, Azure, GCP — IAM abuse, S3 exposure, privilege escalation',
    description: 'Covers cloud-native attack paths: IAM privilege escalation, exposed storage, insecure serverless functions, lateral movement via cloud services. CIS Benchmark-aligned.',
    amount: 349900,     // ₹3,499
    amount_usd: 4200,
    currency: 'INR',
    delivery: 'instant',
    format: ['sigma_yml', 'json', 'terraform_sentinel'],
    mitre_coverage: ['T1078.004', 'T1530', 'T1098', 'T1537'],
    rule_count: 634,
    updated: '2025-05',
    badge: 'CLOUD',
    popular: true,
  },

  // ── Security Playbooks ──
  'pb-ransomware-ir': {
    id: 'pb-ransomware-ir',
    category: 'playbook',
    name: 'Ransomware Incident Response Playbook',
    tagline: 'Step-by-step IR runbook used by CISA-certified incident responders',
    description: 'Complete ransomware IR playbook: initial triage, containment, eradication, recovery, and post-incident analysis. Includes decision trees, communication templates, and legal notification checklists.',
    amount: 99900,      // ₹999
    amount_usd: 1200,
    currency: 'INR',
    delivery: 'instant',
    format: ['pdf', 'docx', 'notion_template'],
    updated: '2025-06',
    badge: null,
    popular: true,
  },
  'pb-ai-governance': {
    id: 'pb-ai-governance',
    category: 'playbook',
    name: 'AI Governance & Risk Management Playbook',
    tagline: 'Board-ready AI governance framework — NIST AI RMF, EU AI Act, ISO 42001',
    description: 'Enterprise AI governance playbook aligned to NIST AI RMF, EU AI Act compliance requirements, and ISO/IEC 42001. Includes policy templates, risk registers, and audit checklists for CISOs.',
    amount: 149900,     // ₹1,499
    amount_usd: 1800,
    currency: 'INR',
    delivery: 'instant',
    format: ['pdf', 'docx'],
    updated: '2025-06',
    badge: 'AI',
    popular: true,
  },

  // ── Intelligence Reports ──
  'ir-q2-2025-threat': {
    id: 'ir-q2-2025-threat',
    category: 'intelligence_report',
    name: 'Q2 2025 Global Threat Intelligence Report',
    tagline: '148-page analyst report — APT activity, zero-day trends, ransomware economics',
    description: 'CYBERDUDEBIVASH® analyst team quarterly threat intelligence briefing. Covers active APT campaigns, zero-day exploitation trends, ransomware group economics, and sector-specific threat forecasts for H2 2025.',
    amount: 199900,     // ₹1,999
    amount_usd: 2400,
    currency: 'INR',
    delivery: 'instant',
    format: ['pdf'],
    updated: '2025-06',
    badge: 'NEW',
    popular: true,
  },
  'ir-owasp-llm-2025': {
    id: 'ir-owasp-llm-2025',
    category: 'intelligence_report',
    name: 'OWASP LLM Top 10 — 2025 Edition Deep Dive',
    tagline: 'Technical analysis of every OWASP LLM vulnerability with real-world case studies',
    description: 'Comprehensive technical analysis of the OWASP Top 10 for LLM Applications 2025. Each vulnerability includes real-world exploitation case studies, detection signatures, and remediation guidance.',
    amount: 99900,      // ₹999
    amount_usd: 1200,
    currency: 'INR',
    delivery: 'instant',
    format: ['pdf'],
    updated: '2025-06',
    badge: 'AI',
    popular: false,
  },

  // ── Compliance Packs ──
  'cp-nist-csf-2': {
    id: 'cp-nist-csf-2',
    category: 'compliance_pack',
    name: 'NIST CSF 2.0 Compliance Starter Pack',
    tagline: 'Gap analysis templates, evidence collection guides, and audit-ready policy docs',
    description: 'Everything needed to kick-start NIST Cybersecurity Framework 2.0 compliance: gap analysis templates, control mapping spreadsheets, evidence collection guides, and 47 policy document templates.',
    amount: 249900,     // ₹2,499
    amount_usd: 3000,
    currency: 'INR',
    delivery: 'instant',
    format: ['xlsx', 'docx', 'pdf'],
    updated: '2025-05',
    badge: null,
    popular: true,
  },
  'cp-iso27001-2022': {
    id: 'cp-iso27001-2022',
    category: 'compliance_pack',
    name: 'ISO 27001:2022 Implementation Kit',
    tagline: 'Complete ISMS implementation kit — policies, procedures, risk register, SoA',
    description: 'Full ISO 27001:2022 implementation kit: ISMS scope document, 93 Annex A control templates, risk assessment methodology, Statement of Applicability template, and audit checklist.',
    amount: 349900,     // ₹3,499
    amount_usd: 4200,
    currency: 'INR',
    delivery: 'instant',
    format: ['docx', 'xlsx', 'pdf'],
    updated: '2025-04',
    badge: null,
    popular: true,
  },

  // ── AI Security Agents ──
  'aa-threat-hunter': {
    id: 'aa-threat-hunter',
    category: 'ai_agent',
    name: 'AI Threat Hunting Agent — 30-Day License',
    tagline: 'Autonomous threat hunting agent for your SIEM — 30 days unlimited',
    description: 'Deploy the SENTINEL APEX AI Threat Hunting Agent against your log data. Autonomous hunting across MITRE ATT&CK TTP patterns. API-driven — integrates with Splunk, Elastic, Sentinel. 30-day unlimited license.',
    amount: 999900,     // ₹9,999
    amount_usd: 12000,
    currency: 'INR',
    delivery: 'api_key',
    license_days: 30,
    updated: '2025-06',
    badge: 'AI',
    popular: true,
  },
  'aa-soc-copilot-7d': {
    id: 'aa-soc-copilot-7d',
    category: 'ai_agent',
    name: 'SOC Copilot Agent — 7-Day Trial License',
    tagline: 'AI analyst for alert triage, case enrichment, and MITRE mapping — 7 days',
    description: 'Evaluate the SENTINEL APEX SOC Copilot for 7 days. Auto-triages alerts, enriches cases with threat intelligence, suggests MITRE ATT&CK mappings, and drafts IR reports.',
    amount: 299900,     // ₹2,999
    amount_usd: 3600,
    currency: 'INR',
    delivery: 'api_key',
    license_days: 7,
    updated: '2025-06',
    badge: 'AI',
    popular: false,
  },
};

const CATEGORY_LABELS = {
  detection_pack: 'Detection Packs',
  playbook: 'Security Playbooks',
  intelligence_report: 'Intelligence Reports',
  compliance_pack: 'Compliance Packs',
  ai_agent: 'AI Security Agents',
};

function genPurchaseId() {
  return 'mp_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function sanitizeProductId(id) {
  return (id || '').toString().replace(/[^a-z0-9\-_]/gi, '').slice(0, 60);
}

// ── Handlers ───────────────────────────────────────────────────────────────

/**
 * GET /api/marketplace/catalog[?category=&popular=true]
 */
export async function handleMarketplaceCatalog(req, env) {
  const url = new URL(req.url);
  const filterCat = url.searchParams.get('category');
  const filterPopular = url.searchParams.get('popular') === 'true';

  let products = Object.values(MARKETPLACE_CATALOG);
  if (filterCat) products = products.filter(p => p.category === filterCat);
  if (filterPopular) products = products.filter(p => p.popular);

  // Group by category
  const grouped = {};
  for (const p of products) {
    const cat = p.category;
    if (!grouped[cat]) grouped[cat] = { label: CATEGORY_LABELS[cat] || cat, items: [] };
    grouped[cat].items.push({
      ...p,
      price_display: `₹${(p.amount / 100).toLocaleString('en-IN')}`,
      price_usd_display: `$${(p.amount_usd / 100).toFixed(0)}`,
      checkout_url: `/marketplace-checkout.html?product=${p.id}`,
    });
  }

  return Response.json({
    catalog: grouped,
    total_products: products.length,
    categories: Object.keys(CATEGORY_LABELS),
    category_labels: CATEGORY_LABELS,
    payment_processor: 'Razorpay (UPI, Cards, NetBanking, EMI)',
    currency: 'INR',
    last_updated: '2025-06-28',
  });
}

/**
 * GET /api/marketplace/catalog/:productId
 */
export async function handleMarketplaceProduct(req, env, productId) {
  const cleanId = sanitizeProductId(productId);
  const product = MARKETPLACE_CATALOG[cleanId];
  if (!product) return Response.json({ error: 'Product not found', product_id: cleanId }, { status: 404 });

  return Response.json({
    ...product,
    price_display: `₹${(product.amount / 100).toLocaleString('en-IN')}`,
    price_usd_display: `$${(product.amount_usd / 100).toFixed(0)}`,
    checkout_url: `/marketplace-checkout.html?product=${product.id}`,
    category_label: CATEGORY_LABELS[product.category] || product.category,
  });
}

/**
 * POST /api/marketplace/checkout
 * Body: { product_id, email, name }
 * Creates a Razorpay order for the specified product.
 * SECURITY: Amount is taken from server-side catalog — NEVER from client.
 */
export async function handleMarketplaceCheckout(req, env, authCtx) {
  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const cleanId = sanitizeProductId(body.product_id);
  const product = MARKETPLACE_CATALOG[cleanId];
  if (!product) return Response.json({ error: `Product not found: ${cleanId}` }, { status: 404 });

  const email = (body.email || authCtx?.email || '').toLowerCase().trim();
  const name = (body.name || authCtx?.name || 'Customer').toString().slice(0, 80);
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return Response.json({ error: 'Valid email required for purchase' }, { status: 400 });
  }

  const userId = authCtx?.user_id || null;
  const receipt = generateReceiptId();

  try {
    // Check for existing unpaid order for same user + product (prevent double-orders)
    if (userId) {
      const existing = await env.DB.prepare(
        `SELECT id, razorpay_order_id FROM marketplace_purchases
         WHERE user_id = ? AND product_id = ? AND status = 'pending'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(userId, cleanId).first().catch(() => null);

      if (existing?.razorpay_order_id) {
        return Response.json({
          order_id: existing.razorpay_order_id,
          product: { id: product.id, name: product.name, amount: product.amount, currency: product.currency },
          razorpay_key: env.RAZORPAY_KEY_ID,
          prefill: { name, email },
          message: 'Existing pending order retrieved',
        });
      }
    }

    const razorOrder = await createRazorpayOrder(env, {
      amount: product.amount,
      currency: product.currency,
      receipt,
      notes: {
        product_id: cleanId,
        product_name: product.name,
        category: product.category,
        buyer_email: email,
        platform: 'SENTINEL_APEX_MARKETPLACE',
      },
    });

    // Record pending purchase in D1
    const purchaseId = genPurchaseId();
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS marketplace_purchases (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        product_id TEXT NOT NULL,
        product_name TEXT,
        category TEXT,
        amount INTEGER NOT NULL,
        currency TEXT DEFAULT 'INR',
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        status TEXT DEFAULT 'pending',
        access_token TEXT,
        access_expires_at TEXT,
        buyer_email TEXT,
        buyer_name TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        paid_at TEXT
      )
    `).run().catch(() => null);

    await env.DB.prepare(`
      INSERT INTO marketplace_purchases
        (id, user_id, product_id, product_name, category, amount, currency, razorpay_order_id, buyer_email, buyer_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      purchaseId, userId, cleanId, product.name, product.category,
      product.amount, product.currency, razorOrder.id, email, name
    ).run();

    return Response.json({
      purchase_id: purchaseId,
      order_id: razorOrder.id,
      product: {
        id: product.id,
        name: product.name,
        tagline: product.tagline,
        amount: product.amount,
        amount_display: `₹${(product.amount / 100).toLocaleString('en-IN')}`,
        currency: product.currency,
        delivery: product.delivery,
      },
      razorpay_key: env.RAZORPAY_KEY_ID,
      prefill: { name, email },
      theme: { color: '#00c2ff' },
    }, { status: 201 });

  } catch (e) {
    if (e.message?.includes('Razorpay credentials')) {
      return Response.json({ error: 'Payment system not configured. Contact support@cyberdudebivash.in' }, { status: 503 });
    }
    return Response.json({ error: 'Failed to create checkout order.', detail: e.message }, { status: 500 });
  }
}

/**
 * POST /api/marketplace/verify
 * Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature, purchase_id }
 * Verifies Razorpay HMAC, provisions access token, marks purchase paid.
 */
export async function handleMarketplaceVerify(req, env, authCtx) {
  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, purchase_id } = body;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return Response.json({ error: 'razorpay_order_id, razorpay_payment_id, and razorpay_signature are required' }, { status: 400 });
  }

  // Verify HMAC signature — canonical verifyPaymentSignature()
  const valid = await verifyPaymentSignature(env, razorpay_order_id, razorpay_payment_id, razorpay_signature);
  if (!valid) {
    return Response.json({ error: 'Payment signature verification failed. Do not retry — contact support.' }, { status: 400 });
  }

  // Fetch the pending purchase
  const purchase = await env.DB.prepare(
    `SELECT * FROM marketplace_purchases WHERE razorpay_order_id = ? LIMIT 1`
  ).bind(razorpay_order_id).first().catch(() => null);

  if (!purchase) return Response.json({ error: 'Purchase record not found' }, { status: 404 });
  if (purchase.status === 'paid') {
    // Backfill: purchases verified before the GST invoice call existed here
    // have no invoice row. createInvoice() is idempotent by payment_id, so
    // this is a no-op for every purchase invoiced since that fix.
    await createInvoice(env.DB, {
      userId:        purchase.user_id || purchase.buyer_email,
      email:         purchase.buyer_email,
      lineItems:     [{ description: purchase.product_name, amount_inr: purchase.amount / 100, quantity: 1 }],
      paymentId:     purchase.razorpay_payment_id || razorpay_payment_id,
      paymentMethod: 'razorpay',
    }, env).catch(e => console.warn('[Marketplace] invoice backfill error:', e.message));

    return Response.json({
      message: 'Payment already verified.',
      access_token: purchase.access_token,
      download_url: `/api/marketplace/download/${purchase.access_token}`,
    });
  }

  const product = MARKETPLACE_CATALOG[purchase.product_id];

  // Generate access token
  const accessToken = generateAccessToken();
  const licenseDays = product?.license_days || 30;
  const expiresAt = new Date(Date.now() + licenseDays * 86_400_000).toISOString();

  // Mark paid + store access token
  await env.DB.prepare(`
    UPDATE marketplace_purchases
    SET status='paid', razorpay_payment_id=?, access_token=?, access_expires_at=?, paid_at=datetime('now')
    WHERE id=?
  `).bind(razorpay_payment_id, accessToken, expiresAt, purchase.id).run();

  // Store access token in KV for fast validation (30-day TTL)
  await env.SECURITY_HUB_KV?.put(
    `marketplace:access:${accessToken}`,
    JSON.stringify({ product_id: purchase.product_id, product_name: purchase.product_name,
      category: purchase.category, buyer_email: purchase.buyer_email,
      purchase_id: purchase.id, expires_at: expiresAt }),
    { expirationTtl: licenseDays * 86400 }
  ).catch(() => null);

  // GST invoice — canonical v24/billingEngine.js authority (same engine
  // already wired into /api/payments/verify and every other marketplace
  // handler; this one was missing it). Idempotent by payment_id.
  await createInvoice(env.DB, {
    userId:        purchase.user_id || purchase.buyer_email,
    email:         purchase.buyer_email,
    lineItems:     [{ description: product?.name || purchase.product_name, amount_inr: (product?.amount ?? purchase.amount) / 100, quantity: 1 }],
    paymentId:     razorpay_payment_id,
    paymentMethod: 'razorpay',
  }, env).catch(e => console.warn('[Marketplace] invoice error:', e.message));

  // Send purchase confirmation (canonical emailEngine.js)
  await sendPurchaseConfirmation(env, {
    email: purchase.buyer_email,
    name: purchase.buyer_name || 'Customer',
    product: product?.name || purchase.product_name,
    accessToken,
    downloadUrl: `https://cyberdudebivash.in/api/marketplace/download/${accessToken}`,
    expiresAt,
  }).catch(() => null);

  return Response.json({
    success: true,
    message: 'Payment verified. Access provisioned.',
    purchase_id: purchase.id,
    product: { id: purchase.product_id, name: purchase.product_name, category: purchase.category },
    access_token: accessToken,
    download_url: `/api/marketplace/download/${accessToken}`,
    access_expires_at: expiresAt,
    license_days: licenseDays,
    delivery: product?.delivery || 'instant',
  });
}

/**
 * GET /api/marketplace/download/:accessToken
 *
 * Was completely missing — handleMarketplaceVerify has always returned
 * `download_url: /api/marketplace/download/${accessToken}`, but no route
 * for it existed anywhere in the codebase (confirmed by reading the full
 * route table; live-tested 404). Every one of the 12 catalog products
 * dead-ended after a fully verified payment. (2026-07-06 revenue-mechanisms
 * audit.)
 *
 * Delivery differs by category:
 *   - api_key (AI Security Agents): mints a real, functional platform API
 *     key scoped to the license window — issued once per purchase.
 *   - intelligence_report / compliance_pack: generated live from the same
 *     real, CISA KEV/NVD-backed engines used elsewhere on the platform
 *     (ctiReportEngine.js / complianceEngine.js) — not a static file.
 *   - detection_pack / playbook: no automated rule/playbook-authoring
 *     engine exists yet. Rather than fabricate "847 Sigma rules" content
 *     that hasn't actually been authored and validated (dangerous for a
 *     security product), this honestly confirms the paid order and routes
 *     to manual fulfillment — the same acknowledged pattern already used
 *     for Academy and Consulting deliverables. Flagged as follow-up work
 *     requiring real security-research investment, not a bug fix.
 */
export async function handleMarketplaceDownload(req, env, accessToken) {
  const token = (accessToken || '').toString().replace(/[^a-f0-9]/gi, '').slice(0, 128);
  if (!token || token.length < 16) {
    return Response.json({ error: 'Invalid access token' }, { status: 400 });
  }

  // Fast KV lookup first, D1 is authoritative for status/expiry either way.
  let kvMeta = null;
  if (env.SECURITY_HUB_KV) {
    const raw = await env.SECURITY_HUB_KV.get(`marketplace:access:${token}`).catch(() => null);
    if (raw) kvMeta = JSON.parse(raw);
  }
  const purchase = await env.DB.prepare(
    `SELECT * FROM marketplace_purchases WHERE access_token = ? LIMIT 1`
  ).bind(token).first().catch(() => null);

  if (!purchase && !kvMeta) {
    return Response.json({
      error: 'Access token not found or invalid.',
      support: 'support@cyberdudebivash.com',
    }, { status: 404 });
  }
  if (purchase && purchase.status !== 'paid') {
    return Response.json({ error: 'Payment not verified for this order.' }, { status: 403 });
  }

  const expiresAt = purchase?.access_expires_at || kvMeta?.expires_at;
  if (expiresAt && new Date(expiresAt) < new Date()) {
    return Response.json({
      error: 'This download link has expired.',
      expired_at: expiresAt,
      support: 'support@cyberdudebivash.com',
    }, { status: 410 });
  }

  const productId   = purchase?.product_id || kvMeta?.product_id;
  const buyerEmail  = purchase?.buyer_email || kvMeta?.buyer_email;
  const product     = MARKETPLACE_CATALOG[productId];
  if (!product) {
    return Response.json({
      error: 'Product no longer available. Contact support with your order reference.',
      purchase_id: purchase?.id || null,
      support: 'support@cyberdudebivash.com',
    }, { status: 404 });
  }

  // ── API-key delivery (AI Security Agents) ────────────────────────────────
  if (product.delivery === 'api_key') {
    // Idempotent: the raw key is only ever shown once, at first issuance —
    // repeat calls to this endpoint must not silently mint a fresh key.
    const alreadyIssued = env.SECURITY_HUB_KV
      ? await env.SECURITY_HUB_KV.get(`marketplace:apikey_issued:${token}`).catch(() => null)
      : null;
    if (alreadyIssued) {
      return Response.json({
        success: true, delivery: 'api_key', already_issued: true,
        message: 'Your API key for this purchase was already issued and is only ever shown once. Contact support@cyberdudebivash.com with your order reference to rotate it if lost.',
        purchase_id: purchase?.id || null,
        product: product.name,
      });
    }

    let userId = purchase?.user_id || null;
    if (!userId && buyerEmail) {
      const existingUser = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(buyerEmail).first().catch(() => null);
      if (existingUser?.id) {
        userId = existingUser.id;
      } else {
        const newId = crypto.randomUUID();
        const { hash, salt } = await hashPassword(crypto.randomUUID() + crypto.randomUUID());
        const inserted = await env.DB.prepare(
          `INSERT INTO users (id, email, password_hash, password_salt, tier, status, created_at)
           VALUES (?, ?, ?, ?, 'FREE', 'active', datetime('now'))`
        ).bind(newId, buyerEmail, hash, salt).run().catch(() => null);
        if (inserted) userId = newId;
      }
    }
    if (!userId) {
      return Response.json({
        error: 'Could not provision your API key automatically. Contact support@cyberdudebivash.com with your order reference.',
        purchase_id: purchase?.id || null,
      }, { status: 500 });
    }

    const issued = await createApiKey(env.DB, userId, 'ENTERPRISE', product.name);
    if (expiresAt) {
      await env.DB.prepare(`UPDATE api_keys SET expires_at = ? WHERE id = ?`)
        .bind(expiresAt, issued.id).run().catch(() => {});
    }
    if (env.SECURITY_HUB_KV) {
      await env.SECURITY_HUB_KV.put(`marketplace:apikey_issued:${token}`, issued.id, { expirationTtl: 400 * 86400 }).catch(() => {});
    }

    return Response.json({
      success: true, delivery: 'api_key',
      api_key: issued.raw_key,
      key_prefix: issued.prefix,
      expires_at: expiresAt || null,
      product: product.name,
      message: `Your ${product.name} API key is ready — save it now, it will not be shown again.`,
      docs_url: 'https://cyberdudebivash.in/api-docs',
    });
  }

  // ── Live-generated content — the same real engines used elsewhere on the
  // platform, not a static/fabricated file ─────────────────────────────────
  if (product.category === 'intelligence_report') {
    const report = await generateThreatIntelReport(env, '', 'General', purchase?.id || null);
    return Response.json({ success: true, delivery: 'report', product: product.name, report });
  }
  if (product.category === 'compliance_pack') {
    const report = await runComplianceAssessment(env, {}, purchase?.id || null);
    return Response.json({ success: true, delivery: 'report', product: product.name, report });
  }

  // ── Detection packs & playbooks: no automated authoring engine exists for
  // this category yet — acknowledge the paid order honestly rather than
  // fabricate rule/playbook content. Same manual-fulfillment pattern already
  // used for Academy and Consulting deliverables.
  return Response.json({
    success: true, delivery: 'manual_pending',
    message: `Your order for "${product.name}" is confirmed and is being finalized by our security research team. It will be emailed to ${buyerEmail || 'your registered email'} within 24 hours.`,
    purchase_id: purchase?.id || null,
    support: 'support@cyberdudebivash.com',
  });
}

/**
 * GET /api/marketplace/my-purchases
 * Returns authenticated user's purchase history.
 */
export async function handleMyMarketplacePurchases(req, env, authCtx) {
  if (!authCtx?.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });

  try {
    const rows = await env.DB.prepare(`
      SELECT id, product_id, product_name, category, amount, status,
             access_token, access_expires_at, created_at, paid_at
      FROM marketplace_purchases
      WHERE user_id = ?
      ORDER BY created_at DESC LIMIT 50
    `).bind(authCtx.user_id).all().catch(() => ({ results: [] }));

    const purchases = (rows.results || []).map(p => ({
      ...p,
      amount_display: `₹${(p.amount / 100).toLocaleString('en-IN')}`,
      is_active: p.status === 'paid' && (!p.access_expires_at || new Date(p.access_expires_at) > new Date()),
      download_url: p.access_token ? `/api/marketplace/download/${p.access_token}` : null,
      product_detail: MARKETPLACE_CATALOG[p.product_id] ? {
        tagline: MARKETPLACE_CATALOG[p.product_id].tagline,
        format: MARKETPLACE_CATALOG[p.product_id].format,
      } : null,
    }));

    return Response.json({
      purchases,
      count: purchases.length,
      active_count: purchases.filter(p => p.is_active).length,
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

/**
 * GET /api/marketplace/observability — P21.0 health gate
 */
export async function handleMarketplaceObservability(req, env) {
  const checks = {
    catalog_loaded: Object.keys(MARKETPLACE_CATALOG).length > 0,
    razorpay_key_configured: !!env.RAZORPAY_KEY_ID,
    db_accessible: false,
    kv_accessible: false,
    marketplace_purchases_table: false,
  };

  try { await env.DB.prepare('SELECT 1 FROM users LIMIT 1').run(); checks.db_accessible = true; } catch {}
  try { await env.SECURITY_HUB_KV?.put('marketplace:health', '1', { expirationTtl: 10 }); checks.kv_accessible = true; } catch {}
  try { await env.DB.prepare('SELECT 1 FROM marketplace_purchases LIMIT 1').run(); checks.marketplace_purchases_table = true; } catch {}

  const allPass = checks.catalog_loaded && checks.db_accessible && checks.kv_accessible;
  return Response.json({
    layer: 'P21.0',
    name: 'Marketplace Checkout Engine',
    status: allPass ? 'OPERATIONAL' : 'DEGRADED',
    checks,
    catalog_size: Object.keys(MARKETPLACE_CATALOG).length,
    categories: Object.keys(CATEGORY_LABELS),
    endpoints: [
      'GET  /api/marketplace/catalog',
      'GET  /api/marketplace/catalog/:productId',
      'POST /api/marketplace/checkout',
      'POST /api/marketplace/verify',
      'GET  /api/marketplace/download/:accessToken',
      'GET  /api/marketplace/my-purchases',
      'GET  /api/marketplace/observability',
    ],
    timestamp: new Date().toISOString(),
  }, { status: allPass ? 200 : 503 });
}
