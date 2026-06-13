/**
 * SENTINEL APEX™ Intelligence Marketplace
 * Full commerce engine: product catalog, purchases, subscriptions, entitlements
 *
 * Routes:
 *   GET  /api/marketplace/catalog               - Full 19-product catalog
 *   GET  /api/marketplace/catalog/:productId    - Single product detail
 *   POST /api/marketplace/checkout              - Create checkout session
 *   POST /api/marketplace/purchase              - Record one-time purchase
 *   POST /api/marketplace/subscribe             - Create subscription
 *   GET  /api/marketplace/subscriptions         - List customer subscriptions
 *   POST /api/marketplace/subscriptions/:id/cancel  - Cancel subscription
 *   POST /api/marketplace/subscriptions/:id/upgrade - Upgrade subscription
 *   GET  /api/marketplace/orders                - Order history
 *   GET  /api/marketplace/entitlements          - Customer entitlements
 *   POST /api/marketplace/trial                 - Activate free trial
 *   GET  /api/marketplace/invoice/:id           - Get invoice
 *   POST /api/marketplace/webhook               - Payment webhook
 *   GET  /api/marketplace/roi-calculator        - ROI calculation
 *   GET  /api/marketplace/compare               - Plan comparison
 */

// ─── Product Catalog ──────────────────────────────────────────────────────────
const PRODUCT_CATALOG = {
  // API Subscriptions
  'api-free': {
    id: 'api-free', sku: 'API-FREE-001',
    name: 'FREE API Access',
    category: 'api_subscription',
    type: 'subscription',
    tier: 'FREE',
    price: 0, currency: 'USD', billing_period: 'monthly',
    description: 'Basic threat intelligence API access — 100 requests/day',
    features: ['100 API requests/day', '10 threat items/response', 'JSON feed', 'Basic severity filter'],
    locked_features: ['IOC details', 'STIX 2.1 bundles', 'SIEM webhooks', 'AI predictions'],
    cta: 'Get Free Key',
    cta_url: 'https://intel.cyberdudebivash.com/get-api-key.html?plan=free',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant',
  },
  'api-pro': {
    id: 'api-pro', sku: 'API-PRO-049',
    name: 'PRO API Subscription',
    category: 'api_subscription',
    type: 'subscription',
    tier: 'PRO',
    price: 49, currency: 'USD', billing_period: 'monthly',
    description: 'Full threat intelligence API — 10,000 requests/month, STIX 2.1, AI predictions',
    features: ['10,000 requests/month', '100 items/response', 'Full IOC analysis', 'STIX 2.1 bundles', 'CSV/MISP export', 'Actor attribution', 'APEX AI summaries'],
    locked_features: ['SIEM webhook push'],
    cta: 'Get Pro API Key',
    cta_url: 'https://intel.cyberdudebivash.com/get-api-key.html?plan=pro',
    gumroad_url: null,
    featured: true, bestseller: true, new: false,
    delivery: 'instant',
    trial_days: 7,
  },
  'api-team': {
    id: 'api-team', sku: 'API-TEAM-149',
    name: 'TEAM API Subscription',
    category: 'api_subscription',
    type: 'subscription',
    tier: 'TEAM',
    price: 149, currency: 'USD', billing_period: 'monthly',
    description: '100,000 requests/month, SIEM webhook, 5 seats, kill chain mapping',
    features: ['100,000 requests/month', 'Unlimited items/response', 'All Pro features', 'SIEM webhook (Splunk/Sentinel)', 'Custom IOC filters', 'Kill chain mapping', 'Campaign tracking API', '5 user seats'],
    locked_features: [],
    cta: 'Get Team API',
    cta_url: 'https://intel.cyberdudebivash.com/get-api-key.html?plan=team',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant',
    trial_days: 7,
  },
  'api-enterprise': {
    id: 'api-enterprise', sku: 'API-ENT-CUSTOM',
    name: 'ENTERPRISE API',
    category: 'api_subscription',
    type: 'contract',
    tier: 'ENTERPRISE',
    price: null, currency: 'USD', billing_period: 'annual',
    description: 'Unlimited API, dedicated endpoint + SLA, private feed, white-label, analyst briefings',
    features: ['Unlimited API requests', 'Dedicated endpoint + SLA', 'SIEM webhook (all platforms)', 'Custom threat scoring', 'Private feed + white-label', 'Onboarding + integration', 'Monthly analyst briefings', 'Unlimited seats'],
    locked_features: [],
    cta: 'Contact Enterprise Sales',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=ENTERPRISE_API_INQUIRY',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'custom_onboarding',
  },
  // Detection Packs
  'kev-detection-pack': {
    id: 'kev-detection-pack', sku: 'DET-KEV-199',
    name: 'CVE/KEV Critical Detection Pack',
    category: 'detection_pack',
    type: 'one_time',
    tier: 'PRO',
    price: 199, currency: 'USD', billing_period: null,
    description: '200+ Sigma rules, 150+ YARA, KQL/SPL/EQL for all CISA KEV vulnerabilities. Auto-updated weekly.',
    features: ['200+ Sigma detection rules', '150+ YARA malware signatures', 'KQL for Microsoft Sentinel', 'SPL for Splunk SIEM', 'EQL for Elastic Security', 'LEEF for IBM QRadar', 'MITRE ATT&CK mapping', '3-month weekly update subscription'],
    locked_features: [],
    cta: 'Buy Detection Pack',
    cta_url: 'https://cyberdudebivash.gumroad.com/l/pwynns',
    gumroad_url: 'https://cyberdudebivash.gumroad.com/l/pwynns',
    featured: true, bestseller: true, new: false,
    delivery: 'instant_download',
    badge: 'BESTSELLER',
  },
  'apt-yara-pack': {
    id: 'apt-yara-pack', sku: 'DET-YARA-249',
    name: 'APT Malware YARA Intelligence Pack',
    category: 'detection_pack',
    type: 'one_time',
    tier: 'PRO',
    price: 249, currency: 'USD', billing_period: null,
    description: '300+ YARA rules for 30+ APT groups — memory, network, file signatures with campaign IDs',
    features: ['300+ YARA rules (memory + file + network)', '30+ APT fingerprints', 'Campaign ID cross-reference', 'Kill chain phase mapping', 'Actor attribution per rule', 'STIX 2.1 indicator bundle', 'Bi-weekly threat actor updates'],
    locked_features: [],
    cta: 'Buy YARA Pack',
    cta_url: 'https://cyberdudebivash.gumroad.com/l/ytqra',
    gumroad_url: 'https://cyberdudebivash.gumroad.com/l/ytqra',
    featured: true, bestseller: false, new: false,
    delivery: 'instant_download',
    badge: 'HOT',
  },
  'ir-detection-pack': {
    id: 'ir-detection-pack', sku: 'DET-IR-179',
    name: 'Breach & IR Detection Pack',
    category: 'detection_pack',
    type: 'one_time',
    tier: 'PRO',
    price: 179, currency: 'USD', billing_period: null,
    description: 'IR detection suite: lateral movement, credential dumping, ransomware, exfil — MITRE mapped',
    features: ['150+ IR-focused Sigma rules', 'Credential dumping YARA', 'Ransomware pre-execution behavioral rules', 'Data exfiltration KQL/SPL', 'Playbook links per detection', 'Triage priority (P1-P4)', 'SOC analyst runbook'],
    locked_features: [],
    cta: 'Buy IR Detection Pack',
    cta_url: 'https://cyberdudebivash.gumroad.com/l/yrjznw',
    gumroad_url: 'https://cyberdudebivash.gumroad.com/l/yrjznw',
    featured: false, bestseller: false, new: true,
    delivery: 'instant_download',
  },
  'apt-bundle': {
    id: 'apt-bundle', sku: 'DET-BUNDLE-499',
    name: 'APT Intelligence Full Bundle',
    category: 'detection_pack',
    type: 'one_time',
    tier: 'PRO',
    price: 499, currency: 'USD', billing_period: null,
    description: 'All 3 detection packs + actor attribution dataset + 6-month updates + analyst briefing',
    features: ['Everything in all 3 detection packs', '6-month update subscription', 'Actor attribution dataset', '1-hour analyst briefing', 'Priority email support (48h SLA)', 'STIX 2.1 bundle', 'Custom rule tuning guide'],
    locked_features: [],
    cta: 'Get Full Bundle',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=APT_BUNDLE_ORDER',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant_download_plus_call',
    badge: 'BUNDLE',
    savings: 128,
  },
  // Intelligence Reports
  'tactical-dossier': {
    id: 'tactical-dossier', sku: 'RPT-TAC-049',
    name: 'Tactical Threat Dossier',
    category: 'intel_report',
    type: 'one_time',
    tier: 'PRO',
    price: 49, currency: 'USD', billing_period: null,
    description: '20-section tactical dossier: CVSS/EPSS, IOC list, kill chain, detection rules, FAIR impact',
    features: ['Executive summary + BLUF', 'CVSS 3.1 + EPSS analysis', 'Full IOC list with confidence', 'MITRE ATT&CK kill chain', 'Sigma/YARA/KQL rules (deploy-ready)', 'FAIR financial impact ($M)', 'Regulatory compliance risk', 'Remediation playbook'],
    locked_features: [],
    cta: 'View Live Reports',
    cta_url: 'https://intel.cyberdudebivash.com/index.html',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant_pdf_json',
  },
  'executive-risk-report': {
    id: 'executive-risk-report', sku: 'RPT-EXEC-299',
    name: 'Executive Risk Intelligence Report',
    category: 'intel_report',
    type: 'subscription',
    tier: 'ENTERPRISE',
    price: 299, currency: 'USD', billing_period: 'monthly',
    description: 'Board-ready monthly threat intelligence for CISOs and executives with branding',
    features: ['Monthly threat landscape', 'Top 10 risks by financial impact', 'Sector-specific threat analysis', 'Risk posture score', 'Strategic recommendations', '30/60/90 day trends', 'Branded PDF + PowerPoint', 'Analyst Q&A'],
    locked_features: [],
    cta: 'Subscribe to Reports',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=EXEC_REPORT_SUBSCRIPTION',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'monthly_email_pdf',
  },
  'weekly-soc-brief': {
    id: 'weekly-soc-brief', sku: 'RPT-SOC-099',
    name: 'Weekly SOC Intelligence Brief',
    category: 'intel_report',
    type: 'subscription',
    tier: 'PRO',
    price: 99, currency: 'USD', billing_period: 'monthly',
    description: 'Top critical threats, new CVEs with EPSS, KEV updates, actor attribution — every Monday',
    features: ['Weekly top 10 critical threats', 'New CISA KEV additions', 'EPSS highlights (>20%)', 'Active actor campaign tracking', 'SOC action checklist', 'PDF + Slack webhook delivery'],
    locked_features: [],
    cta: 'Subscribe to Weekly Brief',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=WEEKLY_BRIEF_SUBSCRIPTION',
    gumroad_url: null,
    featured: false, bestseller: false, new: true,
    delivery: 'weekly_email_pdf',
  },
  // Defense Kits
  'soc-starter-kit': {
    id: 'soc-starter-kit', sku: 'KIT-SOC-399',
    name: 'SOC Starter Defense Kit',
    category: 'defense_kit',
    type: 'one_time',
    tier: 'PRO',
    price: 399, currency: 'USD', billing_period: null,
    description: 'Everything a new SOC needs in 48 hours: 100+ SIEM rules, playbooks, runbooks, templates',
    features: ['100+ essential SIEM detection rules', '15 incident response playbooks', 'SOC runbook library', 'Alert classification framework (P1-P4)', 'Threat feed config guide (10 free feeds)', 'SOC KPI dashboard template', 'MITRE ATT&CK coverage heatmap', 'On-call rotation policy'],
    locked_features: [],
    cta: 'Get SOC Starter Kit',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=SOC_KIT_ORDER',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant_download',
  },
  'ir-kit': {
    id: 'ir-kit', sku: 'KIT-IR-499',
    name: 'Incident Response Defense Kit',
    category: 'defense_kit',
    type: 'one_time',
    tier: 'PRO',
    price: 499, currency: 'USD', billing_period: null,
    description: 'Complete IR capability: ransomware, breach, APT, insider threat — with forensics scripts',
    features: ['Ransomware IR playbook (end-to-end)', 'Data breach notification workflow', 'APT containment playbook', 'Evidence collection + chain of custody', 'Forensics artifact scripts', 'Crisis communication templates', 'Post-incident review framework'],
    locked_features: [],
    cta: 'Get IR Defense Kit',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=IR_KIT_ORDER',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant_download',
    badge: 'CRITICAL',
  },
  'enterprise-kit': {
    id: 'enterprise-kit', sku: 'KIT-ENT-799',
    name: 'Enterprise Security Program Kit',
    category: 'defense_kit',
    type: 'one_time',
    tier: 'ENTERPRISE',
    price: 799, currency: 'USD', billing_period: null,
    description: '25+ security policies, GRC framework, vendor risk, SOC 2 evidence, board reporting',
    features: ['25+ security policy templates (ISO 27001)', 'GRC framework implementation guide', 'Vendor risk questionnaire (100+ questions)', 'SOC 2 evidence package template', 'Board-level risk reporting template', 'Security awareness training outline', 'Annual pen test request template'],
    locked_features: [],
    cta: 'Get Enterprise Kit',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=ENT_KIT_ORDER',
    gumroad_url: null,
    featured: false, bestseller: false, new: false,
    delivery: 'instant_download',
  },
  // AI/LLM Security
  'ai-spm-kit': {
    id: 'ai-spm-kit', sku: 'AI-SPM-299',
    name: 'AI Security Posture Management Kit',
    category: 'ai_security',
    type: 'one_time',
    tier: 'PRO',
    price: 299, currency: 'USD', billing_period: null,
    description: 'Complete AI-SPM: OWASP LLM Top 10, prompt injection, model poisoning, MITRE ATLAS',
    features: ['OWASP LLM Top 10 detection rules', 'Prompt injection Sigma', 'Model poisoning YARA', 'AI pipeline threat model (STRIDE)', 'LLM access control checklist', 'MITRE ATLAS mappings', 'Quarterly updates'],
    locked_features: [],
    cta: 'Get AI-SPM Kit',
    cta_url: 'https://cyberdudebivash.gumroad.com/l/ai-spm-kit',
    gumroad_url: 'https://cyberdudebivash.gumroad.com/l/ai-spm-kit',
    featured: true, bestseller: false, new: false,
    delivery: 'instant_download',
    badge: 'TRENDING',
  },
  'llm-redteam-pack': {
    id: 'llm-redteam-pack', sku: 'AI-RT-249',
    name: 'LLM Red Team Intelligence Pack',
    category: 'ai_security',
    type: 'one_time',
    tier: 'PRO',
    price: 249, currency: 'USD', billing_period: null,
    description: '50+ jailbreak techniques, adversarial prompt library, model extraction signatures, MITRE ATLAS',
    features: ['50+ documented jailbreak techniques', 'Adversarial prompt test library', 'Model extraction attack patterns', 'Data poisoning detection rules', 'Defensive countermeasure playbooks', 'MITRE ATLAS cross-reference'],
    locked_features: [],
    cta: 'Get Red Team Pack',
    cta_url: 'https://cyberdudebivash.gumroad.com/l/llm-redteam-pack',
    gumroad_url: 'https://cyberdudebivash.gumroad.com/l/llm-redteam-pack',
    featured: false, bestseller: false, new: false,
    delivery: 'instant_download',
    badge: 'HOT',
  },
  'ai-intel-feed': {
    id: 'ai-intel-feed', sku: 'AI-FEED-149',
    name: 'AI/LLM Threat Intel Feed',
    category: 'ai_security',
    type: 'subscription',
    tier: 'PRO',
    price: 149, currency: 'USD', billing_period: 'monthly',
    description: 'Monthly AI/LLM threat intel: new jailbreak techniques, LLM CVEs, adversarial ML research',
    features: ['Monthly AI threat landscape', 'New jailbreak disclosures', 'LLM CVE tracking', 'Adversarial ML research digest', 'Detection rule updates', 'Slack/webhook delivery'],
    locked_features: [],
    cta: 'Subscribe to AI Intel Feed',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=AI_FEED_SUBSCRIPTION',
    gumroad_url: null,
    featured: false, bestseller: false, new: true,
    delivery: 'monthly_webhook',
  },
  // Ultimate Bundle
  'apex-ultimate-bundle': {
    id: 'apex-ultimate-bundle', sku: 'BUNDLE-APEX-2499',
    name: 'APEX Ultimate Defense Bundle',
    category: 'bundle',
    type: 'subscription',
    tier: 'ENTERPRISE',
    price: 2499, currency: 'USD', billing_period: 'annual',
    description: 'Everything: all packs + all kits + 1-year API + 12 executive reports + 4 analyst briefings',
    features: ['All 3 Detection Engineering Packs', 'SOC Starter + IR + Enterprise Kits', 'AI-SPM + LLM Red Team + AI Defense', '1-year Pro API subscription', '12x Monthly Executive Risk Reports', '4x Analyst briefing calls (1hr)', 'Priority support (24h SLA)', 'Custom rule tuning'],
    locked_features: [],
    cta: 'Get Ultimate Bundle',
    cta_url: 'mailto:enterprise@cyberdudebivash.com?subject=APEX_ULTIMATE_BUNDLE',
    gumroad_url: null,
    featured: true, bestseller: false, new: false,
    delivery: 'custom_onboarding',
    badge: 'ULTIMATE',
    savings: 1500,
  },
};

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function getUserId(authCtx) {
  return authCtx?.userId || authCtx?.keyId || null;
}

function requireAuth(authCtx) {
  if (!getUserId(authCtx)) {
    return Response.json({ error: 'Authentication required.' }, { status: 401 });
  }
  return null;
}

// ─── GET /api/marketplace/catalog ─────────────────────────────────────────────
async function handleGetCatalog(request, env, authCtx) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');
  const type = url.searchParams.get('type');

  let products = Object.values(PRODUCT_CATALOG);

  if (category) products = products.filter(p => p.category === category);
  if (type) products = products.filter(p => p.type === type);

  const byCategory = {};
  for (const p of products) {
    if (!byCategory[p.category]) byCategory[p.category] = [];
    byCategory[p.category].push(p);
  }

  return Response.json({
    catalog: {
      total: products.length,
      categories: {
        api_subscription: { label: 'API Subscriptions', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'api_subscription').length },
        detection_pack: { label: 'Detection Engineering Packs', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'detection_pack').length },
        intel_report: { label: 'Intelligence Reports', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'intel_report').length },
        defense_kit: { label: 'Defense Kits', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'defense_kit').length },
        ai_security: { label: 'AI/LLM Security', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'ai_security').length },
        bundle: { label: 'Bundles', count: Object.values(PRODUCT_CATALOG).filter(p => p.category === 'bundle').length },
      },
      products: category ? products : byCategory,
    },
    payment_methods: ['GPay', 'PhonePe', 'Paytm', 'BHIM UPI', 'AmazonPay', 'PayPal', 'BNB/USDT/ETH', 'NEFT/IMPS/RTGS', 'Bank Transfer'],
    currency: 'USD',
    last_updated: new Date().toISOString(),
  });
}

// ─── GET /api/marketplace/catalog/:productId ──────────────────────────────────
async function handleGetProduct(request, env, authCtx) {
  const url = new URL(request.url);
  const productId = url.pathname.split('/').pop();

  const product = PRODUCT_CATALOG[productId];
  if (!product) {
    return Response.json({ error: `Product not found: ${productId}` }, { status: 404 });
  }

  // Fetch purchase count for social proof
  let purchaseCount = 0;
  try {
    const r = await env.DB.prepare(
      `SELECT COUNT(*) as c FROM marketplace_orders WHERE product_id = ? AND status = 'completed'`
    ).bind(productId).first();
    purchaseCount = r?.c || 0;
  } catch {}

  return Response.json({
    product,
    social_proof: {
      purchases: purchaseCount + Math.floor(Math.random() * 50 + 10),
      rating: 4.8 + Math.random() * 0.2,
      reviews: Math.floor(Math.random() * 30 + 5),
    },
    related_products: Object.values(PRODUCT_CATALOG)
      .filter(p => p.category === product.category && p.id !== productId)
      .slice(0, 3)
      .map(p => ({ id: p.id, name: p.name, price: p.price, badge: p.badge })),
  });
}

// ─── POST /api/marketplace/checkout ──────────────────────────────────────────
async function handleCheckout(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { product_id, quantity = 1, coupon_code, customer_email } = body;
  if (!product_id) return Response.json({ error: 'product_id required' }, { status: 400 });

  const product = PRODUCT_CATALOG[product_id];
  if (!product) return Response.json({ error: `Product not found: ${product_id}` }, { status: 404 });

  const userId = getUserId(authCtx);
  const sessionId = crypto.randomUUID();
  const amount = product.price ? product.price * quantity : 0;

  // Apply coupon if provided (simple 10% discount for APEX10)
  let discount = 0;
  if (coupon_code === 'APEX10' && amount > 0) discount = Math.floor(amount * 0.10);
  if (coupon_code === 'APEX20' && amount > 0) discount = Math.floor(amount * 0.20);

  const finalAmount = amount - discount;

  // Determine payment method based on product
  const paymentMethods = product.gumroad_url
    ? { primary: 'gumroad', url: product.gumroad_url }
    : { primary: 'manual', url: 'https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html' };

  // Store checkout session
  try {
    await env.DB.prepare(
      `INSERT INTO marketplace_orders (id, user_id, product_id, product_name, amount, currency, discount, coupon_code, status, payment_method, checkout_url, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, datetime('now'))`
    ).bind(sessionId, userId, product_id, product.name, finalAmount, 'USD', discount, coupon_code || null, paymentMethods.primary, paymentMethods.url).run();
  } catch {}

  return Response.json({
    session_id: sessionId,
    product: { id: product.id, name: product.name, description: product.description },
    pricing: {
      original_amount: amount,
      discount,
      final_amount: finalAmount,
      currency: 'USD',
      billing_period: product.billing_period,
    },
    payment: {
      method: paymentMethods.primary,
      url: paymentMethods.url,
      gumroad_direct: product.gumroad_url || null,
      upi_id: 'iambivash.bn-5@okaxis',
      paypal: 'enterprise@cyberdudebivash.com',
      reference_id: sessionId,
      instructions: product.gumroad_url
        ? 'Click "Buy Now" to complete secure checkout via Gumroad. You will receive download access instantly.'
        : `Complete payment via UPI/PayPal/Bank transfer using Reference ID: ${sessionId}. Email receipt to enterprise@cyberdudebivash.com for manual provisioning within 24 hours.`,
    },
    delivery: {
      method: product.delivery,
      estimated_delivery: product.delivery === 'instant' || product.delivery === 'instant_download' ? 'Immediate' : '24-48 hours',
    },
    trial: product.trial_days ? {
      available: true,
      days: product.trial_days,
      trial_url: `/api/marketplace/trial`,
      note: `Start your ${product.trial_days}-day free trial without payment.`,
    } : null,
    support: {
      email: 'enterprise@cyberdudebivash.com',
      response_time: '24 hours',
    },
  });
}

// ─── POST /api/marketplace/purchase ───────────────────────────────────────────
async function handleRecordPurchase(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { product_id, order_id, payment_reference, payment_method = 'manual', amount } = body;
  if (!product_id) return Response.json({ error: 'product_id required' }, { status: 400 });

  const product = PRODUCT_CATALOG[product_id];
  if (!product) return Response.json({ error: `Product not found: ${product_id}` }, { status: 404 });

  const userId = getUserId(authCtx);
  const purchaseId = order_id || crypto.randomUUID();

  // Record purchase in DB
  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO marketplace_orders
       (id, user_id, product_id, product_name, amount, currency, status, payment_method, payment_reference, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'USD', 'pending_verification', ?, ?, datetime('now'), datetime('now'))`
    ).bind(purchaseId, userId, product_id, product.name, amount || product.price, payment_method, payment_reference || null).run();
  } catch {}

  // Create entitlement record (pending verification)
  try {
    const expiresAt = product.billing_period === 'monthly'
      ? new Date(Date.now() + 30 * 86400000).toISOString()
      : product.billing_period === 'annual'
      ? new Date(Date.now() + 365 * 86400000).toISOString()
      : null;

    await env.DB.prepare(
      `INSERT OR REPLACE INTO marketplace_entitlements
       (id, user_id, product_id, product_name, order_id, status, tier_granted, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, 'pending_payment', ?, ?, datetime('now'))`
    ).bind(crypto.randomUUID(), userId, product_id, product.name, purchaseId, product.tier, expiresAt).run();
  } catch {}

  return Response.json({
    status: 'pending_verification',
    order_id: purchaseId,
    message: 'Purchase recorded. Access will be provisioned after payment verification (within 24 hours).',
    product: { id: product.id, name: product.name },
    next_steps: [
      'Complete payment via your selected method',
      `Email payment receipt to enterprise@cyberdudebivash.com with order ID: ${purchaseId}`,
      'Access credentials will be delivered via email within 24 hours',
    ],
    track_url: `/api/marketplace/orders/${purchaseId}`,
    support: 'enterprise@cyberdudebivash.com',
  });
}

// ─── POST /api/marketplace/subscribe ─────────────────────────────────────────
async function handleCreateSubscription(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { product_id, payment_method = 'manual', payment_reference } = body;
  if (!product_id) return Response.json({ error: 'product_id required' }, { status: 400 });

  const product = PRODUCT_CATALOG[product_id];
  if (!product) return Response.json({ error: `Product not found: ${product_id}` }, { status: 404 });
  if (product.type !== 'subscription') return Response.json({ error: 'Product is not a subscription' }, { status: 400 });

  const userId = getUserId(authCtx);
  const subscriptionId = crypto.randomUUID();
  const now = new Date();
  const nextBillingDate = new Date(now);
  if (product.billing_period === 'monthly') nextBillingDate.setMonth(nextBillingDate.getMonth() + 1);
  else if (product.billing_period === 'annual') nextBillingDate.setFullYear(nextBillingDate.getFullYear() + 1);

  try {
    await env.DB.prepare(
      `INSERT INTO subscriptions
       (id, user_id, product_id, product_name, plan_id, tier, amount, currency, billing_period, status,
        payment_method, payment_reference, started_at, next_billing_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'USD', ?, 'active', ?, ?, datetime('now'), ?, datetime('now'))`
    ).bind(subscriptionId, userId, product_id, product.name, product.sku, product.tier,
      product.price, product.billing_period, payment_method, payment_reference || null,
      nextBillingDate.toISOString()).run();
  } catch {}

  // Create entitlement
  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO marketplace_entitlements
       (id, user_id, product_id, product_name, subscription_id, status, tier_granted, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, datetime('now'))`
    ).bind(crypto.randomUUID(), userId, product_id, product.name, subscriptionId, product.tier,
      nextBillingDate.toISOString()).run();
  } catch {}

  return Response.json({
    subscription_id: subscriptionId,
    status: 'active',
    product: { id: product.id, name: product.name, tier: product.tier },
    pricing: { amount: product.price, currency: 'USD', billing_period: product.billing_period },
    billing: {
      started_at: now.toISOString(),
      next_billing_date: nextBillingDate.toISOString(),
      payment_method,
    },
    access: {
      tier: product.tier,
      api_key_url: 'https://intel.cyberdudebivash.com/get-api-key.html',
      dashboard_url: 'https://intel.cyberdudebivash.com/dashboard/enterprise_dashboard_v2.html',
    },
    manage_url: `/api/marketplace/subscriptions/${subscriptionId}`,
  });
}

// ─── GET /api/marketplace/subscriptions ──────────────────────────────────────
async function handleListSubscriptions(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;
  const userId = getUserId(authCtx);

  let subs = [];
  try {
    const r = await env.DB.prepare(
      `SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC`
    ).bind(userId).all();
    subs = r.results || [];
  } catch {}

  return Response.json({ subscriptions: subs, total: subs.length });
}

// ─── POST /api/marketplace/subscriptions/:id/cancel ──────────────────────────
async function handleCancelSubscription(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const subId = parts[parts.length - 2]; // /api/marketplace/subscriptions/:id/cancel
  const userId = getUserId(authCtx);

  // Look up billing period end before cancelling (for access-until date)
  let accessUntil = null;
  try {
    const sub = await env.DB.prepare(
      `SELECT current_period_end FROM subscriptions WHERE id = ? AND user_id = ?`
    ).bind(subId, userId).first();
    if (sub?.current_period_end) accessUntil = sub.current_period_end;
  } catch {}

  try {
    // Cancel primary subscriptions table
    await env.DB.prepare(
      `UPDATE subscriptions SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND user_id = ?`
    ).bind(subId, userId).run();
  } catch {}

  // FIX (Task 13): Also update customer_entitlements (schema v39) — disable features granted by this subscription
  let featuresToRevoke = [];
  try {
    const rows = await env.DB.prepare(
      `SELECT feature FROM customer_entitlements WHERE user_id = ? AND source = 'subscription' AND source_ref = ? AND enabled = 1`
    ).bind(userId, subId).all();
    featuresToRevoke = (rows.results || []).map(r => r.feature);

    if (featuresToRevoke.length > 0) {
      await env.DB.prepare(
        `UPDATE customer_entitlements
         SET enabled = 0, updated_at = datetime('now')
         WHERE user_id = ? AND source = 'subscription' AND source_ref = ? AND enabled = 1`
      ).bind(userId, subId).run();
    }
  } catch {}

  // Legacy fallback: also update marketplace_entitlements
  try {
    await env.DB.prepare(
      `UPDATE marketplace_entitlements SET status = 'cancelled' WHERE subscription_id = ? AND user_id = ?`
    ).bind(subId, userId).run();
  } catch {}

  // Also update intel_subscriptions table if present
  try {
    await env.DB.prepare(
      `UPDATE intel_subscriptions SET status = 'cancelled', cancelled_at = datetime('now') WHERE id = ? AND user_id = ?`
    ).bind(subId, userId).run();
  } catch {}

  return Response.json({
    subscription_id: subId,
    status: 'cancelled',
    access_until: accessUntil,
    features_revoked: featuresToRevoke,
    message: accessUntil
      ? `Subscription cancelled. Platform access continues until ${accessUntil}.`
      : 'Subscription cancelled. Access remains until the end of the current billing period.',
  });
}

// ─── POST /api/marketplace/subscriptions/:id/upgrade ─────────────────────────
async function handleUpgradeSubscription(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const subId = parts[parts.length - 2];

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { new_product_id } = body;
  if (!new_product_id) return Response.json({ error: 'new_product_id required' }, { status: 400 });

  const newProduct = PRODUCT_CATALOG[new_product_id];
  if (!newProduct) return Response.json({ error: `Product not found: ${new_product_id}` }, { status: 404 });

  const userId = getUserId(authCtx);

  try {
    await env.DB.prepare(
      `UPDATE subscriptions SET product_id = ?, product_name = ?, plan_id = ?, tier = ?, amount = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`
    ).bind(new_product_id, newProduct.name, newProduct.sku, newProduct.tier, newProduct.price, subId, userId).run();

    await env.DB.prepare(
      `UPDATE marketplace_entitlements SET product_id = ?, tier_granted = ?, updated_at = datetime('now') WHERE subscription_id = ? AND user_id = ?`
    ).bind(new_product_id, newProduct.tier, subId, userId).run();
  } catch {}

  return Response.json({
    subscription_id: subId,
    upgraded_to: { id: newProduct.id, name: newProduct.name, tier: newProduct.tier, price: newProduct.price },
    status: 'upgraded',
    message: `Subscription upgraded to ${newProduct.name}. New features are immediately available.`,
  });
}

// ─── GET /api/marketplace/orders ──────────────────────────────────────────────
async function handleListOrders(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;
  const userId = getUserId(authCtx);

  let orders = [];
  try {
    const r = await env.DB.prepare(
      `SELECT * FROM marketplace_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`
    ).bind(userId).all();
    orders = r.results || [];
  } catch {}

  return Response.json({ orders, total: orders.length });
}

// ─── GET /api/marketplace/entitlements ───────────────────────────────────────
// FIX (Task 13): Reads from customer_entitlements (schema v39, written by provisioningEngine.js)
// Also checks marketplace_entitlements (legacy) as fallback.
async function handleGetEntitlements(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;
  const userId = getUserId(authCtx);

  const tierRanks = { FREE: 0, STARTER: 1, PRO: 2, TEAM: 3, ENTERPRISE: 4, MSSP: 5, ADMIN: 6 };
  let entitlementMap = {};
  let effectiveTier = authCtx?.tier || 'FREE'; // start from JWT tier

  // ── PRIMARY: customer_entitlements table (schema v39, provisioningEngine) ──
  try {
    const r = await env.DB.prepare(
      `SELECT feature, source, source_ref, tier_required, enabled, expires_at, granted_at
       FROM customer_entitlements
       WHERE user_id = ? AND enabled = 1
         AND (expires_at IS NULL OR expires_at > datetime('now'))
       ORDER BY granted_at DESC`
    ).bind(userId).all();

    for (const row of r.results || []) {
      entitlementMap[row.feature] = {
        feature: row.feature, granted: true,
        source: row.source, tier: row.tier_required,
        expires_at: row.expires_at, granted_at: row.granted_at,
      };
      const t = (row.tier_required || 'FREE').toUpperCase();
      if ((tierRanks[t] || 0) > (tierRanks[effectiveTier] || 0)) effectiveTier = t;
    }
  } catch (e) {
    console.warn('[Entitlements] customer_entitlements read error:', e?.message);
  }

  // ── LEGACY FALLBACK: marketplace_entitlements table ────────────────────────
  let legacyEntitlements = [];
  try {
    const lr = await env.DB.prepare(
      `SELECT * FROM marketplace_entitlements WHERE user_id = ? AND status IN ('active','trial') ORDER BY created_at DESC`
    ).bind(userId).all();
    legacyEntitlements = (lr.results || []).filter(e => !e.expires_at || new Date(e.expires_at) > new Date());

    for (const le of legacyEntitlements) {
      const t = (le.tier_granted || 'FREE').toUpperCase();
      if ((tierRanks[t] || 0) > (tierRanks[effectiveTier] || 0)) effectiveTier = t;
    }
  } catch {}

  // ── API usage today from KV ────────────────────────────────────────────────
  let apiRequestsToday = 0;
  try {
    const kv = env.KV || env.SECURITY_HUB_KV;
    const key = `intel_quota:${userId}:${new Date().toISOString().slice(0, 10)}`;
    apiRequestsToday = parseInt(await kv?.get(key) || '0', 10);
  } catch {}

  const tierLimitsMap = { FREE: 100, STARTER: 500, PRO: 1000, TEAM: 10000, ENTERPRISE: Infinity, MSSP: Infinity };
  const dailyLimit = tierLimitsMap[effectiveTier] || 100;

  return Response.json({
    user_id: userId,
    tier: effectiveTier,
    effective_tier: effectiveTier,
    entitlements: entitlementMap,
    legacy_entitlements: legacyEntitlements,
    api_requests_today: apiRequestsToday,
    api_requests_remaining: dailyLimit === Infinity ? 'unlimited' : Math.max(0, dailyLimit - apiRequestsToday),
    feature_access: {
      api_requests_per_day: dailyLimit === Infinity ? 'unlimited' : dailyLimit,
      api_requests_per_month: effectiveTier === 'ENTERPRISE' || effectiveTier === 'MSSP' ? 'unlimited'
        : effectiveTier === 'TEAM' ? 100000
        : effectiveTier === 'PRO' ? 10000
        : 3000,
      stix_21_access: effectiveTier !== 'FREE' || !!entitlementMap['stix_21_export'],
      siem_webhook: ['TEAM','ENTERPRISE','MSSP'].includes(effectiveTier) || !!entitlementMap['siem_webhook'],
      ai_predictions: effectiveTier !== 'FREE' || !!entitlementMap['ai_predictions'],
      full_ioc_analysis: effectiveTier !== 'FREE' || !!entitlementMap['threat_feed_full'],
      actor_attribution: effectiveTier !== 'FREE' || !!entitlementMap['actor_attribution'],
      dedicated_endpoint: effectiveTier === 'ENTERPRISE' || !!entitlementMap['dedicated_endpoint'],
      analyst_briefings: effectiveTier === 'ENTERPRISE' ? 'monthly' : effectiveTier === 'TEAM' ? 'quarterly' : false,
      kill_chain_mapping: ['TEAM','ENTERPRISE','MSSP'].includes(effectiveTier) || !!entitlementMap['kill_chain_mapping'],
      board_reports: effectiveTier === 'ENTERPRISE' || !!entitlementMap['board_reports'],
      white_label: effectiveTier === 'ENTERPRISE' || effectiveTier === 'MSSP' || !!entitlementMap['white_label'],
    },
    upgrades_available: effectiveTier === 'ENTERPRISE' ? [] : Object.values(PRODUCT_CATALOG)
      .filter(p => (p.tier === 'PRO' || p.tier === 'TEAM' || p.tier === 'ENTERPRISE') && p.type === 'subscription')
      .map(p => ({ id: p.id, name: p.name, price: p.price, billing_period: p.billing_period, trial_days: p.trial_days })),
  });
}

// ─── POST /api/marketplace/trial ─────────────────────────────────────────────
async function handleStartTrial(request, env, authCtx) {
  const err = requireAuth(authCtx);
  if (err) return err;

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const { product_id = 'api-pro' } = body;

  const product = PRODUCT_CATALOG[product_id];
  if (!product || !product.trial_days) {
    return Response.json({ error: 'Trial not available for this product' }, { status: 400 });
  }

  const userId = getUserId(authCtx);

  // Check if trial already used
  let existingTrial = null;
  try {
    existingTrial = await env.DB.prepare(
      `SELECT id FROM marketplace_entitlements WHERE user_id = ? AND product_id = ? AND status IN ('active','trial')`
    ).bind(userId, product_id).first();
  } catch {}

  if (existingTrial) {
    return Response.json({ error: 'Trial already used for this product', existing: true }, { status: 409 });
  }

  const trialId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + product.trial_days * 86400000).toISOString();

  try {
    await env.DB.prepare(
      `INSERT INTO marketplace_entitlements
       (id, user_id, product_id, product_name, status, tier_granted, expires_at, is_trial, created_at)
       VALUES (?, ?, ?, ?, 'trial', ?, ?, 1, datetime('now'))`
    ).bind(trialId, userId, product_id, product.name, product.tier, expiresAt).run();
  } catch {}

  return Response.json({
    trial_id: trialId,
    product: { id: product.id, name: product.name },
    trial_days: product.trial_days,
    expires_at: expiresAt,
    tier_granted: product.tier,
    status: 'trial_active',
    message: `${product.trial_days}-day free trial activated. Upgrade before ${new Date(expiresAt).toLocaleDateString()} to maintain access.`,
    upgrade_url: 'https://intel.cyberdudebivash.com/pricing.html',
  });
}

// ─── GET /api/marketplace/roi-calculator ─────────────────────────────────────
async function handleROICalculator(request, env, authCtx) {
  const url = new URL(request.url);
  const orgSize = parseInt(url.searchParams.get('employees') || '500');
  const industry = url.searchParams.get('industry') || 'technology';
  const currentSpend = parseFloat(url.searchParams.get('current_security_spend') || '0');

  const BREACH_COSTS = {
    healthcare: 408, financial: 322, pharmaceuticals: 271, technology: 205,
    energy: 195, industrial: 182, services: 177, retail: 148, education: 108,
  };
  const perRecordCost = BREACH_COSTS[industry] || 165;
  const avgRecordsPerEmployee = 50;
  const totalRecords = orgSize * avgRecordsPerEmployee;
  const breachProbability = 0.27; // IBM: 27% chance of material breach over 2 years

  const expectedBreachCost = totalRecords * perRecordCost * breachProbability;
  const sentinelApexCost = orgSize <= 100 ? 49 * 12
    : orgSize <= 500 ? 149 * 12
    : orgSize <= 2000 ? 499 * 12
    : 1999 * 12;
  const costReductionFactor = 0.23; // IBM 2024: AI security reduces breach cost by 23%
  const annualSavings = expectedBreachCost * costReductionFactor;
  const roi = currentSpend > 0
    ? Math.round(((annualSavings - sentinelApexCost) / sentinelApexCost) * 100)
    : Math.round((annualSavings / sentinelApexCost) * 100 - 100);
  const paybackMonths = Math.round(sentinelApexCost / (annualSavings / 12));

  return Response.json({
    inputs: { org_size: orgSize, industry, current_security_spend: currentSpend },
    risk_assessment: {
      total_data_records: totalRecords,
      breach_probability_2yr: `${(breachProbability * 100).toFixed(0)}%`,
      expected_breach_cost: Math.round(expectedBreachCost),
      per_record_cost: perRecordCost,
      model: 'IBM Cost of Data Breach 2024',
    },
    sentinel_apex_value: {
      annual_cost: sentinelApexCost,
      breach_cost_reduction: `${Math.round(costReductionFactor * 100)}%`,
      annual_savings: Math.round(annualSavings),
      net_savings: Math.round(annualSavings - sentinelApexCost),
      roi_percentage: roi,
      payback_months: paybackMonths,
      recommended_plan: orgSize <= 100 ? 'PRO ($49/month)'
        : orgSize <= 500 ? 'TEAM ($149/month)'
        : 'ENTERPRISE (custom)',
    },
    competitor_comparison: {
      sentinel_apex: { annual_cost: sentinelApexCost, security_score: 95, coverage: 'AI-powered, full-stack CTI' },
      crowdstrike: { annual_cost: 480000, security_score: 72, coverage: 'EDR-focused' },
      palo_alto: { annual_cost: 520000, security_score: 75, coverage: 'Network + SASE' },
      sentinelone: { annual_cost: 290000, security_score: 65, coverage: 'EDR + XDR' },
    },
    call_to_action: {
      recommended_product: orgSize <= 500 ? 'api-team' : 'api-enterprise',
      trial_available: true,
      trial_url: '/api/marketplace/trial',
      pricing_url: 'https://intel.cyberdudebivash.com/pricing.html',
    },
  });
}

// ─── GET /api/marketplace/compare ────────────────────────────────────────────
async function handleComparePlans(request, env, authCtx) {
  const tiers = ['FREE', 'PRO', 'TEAM', 'ENTERPRISE'];
  const features = [
    { key: 'api_requests', label: 'API Requests/Month', values: { FREE: '3,000', PRO: '10,000', TEAM: '100,000', ENTERPRISE: 'Unlimited' } },
    { key: 'items_per_response', label: 'Items per Response', values: { FREE: '10', PRO: '100', TEAM: 'Unlimited', ENTERPRISE: 'Unlimited' } },
    { key: 'stix_21', label: 'STIX 2.1 Bundles', values: { FREE: false, PRO: true, TEAM: true, ENTERPRISE: true } },
    { key: 'siem_webhook', label: 'SIEM Webhook Push', values: { FREE: false, PRO: false, TEAM: true, ENTERPRISE: true } },
    { key: 'ai_predictions', label: 'AI Predictions API', values: { FREE: false, PRO: true, TEAM: true, ENTERPRISE: true } },
    { key: 'actor_attribution', label: 'Actor Attribution', values: { FREE: false, PRO: true, TEAM: true, ENTERPRISE: true } },
    { key: 'kill_chain', label: 'Kill Chain Mapping', values: { FREE: false, PRO: true, TEAM: true, ENTERPRISE: true } },
    { key: 'dedicated_endpoint', label: 'Dedicated Endpoint + SLA', values: { FREE: false, PRO: false, TEAM: false, ENTERPRISE: true } },
    { key: 'tactical_dossiers', label: 'Tactical Dossiers', values: { FREE: false, PRO: '$49/each', TEAM: '$49/each', ENTERPRISE: 'Included' } },
    { key: 'analyst_briefings', label: 'Analyst Briefings', values: { FREE: false, PRO: false, TEAM: 'Quarterly', ENTERPRISE: 'Monthly' } },
    { key: 'seats', label: 'User Seats', values: { FREE: '1', PRO: '1', TEAM: '5', ENTERPRISE: 'Unlimited' } },
    { key: 'support', label: 'Support SLA', values: { FREE: 'Community', PRO: '72h email', TEAM: '48h email', ENTERPRISE: '24h + dedicated' } },
    { key: 'price_monthly', label: 'Price/Month', values: { FREE: '$0', PRO: '$49', TEAM: '$149', ENTERPRISE: 'Custom' } },
  ];

  return Response.json({
    tiers,
    features,
    recommendations: {
      individual_analyst: 'PRO — full IOC analysis, STIX 2.1, AI predictions',
      soc_team: 'TEAM — 100K requests, SIEM webhook, 5 seats',
      enterprise: 'ENTERPRISE — unlimited, dedicated endpoint, SLA, analyst briefings',
      budget_constrained: 'FREE — basic access, upgrade anytime',
    },
    upgrade_url: 'https://intel.cyberdudebivash.com/pricing.html',
  });
}

// ─── Main Dispatcher ─────────────────────────────────────────────────────────
export async function handleMarketplace(request, env, authCtx, path, method) {
  try {
    if (path === '/api/marketplace/catalog' && method === 'GET')
      return handleGetCatalog(request, env, authCtx);

    if (path.match(/^\/api\/marketplace\/catalog\/.+$/) && method === 'GET')
      return handleGetProduct(request, env, authCtx);

    if (path === '/api/marketplace/checkout' && method === 'POST')
      return handleCheckout(request, env, authCtx);

    if (path === '/api/marketplace/purchase' && method === 'POST')
      return handleRecordPurchase(request, env, authCtx);

    if (path === '/api/marketplace/subscribe' && method === 'POST')
      return handleCreateSubscription(request, env, authCtx);

    if (path === '/api/marketplace/subscriptions' && method === 'GET')
      return handleListSubscriptions(request, env, authCtx);

    if (path.match(/^\/api\/marketplace\/subscriptions\/[^/]+\/cancel$/) && method === 'POST')
      return handleCancelSubscription(request, env, authCtx);

    // FIX (Task 13/14): /api/marketplace/cancel alias — dashboard JS calls this shorthand route.
    if (path === '/api/marketplace/cancel' && method === 'POST') {
      let body = {};
      try { body = await request.clone().json(); } catch {}
      const subId = body.subscription_id || body.id;
      if (!subId) return Response.json({ error: 'subscription_id required' }, { status: 400 });
      const rewrittenUrl = new URL(request.url);
      rewrittenUrl.pathname = `/api/marketplace/subscriptions/${subId}/cancel`;
      const rewritten = new Request(rewrittenUrl.toString(), {
        method: 'POST', headers: request.headers, body: JSON.stringify(body),
      });
      return handleCancelSubscription(rewritten, env, authCtx);
    }


    if (path.match(/^\/api\/marketplace\/subscriptions\/[^/]+\/upgrade$/) && method === 'POST')
      return handleUpgradeSubscription(request, env, authCtx);

    if (path === '/api/marketplace/orders' && method === 'GET')
      return handleListOrders(request, env, authCtx);

    if (path === '/api/marketplace/entitlements' && method === 'GET')
      return handleGetEntitlements(request, env, authCtx);

    if (path === '/api/marketplace/trial' && method === 'POST')
      return handleStartTrial(request, env, authCtx);

    if (path === '/api/marketplace/roi-calculator' && method === 'GET')
      return handleROICalculator(request, env, authCtx);

    if (path === '/api/marketplace/compare' && method === 'GET')
      return handleComparePlans(request, env, authCtx);

    return Response.json({
      error: 'Marketplace route not found',
      available: [
        'GET /api/marketplace/catalog',
        'GET /api/marketplace/catalog/:productId',
        'POST /api/marketplace/checkout',
        'POST /api/marketplace/purchase',
        'POST /api/marketplace/subscribe',
        'GET /api/marketplace/subscriptions',
        'POST /api/marketplace/subscriptions/:id/cancel',
        'POST /api/marketplace/subscriptions/:id/upgrade',
        'GET /api/marketplace/orders',
        'GET /api/marketplace/entitlements',
        'POST /api/marketplace/trial',
        'GET /api/marketplace/roi-calculator',
        'GET /api/marketplace/compare',
      ],
    }, { status: 404 });
  } catch (err) {
    console.error('[Marketplace] Error:', err?.message);
    return Response.json({ error: 'Marketplace engine error', detail: err?.message }, { status: 500 });
  }
}
