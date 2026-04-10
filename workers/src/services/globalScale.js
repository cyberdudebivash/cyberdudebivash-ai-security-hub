/**
 * CYBERDUDEBIVASH AI Security Hub v10.0
 * Global Scale Engine — Phase 6
 * USD pricing, compliance packs, MSSP white-label, geo-routing
 */

// ─── Currency & pricing config ────────────────────────────────────────────────
const EXCHANGE_RATES = {
  INR: 1,
  USD: 0.012,    // 1 INR = 0.012 USD  (~83 INR = $1)
  EUR: 0.011,
  GBP: 0.0095,
  SGD: 0.016,
  AUD: 0.019,
};

const CURRENCY_SYMBOLS = {
  INR: '₹', USD: '$', EUR: '€', GBP: '£', SGD: 'S$', AUD: 'A$',
};

// Country → Default currency mapping
const GEO_CURRENCY = {
  IN: 'INR', US: 'USD', CA: 'USD', GB: 'GBP',
  DE: 'EUR', FR: 'EUR', NL: 'EUR', SG: 'SGD',
  AU: 'AUD', NZ: 'AUD',
};

// Regional pricing multipliers (PPP adjustment)
const REGIONAL_MULTIPLIERS = {
  IN: 1.0,   // Base
  US: 1.8,   // US premium
  EU: 1.6,   // EU premium
  GB: 1.7,   // UK premium
  SG: 1.5,   // SEA premium
  AU: 1.6,   // AUS premium
};

// ─── Compliance pack catalog ──────────────────────────────────────────────────
export const COMPLIANCE_PACKS = {
  iso27001: {
    id:          'iso27001',
    name:        'ISO 27001:2022 Compliance Pack',
    description: 'Complete ISMS implementation kit — gap analysis, policy templates, control mapping, audit checklist',
    price_inr:   4999,
    price_usd:   60,
    regions:     ['global'],
    framework:   'ISO 27001:2022',
    deliverables: [
      'Gap analysis template (100+ controls)',
      '25 mandatory policy documents',
      'Risk assessment methodology',
      'Statement of Applicability (SoA)',
      'Internal audit checklist',
      'Management review template',
      'Incident register',
      'Asset inventory template',
    ],
    badge: 'GLOBAL STANDARD',
  },
  soc2: {
    id:          'soc2',
    name:        'SOC 2 Type II Readiness Pack',
    description: 'Complete SOC 2 preparation for US/global SaaS companies — Trust Service Criteria controls',
    price_inr:   6999,
    price_usd:   85,
    regions:     ['US', 'global'],
    framework:   'SOC 2 Type II',
    deliverables: [
      'TSC mapping (Security, Availability, Confidentiality)',
      'CC6 logical access controls checklist',
      'Vendor management assessment',
      'Evidence collection templates',
      'Penetration testing scope template',
      'Incident response procedure',
      'Change management policy',
    ],
    badge: 'US COMPLIANCE',
  },
  gdpr: {
    id:          'gdpr',
    name:        'GDPR Compliance Pack (EU/EEA)',
    description: 'Full GDPR compliance toolkit for EU data controllers and processors',
    price_inr:   5999,
    price_usd:   72,
    regions:     ['EU', 'GB', 'EEA'],
    framework:   'GDPR / UK GDPR',
    deliverables: [
      'Data processing register (RoPA)',
      'Privacy notice templates',
      'Consent management framework',
      'DSAR (Data Subject Access Request) procedure',
      'Data breach notification checklist (72h)',
      'DPA / DPO agreement templates',
      'DPIA template for high-risk processing',
      'Data retention policy',
    ],
    badge: 'EU REQUIRED',
  },
  dpdp: {
    id:          'dpdp',
    name:        'India DPDP Act 2023 Compliance Pack',
    description: 'India-specific Digital Personal Data Protection Act compliance for data fiduciaries',
    price_inr:   2999,
    price_usd:   36,
    regions:     ['IN'],
    framework:   'DPDP Act 2023',
    deliverables: [
      'Data fiduciary obligations checklist',
      'Consent Notice templates (Hindi + English)',
      'Significant Data Fiduciary assessment',
      'Data principal rights procedure',
      'Grievance officer appointment template',
      'Cross-border data transfer protocol',
      'DPDPB reporting templates',
    ],
    badge: 'INDIA MANDATE',
  },
  hipaa: {
    id:          'hipaa',
    name:        'HIPAA Security Rule Pack',
    description: 'Healthcare cybersecurity compliance for US covered entities and business associates',
    price_inr:   7499,
    price_usd:   90,
    regions:     ['US'],
    framework:   'HIPAA Security Rule',
    deliverables: [
      'Risk analysis & management framework',
      'Administrative safeguards checklist',
      'Physical safeguards assessment',
      'Technical safeguards implementation',
      'BAA (Business Associate Agreement) template',
      'PHI audit log requirements',
      'Workforce training program outline',
      'Contingency plan template',
    ],
    badge: 'HEALTHCARE',
  },
  pci_dss: {
    id:          'pci_dss',
    name:        'PCI DSS v4.0 Compliance Pack',
    description: 'Payment card security compliance for merchants and service providers',
    price_inr:   5499,
    price_usd:   66,
    regions:     ['global'],
    framework:   'PCI DSS v4.0',
    deliverables: [
      'SAQ-D self-assessment questionnaire',
      'Network segmentation design guide',
      'Cardholder data flow diagram template',
      'Vulnerability management program',
      'Penetration testing scope guide',
      'Incident response plan for card data',
      'Third-party vendor assessment',
    ],
    badge: 'PAYMENTS',
  },
  nist_csf: {
    id:          'nist_csf',
    name:        'NIST CSF 2.0 Implementation Pack',
    description: 'US federal-aligned cybersecurity framework implementation for enterprises',
    price_inr:   4499,
    price_usd:   54,
    regions:     ['US', 'global'],
    framework:   'NIST CSF 2.0',
    deliverables: [
      'Current state assessment (5 functions)',
      'Target profile definition template',
      'Gap analysis & prioritization matrix',
      'Implementation roadmap',
      'Maturity tier assessment',
      'Control mapping to ISO 27001/SOC 2',
    ],
    badge: 'US FEDERAL',
  },
};

// ─── MSSP white-label tiers ───────────────────────────────────────────────────
export const MSSP_TIERS = {
  reseller: {
    id:          'reseller',
    name:        'Reseller',
    price_inr:   14999,
    price_usd:   180,
    billing:     'monthly',
    clients:     10,
    margin:      '30%',
    features:    ['Co-branded reports', 'API access', '10 client accounts', 'Email support'],
  },
  silver: {
    id:          'silver',
    name:        'MSSP Silver',
    price_inr:   29999,
    price_usd:   360,
    billing:     'monthly',
    clients:     50,
    margin:      '40%',
    features:    ['White-label dashboard', 'Custom domain', '50 client accounts', 'Priority support', 'Co-marketing'],
  },
  gold: {
    id:          'gold',
    name:        'MSSP Gold',
    price_inr:   49999,
    price_usd:   600,
    billing:     'monthly',
    clients:     -1, // unlimited
    margin:      '50%',
    features:    ['Full white-label platform', 'Unlimited clients', 'Custom integrations', 'Dedicated account manager', 'SLA guarantee', 'White-label mobile app'],
  },
};

// ─── Currency conversion ──────────────────────────────────────────────────────
export function convertPrice(amountInr, toCurrency = 'USD') {
  const rate = EXCHANGE_RATES[toCurrency] || EXCHANGE_RATES.USD;
  const converted = amountInr * rate;
  return {
    amount:   Math.ceil(converted),
    currency: toCurrency,
    symbol:   CURRENCY_SYMBOLS[toCurrency] || '$',
    formatted: `${CURRENCY_SYMBOLS[toCurrency] || '$'}${Math.ceil(converted).toLocaleString()}`,
  };
}

// ─── Detect visitor currency from Cloudflare geo headers ─────────────────────
export function detectCurrency(request) {
  const country = request.cf?.country || request.headers.get('CF-IPCountry') || 'US';
  const currency = GEO_CURRENCY[country] || 'USD';
  return { country, currency, symbol: CURRENCY_SYMBOLS[currency] || '$' };
}

// ─── Price object with all currencies ────────────────────────────────────────
export function buildMultiCurrencyPrice(priceInr) {
  return {
    INR: { amount: priceInr, symbol: '₹', formatted: `₹${priceInr.toLocaleString('en-IN')}` },
    USD: convertPrice(priceInr, 'USD'),
    EUR: convertPrice(priceInr, 'EUR'),
    GBP: convertPrice(priceInr, 'GBP'),
    SGD: convertPrice(priceInr, 'SGD'),
  };
}

// ─── GET /api/global/pricing ──────────────────────────────────────────────────
export async function handleGetGlobalPricing(request, env) {
  const { country, currency } = detectCurrency(request);

  const plans = {
    freemium:   { price_inr: 0,    name: 'Freemium',   description: 'Limited access, no CC required', scans: 5, ...(currency !== 'INR' ? { price_local: convertPrice(0, currency) } : {}) },
    starter:    { price_inr: 499,  name: 'Starter',    ...(currency !== 'INR' ? { price_local: convertPrice(499, currency) } : {}) },
    pro:        { price_inr: 1499, name: 'Pro',        ...(currency !== 'INR' ? { price_local: convertPrice(1499, currency) } : {}) },
    enterprise: { price_inr: 4999, name: 'Enterprise', ...(currency !== 'INR' ? { price_local: convertPrice(4999, currency) } : {}) },
  };

  return json({
    success:  true,
    country,
    currency,
    symbol:   CURRENCY_SYMBOLS[currency] || '₹',
    plans,
    compliance_packs: Object.values(COMPLIANCE_PACKS).map(p => ({
      ...p,
      price_local: currency !== 'INR' ? convertPrice(p.price_inr, currency) : null,
      is_regional: p.regions.includes(country) || p.regions.includes('global'),
    })),
    mssp_tiers: Object.values(MSSP_TIERS).map(t => ({
      ...t,
      price_local: currency !== 'INR' ? convertPrice(t.price_inr, currency) : null,
    })),
  });
}

// ─── GET /api/global/compliance-packs ────────────────────────────────────────
export async function handleGetCompliancePacks(request, env) {
  const { country, currency } = detectCurrency(request);
  const region = request.cf?.continent || 'global';

  // Sort by regional relevance
  const packs = Object.values(COMPLIANCE_PACKS)
    .map(p => ({
      ...p,
      price_local:   currency !== 'INR' ? convertPrice(p.price_inr, currency) : null,
      is_recommended: p.regions.includes(country) || p.regions.includes('global'),
    }))
    .sort((a, b) => (b.is_recommended ? 1 : 0) - (a.is_recommended ? 1 : 0));

  return json({ success: true, country, currency, packs });
}

// ─── POST /api/global/compliance-packs/purchase ──────────────────────────────
export async function handlePurchaseCompliancePack(request, env, authCtx) {
  try {
    const body = await request.json();
    const { pack_id, email, currency = 'INR' } = body;
    const pack = COMPLIANCE_PACKS[pack_id];
    if (!pack) return json({ success: false, error: 'Pack not found' }, 404);
    if (!email) return json({ success: false, error: 'Email required' }, 400);

    const priceLocal = currency === 'INR' ? pack.price_inr : convertPrice(pack.price_inr, currency).amount;
    const amount     = priceLocal * 100; // paise / cents

    let razorpayOrderId = null;
    const rzKey    = env.RAZORPAY_KEY_ID;
    const rzSecret = env.RAZORPAY_KEY_SECRET;
    if (rzKey && rzSecret) {
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}` },
        body: JSON.stringify({
          amount,
          currency,
          receipt: `comp_${pack_id}_${Date.now()}`,
          notes:   { pack_id, email },
        }),
      });
      if (r.ok) razorpayOrderId = (await r.json()).id;
    }

    return json({
      success: true,
      order: {
        razorpay_order_id: razorpayOrderId,
        pack_id,
        pack_name:   pack.name,
        amount,
        currency,
        razorpay_key: rzKey,
        prefill:     { email },
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── GET /api/global/mssp ─────────────────────────────────────────────────────
export async function handleGetMSSPInfo(request, env) {
  const { currency } = detectCurrency(request);
  const tiers = Object.values(MSSP_TIERS).map(t => ({
    ...t,
    price_local: currency !== 'INR' ? convertPrice(t.price_inr, currency) : null,
  }));
  return json({ success: true, currency, tiers });
}

// ─── POST /api/global/mssp/apply — MSSP partner application ─────────────────
export async function handleMSSPApplication(request, env) {
  try {
    const body = await request.json();
    const { company_name, email, website, clients_count, tier, country, message } = body;
    if (!email || !company_name) return json({ success: false, error: 'Company name and email required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO enterprise_leads (id, company_name, email, domain, requirements, package_interest, source, status)
       VALUES (?,?,?,?,?,?,?,?)`
    ).bind(id, company_name, email, website || null,
           `MSSP Application. Clients: ${clients_count}. Tier: ${tier}. Country: ${country}. ${message || ''}`,
           `mssp_${tier || 'silver'}`, 'mssp_application', 'new').run();

    await env.SECURITY_HUB_KV?.put(
      `email:queue:mssp_application:${id}`,
      JSON.stringify({ type: 'mssp_application', company_name, email, tier, clients_count }),
      { expirationTtl: 86400 * 30 }
    );

    return json({ success: true, application_id: id, message: 'MSSP application received. We\'ll review and respond within 24 hours.' });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
