// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Global Expansion Engine
// GTM Growth Engine Phase 7: Region Awareness + Localization + Compliance
// ═══════════════════════════════════════════════════════════════════════════

// ── Region → Currency + Timezone map ────────────────────────────────────────
export const REGION_CONFIG = {
  IN: { currency: 'INR', symbol: '₹', timezone: 'Asia/Kolkata',     locale: 'en-IN', tax_label: 'GST 18%',    compliance: ['IT Act 2000', 'CERT-In'] },
  US: { currency: 'USD', symbol: '$', timezone: 'America/New_York',  locale: 'en-US', tax_label: '',           compliance: ['SOC 2', 'NIST CSF', 'CCPA'] },
  GB: { currency: 'GBP', symbol: '£', timezone: 'Europe/London',     locale: 'en-GB', tax_label: 'VAT 20%',   compliance: ['GDPR', 'Cyber Essentials', 'NIS2'] },
  EU: { currency: 'EUR', symbol: '€', timezone: 'Europe/Berlin',     locale: 'de-DE', tax_label: 'VAT',       compliance: ['GDPR', 'NIS2', 'DORA'] },
  SG: { currency: 'SGD', symbol: 'S$',timezone: 'Asia/Singapore',    locale: 'en-SG', tax_label: 'GST 9%',    compliance: ['MAS TRM', 'PDPA'] },
  AU: { currency: 'AUD', symbol: 'A$',timezone: 'Australia/Sydney',  locale: 'en-AU', tax_label: 'GST 10%',   compliance: ['ASD Essential 8', 'Privacy Act'] },
  CA: { currency: 'CAD', symbol: 'CA$',timezone:'America/Toronto',   locale: 'en-CA', tax_label: 'GST/HST',   compliance: ['PIPEDA', 'NIST CSF'] },
  AE: { currency: 'AED', symbol: 'AED',timezone: 'Asia/Dubai',       locale: 'en-AE', tax_label: 'VAT 5%',    compliance: ['UAE PDPL', 'NESA'] },
  JP: { currency: 'JPY', symbol: '¥',  timezone: 'Asia/Tokyo',       locale: 'ja-JP', tax_label: 'JCT 10%',   compliance: ['APPI', 'METI Guidelines'] },
  DEFAULT: { currency: 'USD', symbol: '$', timezone: 'UTC', locale: 'en-US', tax_label: '', compliance: ['ISO 27001', 'SOC 2'] },
};

// ── Pricing by region (INR base × region multiplier) ─────────────────────────
const PRICING_TIERS = {
  starter:    { INR: 499,   USD: 9,    GBP: 7,   EUR: 8,   SGD: 12,  AUD: 14,  CAD: 12,  AED: 33,  JPY: 1300 },
  pro:        { INR: 1499,  USD: 25,   GBP: 19,  EUR: 23,  SGD: 34,  AUD: 38,  CAD: 34,  AED: 92,  JPY: 3800 },
  enterprise: { INR: 4999,  USD: 79,   GBP: 62,  EUR: 72,  SGD: 108, AUD: 122, CAD: 108, AED: 290, JPY: 11800 },
};

// ── Compliance frameworks by use case ────────────────────────────────────────
const COMPLIANCE_MESSAGING = {
  GDPR:           { label: 'GDPR Compliant', icon: '🇪🇺', desc: 'All data processed within EU boundaries. DPIA available on request.' },
  'SOC 2':        { label: 'SOC 2 Ready',    icon: '🔒', desc: 'Sentinel APEX supports SOC 2 Type II evidence collection workflows.' },
  HIPAA:          { label: 'HIPAA Aware',    icon: '🏥', desc: 'PHI-aware scanning rules. BAA available for Enterprise customers.' },
  'ISO 27001':    { label: 'ISO 27001',      icon: '📋', desc: 'Threat intel feeds aligned with ISO 27001 Annex A controls.' },
  'NIST CSF':     { label: 'NIST CSF',       icon: '🇺🇸', desc: 'Mapped to NIST CSF Identify, Protect, Detect, Respond, Recover.' },
  'IT Act 2000':  { label: 'India IT Act',   icon: '🇮🇳', desc: 'CERT-In compliant. Supports 6-hour incident reporting requirements.' },
  'CERT-In':      { label: 'CERT-In Ready',  icon: '🛡',  desc: 'Aligned with CERT-In Directions 2022 for incident reporting.' },
  'NIS2':         { label: 'NIS2 Ready',     icon: '🇪🇺', desc: 'Helps meet NIS2 Directive Article 21 security measures.' },
  'MAS TRM':      { label: 'MAS TRM',        icon: '🇸🇬', desc: 'Aligns with MAS Technology Risk Management Guidelines 2021.' },
  'ASD Essential 8': { label: 'Essential 8', icon: '🇦🇺', desc: 'Maps findings to ASD Essential 8 Maturity Model controls.' },
};

// ─────────────────────────────────────────────────────────────────────────────
// REGION DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detect region from Cloudflare request headers
 * CF provides CF-IPCountry header on all requests
 */
export function detectRegion(request) {
  const country = request?.headers?.get('CF-IPCountry') || 'XX';
  const timezone = request?.headers?.get('CF-Timezone') || null;
  const city     = request?.headers?.get('CF-IPCity')    || null;

  // Map EU countries to single EU config
  const euCountries = new Set(['DE','FR','IT','ES','NL','BE','SE','PL','PT','CZ','RO','HU','AT','DK','FI','SK','IE','HR','BG','LT','LV','EE','SI','CY','LU','MT']);
  const resolvedCountry = euCountries.has(country) ? 'EU' : country;

  const config = REGION_CONFIG[resolvedCountry] || REGION_CONFIG.DEFAULT;

  return {
    country,
    resolved_region: resolvedCountry,
    city,
    ...config,
    timezone: timezone || config.timezone,
  };
}

/**
 * Get region from env (for non-request contexts, e.g. cron)
 */
export function getDefaultRegion() {
  return REGION_CONFIG.IN; // India-first (founder's region)
}

// ─────────────────────────────────────────────────────────────────────────────
// LOCALIZED PRICING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get localized pricing for a region
 * @param {string} currency - e.g. 'USD', 'GBP'
 * @param {string} symbol   - e.g. '$', '£'
 * @returns {object} Plans with localized prices
 */
export function getLocalizedPricing(currency = 'USD', symbol = '$') {
  const plans = {};

  for (const [plan, prices] of Object.entries(PRICING_TIERS)) {
    const price = prices[currency] || prices.USD;
    plans[plan] = {
      plan,
      price_monthly:  price,
      price_annual:   Math.floor(price * 10),   // 2 months free on annual
      formatted:      `${symbol}${price}/mo`,
      formatted_annual: `${symbol}${Math.floor(price * 10)}/yr`,
      currency,
      savings_annual: `Save ${symbol}${price * 2}`,
    };
  }

  return plans;
}

/**
 * Format a price for a specific region
 */
export function formatPrice(amount, currency, locale) {
  try {
    return new Intl.NumberFormat(locale, { style: 'currency', currency }).format(amount);
  } catch {
    return `${amount} ${currency}`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPLIANCE POSITIONING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get compliance frameworks relevant to a region
 * @param {string} resolvedRegion - e.g. 'IN', 'EU', 'US'
 * @returns {Array} compliance badge objects
 */
export function getComplianceBadges(resolvedRegion) {
  const regionConfig = REGION_CONFIG[resolvedRegion] || REGION_CONFIG.DEFAULT;
  const frameworks = regionConfig.compliance || [];

  return frameworks.map(fw => COMPLIANCE_MESSAGING[fw] || {
    label: fw, icon: '✅', desc: `Aligned with ${fw} requirements.`
  });
}

/**
 * Build region-aware compliance section for landing pages / emails
 */
export function buildComplianceSection(resolvedRegion) {
  const badges = getComplianceBadges(resolvedRegion);

  return {
    headline: 'Built for compliance in your region',
    badges,
    cta:      'View compliance documentation →',
    cta_url:  'https://cyberdudebivash.in/compliance',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// REGION-AWARE CONTENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get region-specific headline and value proposition
 */
export function getRegionalValueProp(resolvedRegion, plan = 'pro') {
  const props = {
    IN: {
      headline: '🇮🇳 India\'s Premier AI Threat Intelligence Platform',
      sub:      'CERT-In compliant. Built for Indian enterprises facing APT41, Lazarus, and ransomware campaigns targeting BFSI and IT sectors.',
      stat:     '₹2.3Cr average breach cost in India (2024)',
    },
    US: {
      headline: '🇺🇸 Real-Time Threat Intelligence for US Enterprises',
      sub:      'NIST CSF aligned. Detects CVEs exploited by Volt Typhoon, LockBit, and state-sponsored actors targeting US infrastructure.',
      stat:     '$4.8M average breach cost in the US (2024)',
    },
    EU: {
      headline: '🇪🇺 GDPR-Compliant Cyber Threat Intelligence',
      sub:      'NIS2 Directive ready. Autonomous threat detection for European enterprises facing Cl0p and ALPHV/BlackCat campaigns.',
      stat:     '€4.1M average breach cost in the EU (2024)',
    },
    SG: {
      headline: '🇸🇬 MAS TRM-Aligned Threat Intelligence for Singapore',
      sub:      'PDPA compliant. Real-time CVE monitoring for APAC financial institutions and tech companies.',
      stat:     'SGD 5.8M average breach cost in Singapore (2024)',
    },
    DEFAULT: {
      headline: '🌍 Global AI-Powered Threat Intelligence',
      sub:      'Enterprise-grade CVE monitoring, AI SOC automation, and autonomous defense for security teams worldwide.',
      stat:     '$4.45M average global breach cost (2024)',
    },
  };

  const p = props[resolvedRegion] || props.DEFAULT;
  const pricing = getLocalizedPricing(
    (REGION_CONFIG[resolvedRegion] || REGION_CONFIG.DEFAULT).currency,
    (REGION_CONFIG[resolvedRegion] || REGION_CONFIG.DEFAULT).symbol
  );

  return {
    ...p,
    cta:    `Start for ${pricing[plan]?.formatted || 'free'}`,
    pricing: pricing[plan],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// REGION TRACKING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Record a region event in D1 (non-blocking)
 */
export async function trackRegionEvent(env, request, email = null, page = '/') {
  const region = detectRegion(request);
  try {
    await env.DB.prepare(`
      INSERT INTO region_events (id, email, country, region, currency, timezone, page, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      email || 'anonymous',
      region.country,
      region.resolved_region,
      region.currency,
      region.timezone,
      page,
    ).run();
  } catch {
    // Non-blocking
  }
  return region;
}

/**
 * Get geographic distribution of users
 */
export async function getRegionStats(env) {
  try {
    const result = await env.DB.prepare(`
      SELECT country, region, COUNT(*) as visits, COUNT(DISTINCT email) as unique_visitors
      FROM region_events
      WHERE email != 'anonymous'
      GROUP BY country
      ORDER BY visits DESC
      LIMIT 20
    `).all();

    const rows = result.results || [];

    // Revenue potential by region
    const withRevenue = rows.map(r => {
      const config = REGION_CONFIG[r.region] || REGION_CONFIG.DEFAULT;
      const proPrice = PRICING_TIERS.pro[config.currency] || PRICING_TIERS.pro.USD;
      return {
        ...r,
        currency:        config.currency,
        symbol:          config.symbol,
        mrr_potential:   proPrice * r.unique_visitors,
        compliance_tags: config.compliance?.slice(0, 2) || [],
      };
    });

    return {
      top_regions:     withRevenue,
      total_countries: rows.length,
    };
  } catch (err) {
    return { error: err.message, top_regions: [] };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GLOBAL EXPANSION DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Full global expansion dashboard — region stats + pricing + compliance
 */
export async function buildGlobalDashboard(env) {
  const regionStats = await getRegionStats(env);

  // Build pricing table for all regions
  const pricingByRegion = {};
  for (const [code, config] of Object.entries(REGION_CONFIG)) {
    if (code === 'DEFAULT') continue;
    pricingByRegion[code] = {
      currency:   config.currency,
      symbol:     config.symbol,
      locale:     config.locale,
      compliance: config.compliance,
      plans:      getLocalizedPricing(config.currency, config.symbol),
    };
  }

  return {
    generated_at:       new Date().toISOString(),
    region_stats:       regionStats,
    pricing_by_region:  pricingByRegion,
    total_regions_supported: Object.keys(REGION_CONFIG).length - 1,
    expansion_priority: ['IN', 'US', 'SG', 'EU', 'AU', 'AE'],
    compliance_frameworks: Object.keys(COMPLIANCE_MESSAGING).length,
  };
}

/**
 * Build region-optimized API response context
 * Attach to all API responses to give the frontend region signals
 */
export function buildRegionContext(request) {
  const region = detectRegion(request);
  return {
    region:     region.resolved_region,
    country:    region.country,
    currency:   region.currency,
    symbol:     region.symbol,
    timezone:   region.timezone,
    locale:     region.locale,
    compliance: region.compliance,
    pricing:    getLocalizedPricing(region.currency, region.symbol),
    value_prop: getRegionalValueProp(region.resolved_region),
  };
}
