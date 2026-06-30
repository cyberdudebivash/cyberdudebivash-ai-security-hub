/**
 * CYBERDUDEBIVASH AI Security Hub — Global SEO Structured Data Engine v42.0
 * Injects JSON-LD schemas dynamically based on current page.
 * Google Rich Results + AI Search (Perplexity, ChatGPT, Gemini) optimized.
 */

const SITE = {
  name:    'CYBERDUDEBIVASH AI Security Hub',
  brand:   'CYBERDUDEBIVASH®',
  url:     'https://cyberdudebivash.in',
  logo:    'https://cyberdudebivash.in/assets/images/logo.png',
  og:      'https://cyberdudebivash.in/og-image.png',
  email:   'info@cyberdudebivash.in',
  support: 'support@cyberdudebivash.in',
  twitter: '@cyberdudebivash',
  linkedin:'https://linkedin.com/company/cyberdudebivash',
  github:  'https://github.com/cyberdudebivash',
  founded: '2024',
  country: 'IN',
  currency:'INR',
};

// ─── Core Organization schema (always injected) ────────────────────────────
const ORGANIZATION_SCHEMA = {
  '@context':   'https://schema.org',
  '@type':      ['Organization', 'Corporation'],
  '@id':        `${SITE.url}/#organization`,
  name:         SITE.name,
  alternateName:['CyberDudeBivash', 'CYBERDUDEBIVASH', 'CDB Security'],
  url:          SITE.url,
  logo: {
    '@type':    'ImageObject',
    url:        SITE.logo,
    width:      512,
    height:     512,
  },
  image:        SITE.og,
  description:  'AI-Native Cybersecurity Platform offering Threat Intelligence, AI Red Teaming, SOC Operations, MSSP Services, OWASP LLM Security, and Enterprise Cyber Defense powered by the APEX AI Engine.',
  foundingDate: SITE.founded,
  founder: {
    '@type':    'Person',
    name:       'Bivash Kumar Nayak',
    jobTitle:   'Founder & CEO',
    url:        'https://linkedin.com/in/cyberdudebivash',
  },
  address: {
    '@type':           'PostalAddress',
    addressCountry:    'IN',
    addressRegion:     'Odisha',
  },
  contactPoint: [
    {
      '@type':            'ContactPoint',
      email:              SITE.support,
      contactType:        'customer support',
      availableLanguage:  'English',
      contactOption:      'TollFree',
    },
    {
      '@type':            'ContactPoint',
      email:              'enterprise@cyberdudebivash.in',
      contactType:        'sales',
      availableLanguage:  'English',
    },
    {
      '@type':            'ContactPoint',
      email:              'security@cyberdudebivash.in',
      contactType:        'technical support',
      availableLanguage:  'English',
    },
  ],
  sameAs: [
    SITE.linkedin,
    SITE.github,
    'https://twitter.com/cyberdudebivash',
    'https://t.me/cyberdudebivashSentinelApex',
  ],
  hasOfferCatalog: {
    '@type': 'OfferCatalog',
    name:    'AI Security Services',
    itemListElement: [
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'Enterprise Threat Intelligence' } },
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'AI Red Teaming' } },
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'SOC Operations' } },
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'MSSP Platform' } },
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'DPDP Act Compliance' } },
      { '@type': 'Offer', itemOffered: { '@type': 'Service', name: 'AI Governance' } },
    ],
  },
};

// ─── WebSite schema + SearchAction (enables Google sitelinks searchbox) ─────
const WEBSITE_SCHEMA = {
  '@context':   'https://schema.org',
  '@type':      'WebSite',
  '@id':        `${SITE.url}/#website`,
  name:         SITE.name,
  url:          SITE.url,
  description:  'Enterprise AI-Native Cybersecurity Platform — Threat Intelligence, SOC, MSSP, AI Red Team',
  publisher: { '@id': `${SITE.url}/#organization` },
  potentialAction: {
    '@type':        'SearchAction',
    target: {
      '@type':      'EntryPoint',
      urlTemplate:  `${SITE.url}/cve-hub?q={search_term_string}`,
    },
    'query-input':  'required name=search_term_string',
  },
  inLanguage:   'en-US',
};

// ─── SoftwareApplication schema (for the platform product) ──────────────────
const SOFTWARE_SCHEMA = {
  '@context':       'https://schema.org',
  '@type':          'SoftwareApplication',
  '@id':            `${SITE.url}/#software`,
  name:             SITE.name,
  applicationCategory: 'SecurityApplication',
  applicationSubCategory: ['ThreatIntelligence', 'SOCPlatform', 'AISecurityPlatform'],
  operatingSystem:  'Web-based (Cloud)',
  url:              SITE.url,
  screenshot:       SITE.og,
  featureList: [
    'AI-Native Threat Intelligence (1,600+ CVEs, CISA KEV, EPSS)',
    'Real-time IOC Enrichment (VirusTotal v3 + AbuseIPDB + Shodan)',
    'APEX AI Copilot (GROQ llama-3.3-70b, 19-tool God Mode)',
    'SIEM Export (JSON/CEF/STIX 2.1/Sigma/CSV)',
    'DPDP Act 2023 Compliance Engine',
    'Multi-tenant MSSP Platform with white-label support',
    'Enterprise API Economy (versioned REST API)',
    'AI Red Teaming & Adversarial Testing',
    'OWASP LLM Top 10 Security Assessment',
    'Google SSO (OAuth2/OIDC)',
    'GST Invoice Auto-generation (IGST/CGST/SGST)',
  ],
  offers: [
    {
      '@type':    'Offer',
      name:       'Free Tier',
      price:      '0',
      priceCurrency: SITE.currency,
      description: '3 scans/day, Basic threat intel',
    },
    {
      '@type':    'Offer',
      name:       'Starter',
      price:      '999',
      priceCurrency: SITE.currency,
      billingIncrement: 'monthly',
      description: '25 scans/month, AI analysis, PDF reports',
    },
    {
      '@type':    'Offer',
      name:       'Pro',
      price:      '2999',
      priceCurrency: SITE.currency,
      billingIncrement: 'monthly',
      description: 'Unlimited scans, Full AI Copilot, SIEM export, DPDP compliance',
    },
    {
      '@type':    'Offer',
      name:       'Enterprise',
      price:      '25000',
      priceCurrency: SITE.currency,
      billingIncrement: 'monthly',
      description: 'MSSP white-label, 4h SLA, dedicated account manager',
    },
  ],
  provider: { '@id': `${SITE.url}/#organization` },
};

// ─── Page-specific schema registry ──────────────────────────────────────────
const PAGE_SCHEMAS = {

  '/': [
    ORGANIZATION_SCHEMA,
    WEBSITE_SCHEMA,
    SOFTWARE_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'FAQPage',
      mainEntity: [
        {
          '@type':          'Question',
          name:             'What is CYBERDUDEBIVASH AI Security Hub?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:    'CYBERDUDEBIVASH AI Security Hub is an AI-native cybersecurity platform offering real-time threat intelligence (1,600+ CVEs), AI Red Teaming, Autonomous SOC, MSSP capabilities, OWASP LLM security, and enterprise API economy powered by the APEX AI Engine.',
          },
        },
        {
          '@type':          'Question',
          name:             'What cybersecurity services does CyberDudeBivash offer?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:    'Services include: AI Security Consulting, Enterprise Threat Intelligence, Managed Security Services (MSSP), SOC Operations, AI Governance & Risk Assessments, Cloud Security, Incident Response, Threat Hunting, DevSecOps, and Executive Cybersecurity Advisory.',
          },
        },
        {
          '@type':          'Question',
          name:             'Is there a free tier available?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:    'Yes. The Free tier includes 3 security scans per day, access to 5 CVEs, and 1 API key. Paid plans start at ₹999/month (Starter) with full AI capabilities available from ₹2,999/month (Pro).',
          },
        },
        {
          '@type':          'Question',
          name:             'Does the platform support MSSP operations?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:    'Yes. The MSSP tier (₹75,000/month) provides a full white-label multi-tenant SOC platform, revenue share (60/40), per-tenant API keys, custom branding, reseller API, and co-marketing support.',
          },
        },
        {
          '@type':          'Question',
          name:             'Is DPDP Act 2023 compliance supported?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:    'Yes. The platform includes a full DPDP Act 2023 compliance engine with 9-section gap analysis, Record of Processing Activities (RoPA) generation, maturity scoring, and automated GST-compliant invoicing.',
          },
        },
      ],
    },
  ],

  '/threat-intelligence': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'Service',
      name:       'Enterprise Threat Intelligence',
      provider:   { '@id': `${SITE.url}/#organization` },
      description: 'Real-time CVE database (1,600+ advisories), CISA KEV integration, EPSS scoring, IOC enrichment via VirusTotal v3 + AbuseIPDB + Shodan, SIEM export in JSON/CEF/STIX 2.1/Sigma format.',
      serviceType: 'Threat Intelligence',
      areaServed:  'Worldwide',
    },
  ],

  '/mssp': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'Service',
      name:       'Managed Security Services (MSSP) Platform',
      provider:   { '@id': `${SITE.url}/#organization` },
      description: 'Multi-tenant MSSP platform with white-label dashboard, per-tenant API keys, revenue share (60/40), and enterprise SOC capabilities for managed security service providers.',
      serviceType: 'Managed Security Service',
      areaServed:  'Worldwide',
      offers: {
        '@type':       'Offer',
        price:         '75000',
        priceCurrency: 'INR',
        billingIncrement: 'monthly',
      },
    },
  ],

  '/ai-security': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'Service',
      name:       'AI Security Services',
      provider:   { '@id': `${SITE.url}/#organization` },
      description: 'Comprehensive AI security services including OWASP LLM Top 10 assessments, prompt injection testing, AI red teaming, model security evaluation, and AI governance consulting.',
      serviceType: 'AI Security',
      areaServed:  'Worldwide',
    },
  ],

  '/owasp-llm-security': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'TechArticle',
      name:       'OWASP LLM Top 10 Security Assessment',
      author:     { '@id': `${SITE.url}/#organization` },
      description: 'Comprehensive OWASP LLM Top 10 security assessment covering prompt injection, insecure output handling, training data poisoning, model denial of service, and supply chain vulnerabilities.',
      about: { '@type': 'Thing', name: 'OWASP LLM Top 10' },
    },
  ],

  '/blog/': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'Blog',
      name:       'CYBERDUDEBIVASH Security Research & Intelligence Blog',
      url:        `${SITE.url}/blog/`,
      description: 'Expert cybersecurity research, threat intelligence reports, CVE analysis, AI security insights, and enterprise security guidance from the CYBERDUDEBIVASH security team.',
      publisher:  { '@id': `${SITE.url}/#organization` },
      inLanguage: 'en',
    },
  ],

  '/api-docs': [
    ORGANIZATION_SCHEMA,
    {
      '@context': 'https://schema.org',
      '@type':    'TechArticle',
      name:       'CYBERDUDEBIVASH AI Security Hub API Documentation',
      author:     { '@id': `${SITE.url}/#organization` },
      description: 'Complete REST API reference for the CYBERDUDEBIVASH AI Security Hub. Endpoints for threat intelligence, IOC enrichment, SIEM export, AI copilot, MSSP management, and compliance.',
      url:        `${SITE.url}/api-docs`,
      about: { '@type': 'Thing', name: 'Security API' },
      teaches:    'Enterprise security API integration',
    },
  ],

  '/pricing': [
    ORGANIZATION_SCHEMA,
    SOFTWARE_SCHEMA,
  ],

  '/upgrade': [
    ORGANIZATION_SCHEMA,
    SOFTWARE_SCHEMA,
  ],
};

// ─── Breadcrumb helper ───────────────────────────────────────────────────────
function buildBreadcrumb(items) {
  return {
    '@context':    'https://schema.org',
    '@type':       'BreadcrumbList',
    itemListElement: items.map((item, i) => ({
      '@type':   'ListItem',
      position:  i + 1,
      name:      item.name,
      item:      item.url || undefined,
    })),
  };
}

// ─── Blog article schema builder ─────────────────────────────────────────────
function buildArticleSchema(meta) {
  return {
    '@context':        'https://schema.org',
    '@type':           'Article',
    headline:          meta.title || document.title,
    description:       meta.description || document.querySelector('meta[name="description"]')?.content,
    image:             meta.image || SITE.og,
    author:            { '@id': `${SITE.url}/#organization` },
    publisher:         { '@id': `${SITE.url}/#organization` },
    datePublished:     meta.published || '',
    dateModified:      meta.modified || meta.published || '',
    mainEntityOfPage:  { '@type': 'WebPage', '@id': window.location.href },
    inLanguage:        'en',
    keywords:          meta.keywords || '',
    articleSection:    meta.section || 'Cybersecurity',
  };
}

// ─── CVE page schema builder ─────────────────────────────────────────────────
function buildCVESchema(cveId, description) {
  return [
    ORGANIZATION_SCHEMA,
    {
      '@context':    'https://schema.org',
      '@type':       'TechArticle',
      name:          `${cveId} Vulnerability Analysis`,
      headline:      `${cveId} — Security Vulnerability Details, CVSS Score & Remediation`,
      description:   description || `Detailed analysis of ${cveId} including CVSS score, affected systems, exploitation status, and remediation guidance.`,
      author:        { '@id': `${SITE.url}/#organization` },
      publisher:     { '@id': `${SITE.url}/#organization` },
      about: {
        '@type':       'Thing',
        name:          cveId,
        identifier:    cveId,
        description:   description,
        sameAs:        `https://nvd.nist.gov/vuln/detail/${cveId}`,
      },
      url:           window.location.href,
      mainEntityOfPage: { '@type': 'WebPage', '@id': window.location.href },
      inLanguage:    'en',
    },
    {
      '@context':    'https://schema.org',
      '@type':       'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Home',             item: SITE.url },
        { '@type': 'ListItem', position: 2, name: 'CVE Database',     item: `${SITE.url}/cve-hub` },
        { '@type': 'ListItem', position: 3, name: cveId },
      ],
    },
  ];
}

// ─── Inject JSON-LD into page <head> ─────────────────────────────────────────
function injectSchema(schemas) {
  const arr = Array.isArray(schemas) ? schemas : [schemas];
  arr.forEach(schema => {
    const el = document.createElement('script');
    el.type = 'application/ld+json';
    el.textContent = JSON.stringify(schema, null, 0);
    document.head.appendChild(el);
  });
}

// ─── International SEO readiness — self-referencing hreflang + geo tags ──────
// Single-language (en) platform today; x-default + en-IN signal correct
// regional targeting without claiming localized content that doesn't exist.
function injectInternationalTags() {
  const path = window.location.pathname.replace(/\/$/, '') || '/';
  const canonicalUrl = `${SITE.url}${path}`;
  const head = document.head;

  if (!document.querySelector('link[hreflang="x-default"]')) {
    const xDefault = document.createElement('link');
    xDefault.rel = 'alternate';
    xDefault.hreflang = 'x-default';
    xDefault.href = canonicalUrl;
    head.appendChild(xDefault);
  }
  if (!document.querySelector('link[hreflang="en"]')) {
    const en = document.createElement('link');
    en.rel = 'alternate';
    en.hreflang = 'en';
    en.href = canonicalUrl;
    head.appendChild(en);
  }
  if (!document.querySelector('link[hreflang="en-IN"]')) {
    const enIN = document.createElement('link');
    enIN.rel = 'alternate';
    enIN.hreflang = 'en-IN';
    enIN.href = canonicalUrl;
    head.appendChild(enIN);
  }
  if (!document.querySelector('meta[name="geo.region"]')) {
    const geoRegion = document.createElement('meta');
    geoRegion.name = 'geo.region';
    geoRegion.content = 'IN';
    head.appendChild(geoRegion);
  }
  if (!document.querySelector('meta[name="geo.placename"]')) {
    const geoPlace = document.createElement('meta');
    geoPlace.name = 'geo.placename';
    geoPlace.content = 'Odisha, India';
    head.appendChild(geoPlace);
  }
}
injectInternationalTags();

// ─── Detect current page and inject appropriate schemas ──────────────────────
function initSEOSchemas() {
  const path = window.location.pathname.replace(/\/$/, '') || '/';

  // CVE detail pages
  if (path.startsWith('/cve/')) {
    const cveId    = path.split('/').pop().toUpperCase();
    const descEl   = document.querySelector('meta[name="description"]');
    injectSchema(buildCVESchema(cveId, descEl?.content));

    // Breadcrumb for CVE
    injectSchema(buildBreadcrumb([
      { name: 'Home', url: SITE.url },
      { name: 'CVE Database', url: `${SITE.url}/cve-hub` },
      { name: cveId },
    ]));
    return;
  }

  // Blog posts
  if (path.startsWith('/blog/') && path.length > 6) {
    const title   = document.title;
    const desc    = document.querySelector('meta[name="description"]')?.content;
    const pubDate = document.querySelector('meta[name="article:published_time"]')?.content ||
                    document.querySelector('time')?.getAttribute('datetime') || '';
    injectSchema([
      ORGANIZATION_SCHEMA,
      WEBSITE_SCHEMA,
      buildArticleSchema({ title, description: desc, published: pubDate, section: 'Cybersecurity' }),
      buildBreadcrumb([
        { name: 'Home', url: SITE.url },
        { name: 'Blog', url: `${SITE.url}/blog/` },
        { name: title },
      ]),
    ]);
    return;
  }

  // Page-specific schemas
  const pageSchemas = PAGE_SCHEMAS[path] || PAGE_SCHEMAS[path + '/'];
  if (pageSchemas) {
    injectSchema(pageSchemas);

    // Add breadcrumb for service pages
    if (path !== '/' && !path.startsWith('/blog')) {
      const pageTitle = document.title.split('|')[0].trim();
      injectSchema(buildBreadcrumb([
        { name: 'Home', url: SITE.url },
        { name: pageTitle },
      ]));
    }
    return;
  }

  // Default: Organization + WebSite on all other pages
  injectSchema([ORGANIZATION_SCHEMA, WEBSITE_SCHEMA]);
}

// ─── Boot ────────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSEOSchemas);
} else {
  initSEOSchemas();
}

// ─── GA4 — fire page_view on landing pages (skips pages that already load it,
// e.g. index.html, to avoid double-counting) ──────────────────────────────────
(function initGA4() {
  if (window.gtag || window.dataLayer) return; // already loaded by this page
  const GA4_ID = 'G-E78VH3NJS6';
  const s = document.createElement('script');
  s.async = true;
  s.src = `https://www.googletagmanager.com/gtag/js?id=${GA4_ID}`;
  document.head.appendChild(s);
  window.dataLayer = window.dataLayer || [];
  function gtag(){ dataLayer.push(arguments); }
  window.gtag = gtag;
  gtag('js', new Date());
  gtag('config', GA4_ID, {
    send_page_view: true,
    allow_ad_personalization_signals: false,
  });
})();

// ─── Microsoft Clarity — session replay + heatmaps (skips pages that already
// load it, e.g. index.html, to avoid double-counting) ─────────────────────────
(function initClarity() {
  if (window.clarity) return; // already loaded by this page
  (function(c,l,a,r,i,t,y){
    c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
    t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
    y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
  })(window, document, "clarity", "script", "xf1wpk7u1x");
})();

// ─── IndexNow ping on page load (tells Bing/Yandex about new content) ────────
async function pingIndexNow() {
  try {
    const key = 'cdb-indexnow-' + window.location.hostname.replace(/\./g, '-');
    await fetch(`https://api.indexnow.org/indexnow?url=${encodeURIComponent(window.location.href)}&key=${key}`)
      .catch(() => {});
  } catch (_) {}
}
// Only ping on first visit (not every page load) to avoid spam
if (!sessionStorage.getItem('indexed_' + window.location.pathname)) {
  sessionStorage.setItem('indexed_' + window.location.pathname, '1');
  // Defer to not block rendering
  setTimeout(pingIndexNow, 5000);
}

export { buildArticleSchema, buildCVESchema, buildBreadcrumb, injectSchema, SITE };
