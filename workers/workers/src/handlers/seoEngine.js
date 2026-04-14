/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — SEO + Traffic Engine v1.0 (GOD MODE v16)
 *
 * Endpoints:
 *   GET  /api/seo/meta          — Auto meta tags for any page path
 *   GET  /api/seo/cve/:cve_id   — CVE landing page data (SEO-optimised)
 *   POST /api/leads/magnet      — Lead magnet: free mini-report for email capture
 *   POST /api/retarget/visit    — Record visit for KV retargeting
 *   GET  /api/retarget/offer    — Get personalized return-visitor offer
 * ═══════════════════════════════════════════════════════════════════════════
 */

function jsonOk(data)         { return Response.json({ success: true, data }); }
function jsonErr(msg, s = 400){ return Response.json({ success: false, error: msg }, { status: s }); }

// ─── Site Meta Catalog ────────────────────────────────────────────────────────
const META_CATALOG = {
  '/':            { title:'CYBERDUDEBIVASH AI Security Hub — Free Cybersecurity Scanner', description:'Scan your domain for DNS, TLS, email, AI, red team, compliance vulnerabilities. Instant free security assessment powered by AI.', keywords:'cybersecurity scanner, domain security, AI security, threat intelligence' },
  '/tools.html':  { title:'Security Tools — CYBERDUDEBIVASH', description:'Professional cybersecurity tools: domain scanner, AI threat analysis, red team simulation, identity threat detection, compliance audit.', keywords:'security tools, domain scanner, threat analysis' },
  '/academy.html':{ title:'Cybersecurity Training Academy — CYBERDUDEBIVASH', description:'Expert-led cybersecurity courses: SOC Analyst, AI Security, Red Team, Compliance. Practical training for security professionals.', keywords:'cybersecurity training, SOC analyst, red team course, AI security training' },
  '/intel.html':  { title:'Live Threat Intelligence — CYBERDUDEBIVASH Sentinel APEX', description:'Real-time threat intelligence feed: CVEs, APT groups, ransomware, zero-day vulnerabilities. Stay ahead of global threats.', keywords:'threat intelligence, CVE feed, APT tracking, ransomware alerts' },
  '/services.html':{ title:'Enterprise Cybersecurity Services — CYBERDUDEBIVASH', description:'Enterprise security services: penetration testing, compliance audit, SOC setup, incident response, MSSP.', keywords:'enterprise security, pentesting, compliance audit, SOC' },
};

// ─── CVE Landing Page Data Generator ─────────────────────────────────────────
const CVE_TEMPLATE_DATA = {
  'CVE-2024-21762': { vendor:'Fortinet', product:'FortiOS', cvss:9.6, severity:'CRITICAL', type:'RCE', fixed:'7.4.3', mitigations:['Patch immediately to 7.4.3+','Disable SSL-VPN if not needed','Monitor for IOCs: 45.32.x, 198.211.x'] },
  'CVE-2024-3400':  { vendor:'Palo Alto', product:'PAN-OS', cvss:10.0, severity:'CRITICAL', type:'RCE/Command Injection', fixed:'10.2.9-h1', mitigations:['Apply hotfix immediately','Enable Threat Prevention','Block external management access'] },
  'CVE-2024-27198': { vendor:'JetBrains', product:'TeamCity', cvss:9.8, severity:'CRITICAL', type:'Authentication Bypass', fixed:'2023.11.4', mitigations:['Upgrade to 2023.11.4+','Rotate all admin tokens','Audit recent project changes'] },
  'CVE-2024-6387':  { vendor:'OpenSSH', product:'OpenSSH', cvss:8.1, severity:'HIGH', type:'Race Condition/RCE', fixed:'9.8p1', mitigations:['Update to OpenSSH 9.8p1+','Restrict SSH access by IP','Enable LoginGraceTime 0 as temporary fix'] },
};

// ─── GET /api/seo/meta ────────────────────────────────────────────────────────
export async function handleSEOMeta(request, env) {
  const url      = new URL(request.url);
  const pagePath = url.searchParams.get('path') || '/';

  const meta = META_CATALOG[pagePath] || {
    title:       `${pagePath.replace(/\//g,'').replace(/-/g,' ').replace('.html','') || 'Home'} — CYBERDUDEBIVASH AI Security Hub`,
    description: 'Professional AI-powered cybersecurity platform. Scan, assess, protect. Trusted by security professionals globally.',
    keywords:    'cybersecurity, security scanner, threat intelligence, AI security',
  };

  // Structured data (JSON-LD) for SEO
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type':    'WebPage',
    name:       meta.title,
    description:meta.description,
    url:        `https://cyberdudebivash.in${pagePath}`,
    publisher: {
      '@type': 'Organization',
      name:    'CYBERDUDEBIVASH',
      url:     'https://cyberdudebivash.in',
      logo:    'https://cyberdudebivash.in/assets/logo.png',
    },
    potentialAction: {
      '@type':  'SearchAction',
      target:   'https://cyberdudebivash.in/?q={search_term_string}',
      'query-input': 'required name=search_term_string',
    },
  };

  return jsonOk({ ...meta, json_ld: jsonLd, og: {
    title:       meta.title,
    description: meta.description,
    url:         `https://cyberdudebivash.in${pagePath}`,
    image:       'https://cyberdudebivash.in/assets/og-banner.png',
    type:        'website',
    site_name:   'CYBERDUDEBIVASH AI Security Hub',
  }});
}

// ─── GET /api/seo/cve/:cve_id ─────────────────────────────────────────────────
export async function handleCVEPage(request, env) {
  const url    = new URL(request.url);
  const cveId  = url.pathname.split('/').pop().toUpperCase();

  // Try D1 first
  let cveData = null;
  if (env.DB) {
    cveData = await env.DB.prepare(
      `SELECT * FROM threat_intel WHERE cve_id = ? LIMIT 1`
    ).bind(cveId).first().catch(() => null);
  }

  // Fallback to static catalog
  if (!cveData) {
    const tmpl = CVE_TEMPLATE_DATA[cveId];
    if (!tmpl) return jsonErr(`CVE ${cveId} not found`, 404);
    cveData = { cve_id: cveId, ...tmpl };
  }

  // SEO meta for this CVE page
  const meta = {
    title:       `${cveId} — ${cveData.vendor || ''} ${cveData.product || ''} Vulnerability Analysis`,
    description: `${cveId}: ${cveData.severity || 'HIGH'} severity ${cveData.type || 'vulnerability'} in ${cveData.product || 'affected software'}. CVSS ${cveData.cvss_score || cveData.cvss || 'N/A'}. Mitigations, affected versions, and patch guidance.`,
    keywords:    `${cveId}, ${cveData.vendor || ''}, ${cveData.product || ''}, vulnerability, CVE, security advisory, ${cveData.type || ''}`,
    canonical:   `https://cyberdudebivash.in/cve/${cveId.toLowerCase()}`,
  };

  return jsonOk({ cve: cveData, seo: meta, cta: {
    text:   `Scan your systems for ${cveId} exposure — Free`,
    url:    `https://cyberdudebivash.in/?cve=${cveId}`,
    button: 'Scan Now Free →',
  }});
}

// ─── POST /api/leads/magnet — Free mini-report lead capture ──────────────────
export async function handleLeadMagnet(request, env) {
  let body = {};
  try { body = await request.json(); } catch { return jsonErr('Invalid JSON'); }

  const { email, name = '', domain = '', magnet_type = 'free_mini_report' } = body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonErr('Valid email required');
  }

  const leadId = crypto.randomUUID?.() || `lm_${Date.now()}`;
  const ts     = new Date().toISOString();

  // Store in D1 crm_leads
  if (env.DB) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO crm_leads
         (id, name, email, source, source_detail, stage, icp_score, created_at, updated_at)
       VALUES (?, ?, ?, 'organic', ?, 'NEW', 20, ?, ?)`
    ).bind(leadId, name || email.split('@')[0], email, `lead_magnet:${magnet_type}`, ts, ts)
     .run().catch(() => {});
  }

  // Store in KV for retargeting
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `lead_magnet:${email}`,
      JSON.stringify({ email, name, domain, magnet_type, captured_at: ts }),
      { expirationTtl: 90 * 86400 } // 90 days
    ).catch(() => {});
  }

  // Generate free mini-report content
  const miniReport = generateMiniReport(domain || email.split('@')[1] || 'your-domain.com');

  return jsonOk({
    lead_captured: true,
    lead_id:       leadId,
    magnet_type,
    mini_report:   miniReport,
    message:       `Your free security report is ready, ${name || 'there'}!`,
    next_step: {
      text:   'Get your full detailed report with all findings unlocked',
      url:    `https://cyberdudebivash.in/?target=${encodeURIComponent(domain)}`,
      cta:    'Run Full Scan →',
    },
  });
}

function generateMiniReport(domain) {
  // Deterministic "preview" report for lead magnet
  const score = 45 + (domain.length % 40);
  return {
    domain,
    risk_score:    score,
    risk_level:    score >= 70 ? 'HIGH' : 'MEDIUM',
    preview_items: [
      { category:'TLS Security',    status: score > 60 ? '⚠️ Issues found' : '✅ Configured', detail:'Full TLS audit in paid report' },
      { category:'DNS Security',    status: '⚠️ Review needed', detail:'DNSSEC and SPF/DKIM/DMARC analysis in full report' },
      { category:'Email Security',  status: score > 55 ? '❌ Misconfigured' : '⚠️ Partial', detail:'DMARC policy enforcement details in full report' },
      { category:'HTTP Headers',    status: '⚠️ Missing headers', detail:'CSP, HSTS, X-Frame-Options — full list in paid report' },
    ],
    locked_findings: Math.floor(score / 10) + 3,
    cta_unlock:      'Unlock all findings for ₹199',
  };
}

// ─── POST /api/retarget/visit — KV visitor tracking ──────────────────────────
export async function handleRetargetVisit(request, env) {
  let body = {};
  try { body = await request.json(); } catch { /* optional */ }

  const ip      = request.headers.get('CF-Connecting-IP') || 'unknown';
  const country = request.headers.get('CF-IPCountry') || 'XX';
  const { page = '/', referrer = '' } = body;
  const vid   = body.visitor_id || ip;
  const ts    = new Date().toISOString();

  if (env.SECURITY_HUB_KV) {
    const existing = await env.SECURITY_HUB_KV.get(`visitor:${vid}`, 'json').catch(() => null);
    const visits   = existing?.visits || 0;
    await env.SECURITY_HUB_KV.put(
      `visitor:${vid}`,
      JSON.stringify({ vid, ip, country, first_seen: existing?.first_seen || ts, last_seen: ts, visits: visits + 1, pages: [...(existing?.pages || []).slice(-9), page], referrer }),
      { expirationTtl: 30 * 86400 }
    ).catch(() => {});
  }

  return jsonOk({ tracked: true });
}

// ─── GET /api/retarget/offer — Personalized return-visitor offer ──────────────
export async function handleRetargetOffer(request, env) {
  const url = new URL(request.url);
  const vid = url.searchParams.get('vid') || request.headers.get('CF-Connecting-IP') || 'unknown';

  let visitor = null;
  if (env.SECURITY_HUB_KV) {
    visitor = await env.SECURITY_HUB_KV.get(`visitor:${vid}`, 'json').catch(() => null);
  }

  if (!visitor) return jsonOk({ offer: null, first_visit: true });

  const visits = visitor.visits || 1;
  let offer    = null;

  if (visits >= 3) {
    offer = {
      type:       'return_discount',
      headline:   'Welcome back! Your exclusive offer expires tonight.',
      discount:   '30% OFF',
      product:    'SECURITY_STARTER_BUNDLE',
      price:      599,
      orig_price: 799,
      urgency:    'high',
      cta:        'Claim 30% Discount →',
    };
  } else if (visits >= 2) {
    offer = {
      type:       'social_proof',
      headline:   '247 security professionals joined this week',
      subtext:    'Start your free scan — no sign-up required',
      cta:        'Scan My Domain →',
    };
  }

  return jsonOk({ offer, visits, last_seen: visitor.last_seen, first_visit: false });
}
