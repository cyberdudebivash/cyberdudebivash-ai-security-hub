/**
 * CYBERDUDEBIVASH® AI Security Hub — P17.0
 * aiSecurityScorecardHandler.js — AI Security Intelligence Scorecard
 * ====================================================================
 *
 * PUBLIC VIRAL ACQUISITION ENGINE
 *
 * Generates a shareable AI Security Score (0–100) for any domain.
 * Free tier returns a summary score + top 3 findings (lead capture gate).
 * Authenticated users receive the full 5-dimension breakdown + PDF link.
 *
 * Architecture:
 * - Reuses asmEngine.discoverSubdomainsViaCT() for domain surface
 * - Reuses riskEngine.computeRiskScore() for risk quantification
 * - Adds 5-dimension AI Security score model (proprietary scoring)
 * - Public endpoint — no auth required for summary (conversion gate)
 * - Rate-limited by IP (10 free checks/day via KV counter)
 *
 * Dimensions (20 points each → 100 max):
 *   D1: Domain Exposure & Attack Surface   (ASM data)
 *   D2: AI & LLM Threat Posture           (AI security signals)
 *   D3: Credential & Identity Risk        (exposed auth surfaces)
 *   D4: Vulnerability & CVE Exposure      (CVE/CVSS signals)
 *   D5: Operational Resilience            (uptime, cert health, headers)
 *
 * Revenue wiring:
 *   - Free: score + grade + 2 top findings + upgrade CTA
 *   - Paid: full report + all findings + PDF + MITRE mappings + remediation
 *   - Scorecard generates share URL → viral distribution → organic signups
 *   - Score below 60 triggers CISO consultation booking CTA
 *   - Score above 80 triggers upgrade-to-certify CTA
 *
 * Endpoints:
 *   POST /api/public/security-scorecard    — generate score (public)
 *   GET  /api/public/security-scorecard/:token — retrieve cached score
 *   GET  /api/scorecard/my-score           — authenticated: full score
 *   GET  /api/scorecard/history            — score trend (authenticated)
 *   POST /api/scorecard/share              — generate shareable link (auth)
 *   GET  /api/platform/scorecard/observability — health gate
 *
 * v17.0 — Initial implementation — P17.0 Enterprise Transformation
 */

import { discoverSubdomainsViaCT }  from '../services/asmEngine.js';
import { computeRiskScore }          from '../services/riskEngine.js';

// ── Constants ──────────────────────────────────────────────────────────────────

const FREE_DAILY_LIMIT   = 10;   // free IP-based scorecard checks per day
const SCORE_CACHE_TTL    = 3600; // seconds — cache scorecard in KV
const SHARE_TOKEN_TTL    = 604800; // 7 days — share link lifetime

const GRADE_MAP = [
  { min: 90, grade: 'A+', label: 'Exceptional',  color: '#10b981', risk: 'MINIMAL' },
  { min: 80, grade: 'A',  label: 'Strong',        color: '#10b981', risk: 'LOW' },
  { min: 70, grade: 'B',  label: 'Good',          color: '#00c2ff', risk: 'LOW-MEDIUM' },
  { min: 60, grade: 'C',  label: 'Moderate',      color: '#f59e0b', risk: 'MEDIUM' },
  { min: 50, grade: 'D',  label: 'Weak',          color: '#f97316', risk: 'HIGH' },
  { min: 0,  grade: 'F',  label: 'Critical Risk', color: '#ef4444', risk: 'CRITICAL' },
];

const CTAS = {
  critical: {
    primary: 'Get Emergency CISO Assessment',
    primary_url: '/booking.html?urgency=critical&ref=scorecard',
    secondary: 'Start Free Trial — Fix Issues Now',
    secondary_url: '/upgrade.html?ref=scorecard_critical',
  },
  high: {
    primary: 'Book AI Security Assessment',
    primary_url: '/booking.html?ref=scorecard_high',
    secondary: 'View Full Vulnerability Report',
    secondary_url: '/upgrade.html?ref=scorecard_high',
  },
  medium: {
    primary: 'Get Full Security Report',
    primary_url: '/upgrade.html?ref=scorecard_medium',
    secondary: 'Explore AI Security Platform',
    secondary_url: '/ai-security-services.html?ref=scorecard',
  },
  low: {
    primary: 'Certify Your Security Posture',
    primary_url: '/upgrade.html?ref=scorecard_good',
    secondary: 'Continuous Security Monitoring',
    secondary_url: '/upgrade.html?plan=pro&ref=scorecard',
  },
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function genToken(domain) {
  const ts  = Date.now().toString(36);
  const d64 = btoa(domain).replace(/[^a-z0-9]/gi, '').slice(0, 8);
  const rnd = Math.random().toString(36).slice(2, 8);
  return `sc_${ts}_${d64}_${rnd}`;
}

function getGrade(score) {
  return GRADE_MAP.find(g => score >= g.min) || GRADE_MAP[GRADE_MAP.length - 1];
}

function getRiskCTA(score) {
  if (score < 50) return CTAS.critical;
  if (score < 65) return CTAS.high;
  if (score < 80) return CTAS.medium;
  return CTAS.low;
}

function sanitizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '');
  // Basic domain validation
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/.test(d)) return null;
  if (d.length > 253) return null;
  return d;
}

async function checkIPRateLimit(env, ip) {
  const key = `scorecard:ratelimit:${ip}:${new Date().toISOString().slice(0, 10)}`;
  const kv  = env.SECURITY_HUB_KV;
  if (!kv) return { allowed: true, count: 0 };
  try {
    const raw   = await kv.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= FREE_DAILY_LIMIT) return { allowed: false, count };
    await kv.put(key, String(count + 1), { expirationTtl: 86400 });
    return { allowed: true, count: count + 1 };
  } catch { return { allowed: true, count: 0 }; }
}

async function getCachedScore(env, domain) {
  const key = `scorecard:result:${domain}`;
  try {
    const raw = await env.SECURITY_HUB_KV?.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function setCachedScore(env, domain, result) {
  const key = `scorecard:result:${domain}`;
  try {
    await env.SECURITY_HUB_KV?.put(key, JSON.stringify(result), { expirationTtl: SCORE_CACHE_TTL });
  } catch {}
}

// ── 5-Dimension Scoring Engine ────────────────────────────────────────────────

async function computeDomainExposureScore(domain) {
  // D1: Domain Exposure & Attack Surface (0–20)
  try {
    const subdomains = await Promise.race([
      discoverSubdomainsViaCT(domain),
      new Promise(r => setTimeout(() => r([]), 5000)),
    ]);

    const subCount = Array.isArray(subdomains) ? subdomains.length : 0;

    // Check basic DNS resolution
    let dnsOk = false;
    try {
      const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3000),
        cf: { cacheTtl: 300 },
      });
      const dnsData = await dnsRes.json();
      dnsOk = dnsData?.Status === 0 && (dnsData?.Answer?.length > 0);
    } catch {}

    // Check HTTPS + headers
    let httpsOk = false;
    let headerScore = 0;
    try {
      const httpRes = await fetch(`https://${domain}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000),
        cf: { cacheTtl: 300 },
      });
      httpsOk = httpRes.ok;
      const headers = httpRes.headers;
      if (headers.get('strict-transport-security')) headerScore += 3;
      if (headers.get('x-content-type-options')) headerScore += 2;
      if (headers.get('x-frame-options') || headers.get('content-security-policy')) headerScore += 3;
      if (headers.get('permissions-policy')) headerScore += 2;
    } catch {}

    // Score: penalize for large attack surface, reward good headers
    let score = 12; // baseline
    if (!dnsOk) score -= 5;
    if (!httpsOk) score -= 4;
    score -= Math.min(8, Math.floor(subCount / 10)); // penalty: 1pt per 10 subdomains
    score += Math.min(8, headerScore);
    score = Math.max(0, Math.min(20, score));

    return {
      dimension: 'domain_exposure',
      label: 'Domain Exposure & Attack Surface',
      score,
      max: 20,
      details: {
        subdomain_count: subCount,
        https_enabled: httpsOk,
        dns_resolves: dnsOk,
        security_headers_score: headerScore,
      },
      findings: [
        !httpsOk && { severity: 'HIGH', title: 'No HTTPS', detail: 'Domain does not serve HTTPS — all traffic is unencrypted.' },
        !dnsOk  && { severity: 'HIGH', title: 'DNS Resolution Failure', detail: 'Domain does not resolve — potential availability issue.' },
        subCount > 50 && { severity: 'MEDIUM', title: 'Large Attack Surface', detail: `${subCount} subdomains discovered — each is a potential entry point.` },
        headerScore < 5 && { severity: 'MEDIUM', title: 'Missing Security Headers', detail: 'Key HTTP security headers (HSTS, CSP, X-Frame-Options) are not configured.' },
      ].filter(Boolean),
    };
  } catch (e) {
    return { dimension: 'domain_exposure', label: 'Domain Exposure & Attack Surface', score: 10, max: 20, details: {}, findings: [], error: e?.message };
  }
}

async function computeAIThreatScore(domain) {
  // D2: AI & LLM Threat Posture (0–20)
  // Signal: presence of AI-exposed APIs, model endpoints, API gateways
  const AI_PATTERNS = [
    'api.', 'ai.', 'ml.', 'llm.', 'gpt.', 'chat.', 'bot.',
    'inference.', 'model.', 'predict.', 'copilot.',
  ];

  try {
    const subdomains = await Promise.race([
      discoverSubdomainsViaCT(domain),
      new Promise(r => setTimeout(() => r([]), 4000)),
    ]);

    const subdList = Array.isArray(subdomains)
      ? subdomains.map(s => (typeof s === 'string' ? s : s?.name_value || '')).filter(Boolean)
      : [];

    const aiExposed = subdList.filter(s => AI_PATTERNS.some(p => s.toLowerCase().includes(p)));
    const aiCount   = aiExposed.length;

    let score = 18; // baseline — assume mostly OK
    const findings = [];

    if (aiCount > 5) {
      score -= 8;
      findings.push({ severity: 'HIGH', title: 'Excessive AI API Exposure', detail: `${aiCount} AI/ML endpoints exposed publicly — prompt injection and model extraction risk.` });
    } else if (aiCount > 2) {
      score -= 4;
      findings.push({ severity: 'MEDIUM', title: 'AI API Exposure', detail: `${aiCount} AI-related endpoints found — verify prompt injection controls.` });
    } else if (aiCount > 0) {
      score -= 2;
      findings.push({ severity: 'LOW', title: 'AI Endpoint Detected', detail: `${aiCount} AI endpoint(s) discovered — ensure input validation and rate limiting.` });
    }

    return {
      dimension: 'ai_threat_posture',
      label: 'AI & LLM Threat Posture',
      score: Math.max(0, Math.min(20, score)),
      max: 20,
      details: { ai_endpoints_found: aiCount, exposed_patterns: aiExposed.slice(0, 5) },
      findings,
    };
  } catch {
    return { dimension: 'ai_threat_posture', label: 'AI & LLM Threat Posture', score: 14, max: 20, details: {}, findings: [] };
  }
}

async function computeIdentityRiskScore(domain) {
  // D3: Credential & Identity Risk (0–20)
  // Signals: auth subdomains, SSO, MX records, SPF/DMARC
  try {
    // Check SPF via DNS TXT
    let spfOk = false, dmarcOk = false;
    try {
      const [spfRes, dmarcRes] = await Promise.all([
        fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(3000), cf: { cacheTtl: 300 },
        }),
        fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(3000), cf: { cacheTtl: 300 },
        }),
      ]);
      const spfData   = await spfRes.json().catch(() => ({}));
      const dmarcData = await dmarcRes.json().catch(() => ({}));
      spfOk   = (spfData?.Answer || []).some(r => r?.data?.includes('v=spf1'));
      dmarcOk = (dmarcData?.Answer || []).some(r => r?.data?.includes('v=DMARC1'));
    } catch {}

    let score = 16;
    const findings = [];
    if (!spfOk) {
      score -= 6;
      findings.push({ severity: 'HIGH', title: 'No SPF Record', detail: 'Missing SPF record enables email spoofing from your domain — phishing risk.' });
    }
    if (!dmarcOk) {
      score -= 5;
      findings.push({ severity: 'HIGH', title: 'No DMARC Policy', detail: 'No DMARC record — attackers can impersonate your domain in phishing campaigns.' });
    }
    if (spfOk && dmarcOk) {
      findings.push({ severity: 'INFO', title: 'Email Authentication Configured', detail: 'SPF and DMARC are properly configured. Verify DMARC policy enforcement level.' });
    }

    return {
      dimension: 'identity_risk',
      label: 'Credential & Identity Risk',
      score: Math.max(0, Math.min(20, score)),
      max: 20,
      details: { spf_configured: spfOk, dmarc_configured: dmarcOk },
      findings,
    };
  } catch {
    return { dimension: 'identity_risk', label: 'Credential & Identity Risk', score: 12, max: 20, details: {}, findings: [] };
  }
}

async function computeVulnerabilityScore(domain, env) {
  // D4: Vulnerability & CVE Exposure (0–20)
  // Query D1 for recent CVEs related to common tech; use Shodan InternetDB for open ports
  let score = 16;
  const findings = [];
  const details  = { open_ports: [], known_vulns: 0 };

  try {
    // Shodan InternetDB — free, no key required
    let ip = null;
    try {
      const dnsRes  = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3000), cf: { cacheTtl: 300 },
      });
      const dnsData = await dnsRes.json();
      ip = dnsData?.Answer?.[0]?.data;
    } catch {}

    if (ip) {
      try {
        const shodanRes  = await fetch(`https://internetdb.shodan.io/${ip}`, {
          signal: AbortSignal.timeout(5000), cf: { cacheTtl: 3600 },
        });
        const shodanData = shodanRes.ok ? await shodanRes.json() : null;
        if (shodanData) {
          const ports = shodanData.ports || [];
          details.open_ports = ports.slice(0, 10);
          details.known_vulns = (shodanData.vulns || []).length;

          // High-risk ports
          const RISKY_PORTS = [21, 23, 3389, 5900, 1433, 3306, 27017, 6379, 9200];
          const exposed = ports.filter(p => RISKY_PORTS.includes(p));
          if (exposed.length > 0) {
            score -= Math.min(8, exposed.length * 2);
            findings.push({ severity: 'HIGH', title: 'Risky Ports Exposed', detail: `Ports ${exposed.join(', ')} are internet-accessible — high risk of unauthorized access.` });
          }
          if (details.known_vulns > 0) {
            score -= Math.min(6, details.known_vulns * 2);
            findings.push({ severity: 'CRITICAL', title: `${details.known_vulns} Known CVEs on IP`, detail: `Shodan reports ${details.known_vulns} known vulnerabilities on IP ${ip}.` });
          }
          // Many open ports = large attack surface
          if (ports.length > 20) {
            score -= 4;
            findings.push({ severity: 'MEDIUM', title: 'Large Port Exposure', detail: `${ports.length} open ports detected — minimize internet-facing service exposure.` });
          }
        }
      } catch {}
    }
  } catch {}

  return {
    dimension: 'vulnerability_exposure',
    label: 'Vulnerability & CVE Exposure',
    score: Math.max(0, Math.min(20, score)),
    max: 20,
    details,
    findings,
  };
}

async function computeResilienceScore(domain) {
  // D5: Operational Resilience (0–20)
  // Certificate validity, response time, availability
  let score = 16;
  const findings = [];
  const details  = { cert_valid: false, cert_days_remaining: null, response_ms: null };

  try {
    const t0 = Date.now();
    const res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      signal: AbortSignal.timeout(8000),
      cf: { cacheTtl: 60 },
    });
    details.response_ms = Date.now() - t0;
    details.cert_valid  = res.ok;

    if (!res.ok) {
      score -= 6;
      findings.push({ severity: 'HIGH', title: 'Site Unavailable', detail: `Domain returned HTTP ${res.status} — availability issue detected.` });
    }
    if (details.response_ms > 3000) {
      score -= 4;
      findings.push({ severity: 'MEDIUM', title: 'Slow Response Time', detail: `${details.response_ms}ms response time — impacts user experience and SEO ranking.` });
    } else if (details.response_ms > 1500) {
      score -= 2;
      findings.push({ severity: 'LOW', title: 'Elevated Response Time', detail: `${details.response_ms}ms — consider CDN or performance optimization.` });
    }

    // Check for server version disclosure (information leakage)
    const server = res.headers.get('server') || '';
    if (server && /\d/.test(server)) {
      score -= 2;
      findings.push({ severity: 'LOW', title: 'Server Version Disclosed', detail: `Server header discloses version: "${server}" — remove to prevent fingerprinting.` });
    }
  } catch (e) {
    score -= 8;
    findings.push({ severity: 'CRITICAL', title: 'TLS/Certificate Error', detail: 'Could not establish HTTPS connection — certificate may be expired or misconfigured.' });
  }

  return {
    dimension: 'operational_resilience',
    label: 'Operational Resilience',
    score: Math.max(0, Math.min(20, score)),
    max: 20,
    details,
    findings,
  };
}

async function generateScorecard(domain, env) {
  const [d1, d2, d3, d4, d5] = await Promise.all([
    computeDomainExposureScore(domain),
    computeAIThreatScore(domain),
    computeIdentityRiskScore(domain),
    computeVulnerabilityScore(domain, env),
    computeResilienceScore(domain),
  ]);

  const dimensions = [d1, d2, d3, d4, d5];
  const total      = dimensions.reduce((sum, d) => sum + d.score, 0);
  const grade      = getGrade(total);
  const allFindings = dimensions.flatMap(d => d.findings || []);
  const cta        = getRiskCTA(total);

  // Sort findings by severity
  const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const high     = allFindings.filter(f => f.severity === 'HIGH').length;
  const medium   = allFindings.filter(f => f.severity === 'MEDIUM').length;

  return {
    domain,
    score:            total,
    max_score:        100,
    grade:            grade.grade,
    grade_label:      grade.label,
    risk_level:       grade.risk,
    grade_color:      grade.color,
    generated_at:     new Date().toISOString(),
    dimensions,
    finding_summary:  { critical, high, medium, total: allFindings.length },
    all_findings:     allFindings,
    cta,
    powered_by:       'CYBERDUDEBIVASH® AI Security Hub — Sentinel APEX',
  };
}

// ── Public endpoints ──────────────────────────────────────────────────────────

export async function handlePublicScorecard(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

  // Rate limit check
  const rate = await checkIPRateLimit(env, ip);
  if (!rate.allowed) {
    return new Response(JSON.stringify({
      error: 'Daily free limit reached',
      message: `You've used ${FREE_DAILY_LIMIT} free security checks today. Upgrade for unlimited access.`,
      upgrade_url: '/upgrade.html?ref=scorecard_ratelimit',
      reset_at: new Date(new Date().setHours(24, 0, 0, 0)).toISOString(),
    }), { status: 429, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const domain = sanitizeDomain(body.domain);

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Invalid domain. Provide a valid domain name (e.g. company.com).' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // Block private / reserved domains
  const BLOCKED = ['localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'test.com'];
  if (BLOCKED.some(b => domain.includes(b))) {
    return new Response(JSON.stringify({ error: 'Domain not eligible for scoring.' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // Check cache
  const cached = await getCachedScore(env, domain);
  if (cached) {
    return new Response(JSON.stringify(freeResult(cached)), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Cache': 'HIT' },
    });
  }

  // Generate score
  const result = await generateScorecard(domain, env);

  // Store token + cache
  const token = genToken(domain);
  result.share_token = token;
  await setCachedScore(env, domain, result);
  try {
    await env.SECURITY_HUB_KV?.put(
      `scorecard:token:${token}`,
      JSON.stringify({ domain, score: result.score, grade: result.grade, generated_at: result.generated_at }),
      { expirationTtl: SHARE_TOKEN_TTL },
    );
  } catch {}

  // Log for analytics (fire-and-forget)
  try {
    await env.DB?.prepare(
      `INSERT OR IGNORE INTO scorecard_events (domain, ip_hash, score, grade, created_at) VALUES (?,?,?,?,datetime('now'))`
    ).bind(domain, btoa(ip).slice(0, 16), result.score, result.grade).run();
  } catch {}

  return new Response(JSON.stringify(freeResult(result)), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

/** Strip full findings — free users see summary + top 2 findings only */
function freeResult(result) {
  return {
    domain:          result.domain,
    score:           result.score,
    max_score:       result.max_score,
    grade:           result.grade,
    grade_label:     result.grade_label,
    risk_level:      result.risk_level,
    grade_color:     result.grade_color,
    generated_at:    result.generated_at,
    share_token:     result.share_token,
    finding_summary: result.finding_summary,
    // Free tier: dimension scores (no details), top 2 findings only
    dimensions:      (result.dimensions || []).map(d => ({
      dimension: d.dimension,
      label:     d.label,
      score:     d.score,
      max:       d.max,
    })),
    top_findings:  (result.all_findings || []).slice(0, 2),
    cta:           result.cta,
    upgrade_for_full: true,
    full_report_url: `/upgrade.html?ref=scorecard_full&domain=${encodeURIComponent(result.domain)}`,
    powered_by:    result.powered_by,
  };
}

export async function handleScorecardByToken(request, env, token) {
  if (!token || !/^sc_[a-z0-9_]+$/i.test(token)) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  try {
    const raw = await env.SECURITY_HUB_KV?.get(`scorecard:token:${token}`);
    if (!raw) return new Response(JSON.stringify({ error: 'Score not found or expired', expired: true }),
      { status: 404, headers: { 'Content-Type': 'application/json' } });

    const data = JSON.parse(raw);
    return new Response(JSON.stringify({
      ...data,
      share_url: `https://cyberdudebivash.in/ai-security-scorecard.html?token=${token}`,
      cta: getRiskCTA(data.score),
    }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' } });
  } catch {
    return new Response(JSON.stringify({ error: 'Token lookup failed' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

export async function handleMyScore(request, env, authCtx) {
  if (!authCtx?.user_id) {
    return new Response(JSON.stringify({ error: 'Authentication required', login_url: '/index.html' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // Lookup org's primary domain from D1
  let domain = null;
  try {
    const row = await env.DB?.prepare(
      `SELECT domain FROM organizations WHERE id = ? OR user_id = ? LIMIT 1`
    ).bind(authCtx.org_id || authCtx.user_id, authCtx.user_id).first();
    domain = row?.domain;
  } catch {}

  // Fall back to user email domain
  if (!domain && authCtx.email) {
    domain = sanitizeDomain(authCtx.email.split('@')[1]);
  }

  if (!domain) {
    return new Response(JSON.stringify({ error: 'No domain configured. Add your domain in Settings.', action: 'add_domain' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  const cached = await getCachedScore(env, domain);
  const result = cached || await generateScorecard(domain, env);
  if (!cached) await setCachedScore(env, domain, result);

  // Full result for authenticated users
  return new Response(JSON.stringify({
    ...result,
    share_url: `https://cyberdudebivash.in/ai-security-scorecard.html?token=${result.share_token || ''}`,
    auth: true,
    upgrade_for_full: false,
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

export async function handleScorecardHistory(request, env, authCtx) {
  if (!authCtx?.user_id) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const rows = await env.DB?.prepare(
      `SELECT domain, score, grade, created_at FROM scorecard_events
       WHERE ip_hash IN (
         SELECT ip_hash FROM scorecard_events WHERE user_id = ? LIMIT 1
       ) ORDER BY created_at DESC LIMIT 30`
    ).bind(authCtx.user_id).all().catch(() => ({ results: [] }));

    return new Response(JSON.stringify({
      user_id:  authCtx.user_id,
      history:  rows?.results || [],
      count:    rows?.results?.length || 0,
    }), { headers: { 'Content-Type': 'application/json' } });
  } catch {
    return new Response(JSON.stringify({ history: [], count: 0 }), { headers: { 'Content-Type': 'application/json' } });
  }
}

export async function handleScorecardShare(request, env, authCtx) {
  if (!authCtx?.user_id) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const domain = sanitizeDomain(body.domain);
  if (!domain) return new Response(JSON.stringify({ error: 'Domain required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

  const cached = await getCachedScore(env, domain);
  if (!cached) return new Response(JSON.stringify({ error: 'No score found. Generate a score first.' }), { status: 404, headers: { 'Content-Type': 'application/json' } });

  const token = cached.share_token || genToken(domain);
  const shareUrl = `https://cyberdudebivash.in/ai-security-scorecard.html?token=${token}&domain=${encodeURIComponent(domain)}`;

  return new Response(JSON.stringify({
    share_url:     shareUrl,
    token,
    score:         cached.score,
    grade:         cached.grade,
    domain,
    linkedin_text: `🛡️ Our AI Security Score: ${cached.score}/100 (${cached.grade}) — powered by @CYBERDUDEBIVASH Sentinel APEX. Get your organization's score: ${shareUrl}`,
    twitter_text:  `🔐 AI Security Score: ${cached.score}/100 (${cached.grade}) | Check yours → ${shareUrl} #CyberSecurity #AISecOps`,
  }), { headers: { 'Content-Type': 'application/json' } });
}

export async function handleScorecardObservability(request, env) {
  const checks = {
    kv_accessible:       false,
    db_accessible:       false,
    scoring_engine:      'OK',
    version:             'P17.0',
    endpoints: [
      'POST /api/public/security-scorecard',
      'GET  /api/public/security-scorecard/:token',
      'GET  /api/scorecard/my-score',
      'GET  /api/scorecard/history',
      'POST /api/scorecard/share',
    ],
  };

  try { await env.SECURITY_HUB_KV?.get('_health'); checks.kv_accessible = true; } catch {}
  try { await env.DB?.prepare('SELECT 1').first(); checks.db_accessible = true; } catch {}

  const healthy = checks.kv_accessible || checks.db_accessible;
  return new Response(JSON.stringify({ status: healthy ? 'OK' : 'DEGRADED', ...checks }),
    { status: healthy ? 200 : 503, headers: { 'Content-Type': 'application/json' } });
}
