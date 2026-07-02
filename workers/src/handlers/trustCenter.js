/**
 * CYBERDUDEBIVASH v27 — Trust Center Handler
 * Rule #3: Trust First — Real company, real founder, real metrics
 *
 * GET /api/trust/center          -> trust center data (public)
 * GET /api/trust/metrics         -> real platform metrics from D1
 * POST /api/trust/testimonial    -> submit testimonial (pending verification)
 * GET /api/trust/company         -> verified company information
 */

import { fetchLiveMetricsFromD1 } from '../services/metricsHydration.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

// Verified, static company facts — these are facts, not metrics, no DB needed
const COMPANY_INFO = {
  name:       'CYBERDUDEBIVASH PRIVATE LIMITED',
  cin:        'U74999OR2024PTC049281',
  gst:        '21ARKPN8270G1ZP',
  founded:    '2024',
  location:   'Odisha, India',
  website:    'https://cyberdudebivash.in',
  email:      'contact@cyberdudebivash.in',
  whatsapp:   '+91 81798 81447',
  founder: {
    name:     'Bivash',
    role:     'Founder & Principal Security Architect',
    linkedin: 'https://linkedin.com/in/cyberdudebivash',
    bio:      'Cybersecurity practitioner specializing in AI-powered threat intelligence, domain security analysis, and enterprise security architecture.',
  },
  methodology: {
    scan_engine:  'Multi-layer active reconnaissance: DNS, TLS, HTTP headers, CVE correlation, OWASP mapping',
    ai_analysis:  'MYTHOS AI: deterministic threat correlation, no data sent to external LLMs',
    data_handling:'Scan targets processed in-flight, not stored. No PII collected on scan targets.',
    standards:    ['OWASP Top 10', 'OWASP LLM Top 10', 'MITRE ATT&CK', 'CIS Controls', 'NIST 800-53', 'ISO 27001', 'DPDP Act 2023'],
    sla: {
      report_delivery:     'Instant (automated) to 4 hours (human review)',
      assessment_delivery: '72 hours (standard), 48h (premium), 24h (enterprise)',
      cve_alert:           'Critical CVEs: < 2 hours from NVD publication',
      support_response:    '< 4 business hours (email), immediate (WhatsApp)',
    },
  },
  certifications: [],  // Populated when certifications are obtained
  platform: {
    infrastructure: 'Cloudflare Workers + D1 (SQLite) + KV Storage',
    uptime_sla:     '99.9%',
    data_residency: 'Cloudflare edge — India region preference',
    security:       'JWT auth, rate limiting, OWASP input validation, audit logging',
    open_source:    'Threat intel feeds: github.com/cyberdudebivash/cyberdudebivash-ai-security-hub',
  },
};

// GET /api/trust/company
export async function handleTrustCompany(request, env) {
  return json({ success: true, company: COMPANY_INFO });
}

// GET /api/trust/compliance — framework alignment records ("honest badges").
// frontend/assets/js/sentinel-apex-live-metrics.js has called this since it
// was written but the route never existed. COMPANY_INFO.certifications is
// deliberately []: this platform holds no formal third-party certifications
// yet, so no framework is ever reported "certified" here — only "aligned"
// (explicitly referenced in the real methodology.standards list above) or
// "partial" (not yet formally mapped), matching the codebase's existing
// de-fabrication stance.
const COMPLIANCE_FRAMEWORKS = [
  { framework: 'iso27001',  alignment_level: 'aligned', scope_note: 'ISO 27001 controls referenced in platform security architecture; no formal certification held.' },
  { framework: 'dpdp',      alignment_level: 'aligned', scope_note: 'DPDP Act 2023 — dedicated compliance engine (/api/compliance/dpdp) available on PRO+.' },
  { framework: 'owasp_llm', alignment_level: 'aligned', scope_note: 'OWASP LLM Top 10 mapped across AI Security scan modules.' },
  { framework: 'mitre',     alignment_level: 'aligned', scope_note: 'MITRE ATT&CK techniques mapped in Red Team and Threat Intel modules.' },
  { framework: 'soc2',      alignment_level: 'partial', scope_note: 'Not yet formally assessed against SOC 2 Trust Service Criteria.' },
  { framework: 'gdpr',      alignment_level: 'partial', scope_note: 'Not yet formally assessed against GDPR 2016/679.' },
  { framework: 'pcidss',    alignment_level: 'partial', scope_note: 'No cardholder data is stored by the platform; formal PCI-DSS assessment not performed.' },
  { framework: 'hipaa',     alignment_level: 'partial', scope_note: 'Not yet formally assessed against HIPAA/HITECH.' },
  { framework: 'nist_ai',   alignment_level: 'partial', scope_note: 'Not yet formally assessed against NIST AI RMF.' },
];

export async function handleTrustCompliance(request, env) {
  return json({ success: true, frameworks: COMPLIANCE_FRAMEWORKS, generated_at: new Date().toISOString() });
}

// GET /api/trust/metrics — real numbers only
//
// The response envelope is ALWAYS { success, metrics: { … } }. The frontend
// Trust Center hydrator (frontend/index.html) reads `d.metrics.*`; an earlier
// version spread the cached metrics to the TOP LEVEL on cache hits
// (`...JSON.parse(cached)`) while nesting them under `metrics` on cache misses,
// so on every warm-cache load `d.metrics` was undefined and the tiles silently
// fell back to their hardcoded HTML/baseline defaults. Both branches now nest.
//
// Counts come from the SAME hydrated source as GET /api/platform/metrics
// (KV key `platform:metrics:live`, refreshed every cron firing) so the Trust
// Center can never contradict the live dashboard. The previous implementation
// read platform_metrics keys `total_scans`/`total_cves`/`total_customers` that
// NO writer populates — they were structurally pinned to 0 forever, which is
// why the public Trust Center reported "0 scans / 0 CVEs" while 60+ scans and
// 1600+ CVEs actually existed. Cache key is bumped to :v2 so the old flat/zero
// value is never served by this nested-shape reader.
export async function handleTrustMetrics(request, env) {
  try {
    const cacheKey = 'cache:trust:metrics:v2';
    const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
    if (cached) return json({ success: true, cached: true, metrics: JSON.parse(cached) });

    // Single source of truth: the SAME canonical metric blend /api/platform/metrics
    // serves. Prefer the hydrated KV snapshot; if cold, recompute via the shared
    // hydrator (never a divergent trust-only query). This guarantees the Trust
    // Center's scan/CVE/customer counts equal the platform dashboard's by
    // construction — the earlier bug served scan_history-only (21) while the
    // platform showed the KV+D1 blend (62), an enterprise-visible contradiction.
    let live = null;
    try {
      const raw = await env.SECURITY_HUB_KV?.get('platform:metrics:live');
      if (raw) live = JSON.parse(raw);
    } catch { /* fall through to hydrator */ }
    if (!live) {
      try { live = await fetchLiveMetricsFromD1(env); }
      catch { /* leave null → COALESCE to 0 below */ }
    }

    const [customersRow, soarRow, uptimeRow] = await Promise.all([
      env.DB.prepare("SELECT COALESCE(COUNT(*),0) AS v FROM subscriptions WHERE status='active'").first().catch(() => null),
      env.DB.prepare("SELECT COALESCE(value_int,0) AS v FROM platform_metrics WHERE key='soar_rules_total'").first().catch(() => null),
      // Real measured uptime from the self-probe written every cron firing (index.js scheduled()).
      env.DB.prepare(`
        SELECT COUNT(*) AS checks, COUNT(CASE WHEN status='operational' THEN 1 END) AS ok_checks
        FROM uptime_log WHERE service='api' AND checked_at > datetime('now','-30 days')
      `).first().catch(() => null),
    ]);

    const metrics = {
      // Canonical counts — identical to /api/platform/metrics (blended total, not scan_history-only).
      total_scans:      live?.total_scans        ?? 0,
      total_cves:       live?.total_cves_tracked ?? 0,
      // active_customers comes from the same hydrator; the direct subscriptions
      // count is the fallback only when the hydrator itself was unavailable.
      total_customers:  live?.active_customers   ?? (customersRow?.v ?? 0),
      total_soar_rules: live?.soar_rules_total   ?? (soarRow?.v ?? 0),
      uptime_pct:       uptimeRow?.checks > 0 ? Math.round((uptimeRow.ok_checks / uptimeRow.checks) * 1000) / 10 : null,
      // Static/factual metrics (not from user counts)
      cve_alert_sla:    '< 2 hours',
      assessment_sla:   '72 hours',
      support_sla:      '< 4 business hours',
      last_updated:     new Date().toISOString(),
    };

    // 60s TTL keeps the Trust Center within ~1 min of the platform dashboard's
    // 45s-fresh metrics — a previous 600s TTL let the two surfaces disagree by
    // up to 10 minutes of organic growth even after sourcing was unified.
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(metrics), { expirationTtl: 60 });
    return json({ success: true, metrics });

  } catch(e) {
    // Graceful degradation — return only static/safe metrics on DB error.
    // Shape stays { success, metrics } so the frontend contract holds.
    return json({
      success: true,
      metrics: {
        total_scans:    null,
        total_cves:     null,
        uptime_pct:     null,
        cve_alert_sla:  '< 2 hours',
        assessment_sla: '72 hours',
        note:           'Live counts temporarily unavailable',
      }
    });
  }
}

// GET /api/trust/center — full trust center payload
export async function handleTrustCenter(request, env) {
  try {
    const [metricsRes, testimonialsRow, deliverableRow] = await Promise.all([
      handleTrustMetrics(request, env),
      // Only verified testimonials
      env.DB.prepare(
        "SELECT id,type,title,content,company,sector FROM trust_signals WHERE verified=1 AND visible=1 ORDER BY display_order ASC LIMIT 6"
      ).all().catch(() => ({ results: [] })),
      Promise.resolve(null),
    ]);

    const metricsData = await metricsRes.json();

    return json({
      success:      true,
      company:      COMPANY_INFO,
      metrics:      metricsData.metrics,
      testimonials: testimonialsRow.results || [],
      assessment_deliverables: [
        'Executive summary with business risk context',
        'Complete vulnerability inventory with CVSS scores',
        'OWASP + MITRE ATT&CK mapping',
        'Prioritized remediation roadmap (30/60/90 day)',
        'Compliance gap analysis (ISO 27001 / DPDP / PCI-DSS)',
        '30-minute analyst walkthrough call',
        'GST-compliant invoice',
      ],
      process_steps: [
        { step: 1, title: 'Book & Pay',      desc: 'Instant Razorpay checkout. GST invoice sent immediately.' },
        { step: 2, title: 'Intake Form',     desc: 'We send a 5-question form to understand your scope and priorities.' },
        { step: 3, title: 'Analysis',        desc: 'Our analyst runs comprehensive assessment (automated + manual review).' },
        { step: 4, title: 'Report Delivery', desc: 'Full PDF report delivered within 72 hours to your email.' },
        { step: 5, title: 'Expert Call',     desc: '30-minute video walkthrough of all findings with Q&A.' },
      ],
      service_levels: COMPANY_INFO.methodology.sla,
      contact: {
        email:     COMPANY_INFO.email,
        whatsapp:  COMPANY_INFO.whatsapp,
        booking:   '/booking.html',
      },
    });
  } catch(e) {
    return json({ success: false, error: e.message }, 500);
  }
}

// POST /api/trust/testimonial — submit for review (not auto-published)
export async function handleSubmitTestimonial(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ success: false, error: 'Invalid JSON' }, 400); }

  const { name, role, company, content, rating, email } = body;
  if (!content || content.length < 20) return json({ success: false, error: 'Content too short' }, 400);

  const id = 'ts_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

  await env.DB.prepare(
    "INSERT INTO trust_signals (id,type,title,content,company,verified,visible) VALUES (?,?,?,?,?,0,0)"
  ).bind(id, 'testimonial', (name || 'Anonymous') + ' — ' + (role || ''), content, company || null).run();

  return json({ success: true, message: 'Thank you. Your testimonial will appear after verification.' });
}
