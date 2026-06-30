/**
 * CYBERDUDEBIVASH v27 — Trust Center Handler
 * Rule #3: Trust First — Real company, real founder, real metrics
 *
 * GET /api/trust/center          -> trust center data (public)
 * GET /api/trust/metrics         -> real platform metrics from D1
 * POST /api/trust/testimonial    -> submit testimonial (pending verification)
 * GET /api/trust/company         -> verified company information
 */

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

// GET /api/trust/metrics — real numbers from D1 only
export async function handleTrustMetrics(request, env) {
  try {
    // Cache in KV for 10 minutes
    const cacheKey = 'cache:trust:metrics';
    const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
    if (cached) return json({ success: true, cached: true, ...JSON.parse(cached) });

    const [scansRow, cvesRow, customersRow, uptimeRow] = await Promise.all([
      env.DB.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_scans'").first(),
      env.DB.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_cves'").first(),
      env.DB.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_customers'").first(),
      // Real measured uptime from the self-probe written every cron firing (index.js
      // scheduled()) — trust_metrics_cache was never written by anything and always
      // forced a fabricated 99.9% here; replaced with the actual uptime_log table.
      env.DB.prepare(`
        SELECT COUNT(*) AS checks, COUNT(CASE WHEN status='operational' THEN 1 END) AS ok_checks
        FROM uptime_log WHERE service='api' AND checked_at > datetime('now','-30 days')
      `).first().catch(() => null),
    ]);

    const metrics = {
      total_scans:      scansRow?.val     || 0,
      total_cves:       cvesRow?.val      || 0,
      total_customers:  customersRow?.val || 0,
      uptime_pct:       uptimeRow?.checks > 0 ? Math.round((uptimeRow.ok_checks / uptimeRow.checks) * 1000) / 10 : null,
      // Static/factual metrics (not from user counts)
      cve_alert_sla:    '< 2 hours',
      assessment_sla:   '72 hours',
      support_sla:      '< 4 business hours',
      last_updated:     new Date().toISOString(),
    };

    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(metrics), { expirationTtl: 600 });
    return json({ success: true, metrics });

  } catch(e) {
    // Graceful degradation — return only static/safe metrics on DB error
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
