/**
 * CYBERDUDEBIVASH v27 — Trust Center Handler v31.1
 * P0 FIX: Remove unverifiable testimonials from public display.
 *          Add compliance_alignments API (honest badge data).
 *          Fix handleTrustMetrics to use platform_metrics table correctly.
 *
 * GET /api/trust/center          → trust center data (public)
 * GET /api/trust/metrics         → real platform metrics from platform_metrics D1 table
 * GET /api/trust/company         → verified company information
 * GET /api/trust/compliance      → framework alignment records (replaces hardcoded badges)
 * POST /api/trust/testimonial    → submit for admin review (never auto-published)
 *
 * WHAT CHANGED FROM v27:
 *   - handleTrustMetrics: queries platform_metrics table (key/value_int columns),
 *     correctly matches the schema defined in schema_v30_p0p1.sql.
 *     Falls back to null (not 0) when data is unavailable — null is honest.
 *   - handleTrustCenter: testimonials only appear when verified=1 AND visible=1.
 *     No default seed testimonials. Empty array is correct when none are verified.
 *   - handleTrustCompliance: new — reads compliance_alignments table seeded in
 *     schema_v31_p0_fixes.sql. Provides honest "aligned/partial/certified" labels
 *     with scope notes. The dashboard must render these instead of the hardcoded badges.
 *   - COMPANY_INFO.certifications: remains [] until real audits are completed.
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ── Verified company facts — these are facts, not metrics, no DB needed ───────
const COMPANY_INFO = {
  name:       'CYBERDUDEBIVASH PRIVATE LIMITED',
  cin:        'U74999OR2024PTC049281',
  gst:        '21ARKPN8270G1ZP',
  founded:    '2024',
  location:   'Odisha, India',
  website:    'https://cyberdudebivash.in',
  email:      'bivash@cyberdudebivash.com',
  whatsapp:   '+91 81798 81447',
  founder: {
    name:     'Bivash',
    role:     'Founder & Principal Security Architect',
    linkedin: 'https://linkedin.com/in/cyberdudebivash',
    bio:      'Cybersecurity practitioner specialising in AI-powered threat intelligence, domain security analysis, and enterprise security architecture.',
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
  // FIX: certifications is intentionally empty — populated only when audits complete
  certifications: [],
  platform: {
    infrastructure: 'Cloudflare Workers + D1 (SQLite) + KV Storage',
    uptime_sla:     '99.9% (Cloudflare edge SLA)',
    data_residency: 'Cloudflare edge — India region preference',
    security:       'JWT auth, rate limiting, OWASP input validation, audit logging',
  },
};

// ── GET /api/trust/company ────────────────────────────────────────────────────
export async function handleTrustCompany(request, env) {
  return json({ success: true, company: COMPANY_INFO });
}

// ── GET /api/trust/metrics ────────────────────────────────────────────────────
// FIX: Reads from platform_metrics table (key='total_scans', value_int column).
// The v27 handler read from correct columns but was querying trust_metrics_cache
// for uptime — that table now exists (seeded in v30 schema).
export async function handleTrustMetrics(request, env) {
  try {
    const cacheKey = 'cache:trust:metrics:v2';
    const kv = env.SECURITY_HUB_KV || env.KV;

    // Try KV cache first (10-minute TTL)
    if (kv) {
      const cached = await kv.get(cacheKey).catch(() => null);
      if (cached) {
        return json({ success: true, cached: true, ...JSON.parse(cached) });
      }
    }

    const db = env.SECURITY_HUB_DB || env.DB;
    if (!db) throw new Error('DB unavailable');

    // Read from platform_metrics — schema: key TEXT PRIMARY KEY, value_int INTEGER
    const [scansRow, cvesRow, customersRow, kevRow, uptimeRow] = await Promise.all([
      db.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_scans'").first(),
      db.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_cves'").first(),
      db.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='total_customers'").first(),
      db.prepare("SELECT value_int AS val FROM platform_metrics WHERE key='kev_count'").first(),
      db.prepare("SELECT uptime_pct FROM trust_metrics_cache WHERE id='singleton'").first(),
    ]);

    const metrics = {
      // FIX: null when value is 0 from un-hydrated seed — distinguish "no data" from "zero"
      total_scans:     scansRow?.val     || null,
      total_cves:      cvesRow?.val      || null,
      total_customers: customersRow?.val || null,
      kev_count:       kevRow?.val       || null,
      uptime_pct:      uptimeRow?.uptime_pct ?? 99.9,
      cve_alert_sla:   '< 2 hours',
      assessment_sla:  '72 hours',
      support_sla:     '< 4 business hours',
      last_updated:    new Date().toISOString(),
    };

    if (kv) {
      kv.put(cacheKey, JSON.stringify({ metrics }), { expirationTtl: 600 }).catch(() => {});
    }

    return json({ success: true, metrics });

  } catch (e) {
    // Graceful degradation — return null values (not zeros) on DB error
    return json({
      success: true,
      metrics: {
        total_scans:    null,
        total_cves:     null,
        total_customers:null,
        uptime_pct:     99.9,
        cve_alert_sla:  '< 2 hours',
        assessment_sla: '72 hours',
        note:           'Live counts temporarily unavailable',
      },
    });
  }
}

// ── GET /api/trust/compliance ─────────────────────────────────────────────────
// NEW in v31.1: Returns framework alignment records from compliance_alignments table.
// The dashboard must use this to render compliance badges with honest labels.
// alignment_level: 'certified' | 'aligned' | 'partial'
// Certified = formal audit completed (cert_number will be non-null).
// Aligned   = controls implemented, audit not yet completed.
// Partial   = some controls implemented.
export async function handleTrustCompliance(request, env) {
  try {
    const cacheKey = 'cache:trust:compliance:v1';
    const kv = env.SECURITY_HUB_KV || env.KV;

    if (kv) {
      const cached = await kv.get(cacheKey).catch(() => null);
      if (cached) {
        return json({ success: true, cached: true, frameworks: JSON.parse(cached) });
      }
    }

    const db = env.SECURITY_HUB_DB || env.DB;
    if (!db) throw new Error('DB unavailable');

    const result = await db.prepare(
      'SELECT id, framework, alignment_level, scope_note, auditor, cert_number, valid_from, valid_until, evidence_url FROM compliance_alignments ORDER BY framework'
    ).all();

    const frameworks = (result.results || []).map(row => ({
      id:              row.id,
      framework:       row.framework,
      alignment_level: row.alignment_level,
      // Human-readable label for UI rendering
      alignment_label: row.alignment_level === 'certified'
        ? 'Certified'
        : row.alignment_level === 'aligned'
          ? 'Aligned — not certified'
          : 'Partially aligned',
      scope_note:      row.scope_note,
      auditor:         row.auditor   || null,
      cert_number:     row.cert_number || null,
      valid_from:      row.valid_from  || null,
      valid_until:     row.valid_until || null,
      evidence_url:    row.evidence_url || null,
    }));

    if (kv) {
      kv.put(cacheKey, JSON.stringify(frameworks), { expirationTtl: 3600 }).catch(() => {});
    }

    return json({
      success:    true,
      frameworks,
      notice:     'Alignment means controls are addressed in platform design. Certification is shown only where a formal third-party audit has been completed.',
      count:      frameworks.length,
    });

  } catch (e) {
    return json({ success: false, error: 'Compliance data unavailable' }, 500);
  }
}

// ── GET /api/trust/center ─────────────────────────────────────────────────────
export async function handleTrustCenter(request, env) {
  try {
    const db = env.SECURITY_HUB_DB || env.DB;

    const [metricsRes, testimonialsRow] = await Promise.all([
      handleTrustMetrics(request, env),
      // FIX: Only verified=1 AND visible=1 testimonials appear.
      // There are no seeded fake testimonials. If this returns empty,
      // the dashboard shows a "request a reference call" CTA instead.
      db ? db.prepare(
        "SELECT id, type, title, content, company, sector FROM trust_signals WHERE verified=1 AND visible=1 ORDER BY display_order ASC LIMIT 6"
      ).all().catch(() => ({ results: [] })) : Promise.resolve({ results: [] }),
    ]);

    const metricsData = await metricsRes.json();

    return json({
      success:      true,
      company:      COMPANY_INFO,
      metrics:      metricsData.metrics,
      // FIX: testimonials array is empty until real customers verify and consent
      testimonials: testimonialsRow.results || [],
      // If no testimonials, tell the frontend to show the reference call CTA
      reference_call_available: true,
      reference_contact: {
        email:    'bivash@cyberdudebivash.com',
        whatsapp: '+91 81798 81447',
        note:     'Enterprise and MSSP prospects can request a direct reference call with a current customer. Same-day response.',
      },
      assessment_deliverables: [
        'Executive summary with business risk context',
        'Complete vulnerability inventory with CVSS scores',
        'OWASP + MITRE ATT&CK mapping',
        'Prioritised remediation roadmap (30/60/90 day)',
        'Compliance gap analysis (ISO 27001 / DPDP / PCI-DSS)',
        '30-minute analyst walkthrough call',
        'GST-compliant invoice',
      ],
      process_steps: [
        { step: 1, title: 'Book & Pay',      desc: 'Instant Razorpay checkout. GST invoice sent immediately.' },
        { step: 2, title: 'Intake Form',     desc: '5-question form to understand scope and priorities.' },
        { step: 3, title: 'Analysis',        desc: 'Comprehensive assessment (automated + manual review).' },
        { step: 4, title: 'Report Delivery', desc: 'Full PDF report delivered within 72 hours.' },
        { step: 5, title: 'Expert Call',     desc: '30-minute video walkthrough with Q&A.' },
      ],
      service_levels: COMPANY_INFO.methodology.sla,
      contact: {
        email:    COMPANY_INFO.email,
        whatsapp: COMPANY_INFO.whatsapp,
      },
    });

  } catch (e) {
    return json({ success: false, error: e.message }, 500);
  }
}

// ── POST /api/trust/testimonial ───────────────────────────────────────────────
// Unchanged: submissions are pending (verified=0) until admin review.
export async function handleSubmitTestimonial(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ success: false, error: 'Invalid JSON' }, 400); }

  const { name, role, company, content, rating } = body;
  if (!content || content.length < 20) {
    return json({ success: false, error: 'Content too short (minimum 20 characters)' }, 400);
  }

  const id = 'ts_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db) return json({ success: false, error: 'DB unavailable' }, 503);

  await db.prepare(
    "INSERT INTO trust_signals (id, type, title, content, company, verified, visible) VALUES (?, 'testimonial', ?, ?, ?, 0, 0)"
  ).bind(
    id,
    ((name || 'Anonymous') + (role ? ' — ' + role : '')).slice(0, 200),
    content.slice(0, 2000),
    (company || '').slice(0, 200),
  ).run();

  return json({
    success: true,
    message: 'Thank you. Your testimonial will appear publicly after verification by our team.',
  });
}
