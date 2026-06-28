/**
 * CYBERDUDEBIVASH AI Security Hub — Agent Threat Advisories Engine v1.0
 * Live, D1-backed replacement for the static "Security Advisories" list and
 * fabricated per-framework risk counters on frontend/agent-threats.html.
 *
 * Routes:
 *   GET  /api/agent-threats/advisories        → list (filter/sort/paginate)
 *   GET  /api/agent-threats/overview          → real per-framework counts + risk score
 *   POST /api/admin/agent-threats/advisories  → publish a new advisory (ADMIN_TOKEN)
 */

const FRAMEWORKS = ['mcp', 'langchain', 'autogen', 'openai', 'crewai', 'semantic_kernel', 'llama_index', 'custom'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEVERITY_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function rowToAdvisory(row) {
  let tags = [];
  try { tags = JSON.parse(row.tags || '[]'); } catch { tags = []; }
  return {
    advisory_id:        row.advisory_id,
    title:               row.title,
    description:         row.description,
    framework:           row.framework,
    affected_versions:   row.affected_versions,
    affected_products:   row.affected_products,
    severity:            row.severity,
    cvss_score:          row.cvss_score,
    owasp_llm_id:        row.owasp_llm_id,
    cwe_id:              row.cwe_id,
    mitre_atlas_id:      row.mitre_atlas_id,
    tags,
    patch_status:        row.patch_status,
    patch_version:       row.patch_version,
    published_at:        row.published_at,
    updated_at:          row.updated_at,
    source:              row.source,
    is_new:              !!row.is_new,
    full_advisory_url:   row.full_advisory_url,
  };
}

// ── GET /api/agent-threats/advisories ─────────────────────────────────────────
export async function handleListAgentAdvisories(request, env) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable', advisories: [] }, 503);

  const url       = new URL(request.url);
  const framework = (url.searchParams.get('framework') || 'all').toLowerCase();
  const sort      = (url.searchParams.get('sort') || 'latest').toLowerCase();
  const limit     = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '20', 10) || 20, 1), 100);
  const offset    = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

  const where  = [];
  const binds  = [];
  if (framework !== 'all' && FRAMEWORKS.includes(framework)) {
    where.push('framework = ?');
    binds.push(framework);
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const orderSql = sort === 'critical'
    ? `ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC, published_at DESC`
    : `ORDER BY published_at DESC`;

  try {
    const [rows, countRow] = await Promise.all([
      env.DB.prepare(
        `SELECT * FROM agent_threat_advisories ${whereSql} ${orderSql} LIMIT ? OFFSET ?`
      ).bind(...binds, limit, offset).all(),
      env.DB.prepare(
        `SELECT COUNT(*) as total FROM agent_threat_advisories ${whereSql}`
      ).bind(...binds).first(),
    ]);

    return json({
      success:     true,
      advisories:  (rows.results || []).map(rowToAdvisory),
      total:       countRow?.total ?? 0,
      limit,
      offset,
      framework,
      sort,
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return json({ success: false, error: 'Query failed', detail: e.message, advisories: [] }, 500);
  }
}

// ── GET /api/agent-threats/overview ───────────────────────────────────────────
// Real per-framework advisory counts + a risk score derived from actual
// severity/CVSS data in the table — replaces the hardcoded fake percentages
// ("72%", "85%"...) and fake "N active advisories" labels that used to be
// baked into the page HTML and never matched the real 5-advisory dataset.
export async function handleAgentThreatOverview(request, env) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable', frameworks: [] }, 503);

  try {
    const rows = await env.DB.prepare(
      `SELECT framework, severity, cvss_score, patch_status FROM agent_threat_advisories`
    ).all();

    const byFw = {};
    for (const fw of FRAMEWORKS) byFw[fw] = { framework: fw, advisory_count: 0, weighted_risk_sum: 0, max_cvss: 0, unpatched_count: 0 };

    for (const r of rows.results || []) {
      const bucket = byFw[r.framework];
      if (!bucket) continue;
      bucket.advisory_count += 1;
      bucket.weighted_risk_sum += (SEVERITY_WEIGHT[r.severity] || 1) * 5; // 0-100 scale contribution
      bucket.max_cvss = Math.max(bucket.max_cvss, r.cvss_score || 0);
      if (r.patch_status === 'no_patch') bucket.unpatched_count += 1;
    }

    const frameworks = Object.values(byFw)
      .filter(b => b.advisory_count > 0)
      .map(b => {
        // Risk score: capped 0-100, driven by severity mix + max CVSS + unpatched ratio.
        const cvssComponent   = Math.round((b.max_cvss / 10) * 60);
        const severityComponent = Math.min(30, Math.round(b.weighted_risk_sum / b.advisory_count));
        const unpatchedComponent = Math.min(10, b.unpatched_count * 5);
        const risk_score = Math.min(100, cvssComponent + severityComponent + unpatchedComponent);
        return {
          framework:       b.framework,
          advisory_count:  b.advisory_count,
          unpatched_count: b.unpatched_count,
          max_cvss:        b.max_cvss,
          risk_score,
          risk_level: risk_score >= 80 ? 'CRITICAL' : risk_score >= 60 ? 'HIGH' : risk_score >= 35 ? 'MEDIUM' : 'LOW',
        };
      })
      .sort((a, b) => b.risk_score - a.risk_score);

    const totalAdvisories = frameworks.reduce((s, f) => s + f.advisory_count, 0);
    const overallRisk = frameworks.length
      ? Math.round(frameworks.reduce((s, f) => s + f.risk_score, 0) / frameworks.length)
      : 0;

    return json({
      success: true,
      frameworks,
      total_advisories: totalAdvisories,
      overall_risk_score: overallRisk,
      overall_risk_level: overallRisk >= 80 ? 'CRITICAL' : overallRisk >= 60 ? 'HIGH' : overallRisk >= 35 ? 'MEDIUM' : 'LOW',
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return json({ success: false, error: 'Query failed', detail: e.message, frameworks: [] }, 500);
  }
}

// ── POST /api/admin/agent-threats/advisories ──────────────────────────────────
// Publish a new advisory. Admin-only (ADMIN_TOKEN bearer), fail-closed —
// the same auth pattern as /api/admin/bootstrap (defenseSeed.js).
export async function handleCreateAgentAdvisory(request, env) {
  // Fail-closed, constant-time admin check — same pattern as
  // isAdminAuthorized() in index.js (used by /api/admin/bootstrap).
  const configured = (env.ADMIN_TOKEN || '').trim();
  if (!configured) return json({ success: false, error: 'Admin token not configured' }, 503);
  const auth = request.headers.get('Authorization') || '';
  const presented = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  let authorized = presented.length > 0 && presented.length === configured.length;
  if (authorized) {
    let diff = 0;
    for (let i = 0; i < configured.length; i++) diff |= configured.charCodeAt(i) ^ presented.charCodeAt(i);
    authorized = diff === 0;
  }
  if (!authorized) return json({ success: false, error: 'Unauthorized' }, 401);

  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  let body;
  try { body = await request.json(); }
  catch { return json({ success: false, error: 'Invalid JSON body' }, 400); }

  const {
    advisory_id, title, description, framework, affected_versions, affected_products,
    severity, cvss_score, owasp_llm_id, cwe_id, mitre_atlas_id, tags = [],
    patch_status = 'no_patch', patch_version, published_at, full_advisory_url,
  } = body;

  if (!advisory_id || !title || !description || !framework || !severity || !published_at) {
    return json({ success: false, error: 'advisory_id, title, description, framework, severity, published_at are required' }, 400);
  }
  if (!FRAMEWORKS.includes(framework)) {
    return json({ success: false, error: `framework must be one of: ${FRAMEWORKS.join(', ')}` }, 400);
  }
  if (!SEVERITIES.includes(severity)) {
    return json({ success: false, error: `severity must be one of: ${SEVERITIES.join(', ')}` }, 400);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO agent_threat_advisories
        (advisory_id, title, description, framework, affected_versions, affected_products,
         severity, cvss_score, owasp_llm_id, cwe_id, mitre_atlas_id, tags,
         patch_status, patch_version, published_at, full_advisory_url, is_new)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
    ).bind(
      advisory_id, title, description, framework, affected_versions || null, affected_products || null,
      severity, cvss_score || null, owasp_llm_id || null, cwe_id || null, mitre_atlas_id || null,
      JSON.stringify(Array.isArray(tags) ? tags : []),
      patch_status, patch_version || null, published_at, full_advisory_url || null,
    ).run();

    return json({ success: true, advisory_id, message: 'Advisory published' }, 201);
  } catch (e) {
    if (/UNIQUE/.test(e.message)) {
      return json({ success: false, error: `advisory_id ${advisory_id} already exists` }, 409);
    }
    return json({ success: false, error: 'Insert failed', detail: e.message }, 500);
  }
}
