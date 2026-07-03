/**
 * CYBERDUDEBIVASH AI Security Hub — Attack Library Engine v1.0
 * Live, D1-backed replacement for the static "AI Attack Library" page and its
 * fabricated "87 Attack Techniques" / "Weekly Updated" hero stats, which
 * never matched the real 11-technique static dataset.
 *
 * Routes:
 *   GET  /api/attack-library/techniques       → list (filter/search/paginate)
 *   GET  /api/attack-library/overview         → real technique/category counts
 *   POST /api/admin/attack-library/techniques → publish a new technique (ADMIN_TOKEN)
 */

import { ensureAttackLibraryTable } from '../services/attackLibraryIngestion.js';

const CATEGORIES = ['prompt-injection', 'jailbreak', 'agent-takeover', 'rag-poisoning', 'data-exfil', 'model-abuse'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function rowToTechnique(row) {
  let tags = [];
  let defenses = null;
  try { tags = JSON.parse(row.tags || '[]'); } catch { tags = []; }
  if (row.defenses) {
    try { defenses = JSON.parse(row.defenses); } catch { defenses = null; }
  }
  return {
    technique_id:      row.technique_id,
    name:               row.name,
    category:           row.category,
    severity:           row.severity,
    icon:               row.icon,
    description:        row.description,
    full_description:   row.full_description || null,
    example_payload:     row.example_payload || null,
    defenses,
    tags,
    complexity:         row.complexity,
    impact:             row.impact,
    detectability:      row.detectability,
    mitre_atlas_id:     row.mitre_atlas_id,
    owasp_llm_id:       row.owasp_llm_id,
    cwe_id:             row.cwe_id,
    published_at:       row.published_at,
    updated_at:         row.updated_at,
    source:             row.source,
    has_full_detail:    !!(row.full_description && row.example_payload && row.defenses),
  };
}

// ── GET /api/attack-library/techniques ────────────────────────────────────────
export async function handleListAttackTechniques(request, env) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable', techniques: [] }, 503);

  const url      = new URL(request.url);
  const category = (url.searchParams.get('category') || 'all').toLowerCase();
  const search   = (url.searchParams.get('search') || '').trim().toLowerCase();
  const limit    = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
  const offset   = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

  const where = [];
  const binds = [];
  if (category !== 'all' && CATEGORIES.includes(category)) {
    where.push('category = ?');
    binds.push(category);
  }
  if (search) {
    where.push('(LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(tags) LIKE ?)');
    const term = `%${search}%`;
    binds.push(term, term, term);
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const [rows, countRow] = await Promise.all([
      env.DB.prepare(
        `SELECT * FROM attack_library_techniques ${whereSql} ORDER BY published_at DESC LIMIT ? OFFSET ?`
      ).bind(...binds, limit, offset).all(),
      env.DB.prepare(
        `SELECT COUNT(*) as total FROM attack_library_techniques ${whereSql}`
      ).bind(...binds).first(),
    ]);

    return json({
      success:      true,
      techniques:   (rows.results || []).map(rowToTechnique),
      total:        countRow?.total ?? 0,
      limit,
      offset,
      category,
      search,
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    return json({ success: false, error: 'Query failed', detail: e.message, techniques: [] }, 500);
  }
}

// ── GET /api/attack-library/overview ──────────────────────────────────────────
// Real counts — replaces the hardcoded "87 Attack Techniques" / "6 Attack
// Categories" / "Weekly" hero stats with figures computed from the table.
export async function handleAttackLibraryOverview(request, env) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const [totals, latest] = await Promise.all([
      env.DB.prepare(
        `SELECT COUNT(*) as total_techniques, COUNT(DISTINCT category) as total_categories FROM attack_library_techniques`
      ).first(),
      env.DB.prepare(
        `SELECT MAX(updated_at) as last_updated FROM attack_library_techniques`
      ).first(),
    ]);

    return json({
      success:            true,
      total_techniques:   totals?.total_techniques ?? 0,
      total_categories:   totals?.total_categories ?? 0,
      last_updated:        latest?.last_updated || null,
      framework_mapped:   'MITRE ATLAS',
      generated_at:        new Date().toISOString(),
    });
  } catch (e) {
    return json({ success: false, error: 'Query failed', detail: e.message }, 500);
  }
}

// ── POST /api/admin/attack-library/techniques ─────────────────────────────────
// Publish a new technique. Admin-only (ADMIN_TOKEN bearer), fail-closed — same
// constant-time pattern as isAdminAuthorized() in index.js.
export async function handleCreateAttackTechnique(request, env) {
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
  await ensureAttackLibraryTable(env.DB);

  let body;
  try { body = await request.json(); }
  catch { return json({ success: false, error: 'Invalid JSON body' }, 400); }

  const {
    technique_id, name, category, severity, icon = '🎯', description,
    full_description, example_payload, defenses, tags = [],
    complexity, impact, detectability, mitre_atlas_id, owasp_llm_id, cwe_id,
  } = body;

  if (!technique_id || !name || !category || !severity || !description) {
    return json({ success: false, error: 'technique_id, name, category, severity, description are required' }, 400);
  }
  if (!CATEGORIES.includes(category)) {
    return json({ success: false, error: `category must be one of: ${CATEGORIES.join(', ')}` }, 400);
  }
  if (!SEVERITIES.includes(severity)) {
    return json({ success: false, error: `severity must be one of: ${SEVERITIES.join(', ')}` }, 400);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO attack_library_techniques
        (technique_id, name, category, severity, icon, description, full_description, example_payload,
         defenses, tags, complexity, impact, detectability, mitre_atlas_id, owasp_llm_id, cwe_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      technique_id, name, category, severity, icon, description,
      full_description || null, example_payload || null,
      defenses ? JSON.stringify(defenses) : null,
      JSON.stringify(Array.isArray(tags) ? tags : []),
      complexity || null, impact || null, detectability || null,
      mitre_atlas_id || null, owasp_llm_id || null, cwe_id || null,
    ).run();

    return json({ success: true, technique_id, message: 'Technique published' }, 201);
  } catch (e) {
    if (/UNIQUE/.test(e.message)) {
      return json({ success: false, error: `technique_id ${technique_id} already exists` }, 409);
    }
    return json({ success: false, error: 'Insert failed', detail: e.message }, 500);
  }
}
