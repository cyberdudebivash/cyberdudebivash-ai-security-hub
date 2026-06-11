/**
 * CYBERDUDEBIVASH® AI Security Hub
 * SOC Case Management — /api/soc/cases/*
 *
 * Full case lifecycle: create → triage → investigate → resolve → close
 * D1-backed (soc_cases + soc_case_comments tables from schema_phase2.sql)
 * Requires authenticated session (any plan)
 */

function genId(prefix = 'case') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function caseNumber() {
  const now = new Date();
  const yy  = String(now.getFullYear()).slice(2);
  const mm  = String(now.getMonth() + 1).padStart(2, '0');
  return `CDB-${yy}${mm}-${Math.floor(Math.random() * 9000 + 1000)}`;
}

function slaHours(severity) {
  return { CRITICAL: 4, HIGH: 24, MEDIUM: 72, LOW: 168, INFO: 720 }[severity] || 72;
}

// GET /api/soc/cases
export async function handleListCases(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const url      = new URL(request.url);
  const status   = url.searchParams.get('status');
  const severity = url.searchParams.get('severity');
  const limit    = Math.min(parseInt(url.searchParams.get('limit') || '25'), 100);
  const offset   = parseInt(url.searchParams.get('offset') || '0');

  let where  = [];
  let params = [];

  // Non-admin users only see their org's cases
  if (authCtx.role !== 'admin' && authCtx.role !== 'mssp_admin') {
    where.push('org_id = ?');
    params.push(authCtx.org_id || 'default');
  }
  if (status) { where.push('status = ?'); params.push(status.toUpperCase()); }
  if (severity) { where.push('severity = ?'); params.push(severity.toUpperCase()); }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, case_number, title, severity, status, assignee_id,
              mitre_tactics, created_at, updated_at, sla_due_at, source
       FROM soc_cases ${whereClause}
       ORDER BY
         CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
         created_at DESC
       LIMIT ? OFFSET ?`
    ).bind(...params, limit, offset).all();

    const countQ = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as total FROM soc_cases ${whereClause}`
    ).bind(...params).first();

    // Parse JSON arrays
    const cases = (rows?.results || []).map(c => ({
      ...c,
      mitre_tactics: safeJson(c.mitre_tactics, []),
    }));

    return Response.json({ success: true, cases, total: countQ?.total || 0, limit, offset });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/soc/cases/:id
export async function handleGetCase(request, env, authCtx, caseId) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  try {
    const c = await env.SECURITY_HUB_DB.prepare(
      `SELECT * FROM soc_cases WHERE id = ? OR case_number = ?`
    ).bind(caseId, caseId).first();

    if (!c) return Response.json({ error: 'Case not found' }, { status: 404 });

    // Org check for non-admins
    if (authCtx.role !== 'admin' && authCtx.role !== 'mssp_admin') {
      if (c.org_id !== (authCtx.org_id || 'default')) {
        return Response.json({ error: 'Access denied' }, { status: 403 });
      }
    }

    const comments = await env.SECURITY_HUB_DB.prepare(
      `SELECT * FROM soc_case_comments WHERE case_id = ? ORDER BY created_at ASC`
    ).bind(c.id).all();

    return Response.json({
      success: true,
      case: {
        ...c,
        alert_ids:    safeJson(c.alert_ids, []),
        ioc_list:     safeJson(c.ioc_list, []),
        mitre_tactics: safeJson(c.mitre_tactics, []),
      },
      comments:  comments?.results || [],
      timeline:  buildTimeline(c, comments?.results || []),
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// POST /api/soc/cases
export async function handleCreateCase(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { title, severity = 'MEDIUM', source = 'manual', summary, mitre_tactics, ioc_list, playbook_id } = body;
  if (!title) return Response.json({ error: 'title required' }, { status: 400 });

  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sev = severity.toUpperCase();
  if (!validSeverities.includes(sev)) {
    return Response.json({ error: `severity must be one of: ${validSeverities.join(', ')}` }, { status: 400 });
  }

  const id      = genId('case');
  const caseNum = caseNumber();
  const slaHrs  = slaHours(sev);
  const now     = new Date();
  const sla_due = new Date(now.getTime() + slaHrs * 3600 * 1000).toISOString();
  const org_id  = authCtx.org_id || 'default';

  try {
    await env.SECURITY_HUB_DB.prepare(`
      INSERT INTO soc_cases
        (id, case_number, title, severity, status, assignee_id, org_id, source,
         ioc_list, mitre_tactics, playbook_id, summary, sla_hours, sla_due_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, caseNum, title, sev,
      authCtx.user_id || null, org_id, source,
      JSON.stringify(ioc_list || []),
      JSON.stringify(mitre_tactics || []),
      playbook_id || null, summary || null,
      slaHrs, sla_due, now.toISOString(), now.toISOString(),
    ).run();

    // Auto-add system comment
    await addSystemComment(env.SECURITY_HUB_DB, id, `Case ${caseNum} created by ${authCtx.email || 'analyst'} via ${source}`);

    return Response.json({
      success: true,
      case: { id, case_number: caseNum, severity: sev, status: 'OPEN', sla_due_at: sla_due },
    }, { status: 201 });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// PATCH /api/soc/cases/:id
export async function handleUpdateCase(request, env, authCtx, caseId) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const allowed = ['status','severity','assignee_id','mitre_tactics','ioc_list','playbook_id','summary','resolution'];
  const updates = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));

  if (!Object.keys(updates).length) {
    return Response.json({ error: 'No valid fields' }, { status: 400 });
  }

  const now = new Date().toISOString();
  if (updates.status === 'RESOLVED' || updates.status === 'CLOSED') {
    updates.resolved_at = now;
  }
  if (updates.mitre_tactics) updates.mitre_tactics = JSON.stringify(updates.mitre_tactics);
  if (updates.ioc_list)      updates.ioc_list      = JSON.stringify(updates.ioc_list);

  updates.updated_at = now;
  const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = [...Object.values(updates), caseId, caseId];

  try {
    await env.SECURITY_HUB_DB.prepare(
      `UPDATE soc_cases SET ${fields} WHERE id = ? OR case_number = ?`
    ).bind(...values).run();

    // Add audit comment for status changes
    if (body.status) {
      await addSystemComment(env.SECURITY_HUB_DB, caseId,
        `Status changed to ${body.status} by ${authCtx.email || 'analyst'}`);
    }

    return Response.json({ success: true });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// POST /api/soc/cases/:id/comments
export async function handleAddCaseComment(request, env, authCtx, caseId) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { text, comment_type = 'note', visibility = 'internal' } = body;
  if (!text) return Response.json({ error: 'text required' }, { status: 400 });

  const id = genId('cmt');
  try {
    await env.SECURITY_HUB_DB.prepare(`
      INSERT INTO soc_case_comments
        (id, case_id, author_id, author_name, body, comment_type, visibility, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, caseId,
      authCtx.user_id || 'anon',
      authCtx.email || 'Analyst',
      text, comment_type, visibility,
      new Date().toISOString(),
    ).run();

    // Touch case updated_at
    await env.SECURITY_HUB_DB.prepare(
      `UPDATE soc_cases SET updated_at = ? WHERE id = ? OR case_number = ?`
    ).bind(new Date().toISOString(), caseId, caseId).run();

    return Response.json({ success: true, id }, { status: 201 });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/soc/cases/metrics
export async function handleCaseMetrics(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  try {
    const stats = await env.SECURITY_HUB_DB.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_count,
        SUM(CASE WHEN status = 'IN_PROGRESS' THEN 1 ELSE 0 END) as in_progress,
        SUM(CASE WHEN status = 'ESCALATED' THEN 1 ELSE 0 END) as escalated,
        SUM(CASE WHEN status IN ('RESOLVED','CLOSED') THEN 1 ELSE 0 END) as resolved,
        SUM(CASE WHEN severity = 'CRITICAL' AND status = 'OPEN' THEN 1 ELSE 0 END) as crit_open,
        SUM(CASE WHEN severity = 'HIGH' AND status = 'OPEN' THEN 1 ELSE 0 END) as high_open
      FROM soc_cases
    `).first();

    return Response.json({
      success:     true,
      total:       stats?.total        || 0,
      open:        stats?.open_count   || 0,
      in_progress: stats?.in_progress  || 0,
      escalated:   stats?.escalated    || 0,
      resolved:    stats?.resolved     || 0,
      critical_open: stats?.crit_open  || 0,
      high_open:   stats?.high_open    || 0,
      as_of: new Date().toISOString(),
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
async function addSystemComment(db, caseId, message) {
  try {
    await db.prepare(`
      INSERT INTO soc_case_comments (id, case_id, author_id, author_name, body, comment_type, created_at)
      VALUES (?, ?, 'system', 'System', ?, 'system', ?)
    `).bind(genId('cmt'), caseId, message, new Date().toISOString()).run();
  } catch (_) {}
}

function safeJson(str, fallback) {
  try { return JSON.parse(str); } catch (_) { return fallback; }
}

function buildTimeline(c, comments) {
  const events = [
    { ts: c.created_at,  type: 'created',  text: `Case ${c.case_number} opened`, severity: c.severity },
    ...comments.map(cm => ({
      ts:   cm.created_at,
      type: cm.comment_type || 'note',
      text: cm.body,
      author: cm.author_name,
    })),
  ];
  if (c.resolved_at) {
    events.push({ ts: c.resolved_at, type: 'resolved', text: `Case resolved: ${c.resolution || '—'}` });
  }
  return events.sort((a, b) => a.ts.localeCompare(b.ts));
}
