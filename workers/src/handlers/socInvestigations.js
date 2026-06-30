/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * SOC Investigation Depth Layer — /api/soc/inv/*
 *
 * Extends socCases.js (NEVER modifies it).
 * Adds: evidence vault, analyst notes, investigation timeline, escalation.
 *
 * Tables: soc_evidence, soc_notes, soc_timeline (schema_phase4.sql)
 */

function genId(prefix = 'inv') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function requireAuth(authCtx) { return authCtx?.authenticated === true; }

async function logTimeline(env, caseId, orgId, eventType, description, actor, oldVal, newVal, meta) {
  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO soc_timeline (id, case_id, org_id, event_type, description, actor, old_value, new_value, metadata_json, occurred_at)
       VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))`
    ).bind(genId('tl'), caseId, orgId, eventType, description, actor || null, oldVal || null, newVal || null, meta ? JSON.stringify(meta) : null).run();
  } catch (_) {}
}

// ─── GET /api/soc/inv/:caseId/timeline ───────────────────────────────────────
export async function handleGetTimeline(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  try {
    // Verify the case exists and belongs to this org (or user is admin)
    const caseRow = await env.SECURITY_HUB_DB.prepare(
      `SELECT id FROM soc_cases WHERE id = ? AND (org_id = ? OR ? = 'admin')`
    ).bind(caseId, orgId, authCtx.role || '').first();
    if (!caseRow) return Response.json({ error: 'Case not found' }, { status: 404 });

    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, event_type, description, actor, old_value, new_value, metadata_json, occurred_at
       FROM soc_timeline WHERE case_id = ? ORDER BY occurred_at ASC`
    ).bind(caseId).all();

    return Response.json({ timeline: rows.results || [], case_id: caseId });
  } catch (e) {
    return Response.json({ error: e.message, timeline: [] }, { status: 500 });
  }
}

// ─── GET /api/soc/inv/:caseId/evidence ───────────────────────────────────────
export async function handleListEvidence(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, evidence_type, title, description, file_hash, file_size_bytes,
              source_system, added_by, created_at
       FROM soc_evidence WHERE case_id = ? AND org_id = ?
       ORDER BY created_at DESC`
    ).bind(caseId, orgId).all();

    return Response.json({ evidence: rows.results || [], case_id: caseId });
  } catch (e) {
    return Response.json({ error: e.message, evidence: [] }, { status: 500 });
  }
}

// ─── POST /api/soc/inv/:caseId/evidence ──────────────────────────────────────
export async function handleAddEvidence(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { title, evidence_type = 'ARTIFACT', description, data_json, file_hash, file_size_bytes, source_system } = body;
  if (!title?.trim()) return Response.json({ error: 'title required' }, { status: 400 });

  const VALID_TYPES = ['FILE','LOG','SCREENSHOT','NETWORK_CAPTURE','MEMORY_DUMP','IOC','NOTE','ARTIFACT','PCAP','REGISTRY'];
  if (!VALID_TYPES.includes(evidence_type)) {
    return Response.json({ error: `evidence_type must be one of: ${VALID_TYPES.join(', ')}` }, { status: 400 });
  }

  const id = genId('ev');
  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO soc_evidence (id, case_id, org_id, evidence_type, title, description,
         data_json, file_hash, file_size_bytes, source_system, added_by, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`
    ).bind(
      id, caseId, orgId, evidence_type, title.trim(),
      description || null, data_json ? JSON.stringify(data_json) : null,
      file_hash || null, file_size_bytes || null,
      source_system || 'MANUAL', authCtx.userId || authCtx.email || 'unknown'
    ).run();

    await logTimeline(env, caseId, orgId, 'EVIDENCE_ADDED',
      `Evidence added: ${title} (${evidence_type})`,
      authCtx.userId || authCtx.email
    );

    return Response.json({ success: true, evidence_id: id });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/soc/inv/:caseId/notes ──────────────────────────────────────────
export async function handleListNotes(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, author, content, note_type, is_pinned, created_at, updated_at
       FROM soc_notes WHERE case_id = ? AND org_id = ?
       ORDER BY is_pinned DESC, created_at ASC`
    ).bind(caseId, orgId).all();

    return Response.json({ notes: rows.results || [], case_id: caseId });
  } catch (e) {
    return Response.json({ error: e.message, notes: [] }, { status: 500 });
  }
}

// ─── POST /api/soc/inv/:caseId/notes ─────────────────────────────────────────
export async function handleAddNote(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { content, note_type = 'ANALYST', is_pinned = false } = body;
  if (!content?.trim()) return Response.json({ error: 'content required' }, { status: 400 });

  const VALID_NOTE_TYPES = ['ANALYST','AUTOMATED','ESCALATION','RESOLUTION','INTEL_UPDATE','PLAYBOOK','CLOSURE'];
  if (!VALID_NOTE_TYPES.includes(note_type)) {
    return Response.json({ error: `note_type must be one of: ${VALID_NOTE_TYPES.join(', ')}` }, { status: 400 });
  }

  const id     = genId('note');
  const author = authCtx.userId || authCtx.email || 'unknown';

  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO soc_notes (id, case_id, org_id, author, content, note_type, is_pinned, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now'))`
    ).bind(id, caseId, orgId, author, content.trim(), note_type, is_pinned ? 1 : 0).run();

    await logTimeline(env, caseId, orgId, 'NOTE_ADDED',
      `${note_type} note added by ${author}`, author
    );

    return Response.json({ success: true, note_id: id });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── POST /api/soc/inv/:caseId/escalate ──────────────────────────────────────
export async function handleEscalateCase(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  let body;
  try { body = await request.json(); }
  catch { body = {}; }

  const { reason, assignee_id } = body;

  try {
    // Update soc_cases status to ESCALATED (extend, not replace)
    const updateResult = await env.SECURITY_HUB_DB.prepare(
      `UPDATE soc_cases SET status = 'ESCALATED', assignee_id = COALESCE(?, assignee_id), updated_at = datetime('now')
       WHERE id = ? AND (org_id = ? OR ? = 'admin')`
    ).bind(assignee_id || null, caseId, orgId, authCtx.role || '').run();

    if (updateResult.meta?.changes === 0) {
      return Response.json({ error: 'Case not found or access denied' }, { status: 404 });
    }

    // Add escalation note
    const noteId = genId('note');
    const actor  = authCtx.userId || authCtx.email || 'unknown';
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO soc_notes (id, case_id, org_id, author, content, note_type, created_at, updated_at)
       VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'))`
    ).bind(noteId, caseId, orgId, actor,
      reason ? `Escalation: ${reason}` : 'Case escalated for priority handling',
      'ESCALATION'
    ).run();

    await logTimeline(env, caseId, orgId, 'ESCALATED',
      `Case escalated${reason ? ': ' + reason : ''}`,
      actor, 'INVESTIGATING', 'ESCALATED'
    );

    return Response.json({ success: true, case_id: caseId, status: 'ESCALATED' });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/soc/inv/:caseId/summary ────────────────────────────────────────
// Full investigation summary: case + timeline + evidence count + notes count
export async function handleInvestigationSummary(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  try {
    const [caseRow, evidenceCount, notesCount, timeline] = await Promise.all([
      env.SECURITY_HUB_DB.prepare(
        `SELECT id, case_number, title, severity, status, assignee_id, source,
                mitre_tactics, sla_due_at, created_at, updated_at
         FROM soc_cases WHERE id = ? AND (org_id = ? OR ? = 'admin')`
      ).bind(caseId, orgId, authCtx.role || '').first(),
      env.SECURITY_HUB_DB.prepare('SELECT COUNT(*) cnt FROM soc_evidence WHERE case_id = ?').bind(caseId).first(),
      env.SECURITY_HUB_DB.prepare('SELECT COUNT(*) cnt FROM soc_notes WHERE case_id = ?').bind(caseId).first(),
      env.SECURITY_HUB_DB.prepare(
        `SELECT event_type, description, actor, occurred_at
         FROM soc_timeline WHERE case_id = ? ORDER BY occurred_at ASC`
      ).bind(caseId).all(),
    ]);

    if (!caseRow) return Response.json({ error: 'Case not found' }, { status: 404 });

    // SLA status
    const slaRemaining = caseRow.sla_due_at
      ? Math.round((new Date(caseRow.sla_due_at) - new Date()) / 3600000)
      : null;

    return Response.json({
      case: caseRow,
      investigation: {
        evidence_count: evidenceCount?.cnt || 0,
        notes_count:    notesCount?.cnt || 0,
        timeline_events: timeline.results?.length || 0,
        sla_hours_remaining: slaRemaining,
        sla_breached: slaRemaining !== null && slaRemaining < 0,
        timeline:     timeline.results || [],
      },
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── POST /api/soc/inv/:caseId/resolve ───────────────────────────────────────
export async function handleResolveCase(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const caseId = new URL(request.url).pathname.split('/')[4];
  const orgId  = authCtx.org_id || `user:${authCtx.user_id || authCtx.userId || 'anon'}`;

  let body;
  try { body = await request.json(); }
  catch { body = {}; }

  const { resolution, close_after = false } = body;
  const newStatus = close_after ? 'CLOSED' : 'RESOLVED';
  const actor     = authCtx.userId || authCtx.email || 'unknown';

  try {
    const r = await env.SECURITY_HUB_DB.prepare(
      `UPDATE soc_cases SET status = ?, updated_at = datetime('now')
       WHERE id = ? AND (org_id = ? OR ? = 'admin')`
    ).bind(newStatus, caseId, orgId, authCtx.role || '').run();

    if (r.meta?.changes === 0) return Response.json({ error: 'Case not found' }, { status: 404 });

    if (resolution) {
      const noteId = genId('note');
      await env.SECURITY_HUB_DB.prepare(
        `INSERT INTO soc_notes (id, case_id, org_id, author, content, note_type, created_at, updated_at)
         VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'))`
      ).bind(noteId, caseId, orgId, actor, `Resolution: ${resolution}`, 'RESOLUTION').run();
    }

    await logTimeline(env, caseId, orgId, newStatus,
      `Case ${newStatus.toLowerCase()}${resolution ? ': ' + resolution : ''}`,
      actor, undefined, newStatus
    );

    return Response.json({ success: true, case_id: caseId, status: newStatus });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
