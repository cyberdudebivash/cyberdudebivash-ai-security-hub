/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Incident Management (Phase 5)
 *
 * Public (no auth):
 *   GET  /api/incidents           — open + recent resolved incidents
 *   GET  /api/incidents/:id       — single incident with timeline
 *   GET  /api/maintenance         — scheduled maintenance windows
 *
 * Admin (owner-gated via isOwner()):
 *   POST   /api/admin/incidents         — create incident
 *   PATCH  /api/admin/incidents/:id     — update incident / advance status
 *   POST   /api/admin/incidents/:id/update — add timeline entry
 *   POST   /api/admin/maintenance       — schedule maintenance window
 *   PATCH  /api/admin/maintenance/:id  — update maintenance status
 */

import { isOwner } from '../../auth/middleware.js';
import { parseBody } from '../../middleware/validation.js';
import { sendAlert } from '../../lib/alertEngine.js';

const VALID_SEVERITY = new Set(['critical', 'major', 'minor', 'maintenance']);
const VALID_STATUS   = new Set(['open', 'investigating', 'identified', 'monitoring', 'resolved']);
const VALID_MAINT    = new Set(['scheduled', 'in_progress', 'completed', 'cancelled']);

// ─── Public: GET /api/incidents ──────────────────────────────────────────────
export async function handlePublicIncidents(request, env) {
  if (!env.DB) return Response.json({ incidents: [], maintenance: [] });
  try {
    const [active, recent, maintenance] = await Promise.all([
      env.DB.prepare(
        `SELECT id, title, severity, status, affected_services, customer_message, started_at, resolved_at, updated_at
         FROM incidents WHERE status != 'resolved' ORDER BY started_at DESC`
      ).all(),
      env.DB.prepare(
        `SELECT id, title, severity, status, affected_services, customer_message, started_at, resolved_at, updated_at
         FROM incidents WHERE status = 'resolved' AND resolved_at > datetime('now','-30 days')
         ORDER BY resolved_at DESC LIMIT 10`
      ).all(),
      env.DB.prepare(
        `SELECT id, title, description, affected_services, scheduled_start, scheduled_end, status
         FROM maintenance_windows WHERE scheduled_end > datetime('now','-7 days')
         ORDER BY scheduled_start DESC`
      ).all(),
    ]);

    return Response.json({
      active_incidents: (active.results || []).map(formatPublicIncident),
      recent_incidents: (recent.results || []).map(formatPublicIncident),
      maintenance_windows: (maintenance.results || []).map(m => ({
        ...m,
        affected_services: parseJSON(m.affected_services, []),
      })),
      as_of: new Date().toISOString(),
    });
  } catch (e) {
    return Response.json({ error: 'Unavailable', incidents: [] }, { status: 503 });
  }
}

// ─── Public: GET /api/incidents/:id ──────────────────────────────────────────
export async function handlePublicIncident(request, env, id) {
  if (!env.DB) return Response.json({ error: 'Unavailable' }, { status: 503 });
  try {
    const [incident, timeline] = await Promise.all([
      env.DB.prepare(
        `SELECT id, title, severity, status, affected_services, customer_message,
                root_cause, resolution, started_at, resolved_at, updated_at
         FROM incidents WHERE id = ?`
      ).bind(id).first(),
      env.DB.prepare(
        `SELECT status, message, created_at FROM incident_timeline
         WHERE incident_id = ? ORDER BY created_at ASC`
      ).bind(id).all(),
    ]);
    if (!incident) return Response.json({ error: 'Not found' }, { status: 404 });
    return Response.json({
      ...formatPublicIncident(incident),
      timeline: timeline.results || [],
    });
  } catch (_) {
    return Response.json({ error: 'Unavailable' }, { status: 503 });
  }
}

// ─── Public: GET /api/maintenance ────────────────────────────────────────────
export async function handlePublicMaintenance(request, env) {
  if (!env.DB) return Response.json({ windows: [] });
  try {
    const rows = await env.DB.prepare(
      `SELECT id, title, description, affected_services, scheduled_start, scheduled_end, status
       FROM maintenance_windows WHERE status IN ('scheduled','in_progress')
       ORDER BY scheduled_start ASC`
    ).all();
    return Response.json({
      windows: (rows.results || []).map(m => ({
        ...m,
        affected_services: parseJSON(m.affected_services, []),
      })),
    });
  } catch (_) {
    return Response.json({ windows: [] });
  }
}

// ─── Admin: POST /api/admin/incidents ────────────────────────────────────────
export async function handleAdminIncidentCreate(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });
  const body = await parseBody(request);

  const title    = (body?.title || '').trim();
  const severity = body?.severity || 'minor';
  const affected = body?.affected_services || [];
  const message  = (body?.customer_message || '').trim();
  const desc     = (body?.description || '').trim();

  if (!title) return Response.json({ error: 'title required' }, { status: 400 });
  if (!VALID_SEVERITY.has(severity)) return Response.json({ error: `severity must be one of: ${[...VALID_SEVERITY].join(', ')}` }, { status: 400 });

  const id = `inc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;

  try {
    await env.DB.prepare(`
      INSERT INTO incidents (id, title, description, severity, status, affected_services, customer_message, created_by, started_at, updated_at)
      VALUES (?, ?, ?, ?, 'investigating', ?, ?, ?, datetime('now'), datetime('now'))
    `).bind(id, title, desc || null, severity, JSON.stringify(affected), message || null, authCtx.email || 'owner').run();

    // Add initial timeline entry
    await addTimelineEntry(env.DB, id, 'investigating', message || `Incident created: ${title}`, authCtx.email || 'owner');

    // Alert (non-blocking)
    sendAlert(env, {
      type: `incident_created`,
      component: 'Incident Management',
      message: `[${severity.toUpperCase()}] ${title}`,
      severity: severity === 'critical' || severity === 'major' ? severity : 'minor',
      context: { id, affected_services: affected },
    }).catch(() => {});

    return Response.json({ success: true, id, status: 'investigating' }, { status: 201 });
  } catch (e) {
    return Response.json({ error: 'Failed to create incident', detail: e.message?.slice(0, 80) }, { status: 500 });
  }
}

// ─── Admin: PATCH /api/admin/incidents/:id ────────────────────────────────────
export async function handleAdminIncidentUpdate(request, env, authCtx, id) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });
  const body = await parseBody(request);

  const incident = await env.DB.prepare('SELECT * FROM incidents WHERE id = ?').bind(id).first().catch(() => null);
  if (!incident) return Response.json({ error: 'Not found' }, { status: 404 });

  const updates = {};
  if (body?.status && VALID_STATUS.has(body.status)) updates.status = body.status;
  if (body?.title)            updates.title = body.title.trim();
  if (body?.severity && VALID_SEVERITY.has(body.severity)) updates.severity = body.severity;
  if (body?.customer_message !== undefined) updates.customer_message = body.customer_message;
  if (body?.root_cause !== undefined)       updates.root_cause = body.root_cause;
  if (body?.resolution !== undefined)       updates.resolution = body.resolution;
  if (body?.affected_services)              updates.affected_services = JSON.stringify(body.affected_services);
  if (updates.status === 'resolved')        updates.resolved_at = new Date().toISOString().replace('T', ' ').slice(0, 19);

  if (Object.keys(updates).length === 0) return Response.json({ error: 'No valid fields to update' }, { status: 400 });
  updates.updated_at = new Date().toISOString().replace('T', ' ').slice(0, 19);

  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = [...Object.values(updates), id];

  try {
    await env.DB.prepare(`UPDATE incidents SET ${setClauses} WHERE id = ?`).bind(...values).run();
    if (body?.update_message) {
      await addTimelineEntry(env.DB, id, updates.status || incident.status, body.update_message, authCtx.email || 'owner');
    }
    return Response.json({ success: true, id, ...updates });
  } catch (e) {
    return Response.json({ error: 'Update failed', detail: e.message?.slice(0, 80) }, { status: 500 });
  }
}

// ─── Admin: POST /api/admin/incidents/:id/update ──────────────────────────────
export async function handleAdminIncidentTimelineAdd(request, env, authCtx, id) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });
  const body = await parseBody(request);
  const message = (body?.message || '').trim();
  const status  = body?.status || 'investigating';
  if (!message) return Response.json({ error: 'message required' }, { status: 400 });

  try {
    await addTimelineEntry(env.DB, id, status, message, authCtx.email || 'owner');
    return Response.json({ success: true });
  } catch (e) {
    return Response.json({ error: 'Failed', detail: e.message?.slice(0, 80) }, { status: 500 });
  }
}

// ─── Admin: POST /api/admin/maintenance ──────────────────────────────────────
export async function handleAdminMaintenanceCreate(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });
  const body = await parseBody(request);

  const title   = (body?.title || '').trim();
  const start   = body?.scheduled_start;
  const end     = body?.scheduled_end;
  const affected = body?.affected_services || [];

  if (!title || !start || !end) return Response.json({ error: 'title, scheduled_start, scheduled_end required' }, { status: 400 });

  const id = `mnt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;
  try {
    await env.DB.prepare(`
      INSERT INTO maintenance_windows (id, title, description, affected_services, scheduled_start, scheduled_end, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(id, title, body.description || null, JSON.stringify(affected), start, end, authCtx.email || 'owner').run();
    return Response.json({ success: true, id }, { status: 201 });
  } catch (e) {
    return Response.json({ error: 'Failed', detail: e.message?.slice(0, 80) }, { status: 500 });
  }
}

// ─── Admin: PATCH /api/admin/maintenance/:id ─────────────────────────────────
export async function handleAdminMaintenanceUpdate(request, env, authCtx, id) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });
  const body = await parseBody(request);
  const status = body?.status;
  if (!status || !VALID_MAINT.has(status)) return Response.json({ error: `status must be one of: ${[...VALID_MAINT].join(', ')}` }, { status: 400 });

  try {
    await env.DB.prepare('UPDATE maintenance_windows SET status = ? WHERE id = ?').bind(status, id).run();
    return Response.json({ success: true, id, status });
  } catch (e) {
    return Response.json({ error: 'Failed' }, { status: 500 });
  }
}

// ─── Private helpers ──────────────────────────────────────────────────────────
async function addTimelineEntry(db, incidentId, status, message, createdBy) {
  const id = `tl-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;
  await db.prepare(
    `INSERT INTO incident_timeline (id, incident_id, status, message, created_by) VALUES (?, ?, ?, ?, ?)`
  ).bind(id, incidentId, status, message.slice(0, 2000), createdBy).run();
}

function parseJSON(str, fallback) {
  try { return JSON.parse(str); } catch (_) { return fallback; }
}

function formatPublicIncident(inc) {
  return {
    id:               inc.id,
    title:            inc.title,
    severity:         inc.severity,
    status:           inc.status,
    affected_services: parseJSON(inc.affected_services, []),
    customer_message: inc.customer_message || null,
    root_cause:       inc.root_cause || null,
    resolution:       inc.resolution || null,
    started_at:       inc.started_at,
    resolved_at:      inc.resolved_at || null,
    updated_at:       inc.updated_at,
  };
}
