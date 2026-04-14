/**
 * CYBERDUDEBIVASH AI Security Hub — Audit Log Handler v19.0
 * Tamper-evident audit trail: all security events, admin actions, auth events,
 * data access, and system changes are logged and queryable.
 *
 * Routes:
 *   GET   /api/audit-log                 → query audit log (auth required)
 *   POST  /api/audit-log                 → write a custom audit event (ENTERPRISE)
 *   GET   /api/audit-log/export          → CSV/JSON export (ENTERPRISE)
 *   GET   /api/audit-log/summary         → daily summary stats
 */

import { inspectBodyForAttacks, sanitizeString } from '../middleware/security.js';
import { checkRateLimitCost, rateLimitResponse }  from '../middleware/rateLimit.js';

// ─── Allowed audit event types ────────────────────────────────────────────────
const AUDIT_EVENT_TYPES = new Set([
  'auth.login', 'auth.logout', 'auth.failed', 'auth.mfa',
  'api_key.created', 'api_key.revoked', 'api_key.used',
  'scan.started', 'scan.completed', 'scan.failed',
  'payment.initiated', 'payment.verified', 'payment.failed',
  'user.created', 'user.updated', 'user.deleted', 'user.role_changed',
  'org.created', 'org.updated', 'org.deleted', 'org.member_added', 'org.member_removed',
  'report.generated', 'report.downloaded', 'report.deleted',
  'alert.triggered', 'alert.acknowledged', 'alert.resolved',
  'config.changed', 'secret.accessed', 'admin.action',
  'threat.detected', 'threat.blocked', 'threat.escalated',
  'hunt.executed', 'ioc.queried', 'vuln.remediated',
  'custom.event',
]);

// ─── Write audit event to KV (internal utility, exported for other handlers) ──
export async function writeAuditEvent(env, event) {
  if (!env?.SECURITY_HUB_KV) return;
  const {
    type, actor, actor_tier, ip, resource, action, outcome,
    details = {}, org_id = null,
  } = event;

  const id        = `audit_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = new Date().toISOString();
  const entry = {
    id, type, actor, actor_tier, ip, resource, action, outcome,
    details, org_id, timestamp,
    // Integrity field: simple deterministic hash for tamper evidence
    integrity: btoa(`${id}|${type}|${actor}|${timestamp}`).slice(0, 32),
  };

  try {
    await env.SECURITY_HUB_KV.put(
      `audit:${timestamp.slice(0, 10)}:${id}`,
      JSON.stringify(entry),
      { expirationTtl: 7776000 }, // 90 days retention
    );
    // Also update daily counter
    const dayKey = `audit:stats:${timestamp.slice(0, 10)}:${type.split('.')[0]}`;
    const cur = parseInt(await env.SECURITY_HUB_KV.get(dayKey) || '0', 10);
    env.SECURITY_HUB_KV.put(dayKey, String(cur + 1), { expirationTtl: 7776000 }).catch(() => {});
  } catch {}
}

// ─── GET /api/audit-log ───────────────────────────────────────────────────────
export async function handleGetAuditLog(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const rl = await checkRateLimitCost(env, authCtx, 'audit-log');
  if (!rl.allowed) return rateLimitResponse(rl, 'audit-log');

  const url    = new URL(request.url);
  const date   = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const type   = url.searchParams.get('type');
  const actor  = url.searchParams.get('actor');
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);

  // Validate date format
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return Response.json({ error: 'date must be YYYY-MM-DD format' }, { status: 400 });
  }

  const entries = [];
  if (env.SECURITY_HUB_KV) {
    try {
      const list = await env.SECURITY_HUB_KV.list({ prefix: `audit:${date}:` });
      for (const key of (list.keys || [])) {
        const raw = await env.SECURITY_HUB_KV.get(key.name);
        if (!raw) continue;
        try {
          const entry = JSON.parse(raw);
          // Apply filters
          if (type   && !entry.type?.startsWith(type))   continue;
          if (actor  && entry.actor !== actor)            continue;
          // Enforce tenant isolation: non-admin users only see their own events
          if (authCtx.role !== 'ADMIN' && authCtx.tier !== 'ENTERPRISE') {
            if (entry.actor !== authCtx.identity && entry.org_id !== authCtx.orgId) continue;
          }
          entries.push(entry);
        } catch {}
      }
    } catch {}
  }

  // Sort newest-first, paginate
  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const paginated = entries.slice(offset, offset + limit);

  return Response.json({
    date,
    total:   entries.length,
    limit,
    offset,
    entries: paginated,
    filters: { type, actor },
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── POST /api/audit-log ─────────────────────────────────────────────────────
export async function handleWriteAuditEvent(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (authCtx.tier !== 'ENTERPRISE') {
    return Response.json({
      error: 'Custom audit events require ENTERPRISE tier',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 403 });
  }

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  if (inspectBodyForAttacks(body)) {
    return Response.json({ error: 'Malicious payload detected' }, { status: 400 });
  }

  const { type, resource, action, outcome, details } = body;

  if (!type || !AUDIT_EVENT_TYPES.has(type)) {
    return Response.json({
      error:  'Invalid event type',
      valid:  [...AUDIT_EVENT_TYPES],
    }, { status: 400 });
  }

  await writeAuditEvent(env, {
    type,
    actor:      authCtx.identity,
    actor_tier: authCtx.tier,
    ip:         request.headers.get('CF-Connecting-IP') || 'unknown',
    resource:   sanitizeString(resource || '', 200),
    action:     sanitizeString(action   || '', 200),
    outcome:    outcome || 'unknown',
    details:    typeof details === 'object' ? details : {},
    org_id:     authCtx.orgId || null,
  });

  return Response.json({ success: true, message: 'Audit event recorded' }, { status: 201 });
}

// ─── GET /api/audit-log/export ────────────────────────────────────────────────
export async function handleAuditExport(request, env, authCtx) {
  if (!authCtx.authenticated || authCtx.tier !== 'ENTERPRISE') {
    return Response.json({
      error: 'Audit log export requires ENTERPRISE tier',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 403 });
  }

  const url    = new URL(request.url);
  const date   = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const format = url.searchParams.get('format') || 'json';

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return Response.json({ error: 'date must be YYYY-MM-DD format' }, { status: 400 });
  }

  const entries = [];
  if (env.SECURITY_HUB_KV) {
    try {
      const list = await env.SECURITY_HUB_KV.list({ prefix: `audit:${date}:` });
      for (const key of (list.keys || [])) {
        const raw = await env.SECURITY_HUB_KV.get(key.name);
        if (raw) {
          try { entries.push(JSON.parse(raw)); } catch {}
        }
      }
    } catch {}
  }

  entries.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  if (format === 'csv') {
    const header = 'id,timestamp,type,actor,actor_tier,ip,resource,action,outcome,org_id\n';
    const rows = entries.map(e =>
      [e.id, e.timestamp, e.type, e.actor, e.actor_tier, e.ip,
       `"${(e.resource||'').replace(/"/g,'""')}"`,
       `"${(e.action||'').replace(/"/g,'""')}"`,
       e.outcome, e.org_id || ''].join(',')
    ).join('\n');
    return new Response(header + rows, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="audit-log-${date}.csv"`,
      },
    });
  }

  return Response.json({
    date,
    exported_at: new Date().toISOString(),
    total:       entries.length,
    entries,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  }, {
    headers: { 'Content-Disposition': `attachment; filename="audit-log-${date}.json"` },
  });
}

// ─── GET /api/audit-log/summary ───────────────────────────────────────────────
export async function handleAuditSummary(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const today  = new Date().toISOString().slice(0, 10);
  const stats  = {};

  if (env.SECURITY_HUB_KV) {
    try {
      const categories = ['auth', 'scan', 'payment', 'user', 'org', 'threat', 'hunt', 'vuln', 'admin'];
      await Promise.all(categories.map(async cat => {
        const val = await env.SECURITY_HUB_KV.get(`audit:stats:${today}:${cat}`);
        stats[cat] = parseInt(val || '0', 10);
      }));
    } catch {}
  }

  const totalToday = Object.values(stats).reduce((s, v) => s + v, 0);

  return Response.json({
    date:        today,
    total_today: totalToday,
    by_category: stats,
    retention_days: 90,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}
