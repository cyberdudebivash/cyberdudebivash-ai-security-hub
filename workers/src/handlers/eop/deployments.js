/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Deployment Intelligence (Phase 9)
 *
 * POST /api/admin/deployments        — record a deployment (CI/CD webhook, owner-gated)
 * GET  /api/admin/deployments        — list deployments (owner-gated)
 * GET  /api/deployments/latest       — latest deployment info (public, non-sensitive)
 *
 * CI/CD usage — add to deploy.yml after wrangler deploy:
 *   curl -X POST https://<worker>/api/admin/deployments \
 *     -H "Authorization: Bearer $ADMIN_TOKEN" \
 *     -H "Content-Type: application/json" \
 *     -d '{"version":"40.0.0","commit_sha":"$GITHUB_SHA","commit_message":"$CM","status":"success","duration_ms":$DUR,"test_count":730}'
 */

import { isOwner } from '../../auth/middleware.js';
import { parseBody } from '../../middleware/validation.js';

const VALID_STATUS = new Set(['deploying', 'success', 'failed', 'rolled_back']);

// ─── POST /api/admin/deployments ─────────────────────────────────────────────
export async function handleDeploymentRecord(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });

  const body = await parseBody(request);
  const version = (body?.version || env.VERSION || 'unknown').trim();
  const status  = body?.status || 'success';

  if (!VALID_STATUS.has(status)) {
    return Response.json({ error: `status must be one of: ${[...VALID_STATUS].join(', ')}` }, { status: 400 });
  }

  const id = `dep-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;

  try {
    await env.DB.prepare(`
      INSERT INTO deployments (id, version, commit_sha, commit_message, deployed_by, status, duration_ms, test_count, deployed_at, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
    `).bind(
      id,
      version,
      (body?.commit_sha || env.COMMIT || 'unknown').slice(0, 40),
      (body?.commit_message || '').slice(0, 200) || null,
      authCtx.email || 'ci',
      status,
      body?.duration_ms ? Number(body.duration_ms) : null,
      body?.test_count  ? Number(body.test_count)  : null,
      (body?.notes || '').slice(0, 500) || null,
    ).run();

    return Response.json({ success: true, id, version, status }, { status: 201 });
  } catch (e) {
    return Response.json({ error: 'Failed to record deployment', detail: e.message?.slice(0, 80) }, { status: 500 });
  }
}

// ─── GET /api/admin/deployments ──────────────────────────────────────────────
export async function handleDeploymentsList(request, env, authCtx) {
  if (!isOwner(authCtx, env)) return Response.json({ error: 'Owner required' }, { status: 403 });

  const url   = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get('limit') || 20), 100);

  try {
    const rows = await env.DB.prepare(
      `SELECT id, version, commit_sha, commit_message, deployed_by, status, duration_ms, test_count, deployed_at, notes
       FROM deployments ORDER BY deployed_at DESC LIMIT ?`
    ).bind(limit).all();

    return Response.json({ deployments: rows.results || [], total: rows.results?.length || 0 });
  } catch (_) {
    return Response.json({ deployments: [] });
  }
}

// ─── GET /api/deployments/latest ─────────────────────────────────────────────
export async function handleLatestDeployment(request, env) {
  try {
    // Combine DB record (if available) with wrangler.toml vars
    const row = env.DB
      ? await env.DB.prepare(
          `SELECT version, commit_sha, deployed_at, status, test_count FROM deployments ORDER BY deployed_at DESC LIMIT 1`
        ).first().catch(() => null)
      : null;

    return Response.json({
      version:     row?.version || env.VERSION || 'unknown',
      commit_sha:  row?.commit_sha || env.COMMIT || 'unknown',
      deployed_at: row?.deployed_at || null,
      status:      row?.status || 'unknown',
      test_count:  row?.test_count || null,
      environment: env.ENVIRONMENT || 'production',
    });
  } catch (_) {
    return Response.json({
      version:    env.VERSION || 'unknown',
      commit_sha: env.COMMIT  || 'unknown',
      environment: env.ENVIRONMENT || 'production',
    });
  }
}
