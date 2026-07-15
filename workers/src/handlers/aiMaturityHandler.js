/**
 * CYBERDUDEBIVASH AI Security Hub — AI Security Maturity Assessment: Backend Orchestration
 *
 * ESSP Wave 1, PR 1. Persists a run of the existing AI Security Scorecard engine
 * (aiSecurityScorecardHandler.js's generateScorecard) under an org, with org-scoped
 * RBAC and history. framework_scores ships empty until the NIST AI RMF / ISO27001 /
 * GDPR / DevSecOps engines are wired in follow-up PRs — see
 * workers/schema_v50_ai_maturity_assessments.sql for the persisted shape.
 *
 * Routes: POST /api/ai-maturity/assess, GET /api/ai-maturity/assessments/:id,
 *         GET /api/ai-maturity/assessments
 */

import { isRealUser } from '../auth/middleware.js';
import { generateScorecard } from './aiSecurityScorecardHandler.js';
import { writeOrgAuditLog } from './orgManagement.js';
import { ok, notFound, forbidden, unauthorized, badRequest, paginated } from '../lib/response.js';

const ANALYST_PLUS = ['OWNER', 'ADMIN', 'ANALYST'];

// Interim, platform-derived maturity band from the scorecard's 0-100 composite score.
// Not attributed to NIST/ISO/any framework — those engines aren't wired in yet (Wave 1).
function deriveMaturityLevel(score) {
  if (score >= 90) return 'OPTIMIZING';
  if (score >= 75) return 'MANAGED';
  if (score >= 50) return 'DEFINED';
  if (score >= 25) return 'INITIAL';
  return 'INCOMPLETE';
}

async function getOrgMembership(env, orgId, userId) {
  return env.DB.prepare(
    `SELECT role FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).bind(orgId, userId).first();
}

// ─── Run assessment ────────────────────────────────────────────────────────────
export async function handleRunAiMaturityAssessment(request, env, authCtx) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  let body;
  try { body = await request.json(); } catch {
    return badRequest(request, 'Invalid JSON body');
  }

  const orgId = body.org_id;
  const targetScope = body.target_scope;
  if (!orgId || typeof orgId !== 'string') {
    return badRequest(request, 'org_id is required');
  }
  if (!targetScope || typeof targetScope !== 'string' || targetScope.length > 255) {
    return badRequest(request, 'target_scope is required (e.g. a domain name)');
  }

  const membership = await getOrgMembership(env, orgId, authCtx.userId);
  if (!membership) return forbidden(request, 'Not a member of this organization');
  if (!ANALYST_PLUS.includes(membership.role)) {
    return forbidden(request, 'ANALYST role or higher required to run an assessment');
  }

  const scorecard = await generateScorecard(targetScope, env);
  const maturityLevel = deriveMaturityLevel(scorecard.score);
  const id = crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO ai_maturity_assessments
        (id, org_id, requested_by, target_scope, composite_score, maturity_level, scorecard_json, framework_scores_json, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, '{}', 'completed')
    `).bind(id, orgId, authCtx.userId, targetScope, scorecard.score, maturityLevel, JSON.stringify(scorecard)),
    env.DB.prepare(`
      INSERT INTO ai_maturity_score_history (id, org_id, assessment_id, composite_score, maturity_level)
      VALUES (?, ?, ?, ?, ?)
    `).bind(crypto.randomUUID(), orgId, id, scorecard.score, maturityLevel),
  ]);

  await writeOrgAuditLog(env, request, {
    userId: authCtx.userId,
    orgId,
    action: 'ai_maturity_assessment_run',
    metadata: { assessment_id: id, target_scope: targetScope, composite_score: scorecard.score },
  });

  return ok(request, {
    id,
    org_id: orgId,
    target_scope: targetScope,
    composite_score: scorecard.score,
    maturity_level: maturityLevel,
    scorecard,
    framework_scores: {},
  }, 201);
}

// ─── Get one assessment ──────────────────────────────────────────────────────
export async function handleGetAiMaturityAssessment(request, env, authCtx, id) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  const row = await env.DB.prepare(
    `SELECT * FROM ai_maturity_assessments WHERE id = ?`
  ).bind(id).first();
  if (!row) return notFound(request, 'Assessment');

  const membership = await getOrgMembership(env, row.org_id, authCtx.userId);
  if (!membership) return notFound(request, 'Assessment'); // don't leak cross-org existence

  return ok(request, {
    id: row.id,
    org_id: row.org_id,
    requested_by: row.requested_by,
    target_scope: row.target_scope,
    composite_score: row.composite_score,
    maturity_level: row.maturity_level,
    scorecard: JSON.parse(row.scorecard_json || '{}'),
    framework_scores: JSON.parse(row.framework_scores_json || '{}'),
    status: row.status,
    created_at: row.created_at,
  });
}

// ─── List assessments for an org ──────────────────────────────────────────────
export async function handleListAiMaturityAssessments(request, env, authCtx) {
  if (!isRealUser(authCtx)) return unauthorized(request);

  const url = new URL(request.url);
  const orgId = url.searchParams.get('org_id');
  if (!orgId) return badRequest(request, 'org_id query parameter is required');

  const membership = await getOrgMembership(env, orgId, authCtx.userId);
  if (!membership) return forbidden(request, 'Not a member of this organization');

  const page   = Math.max(1, parseInt(url.searchParams.get('page'), 10) || 1);
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 20));
  const offset = (page - 1) * limit;

  const [{ results }, countRow] = await Promise.all([
    env.DB.prepare(`
      SELECT id, org_id, requested_by, target_scope, composite_score, maturity_level, status, created_at
      FROM ai_maturity_assessments
      WHERE org_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(orgId, limit, offset).all(),
    env.DB.prepare(`SELECT COUNT(*) as n FROM ai_maturity_assessments WHERE org_id = ?`).bind(orgId).first(),
  ]);

  return paginated(request, results, countRow?.n || 0, page, limit);
}
