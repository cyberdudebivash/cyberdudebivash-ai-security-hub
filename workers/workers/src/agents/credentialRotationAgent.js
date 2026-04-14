/**
 * CREDENTIAL ROTATION AGENT
 * Triggers when: anomaly detected, suspicious login, account compromise signal
 * Executes: API key revocation, session token invalidation, forced re-auth
 */
import { executeRotateCredentials, createActionRecord, persistActionResult } from './actionExecutor.js';
import { decideAnomalyResponse } from './decisionEngine.js';

function now() { return new Date().toISOString(); }

export async function executeCredentialRotation(env, request, authCtx) {
  const body = await request.json().catch(() => ({}));
  const { user_id, reason = 'manual_trigger', anomaly_score = 100, force = false } = body;

  if (!user_id) return { error: 'user_id required', status: 400 };

  // Check if user exists
  const user = await env.DB.prepare(`SELECT id, email FROM users WHERE id=?`).bind(user_id).first().catch(() => null);
  if (!user && !force) return { error: `User ${user_id} not found`, status: 404 };

  const riskLevel = anomaly_score >= 80 ? 'CRITICAL' : anomaly_score >= 60 ? 'HIGH' : 'MEDIUM';

  const actionId = await createActionRecord(env, {
    agentType:       'credential_rotation',
    actionType:      'rotate_credentials',
    target:          user_id,
    targetType:      'user_id',
    triggerSource:   reason === 'manual_trigger' ? 'manual' : 'anomaly_detected',
    triggerId:       user_id,
    riskLevel,
    decisionScore:   anomaly_score,
    rollbackAvailable: false,
    userId:          authCtx?.userId || null,
  });

  const result = await executeRotateCredentials(env, actionId, user_id, reason);
  await persistActionResult(env, actionId, result, 'credential_rotation', 'manual', user_id, {
    requested_by: authCtx?.userId || 'system',
    anomaly_score,
  });

  return {
    success: result.execution_status === 'SUCCESS',
    action_id:        actionId,
    action_type:      'rotate_credentials',
    target:           user_id,
    risk_level:       riskLevel,
    execution_status: result.execution_status,
    timestamp:        result.timestamp,
    rollback_available: false,
    detail:           result.detail,
    keys_rotated:     result.keys_rotated,
    sessions_killed:  result.sessions_killed,
  };
}

/**
 * Automatically rotate credentials when anomaly score breaches threshold
 * Called by anomaly engine after detecting critical anomaly
 */
export async function autoRotateOnAnomaly(env, userId, anomalyData) {
  const { anomaly_score, anomaly_types = [] } = anomalyData;
  if (anomaly_score < 80) return null; // Only auto-rotate on critical anomalies

  const reason = `anomaly_auto_rotate: score=${anomaly_score}, types=${anomaly_types.join(',')}`;
  const riskLevel = anomaly_score >= 90 ? 'CRITICAL' : 'HIGH';

  const actionId = await createActionRecord(env, {
    agentType:       'credential_rotation',
    actionType:      'rotate_credentials',
    target:          userId,
    targetType:      'user_id',
    triggerSource:   'anomaly_detected',
    triggerId:       userId,
    riskLevel,
    decisionScore:   anomaly_score,
    rollbackAvailable: false,
    userId,
  });

  const result = await executeRotateCredentials(env, actionId, userId, reason);
  await persistActionResult(env, actionId, result, 'credential_rotation', 'anomaly_detected', userId);

  return { actionId, ...result };
}
