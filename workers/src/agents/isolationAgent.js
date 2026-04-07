/**
 * ISOLATION AGENT — Blocks IPs and disables sessions
 * Real enforcement: writes to ip_blocklist + session_blacklist + KV cache
 * Middleware reads KV on every request for sub-ms enforcement
 */
import { executeBlockIP, executeDisableSession, executeRateLimitIP, createActionRecord, persistActionResult } from './actionExecutor.js';

function now() { return new Date().toISOString(); }

export async function executeIsolation(env, request, authCtx) {
  const body = await request.json().catch(() => ({}));
  const {
    action_type = 'block_ip', // 'block_ip' | 'disable_session' | 'rate_limit_ip'
    target,
    reason = 'manual_isolation',
    risk_level = 'HIGH',
    decision_score = 75,
    expiry_hours = 24,
  } = body;

  if (!target) return { error: 'target required', status: 400 };
  if (!['block_ip','disable_session','rate_limit_ip'].includes(action_type)) {
    return { error: 'invalid action_type', status: 400 };
  }

  const targetType = action_type === 'disable_session' ? 'user_id' : 'ip';

  const actionId = await createActionRecord(env, {
    agentType:       'isolation',
    actionType:      action_type,
    target,
    targetType,
    triggerSource:   'manual',
    triggerId:       null,
    riskLevel:       risk_level,
    decisionScore:   decision_score,
    rollbackAvailable: true,
    userId:          authCtx?.userId || null,
  });

  let result;
  if (action_type === 'block_ip') {
    result = await executeBlockIP(env, actionId, target, reason, risk_level, expiry_hours);
  } else if (action_type === 'disable_session') {
    result = await executeDisableSession(env, actionId, target, reason);
  } else {
    result = await executeRateLimitIP(env, actionId, target, 10);
  }

  await persistActionResult(env, actionId, result, 'isolation', 'manual', target, {
    requested_by: authCtx?.userId || 'system',
    expiry_hours,
  });

  return {
    success:          result.execution_status === 'SUCCESS',
    action_id:        actionId,
    action_type,
    target,
    risk_level,
    execution_status: result.execution_status,
    timestamp:        result.timestamp,
    rollback_available: result.rollback_available,
    rollback_action:  result.rollback_action,
    detail:           result.detail,
    expires_at:       result.expires_at,
  };
}

/**
 * Auto-block IP after detecting malicious behavior
 */
export async function autoBlockIP(env, ip, reason, riskLevel, triggerId) {
  const expiry = riskLevel === 'CRITICAL' ? 72 : riskLevel === 'HIGH' ? 24 : 6;

  const actionId = await createActionRecord(env, {
    agentType:       'isolation',
    actionType:      'block_ip',
    target:          ip,
    targetType:      'ip',
    triggerSource:   'anomaly_detected',
    triggerId,
    riskLevel,
    decisionScore:   riskLevel === 'CRITICAL' ? 90 : riskLevel === 'HIGH' ? 75 : 50,
    rollbackAvailable: true,
  });

  const result = await executeBlockIP(env, actionId, ip, reason, riskLevel, expiry);
  await persistActionResult(env, actionId, result, 'isolation', 'anomaly_detected', triggerId);

  return { actionId, ...result };
}

/**
 * Check if an IP is currently blocked (fast KV lookup with D1 fallback)
 */
export async function isIPBlocked(env, ip) {
  // KV first (microsecond)
  if (env.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(`blocklist:ip:${ip}`, 'json').catch(() => null);
    if (cached) return { blocked: true, ...cached };
  }
  // D1 fallback
  const row = await env.DB.prepare(
    `SELECT ip, reason, risk_level, expires_at FROM ip_blocklist WHERE ip=? AND is_active=1 AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1`
  ).bind(ip).first().catch(() => null);

  return row ? { blocked: true, reason: row.reason, riskLevel: row.risk_level, expiresAt: row.expires_at } : { blocked: false };
}

/**
 * Check if a user session is disabled
 */
export async function isSessionDisabled(env, userId) {
  if (env.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(`session_disabled:${userId}`, 'json').catch(() => null);
    if (cached) return { disabled: true, ...cached };
  }
  const row = await env.DB.prepare(
    `SELECT user_id, reason, expires_at FROM session_blacklist WHERE user_id=? AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1`
  ).bind(userId).first().catch(() => null);
  return row ? { disabled: true, reason: row.reason } : { disabled: false };
}
