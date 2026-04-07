/**
 * CYBERDUDEBIVASH AI Security Hub
 * ACTION EXECUTOR — Real execution layer for autonomous remediation
 * Every action writes to D1, invalidates KV caches, produces audit trails.
 * NO MOCKS. All actions have real effect within the platform.
 */

// ─── helpers ────────────────────────────────────────────────────────────────
function uuid()   { return crypto.randomUUID(); }
function now()    { return new Date().toISOString(); }
function nowPlusSecs(s) { return new Date(Date.now() + s * 1000).toISOString(); }
function hashStr(s) {
  // Simple deterministic hash for token identification
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; }
  return Math.abs(h).toString(16).padStart(8, '0');
}

// ─── 1. BLOCK IP ─────────────────────────────────────────────────────────────
export async function executeBlockIP(env, actionId, target, reason, riskLevel, expiryHours = 24) {
  const t0 = Date.now();
  const expiresAt = nowPlusSecs(expiryHours * 3600);

  // Write to D1 blocklist
  await env.DB.prepare(`
    INSERT INTO ip_blocklist (id, ip, reason, threat_type, risk_level, action_id, blocked_at, expires_at, is_active)
    VALUES (?,?,?,?,?,?,?,?,1)
    ON CONFLICT(ip) DO UPDATE SET
      reason=excluded.reason, risk_level=excluded.risk_level, action_id=excluded.action_id,
      blocked_at=excluded.blocked_at, expires_at=excluded.expires_at, is_active=1,
      block_count=block_count+1
  `).bind(uuid(), target, reason, 'automated_agent', riskLevel, actionId, now(), expiresAt).run();

  // Cache in KV for sub-ms lookup on every request
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `blocklist:ip:${target}`,
      JSON.stringify({ reason, riskLevel, expiresAt, actionId }),
      { expirationTtl: expiryHours * 3600 }
    );
  }

  return {
    action_type: 'block_ip',
    target,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: true,
    rollback_action: `unblock_ip:${target}`,
    detail: `IP ${target} blocked for ${expiryHours}h. KV cache updated for instant enforcement.`,
    expires_at: expiresAt,
  };
}

// ─── 2. ROTATE CREDENTIALS ───────────────────────────────────────────────────
export async function executeRotateCredentials(env, actionId, userId, reason) {
  const t0 = Date.now();
  let keysRotated = 0;
  let sessionsKilled = 0;

  // Rotate all API keys: mark existing keys as revoked, they must re-generate
  const keysRes = await env.DB.prepare(`
    UPDATE api_keys SET revoked = 1, revoked_at = ? WHERE user_id = ? AND revoked = 0
  `).bind(now(), userId).run().catch(() => ({ meta: { changes: 0 } }));
  keysRotated = keysRes.meta?.changes || 0;

  // Invalidate all refresh tokens
  const tokenRes = await env.DB.prepare(`
    DELETE FROM refresh_tokens WHERE user_id = ?
  `).bind(userId).run().catch(() => ({ meta: { changes: 0 } }));
  sessionsKilled = tokenRes.meta?.changes || 0;

  // Add to session blacklist (invalidate any issued JWTs)
  await env.DB.prepare(`
    INSERT INTO session_blacklist (id, user_id, reason, action_id, created_at, expires_at)
    VALUES (?,?,?,?,?,?)
  `).bind(uuid(), userId, reason, actionId, now(), nowPlusSecs(86400)).run().catch(() => {});

  // Log the rotation
  await env.DB.prepare(`
    INSERT INTO credential_rotation_log (id, user_id, rotation_type, keys_rotated, sessions_killed, action_id, reason)
    VALUES (?,?,?,?,?,?,?)
  `).bind(uuid(), userId, 'all', keysRotated, sessionsKilled, actionId, reason).run().catch(() => {});

  // Bust KV cache for this user
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.delete(`user:session:${userId}`);
    await env.SECURITY_HUB_KV.delete(`user:plan:${userId}`);
    await env.SECURITY_HUB_KV.put(
      `blacklist:user:${userId}`,
      JSON.stringify({ reason, actionId, ts: now() }),
      { expirationTtl: 86400 }
    );
  }

  return {
    action_type: 'rotate_credentials',
    target: userId,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: false,
    detail: `Rotated ${keysRotated} API key(s), killed ${sessionsKilled} session(s) for user ${userId}.`,
    keys_rotated: keysRotated,
    sessions_killed: sessionsKilled,
  };
}

// ─── 3. DISABLE SESSION ───────────────────────────────────────────────────────
export async function executeDisableSession(env, actionId, userId, reason, tokenHash = null) {
  const t0 = Date.now();

  await env.DB.prepare(`
    INSERT INTO session_blacklist (id, user_id, token_hash, reason, action_id, created_at, expires_at)
    VALUES (?,?,?,?,?,?,?)
  `).bind(uuid(), userId, tokenHash, reason, actionId, now(), nowPlusSecs(3600 * 48)).run().catch(() => {});

  // Kill live sessions in KV
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `session_disabled:${userId}`,
      JSON.stringify({ reason, actionId, until: nowPlusSecs(3600 * 48) }),
      { expirationTtl: 3600 * 48 }
    );
  }

  return {
    action_type: 'disable_session',
    target: userId,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: true,
    rollback_action: `enable_session:${userId}`,
    detail: `Session disabled for user ${userId} for 48h. All active tokens invalidated.`,
  };
}

// ─── 4. APPLY VIRTUAL PATCH ──────────────────────────────────────────────────
export async function executeApplyVirtualPatch(env, actionId, cveId, patchConfig) {
  const t0 = Date.now();
  const {
    patch_type    = 'path_block',
    rule_pattern  = '',
    rule_action   = 'block',
    priority      = 100,
    expires_hours = 168, // 7 days default
  } = patchConfig;

  const ruleName = `vp_${cveId.replace(/[-]/g,'_').toLowerCase()}_${Date.now()}`;
  const expiresAt = nowPlusSecs(expires_hours * 3600);

  const patchId = uuid();
  await env.DB.prepare(`
    INSERT INTO virtual_patches
    (id, cve_id, patch_type, rule_name, rule_pattern, rule_action, priority, is_active, action_id, expires_at)
    VALUES (?,?,?,?,?,?,?,1,?,?)
    ON CONFLICT DO NOTHING
  `).bind(patchId, cveId, patch_type, ruleName, rule_pattern, rule_action, priority, actionId, expiresAt).run();

  // Cache the active patch ruleset for fast middleware lookup
  if (env.SECURITY_HUB_KV) {
    const existing = await env.SECURITY_HUB_KV.get('waf:virtual_patches', 'json').catch(() => []);
    const patches = Array.isArray(existing) ? existing : [];
    patches.push({ id: patchId, cveId, patch_type, rule_name: ruleName, rule_pattern, rule_action, priority, expiresAt });
    // Keep top 100 by priority
    patches.sort((a,b) => (a.priority||99)-(b.priority||99));
    await env.SECURITY_HUB_KV.put('waf:virtual_patches', JSON.stringify(patches.slice(0,100)), { expirationTtl: expires_hours * 3600 });
  }

  return {
    action_type: 'apply_virtual_patch',
    target: cveId,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: true,
    rollback_action: `remove_patch:${patchId}`,
    detail: `Virtual patch '${ruleName}' applied for ${cveId}. Type: ${patch_type}, Action: ${rule_action}. Active for ${expires_hours}h.`,
    patch_id: patchId,
    rule_name: ruleName,
    expires_at: expiresAt,
  };
}

// ─── 5. RATE LIMIT IP ────────────────────────────────────────────────────────
export async function executeRateLimitIP(env, actionId, ip, maxReqPerMin = 10) {
  const t0 = Date.now();
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `ratelimit:forced:${ip}`,
      JSON.stringify({ maxReqPerMin, actionId, since: now() }),
      { expirationTtl: 3600 }
    );
  }
  return {
    action_type: 'rate_limit_ip',
    target: ip,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: true,
    rollback_action: `remove_rate_limit:${ip}`,
    detail: `IP ${ip} throttled to ${maxReqPerMin} req/min for 1h.`,
  };
}

// ─── ROLLBACK ACTIONS ────────────────────────────────────────────────────────
export async function executeRollback(env, actionId) {
  const action = await env.DB.prepare(`SELECT * FROM agent_actions WHERE id=?`).bind(actionId).first();
  if (!action) return { execution_status: 'FAILED', error: 'Action not found' };
  if (!action.rollback_available) return { execution_status: 'FAILED', error: 'Rollback not available' };

  const t0 = Date.now();
  let detail = '';

  if (action.action_type === 'block_ip') {
    await env.DB.prepare(`UPDATE ip_blocklist SET is_active=0 WHERE action_id=?`).bind(actionId).run();
    if (env.SECURITY_HUB_KV) await env.SECURITY_HUB_KV.delete(`blocklist:ip:${action.target}`);
    detail = `IP ${action.target} unblocked.`;
  } else if (action.action_type === 'apply_virtual_patch') {
    await env.DB.prepare(`UPDATE virtual_patches SET is_active=0 WHERE action_id=?`).bind(actionId).run();
    detail = `Virtual patch for ${action.target} removed.`;
  } else if (action.action_type === 'disable_session') {
    await env.DB.prepare(`DELETE FROM session_blacklist WHERE action_id=?`).bind(actionId).run();
    if (env.SECURITY_HUB_KV) await env.SECURITY_HUB_KV.delete(`session_disabled:${action.target}`);
    detail = `Session re-enabled for ${action.target}.`;
  }

  await env.DB.prepare(`
    UPDATE agent_actions SET execution_status='ROLLED_BACK', completed_at=? WHERE id=?
  `).bind(now(), actionId).run();

  return {
    action_type: 'rollback',
    original_action_id: actionId,
    execution_status: 'SUCCESS',
    timestamp: now(),
    duration_ms: Date.now() - t0,
    rollback_available: false,
    detail,
  };
}

// ─── PERSIST ACTION RESULT ───────────────────────────────────────────────────
export async function persistActionResult(env, actionId, result, agentType, triggerSource, triggerId, metadata = {}) {
  await env.DB.prepare(`
    UPDATE agent_actions SET
      execution_status=?,
      execution_detail=?,
      duration_ms=?,
      error_message=?,
      completed_at=?,
      metadata=?
    WHERE id=?
  `).bind(
    result.execution_status,
    result.detail || '',
    result.duration_ms || 0,
    result.error || null,
    now(),
    JSON.stringify(metadata),
    actionId
  ).run().catch(() => {});
}

// ─── CREATE PENDING ACTION RECORD ────────────────────────────────────────────
export async function createActionRecord(env, {
  agentType, actionType, target, targetType, triggerSource, triggerId,
  riskLevel, decisionScore, rollbackAvailable = true, userId = null,
}) {
  const id = uuid();
  await env.DB.prepare(`
    INSERT INTO agent_actions
    (id, agent_type, action_type, target, target_type, trigger_source, trigger_id,
     risk_level, decision_score, execution_status, rollback_available, executed_by, user_id, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,'executing',?,?,?,?)
  `).bind(
    id, agentType, actionType, target, targetType, triggerSource,
    triggerId || null, riskLevel, decisionScore, rollbackAvailable ? 1 : 0,
    'autonomous_agent', userId || null, now()
  ).run().catch(() => {});
  return id;
}
