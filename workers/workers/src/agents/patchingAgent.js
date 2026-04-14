/**
 * PATCHING AGENT — Virtual WAF patch lifecycle management
 * Manages: create, activate, deactivate, rollback, expire virtual patches
 * Real enforcement: KV cache updated on every patch state change
 * Middleware reads KV `waf:virtual_patches` on every request for sub-ms WAF enforcement
 */
import { executeApplyVirtualPatch, executeRollback, createActionRecord, persistActionResult } from './actionExecutor.js';
import { decideCVEResponse } from './decisionEngine.js';

function now() { return new Date().toISOString(); }
function uuid() { return crypto.randomUUID(); }

// Patch types and their WAF enforcement strategies
const PATCH_STRATEGIES = {
  path_block: {
    description: 'Block requests matching path pattern',
    enforcement: 'block_request',
    http_status: 403,
  },
  param_filter: {
    description: 'Strip/reject dangerous query/body parameters',
    enforcement: 'sanitize_params',
    http_status: 400,
  },
  header_injection: {
    description: 'Block header injection attempts',
    enforcement: 'block_request',
    http_status: 400,
  },
  rate_limit: {
    description: 'Apply aggressive rate limiting',
    enforcement: 'rate_limit',
    http_status: 429,
  },
};

/**
 * Execute patching from manual API request
 */
export async function executePatching(env, request, authCtx) {
  const body = await request.json().catch(() => ({}));
  const {
    cve_id,
    patch_type = 'rate_limit',
    rule_pattern = '',
    expires_hours = 168, // 7 days default
    priority = 50,
    force = false,
  } = body;

  if (!cve_id) return { error: 'cve_id required', status: 400 };

  if (!Object.keys(PATCH_STRATEGIES).includes(patch_type)) {
    return { error: `invalid patch_type. Must be one of: ${Object.keys(PATCH_STRATEGIES).join(', ')}`, status: 400 };
  }

  // Check for existing active patch for this CVE
  const existing = await env.DB.prepare(
    `SELECT id, patch_type, is_active FROM virtual_patches WHERE cve_id=? AND is_active=1 LIMIT 1`
  ).bind(cve_id).first().catch(() => null);

  if (existing && !force) {
    return {
      error: `Active patch already exists for ${cve_id} (id: ${existing.id}). Use force=true to override.`,
      existing_patch_id: existing.id,
      status: 409,
    };
  }

  const patchConfig = {
    patch_type,
    rule_pattern,
    expires_hours,
    priority,
    enforcement: PATCH_STRATEGIES[patch_type]?.enforcement || 'block_request',
  };

  const actionId = await createActionRecord(env, {
    agentType:         'patching',
    actionType:        'apply_virtual_patch',
    target:            cve_id,
    targetType:        'cve_id',
    triggerSource:     'manual',
    triggerId:         null,
    riskLevel:         priority <= 10 ? 'CRITICAL' : priority <= 30 ? 'HIGH' : 'MEDIUM',
    decisionScore:     priority <= 10 ? 90 : priority <= 30 ? 70 : 50,
    rollbackAvailable: true,
    userId:            authCtx?.userId || null,
  });

  const result = await executeApplyVirtualPatch(env, actionId, cve_id, patchConfig);
  await persistActionResult(env, actionId, result, 'patching', 'manual', cve_id, {
    requested_by: authCtx?.userId || 'system',
    patch_type,
    rule_pattern,
  });

  return {
    success:          result.execution_status === 'SUCCESS',
    action_id:        actionId,
    cve_id,
    patch_type,
    rule_pattern,
    execution_status: result.execution_status,
    patch_id:         result.patch_id,
    expires_at:       result.expires_at,
    timestamp:        result.timestamp,
    rollback_available: result.rollback_available,
    rollback_action:  result.rollback_action,
    strategy:         PATCH_STRATEGIES[patch_type],
  };
}

/**
 * Rollback a specific patch by action ID
 */
export async function rollbackPatch(env, request, authCtx) {
  const body = await request.json().catch(() => ({}));
  const { action_id } = body;

  if (!action_id) return { error: 'action_id required', status: 400 };

  const action = await env.DB.prepare(
    `SELECT id, action_type, target, execution_status FROM agent_actions WHERE id=? LIMIT 1`
  ).bind(action_id).first().catch(() => null);

  if (!action) return { error: `Action ${action_id} not found`, status: 404 };
  if (action.execution_status === 'ROLLED_BACK') {
    return { error: `Action ${action_id} already rolled back`, status: 409 };
  }

  const result = await executeRollback(env, action_id);

  return {
    success:          result.success,
    action_id,
    rolled_back_target: action.target,
    timestamp:        now(),
    detail:           result.detail,
  };
}

/**
 * List all active virtual patches
 */
export async function listActivePatches(env) {
  const rows = await env.DB.prepare(`
    SELECT vp.id, vp.cve_id, vp.patch_type, vp.rule_pattern, vp.priority,
           vp.is_active, vp.applied_at, vp.expires_at,
           aa.execution_status, aa.trigger_source
    FROM virtual_patches vp
    LEFT JOIN agent_actions aa ON aa.target = vp.cve_id AND aa.action_type='apply_virtual_patch'
    WHERE vp.is_active = 1
      AND (vp.expires_at IS NULL OR vp.expires_at > datetime('now'))
    ORDER BY vp.priority ASC, vp.applied_at DESC
    LIMIT 100
  `).all().catch(() => ({ results: [] }));

  return {
    patches:        rows.results || [],
    total_active:   (rows.results || []).length,
    timestamp:      now(),
  };
}

/**
 * Expire stale patches (called from cron)
 * Deactivates patches past their expiry + refreshes KV cache
 */
export async function expireStalePatches(env) {
  const expired = await env.DB.prepare(`
    UPDATE virtual_patches
    SET is_active = 0
    WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= datetime('now')
  `).run().catch(() => ({ changes: 0 }));

  // Rebuild KV cache after expiry
  await rebuildPatchKVCache(env);

  return {
    expired_count: expired.changes || 0,
    timestamp: now(),
  };
}

/**
 * Rebuild the KV WAF patch cache from D1 (source of truth)
 * Called after any patch state change
 */
export async function rebuildPatchKVCache(env) {
  if (!env.SECURITY_HUB_KV) return;

  const rows = await env.DB.prepare(`
    SELECT cve_id, patch_type, rule_pattern, priority
    FROM virtual_patches
    WHERE is_active=1 AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY priority ASC
    LIMIT 100
  `).all().catch(() => ({ results: [] }));

  const patches = (rows.results || []).map(r => ({
    cve_id:       r.cve_id,
    patch_type:   r.patch_type,
    rule_pattern: r.rule_pattern,
    priority:     r.priority,
  }));

  await env.SECURITY_HUB_KV.put('waf:virtual_patches', JSON.stringify(patches), {
    expirationTtl: 3600, // Re-validate every hour
  }).catch(() => {});

  return { patches_in_cache: patches.length };
}

/**
 * Auto-patch on CVE ingestion (called from cron batch)
 */
export async function autoPatchCVE(env, cveData) {
  const decision = decideCVEResponse(cveData);

  // Only auto-patch CRITICAL or HIGH+KEV
  if (decision.risk_level !== 'CRITICAL' && !(decision.risk_level === 'HIGH' && cveData.is_kev)) {
    return null;
  }

  const patchAction = decision.actions.find(a => a.action_type === 'apply_virtual_patch');
  if (!patchAction) return null;

  const actionId = await createActionRecord(env, {
    agentType:         'patching',
    actionType:        'apply_virtual_patch',
    target:            cveData.cve_id,
    targetType:        'cve_id',
    triggerSource:     'cve_ingestion',
    triggerId:         cveData.cve_id,
    riskLevel:         decision.risk_level,
    decisionScore:     decision.decision_score,
    rollbackAvailable: true,
  });

  const result = await executeApplyVirtualPatch(env, actionId, cveData.cve_id, patchAction.patch_config || {});
  await persistActionResult(env, actionId, result, 'patching', 'cve_ingestion', cveData.cve_id, {
    cvss: cveData.cvss,
    epss: cveData.epss,
    is_kev: cveData.is_kev,
    patch_category: decision.patch_category,
    reasoning: decision.reasoning,
  });

  return { actionId, cve_id: cveData.cve_id, ...result };
}

/**
 * Batch auto-patch for cron runs
 */
export async function runPatchingBatch(env, cves = []) {
  const results = [];
  // Filter to only CRITICAL/HIGH-KEV CVEs
  const targets = cves.filter(c =>
    c.cvss >= 9.0 || (c.cvss >= 7.0 && c.is_kev)
  );

  for (const cve of targets.slice(0, 10)) {
    try {
      const r = await autoPatchCVE(env, cve);
      if (r) results.push(r);
    } catch (e) {
      results.push({ cve_id: cve.cve_id, error: e.message, agent: 'patching' });
    }
  }

  // Expire old patches after new ones applied
  const expired = await expireStalePatches(env);

  return {
    patched:       results.length,
    expired:       expired.expired_count,
    results,
    timestamp:     now(),
  };
}

/**
 * Get WAF stats: total patches, types breakdown, recent activity
 */
export async function getWAFStats(env) {
  const [active, byType, recent] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as cnt FROM virtual_patches WHERE is_active=1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).first().catch(() => ({ cnt: 0 })),
    env.DB.prepare(`SELECT patch_type, COUNT(*) as cnt FROM virtual_patches WHERE is_active=1 GROUP BY patch_type`).all().catch(() => ({ results: [] })),
    env.DB.prepare(`SELECT cve_id, patch_type, priority, applied_at, expires_at FROM virtual_patches WHERE is_active=1 ORDER BY applied_at DESC LIMIT 10`).all().catch(() => ({ results: [] })),
  ]);

  return {
    active_patches: active?.cnt || 0,
    by_type:        byType.results || [],
    recent_patches: recent.results || [],
    timestamp:      now(),
  };
}
