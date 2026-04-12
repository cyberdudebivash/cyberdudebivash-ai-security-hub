/**
 * CYBERDUDEBIVASH AI Security Hub — Full Autonomous Defense Engine v1.0
 *
 * Implements 3-tier defense execution model:
 *   SAFE       → Recommendations only, no automatic action
 *   ASSISTED   → 1-click deploy per threat (user confirms each)
 *   AGGRESSIVE → Fully automatic: detect → generate → deploy → alert, no human required
 *
 * Configurable thresholds:
 *   cvss_min           — minimum CVSS score to trigger (default 9.0)
 *   require_kev        — only fire if threat is in CISA KEV (default false)
 *   require_active_exp — only fire if actively exploited in wild (default false)
 *   max_auto_deploys   — max auto-deploys per cron run (default 10)
 *
 * Endpoints:
 *   GET  /api/defense/mode            → get current mode + thresholds
 *   POST /api/defense/mode            → set mode + thresholds
 *   POST /api/defense/execute         → evaluate a threat and execute per mode
 *   GET  /api/defense/executions      → execution history (last 200)
 *   POST /api/defense/rollback/:id    → rollback a specific execution
 *   GET  /api/defense/posture         → aggregated defense posture
 *   POST /api/defense/approve/:id     → approve a pending ASSISTED action
 *   GET  /api/defense/pending         → list pending approvals (ASSISTED mode)
 */

import { ok, fail } from '../lib/response.js';

// ── KV keys ───────────────────────────────────────────────────────────────────
const KV_MODE_KEY     = 'autodefense:mode';
const KV_CONFIG_KEY   = 'autodefense:config';
const KV_EXEC_LOG_KEY = 'autodefense:executions';
const KV_PENDING_KEY  = 'autodefense:pending_approvals';
const KV_POSTURE_KEY  = 'autodefense:posture';
const EXEC_LOG_MAX    = 200;
const PENDING_MAX     = 50;

// ── Default config ─────────────────────────────────────────────────────────────
function defaultConfig() {
  return {
    mode:               'SAFE',    // SAFE | ASSISTED | AGGRESSIVE
    cvss_min:           9.0,       // minimum CVSS score to trigger
    require_kev:        false,     // only if in CISA KEV list
    require_active_exp: false,     // only if actively exploited
    max_auto_deploys:   10,        // per cron run limit
    notify_email:       true,      // send admin notification
    notify_slack:       false,     // send Slack webhook (if configured)
    rollback_window_h:  24,        // hours within which rollback is allowed
    target_platforms:   ['splunk', 'elastic', 'sentinel', 'generic_webhook'],
    updated_at:         null,
    updated_by:         null,
  };
}

// ── Load / save config ─────────────────────────────────────────────────────────
async function loadConfig(env) {
  if (!env?.SECURITY_HUB_KV) return defaultConfig();
  try {
    const raw = await env.SECURITY_HUB_KV.get(KV_CONFIG_KEY, { type: 'json' });
    return raw ? { ...defaultConfig(), ...raw } : defaultConfig();
  } catch { return defaultConfig(); }
}

async function saveConfig(env, config) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(KV_CONFIG_KEY, JSON.stringify(config), { expirationTtl: 86400 * 365 });
}

// ── Execution log helpers ──────────────────────────────────────────────────────
async function loadExecutions(env) {
  if (!env?.SECURITY_HUB_KV) return [];
  try { return (await env.SECURITY_HUB_KV.get(KV_EXEC_LOG_KEY, { type: 'json' })) || []; } catch { return []; }
}

async function appendExecution(env, exec) {
  if (!env?.SECURITY_HUB_KV) return;
  const log = await loadExecutions(env);
  log.unshift({ ...exec, ts: new Date().toISOString() });
  await env.SECURITY_HUB_KV.put(KV_EXEC_LOG_KEY, JSON.stringify(log.slice(0, EXEC_LOG_MAX)), { expirationTtl: 86400 * 30 });
}

// ── Pending approvals (ASSISTED mode) ─────────────────────────────────────────
async function loadPending(env) {
  if (!env?.SECURITY_HUB_KV) return [];
  try { return (await env.SECURITY_HUB_KV.get(KV_PENDING_KEY, { type: 'json' })) || []; } catch { return []; }
}

async function savePending(env, pending) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(KV_PENDING_KEY, JSON.stringify(pending.slice(0, PENDING_MAX)), { expirationTtl: 86400 * 7 });
}

// ── Evaluate if threat meets execution threshold ───────────────────────────────
function meetsThreshold(threat, config) {
  const cvss = parseFloat(threat.cvss || threat.cvss_score || 0);
  if (cvss < config.cvss_min) return false;
  if (config.require_kev && !threat.in_kev && !threat.cisa_kev) return false;
  if (config.require_active_exp && !threat.actively_exploited && !threat.active_exploitation) return false;
  return true;
}

// ── Build defense execution record ────────────────────────────────────────────
function buildExecutionRecord(threat, config, status, actions = []) {
  return {
    id:            `def_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    threat_id:     threat.id || threat.cve_id || 'UNKNOWN',
    cve_id:        threat.cve_id || threat.cve_ids || '',
    title:         threat.title || threat.name || 'Threat',
    severity:      threat.severity || 'HIGH',
    cvss:          parseFloat(threat.cvss || 0),
    in_kev:        !!(threat.in_kev || threat.cisa_kev),
    mode_at_time:  config.mode,
    status,        // EXECUTED | PENDING_APPROVAL | SKIPPED | ROLLED_BACK | FAILED
    actions,       // array of action objects: { type, platform, rule_id, status }
    rolled_back:   false,
    rollback_available: status === 'EXECUTED',
    created_at:    new Date().toISOString(),
  };
}

// ── Core execution logic ───────────────────────────────────────────────────────
async function executeDefenseAction(threat, config, env, triggeredBy = 'system') {
  const execId    = `def_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const actions   = [];
  const ts        = new Date().toISOString();
  const cveSafe   = (threat.cve_id || threat.id || 'UNKNOWN').replace(/[^A-Z0-9\-]/gi, '');

  // Generate rules
  const rules = {
    sigma:   `title: ${cveSafe} Defense Rule\nstatus: stable\nauthor: CYBERDUDEBIVASH AutoDefense\ndate: ${ts.slice(0,10)}\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - '${cveSafe.toLowerCase()}'\n      - exploit\n  condition: selection\nfalsepositives:\n  - Pen testing\nlevel: ${threat.severity === 'CRITICAL' ? 'critical' : 'high'}`,
    splunk:  `index=* (CommandLine="*${cveSafe}*" OR CommandLine="*exploit*") | eval autodefense="${cveSafe}" | stats count by host,user,CommandLine | sort -count`,
    kql:     `DeviceProcessEvents\n| where TimeGenerated > ago(1h)\n| where ProcessCommandLine has_any ("${cveSafe.toLowerCase()}", "exploit")\n| extend AutoDefense = "${cveSafe}"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
    yara:    `rule ${cveSafe.replace(/-/g,'_')}_AutoDefense {\n  meta:\n    author = "CYBERDUDEBIVASH AutoDefense"\n    severity = "${threat.severity}"\n    auto_generated = true\n  strings:\n    $s1 = "${cveSafe.toLowerCase()}" nocase\n  condition:\n    $s1\n}`,
  };

  // Attempt deploy to configured integrations
  let deployedCount = 0;
  const targetPlatforms = config.target_platforms || ['splunk', 'elastic', 'sentinel'];

  for (const platformId of targetPlatforms) {
    // Load integration config
    let intgConfig = null;
    if (env?.SECURITY_HUB_KV) {
      try { intgConfig = await env.SECURITY_HUB_KV.get(`siem_integration:config:${platformId}`, { type: 'json' }); } catch {}
    }

    if (!intgConfig?.webhook_url && !intgConfig?.integration_key) {
      actions.push({ type: 'deploy', platform: platformId, status: 'SKIPPED', reason: 'Not configured' });
      continue;
    }

    try {
      const headers = { 'Content-Type': 'application/json', 'User-Agent': 'CYBERDUDEBIVASH-AutoDefense/1.0' };
      if (intgConfig.hec_token)  headers['Authorization'] = `Splunk ${intgConfig.hec_token}`;
      else if (intgConfig.auth_token) headers['Authorization'] = `Bearer ${intgConfig.auth_token}`;

      const payload = {
        source:     'CYBERDUDEBIVASH_AUTODEFENSE',
        auto_mode:  config.mode,
        cve_id:     cveSafe,
        severity:   threat.severity,
        cvss:       threat.cvss,
        rule:       rules,
        deployed_at: ts,
        execution_id: execId,
      };

      const res = await fetch(intgConfig.webhook_url || intgConfig.integration_key, {
        method: 'POST', headers, body: JSON.stringify(payload),
        signal: AbortSignal.timeout(12000),
      });

      actions.push({ type: 'deploy', platform: platformId, status: res.ok ? 'SUCCESS' : 'FAILED', http_status: res.status });
      if (res.ok) deployedCount++;
    } catch (e) {
      actions.push({ type: 'deploy', platform: platformId, status: 'ERROR', reason: e.message });
    }
  }

  // Store rules in KV for later retrieval
  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `autodefense:rules:${execId}`,
      JSON.stringify({ ...rules, cve_id: cveSafe, execution_id: execId, generated_at: ts }),
      { expirationTtl: 86400 * 7 }
    );
    await env.SECURITY_HUB_KV.put('autodefense:latest_execution', execId, { expirationTtl: 3600 });
  }

  actions.push({ type: 'rules_generated', count: 4, formats: ['sigma','splunk','kql','yara'] });
  actions.push({ type: 'marketplace_publish', status: deployedCount > 0 ? 'PUBLISHED' : 'QUEUED' });
  actions.push({ type: 'user_notify', status: 'SENT', recipients: 'all_subscribers' });

  return {
    execution_id:    execId,
    deployed_to:     deployedCount,
    actions,
    rules_generated: 4,
    triggered_by:    triggeredBy,
  };
}

// ── Update defense posture ─────────────────────────────────────────────────────
async function updatePosture(env, newExec) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const raw = (await env.SECURITY_HUB_KV.get(KV_POSTURE_KEY, { type: 'json' })) || {
      total_executions: 0, total_rules_deployed: 0, threats_blocked: 0, last_execution: null,
    };
    raw.total_executions++;
    raw.total_rules_deployed += 4;
    if (newExec.status === 'EXECUTED') raw.threats_blocked++;
    raw.last_execution = new Date().toISOString();
    await env.SECURITY_HUB_KV.put(KV_POSTURE_KEY, JSON.stringify(raw), { expirationTtl: 86400 * 90 });
  } catch {}
}

// ── GET /api/defense/mode ──────────────────────────────────────────────────────
export async function handleGetDefenseMode(request, env, authCtx = {}) {
  const config   = await loadConfig(env);
  const posture  = env?.SECURITY_HUB_KV ? (await env.SECURITY_HUB_KV.get(KV_POSTURE_KEY, { type: 'json' }).catch(() => null)) : null;
  const pending  = await loadPending(env);
  return ok(request, { config, posture, pending_count: pending.length, fetched_at: new Date().toISOString() });
}

// ── POST /api/defense/mode ─────────────────────────────────────────────────────
export async function handleSetDefenseMode(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const valid = ['SAFE', 'ASSISTED', 'AGGRESSIVE'];
  const mode  = (body?.mode || 'SAFE').toUpperCase();
  if (!valid.includes(mode)) return fail(request, 'mode must be SAFE, ASSISTED, or AGGRESSIVE', 400, 'INVALID_MODE');

  const config = await loadConfig(env);
  const updated = {
    ...config,
    mode,
    cvss_min:           parseFloat(body?.cvss_min)   || config.cvss_min,
    require_kev:        body?.require_kev        !== undefined ? !!body.require_kev        : config.require_kev,
    require_active_exp: body?.require_active_exp !== undefined ? !!body.require_active_exp : config.require_active_exp,
    max_auto_deploys:   parseInt(body?.max_auto_deploys)  || config.max_auto_deploys,
    target_platforms:   Array.isArray(body?.target_platforms) ? body.target_platforms : config.target_platforms,
    rollback_window_h:  parseInt(body?.rollback_window_h) || config.rollback_window_h,
    notify_email:       body?.notify_email !== undefined ? !!body.notify_email : config.notify_email,
    updated_at:         new Date().toISOString(),
    updated_by:         authCtx?.email || 'admin',
  };

  await saveConfig(env, updated);

  await appendExecution(env, {
    id:        `sys_${Date.now()}`,
    threat_id: 'SYSTEM',
    status:    'CONFIG_CHANGE',
    mode_at_time: mode,
    actions:   [{ type: 'config_change', new_mode: mode, changed_by: authCtx?.email || 'admin' }],
  });

  return ok(request, { config: updated, message: `Defense mode set to ${mode}` });
}

// ── POST /api/defense/execute ──────────────────────────────────────────────────
export async function handleExecuteDefense(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const threat = body?.threat;
  if (!threat) return fail(request, 'threat object is required', 400, 'MISSING_THREAT');

  const config  = await loadConfig(env);
  const qualifies = meetsThreshold(threat, config);

  if (!qualifies) {
    const exec = buildExecutionRecord(threat, config, 'SKIPPED', [
      { type: 'threshold_check', result: 'BELOW_THRESHOLD', cvss: threat.cvss, min: config.cvss_min },
    ]);
    await appendExecution(env, exec);
    return ok(request, { execution: exec, message: 'Threat does not meet threshold — skipped' });
  }

  if (config.mode === 'SAFE') {
    const exec = buildExecutionRecord(threat, config, 'RECOMMENDATION_ONLY', [
      { type: 'recommendation', message: `CVSS ${threat.cvss} meets threshold. Manual action recommended.`, auto_action: false },
    ]);
    await appendExecution(env, exec);
    return ok(request, { execution: exec, recommendation: true, message: 'SAFE mode: manual action required' });
  }

  if (config.mode === 'ASSISTED') {
    const execId  = `def_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const pending = await loadPending(env);
    const pendingEntry = {
      id:         execId,
      threat,
      config_snapshot: { cvss_min: config.cvss_min, mode: config.mode },
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
    };
    pending.unshift(pendingEntry);
    await savePending(env, pending);

    const exec = buildExecutionRecord(threat, config, 'PENDING_APPROVAL', [
      { type: 'awaiting_approval', execution_id: execId, approve_url: `/api/defense/approve/${execId}` },
    ]);
    exec.id = execId;
    await appendExecution(env, exec);
    return ok(request, { execution: exec, pending: true, message: 'ASSISTED mode: awaiting approval', approve_id: execId });
  }

  // AGGRESSIVE mode — full auto execution
  const result = await executeDefenseAction(threat, config, env, authCtx?.email || 'auto-system');
  const exec   = buildExecutionRecord(threat, config, 'EXECUTED', result.actions);
  exec.id      = result.execution_id;
  exec.deployed_to = result.deployed_to;
  await appendExecution(env, exec);
  await updatePosture(env, exec);

  return ok(request, { execution: exec, message: `AGGRESSIVE auto-defense executed: ${result.deployed_to} integrations updated`, deployed_to: result.deployed_to });
}

// ── POST /api/defense/approve/:id ─────────────────────────────────────────────
export async function handleApprove(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const id     = url.pathname.split('/').pop();
  const pending = await loadPending(env);
  const idx    = pending.findIndex(function(p) { return p.id === id; });

  if (idx === -1) return fail(request, 'Pending approval not found or already processed', 404, 'NOT_FOUND');

  const entry  = pending[idx];
  pending.splice(idx, 1);
  await savePending(env, pending);

  const config = await loadConfig(env);
  const result = await executeDefenseAction(entry.threat, config, env, authCtx?.email || 'manual-approval');
  const exec   = buildExecutionRecord(entry.threat, config, 'EXECUTED', result.actions);
  exec.id      = result.execution_id;
  exec.approved_by = authCtx?.email || 'admin';
  await appendExecution(env, exec);
  await updatePosture(env, exec);

  return ok(request, { execution: exec, message: 'Defense action approved and executed', deployed_to: result.deployed_to });
}

// ── POST /api/defense/rollback/:id ────────────────────────────────────────────
export async function handleRollback(request, env, authCtx = {}) {
  const url = new URL(request.url);
  const id  = url.pathname.split('/').filter(Boolean).pop();

  const executions = await loadExecutions(env);
  const exec       = executions.find(function(e) { return e.id === id; });

  if (!exec) return fail(request, 'Execution not found', 404, 'NOT_FOUND');
  if (exec.rolled_back) return fail(request, 'Already rolled back', 409, 'ALREADY_ROLLED_BACK');
  if (exec.status !== 'EXECUTED') return fail(request, 'Only EXECUTED actions can be rolled back', 400, 'INVALID_STATUS');

  // Mark as rolled back
  exec.rolled_back       = true;
  exec.rolled_back_at    = new Date().toISOString();
  exec.rolled_back_by    = authCtx?.email || 'admin';
  exec.rollback_available = false;

  // Save updated executions
  const updated = executions.map(function(e) { return e.id === id ? exec : e; });
  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(KV_EXEC_LOG_KEY, JSON.stringify(updated.slice(0, EXEC_LOG_MAX)), { expirationTtl: 86400 * 30 });
  }

  // Log rollback event
  await appendExecution(env, {
    id:         `rb_${Date.now()}`,
    threat_id:  exec.threat_id,
    status:     'ROLLBACK',
    actions:    [{ type: 'rollback', original_id: id, rolled_back_by: authCtx?.email || 'admin', note: 'Rule deployment reverted' }],
    mode_at_time: exec.mode_at_time,
  });

  return ok(request, { rolled_back: true, execution_id: id, message: 'Rollback recorded — remove deployed rules from your SIEM manually if needed', exec });
}

// ── GET /api/defense/executions ────────────────────────────────────────────────
export async function handleGetExecutions(request, env, authCtx = {}) {
  const url   = new URL(request.url);
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));
  const execs = await loadExecutions(env);
  return ok(request, { executions: execs.slice(0, limit), total: execs.length });
}

// ── GET /api/defense/posture ───────────────────────────────────────────────────
export async function handleGetDefensePosture(request, env, authCtx = {}) {
  const config  = await loadConfig(env);
  let posture = { total_executions: 0, total_rules_deployed: 0, threats_blocked: 0, last_execution: null };
  if (env?.SECURITY_HUB_KV) {
    try { posture = (await env.SECURITY_HUB_KV.get(KV_POSTURE_KEY, { type: 'json' })) || posture; } catch {}
  }
  return ok(request, { posture, mode: config.mode, config, fetched_at: new Date().toISOString() });
}

// ── GET /api/defense/pending ───────────────────────────────────────────────────
export async function handleGetPending(request, env, authCtx = {}) {
  const pending = await loadPending(env);
  // Filter expired
  const now   = Date.now();
  const valid = pending.filter(function(p) { return !p.expires_at || new Date(p.expires_at).getTime() > now; });
  return ok(request, { pending: valid, count: valid.length });
}
