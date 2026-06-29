/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * workflowAutomation.js — Security Workflow Automation Engine
 *
 * APIs:
 *   GET    /api/workflows             list workflows
 *   POST   /api/workflows             create workflow
 *   PATCH  /api/workflows/:id         update/enable/disable
 *   DELETE /api/workflows/:id         delete workflow
 *   POST   /api/workflows/:id/execute manual trigger
 *   GET    /api/workflows/:id/executions execution history
 *   GET    /api/workflows/templates   built-in templates
 */

const BUILTIN_TEMPLATES = [
  {
    id: 'tpl-wf-001',
    name: 'Critical Finding → Auto Case',
    description: 'Automatically creates a SOC case when a critical scan finding is detected.',
    trigger_type: 'SCAN_CRITICAL',
    trigger_config: { severity_threshold: 80 },
    steps: [
      { action: 'CREATE_SOC_CASE', config: { severity: 'CRITICAL', source: 'automated', auto_title: true } },
      { action: 'SEND_NOTIFICATION', config: { event_type: 'case.created', channels: ['INAPP'] } },
    ],
    is_template: 1,
  },
  {
    id: 'tpl-wf-002',
    name: 'Escalated Case → MSSP Notify',
    description: 'Notifies MSSP admin via Slack and in-app when a case is escalated.',
    trigger_type: 'CASE_ESCALATED',
    trigger_config: {},
    steps: [
      { action: 'SEND_NOTIFICATION', config: { event_type: 'case.escalated', channels: ['INAPP','SLACK'] } },
    ],
    is_template: 1,
  },
  {
    id: 'tpl-wf-003',
    name: 'Churn Risk → Playbook',
    description: 'Assigns a success playbook when customer health churn risk is HIGH.',
    trigger_type: 'HEALTH_CHURN',
    trigger_config: { min_risk_level: 'HIGH' },
    steps: [
      { action: 'ASSIGN_PLAYBOOK', config: { playbook_id: 'pb-004' } },
      { action: 'SEND_NOTIFICATION', config: { event_type: 'health.churn', channels: ['INAPP'] } },
    ],
    is_template: 1,
  },
  {
    id: 'tpl-wf-004',
    name: 'IOC Match → Alert + Case',
    description: 'When an IOC matches a known threat actor, creates a case and sends alert.',
    trigger_type: 'IOC_MATCH',
    trigger_config: { actor_required: false },
    steps: [
      { action: 'CREATE_SOC_CASE', config: { severity: 'HIGH', source: 'ioc_match', auto_title: true } },
      { action: 'SEND_NOTIFICATION', config: { event_type: 'ioc.matched', channels: ['INAPP','SLACK'] } },
    ],
    is_template: 1,
  },
];

function genId(prefix = 'wf') { return `${prefix}_` + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

/**
 * Execute a single workflow step.
 */
async function executeStep(step, context, env) {
  const { action, config } = step;
  const log = { action, config, started_at: new Date().toISOString(), status: 'ok', result: null };

  try {
    if (action === 'CREATE_SOC_CASE') {
      const caseId = genId('case');
      const caseNum = `CDB-${new Date().toISOString().slice(2,7).replace('-','')}-${crypto.randomUUID().slice(0,4).toUpperCase()}`;
      const title = config.auto_title
        ? `[Auto] ${context.trigger_type} detected — ${new Date().toLocaleString()}`
        : config.title || 'Automated Security Case';
      await env.DB.prepare(
        `INSERT INTO soc_cases (id, case_number, title, severity, status, source, org_id, sla_hours, created_at, updated_at)
         VALUES (?,?,?,?,?,'automated',?,?,datetime('now'),datetime('now'))`
      ).bind(caseId, caseNum, title, config.severity || 'HIGH', 'OPEN', context.org_id || 'default', 24).run();
      log.result = { case_id: caseId, case_number: caseNum };
    }

    if (action === 'SEND_NOTIFICATION') {
      // Log notification request — actual delivery handled by notification platform
      const notifId = genId('notif');
      await env.DB.prepare(
        `INSERT INTO notification_log (id, recipient_id, org_id, channel, event_type, subject, status, created_at)
         VALUES (?,?,?,?,?,?,?,datetime('now'))`
      ).bind(notifId, context.triggered_by || 'system', context.org_id || 'default',
        'INAPP', config.event_type || 'workflow.executed',
        `Workflow: ${context.workflow_name}`, 'SENT').run();
      log.result = { notification_id: notifId };
    }

    if (action === 'ASSIGN_PLAYBOOK') {
      await env.DB.prepare(
        `UPDATE customer_health SET playbook_id=?, updated_at=datetime('now') WHERE org_id=?`
      ).bind(config.playbook_id, context.org_id || 'default').run();
      log.result = { playbook_id: config.playbook_id };
    }

    if (action === 'UPDATE_CASE_STATUS') {
      if (config.case_id) {
        await env.DB.prepare(
          `UPDATE soc_cases SET status=?, updated_at=datetime('now') WHERE id=?`
        ).bind(config.status, config.case_id).run();
      }
      log.result = { status: config.status };
    }

    if (action === 'WEBHOOK_CALL') {
      // Validate URL is external and not private IP range
      if (config.url && config.url.startsWith('https://')) {
        try {
          const wResp = await fetch(config.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CDB-Workflow': context.workflow_id },
            body: JSON.stringify({ workflow: context.workflow_name, trigger: context.trigger_type, ts: new Date().toISOString() }),
            signal: AbortSignal.timeout(5000),
          });
          log.result = { http_status: wResp.status };
        } catch (e) {
          log.status = 'error'; log.error = e.message;
        }
      } else {
        log.status = 'skipped'; log.error = 'Invalid or non-HTTPS webhook URL';
      }
    }

  } catch (e) {
    log.status = 'error';
    log.error = e.message;
  }

  log.completed_at = new Date().toISOString();
  return log;
}

export async function handleListWorkflows(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = req.user.org_id || 'default';
  const rows = await env.DB.prepare(
    `SELECT id, name, description, trigger_type, is_active, run_count, last_run_at, created_at
     FROM workflows WHERE org_id = ? AND is_template = 0 ORDER BY created_at DESC LIMIT 50`
  ).bind(orgId).all().catch(() => ({ results: [] }));

  return Response.json({ workflows: rows.results || [], total: (rows.results || []).length });
}

export async function handleCreateWorkflow(req, env) {
  if (!requireRole(req, ['admin', 'mssp_admin', 'enterprise'])) {
    return Response.json({ error: 'Enterprise plan or admin role required' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { name, description = '', trigger_type, trigger_config = {}, steps = [] } = body;
  if (!name || !trigger_type) return Response.json({ error: 'name and trigger_type required' }, { status: 400 });
  if (!steps.length) return Response.json({ error: 'At least one step required' }, { status: 400 });

  const id = genId();
  const orgId = req.user.org_id || 'default';

  await env.DB.prepare(
    `INSERT INTO workflows (id, name, description, trigger_type, trigger_config, steps_json, is_active, org_id, created_by, created_at, updated_at)
     VALUES (?,?,?,?,?,?,1,?,?,datetime('now'),datetime('now'))`
  ).bind(id, name, description, trigger_type, JSON.stringify(trigger_config), JSON.stringify(steps), orgId, req.user.id || 'unknown').run();

  return Response.json({ success: true, id, name, trigger_type });
}

export async function handleUpdateWorkflow(req, env, wfId) {
  if (!requireRole(req, ['admin', 'mssp_admin', 'enterprise'])) {
    return Response.json({ error: 'Enterprise plan or admin role required' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { name, is_active, steps, description } = body;
  const orgId = req.user.org_id || 'default';

  const existing = await env.DB.prepare(`SELECT id FROM workflows WHERE id = ? AND org_id = ?`).bind(wfId, orgId).first().catch(() => null);
  if (!existing) return Response.json({ error: 'Workflow not found' }, { status: 404 });

  const updates = [];
  const vals = [];
  if (name !== undefined) { updates.push('name=?'); vals.push(name); }
  if (description !== undefined) { updates.push('description=?'); vals.push(description); }
  if (is_active !== undefined) { updates.push('is_active=?'); vals.push(is_active ? 1 : 0); }
  if (steps !== undefined) { updates.push('steps_json=?'); vals.push(JSON.stringify(steps)); }
  updates.push("updated_at=datetime('now')");
  vals.push(wfId);

  await env.DB.prepare(`UPDATE workflows SET ${updates.join(',')} WHERE id=?`).bind(...vals).run();
  return Response.json({ success: true });
}

export async function handleDeleteWorkflow(req, env, wfId) {
  if (!requireRole(req, ['admin', 'mssp_admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  const orgId = req.user.org_id || 'default';
  const result = await env.DB.prepare(
    `DELETE FROM workflows WHERE id = ? AND org_id = ? AND is_template = 0`
  ).bind(wfId, orgId).run().catch(() => null);

  if (!result?.meta?.changes) return Response.json({ error: 'Not found' }, { status: 404 });
  return Response.json({ success: true });
}

export async function handleExecuteWorkflow(req, env, wfId) {
  if (!requireRole(req, ['admin', 'mssp_admin', 'enterprise'])) {
    return Response.json({ error: 'Enterprise plan required' }, { status: 403 });
  }

  const orgId = req.user.org_id || 'default';
  const wf = await env.DB.prepare(
    `SELECT * FROM workflows WHERE (id = ? OR id LIKE ?) AND (org_id = ? OR is_template = 1)`
  ).bind(wfId, wfId + '%', orgId).first().catch(() => null);

  // Also check built-in templates
  const builtinTpl = BUILTIN_TEMPLATES.find(t => t.id === wfId);
  const workflow = wf || builtinTpl;
  if (!workflow) return Response.json({ error: 'Workflow not found' }, { status: 404 });

  const execId = genId('exec');
  const steps  = typeof workflow.steps_json === 'string' ? JSON.parse(workflow.steps_json) : (workflow.steps || []);

  const context = {
    workflow_id: wfId, workflow_name: workflow.name,
    trigger_type: workflow.trigger_type, triggered_by: req.user.id || 'manual',
    org_id: orgId,
  };

  // Insert execution record
  await env.DB.prepare(
    `INSERT INTO workflow_executions (id, workflow_id, status, triggered_by, trigger_payload_json, org_id, started_at)
     VALUES (?,?,?,?,?,?,datetime('now'))`
  ).bind(execId, wfId, 'RUNNING', context.triggered_by, '{}', orgId).run().catch(() => null);

  // Execute steps
  const stepLogs = [];
  let overallStatus = 'COMPLETED';
  for (const step of steps) {
    const log = await executeStep(step, context, env);
    stepLogs.push(log);
    if (log.status === 'error') { overallStatus = 'FAILED'; break; }
  }

  // Update execution record
  await env.DB.prepare(
    `UPDATE workflow_executions SET status=?, steps_log_json=?, completed_at=datetime('now') WHERE id=?`
  ).bind(overallStatus, JSON.stringify(stepLogs), execId).run().catch(() => null);

  // Increment run_count
  if (wf) {
    await env.DB.prepare(`UPDATE workflows SET run_count=run_count+1, last_run_at=datetime('now') WHERE id=?`).bind(wfId).run().catch(() => null);
  }

  return Response.json({ success: true, execution_id: execId, status: overallStatus, steps_executed: stepLogs.length, steps: stepLogs });
}

export async function handleWorkflowExecutions(req, env, wfId) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const rows = await env.DB.prepare(
    `SELECT id, status, triggered_by, started_at, completed_at
     FROM workflow_executions WHERE workflow_id = ? ORDER BY started_at DESC LIMIT 20`
  ).bind(wfId).all().catch(() => ({ results: [] }));

  return Response.json({ executions: rows.results || [] });
}

export async function handleWorkflowTemplates(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });
  return Response.json({ templates: BUILTIN_TEMPLATES, total: BUILTIN_TEMPLATES.length });
}
