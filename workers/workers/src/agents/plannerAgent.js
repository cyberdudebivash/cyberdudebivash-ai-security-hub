/**
 * CYBERDUDEBIVASH MYTHOS — Planner Agent v1.0
 * ════════════════════════════════════════════
 * Converts threat analysis output into an executable task plan.
 * Determines optimal tool generation strategy per CVE severity/type.
 * Outputs a prioritized task queue for the Orchestrator to execute.
 */

// ── Tool metadata: priority, market value, deploy urgency ────────────────────
const TOOL_META = {
  firewall_script:  { priority: 1, value_inr: 799,  deploy: 'IMMEDIATE' },
  sigma_rule:       { priority: 2, value_inr: 499,  deploy: 'IMMEDIATE' },
  yara_rule:        { priority: 3, value_inr: 599,  deploy: 'FAST'      },
  ir_playbook:      { priority: 4, value_inr: 999,  deploy: 'FAST'      },
  ids_signature:    { priority: 5, value_inr: 599,  deploy: 'FAST'      },
  hardening_script: { priority: 6, value_inr: 799,  deploy: 'SCHEDULED' },
  threat_hunt_pack: { priority: 7, value_inr: 699,  deploy: 'SCHEDULED' },
  python_scanner:   { priority: 8, value_inr: 499,  deploy: 'SCHEDULED' },
  exec_briefing:    { priority: 9, value_inr: 299,  deploy: 'FAST'      },
  api_module:       { priority: 10, value_inr: 399, deploy: 'SCHEDULED' },
};

// ── Baseline tool sets per risk level ────────────────────────────────────────
const RISK_BASELINES = {
  CRITICAL: ['firewall_script', 'sigma_rule', 'yara_rule', 'ir_playbook', 'exec_briefing'],
  HIGH:     ['sigma_rule', 'firewall_script', 'ir_playbook', 'yara_rule'],
  MEDIUM:   ['sigma_rule', 'hardening_script', 'ids_signature'],
  LOW:      ['sigma_rule', 'hardening_script'],
};

// ── Context-based additional tools ───────────────────────────────────────────
function contextTools(intel, analysis) {
  const src  = `${intel.description || ''} ${intel.type || ''}`.toLowerCase();
  const tools = [];
  if (/web|http|api|sql|xss|nginx|apache/.test(src)) tools.push('firewall_script', 'ids_signature');
  if (/linux|bash|shell|unix/.test(src))              tools.push('hardening_script');
  if (/ransomware|malware|worm|trojan/.test(src))     tools.push('yara_rule', 'threat_hunt_pack');
  if (/python|script|automat/.test(src))              tools.push('python_scanner');
  if (/api|rest|graphql|oauth/.test(src))             tools.push('api_module');
  if ((analysis.risk_score || 0) >= 90)               tools.push('exec_briefing');
  return tools;
}

// ── Build a single task entry ─────────────────────────────────────────────────
function makeTask(intel, toolType, overrides = {}) {
  const meta = TOOL_META[toolType] || { priority: 50, value_inr: 299, deploy: 'SCHEDULED' };
  const safeId = (intel.id || intel.cve_id || 'UNKNOWN').replace(/[^a-zA-Z0-9]/g, '_');
  return {
    id:          `task_${safeId}_${toolType}`,
    type:        'GENERATE_TOOL',
    tool_type:   toolType,
    intel_id:    intel.id || intel.cve_id,
    priority:    meta.priority,
    deploy_time: meta.deploy,
    value_inr:   meta.value_inr,
    status:      'PENDING',
    max_retries: 3,
    retry_count: 0,
    created_at:  new Date().toISOString(),
    ...overrides,
  };
}

// ── Master plan builder ───────────────────────────────────────────────────────
export function buildTaskPlan(intel, analysis) {
  const risk     = analysis.risk_level || 'MEDIUM';
  const urgency  = analysis.urgency    || 'SCHEDULED';
  const base     = RISK_BASELINES[risk]  || RISK_BASELINES.MEDIUM;
  const extra    = contextTools(intel, analysis);
  const toolSet  = [...new Set([...base, ...extra])];
  toolSet.sort((a, b) => (TOOL_META[a]?.priority || 99) - (TOOL_META[b]?.priority || 99));

  const safeId  = (intel.id || intel.cve_id || 'UNKNOWN').replace(/[^a-zA-Z0-9]/g, '_');
  const tasks   = toolSet.map(t => makeTask(intel, t));

  // Validation task — depends on all tool tasks
  tasks.push({
    id:         `task_${safeId}_validate`,
    type:       'VALIDATE_ALL',
    intel_id:   intel.id || intel.cve_id,
    priority:   50,
    status:     'PENDING',
    depends_on: tasks.map(t => t.id),
    created_at: new Date().toISOString(),
  });

  // Publish task — depends on validation
  tasks.push({
    id:         `task_${safeId}_publish`,
    type:       'PUBLISH_MARKETPLACE',
    intel_id:   intel.id || intel.cve_id,
    priority:   99,
    status:     'PENDING',
    depends_on: [`task_${safeId}_validate`],
    created_at: new Date().toISOString(),
  });

  const estimatedValue = toolSet.reduce((s, t) => s + (TOOL_META[t]?.value_inr || 299), 0);

  return {
    plan_id:         `plan_${safeId}_${Date.now()}`,
    intel_id:        intel.id || intel.cve_id,
    total_tasks:     tasks.length,
    tool_count:      toolSet.length,
    tools:           toolSet,
    urgency,
    risk_level:      risk,
    tasks,
    estimated_value_inr: estimatedValue,
    created_at:      new Date().toISOString(),
  };
}

// ── Batch plan builder ────────────────────────────────────────────────────────
export function buildBatchPlan(intelItems, analyses) {
  const ORDER = { IMMEDIATE: 0, URGENT: 1, SCHEDULED: 2 };
  const plans = intelItems.map((intel, i) => {
    try { return buildTaskPlan(intel, analyses[i]?.analysis || {}); }
    catch (err) { console.error(`[plannerAgent] plan failed for ${intel.id}:`, err.message); return null; }
  }).filter(Boolean);

  plans.sort((a, b) => (ORDER[a.urgency] ?? 2) - (ORDER[b.urgency] ?? 2));

  return {
    total_plans:     plans.length,
    total_tasks:     plans.reduce((s, p) => s + p.total_tasks, 0),
    total_tools:     plans.reduce((s, p) => s + p.tool_count, 0),
    estimated_value_inr: plans.reduce((s, p) => s + p.estimated_value_inr, 0),
    plans,
    created_at:      new Date().toISOString(),
  };
}
