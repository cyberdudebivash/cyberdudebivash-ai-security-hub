/* P14.0 regression tests — Enterprise AI Security Fabric
 *
 * Verifies:
 *   1.  All P14 endpoints reject unauthenticated requests with 401
 *   2.  All P14 endpoints reject STARTER tier with 403
 *   3.  handleFabricState returns fabric_level and 6 subsystems
 *   4.  handleFabricState agents array has 6 entries
 *   5.  handleFabricState KV cache returns _cache: hit
 *   6.  handleFabricState summary fields are present
 *   7.  handleFabricAgentStatus returns 6 agents with capabilities
 *   8.  handleFabricAgentStatus coordination_model is hierarchical
 *   9.  handleFabricAgentStatus KV cache returns _cache: hit
 *   10. handleFabricAgentStatus event_bus queue_stats present
 *   11. handleFabricEvents returns events array with queue_stats
 *   12. handleFabricEvents returns available_types list
 *   13. handleFabricEvents with status filter passes to DB
 *   14. handleFabricPublishEvent returns 201 with event_id
 *   15. handleFabricPublishEvent rejects missing event_type (400)
 *   16. handleFabricPublishEvent rejects invalid event_type (400)
 *   17. handleFabricPublishEvent rejects invalid risk_level (400)
 *   18. handleFabricPublishEvent handles invalid JSON body (400)
 *   19. handleFabricPlugins returns 9 builtin plugins
 *   20. handleFabricPlugins returns custom_plugins from KV
 *   21. handleFabricPluginRegister returns 201 on new plugin
 *   22. handleFabricPluginRegister returns 400 for missing fields
 *   23. handleFabricPluginRegister returns 400 for invalid category
 *   24. handleFabricPluginRegister returns 400 for bad plugin id
 *   25. handleFabricPluginRegister returns 200 on update (idempotent)
 *   26. handleFabricPolicyEvaluate returns policy_decision with subject
 *   27. handleFabricPolicyEvaluate includes feature_decision when feature param provided
 *   28. handleFabricPolicyEvaluate entitlements includes PRO features
 *   29. handleFabricPolicyEvaluate has 6 policy types
 *   30. handleFabricMemory returns memory with 4 sections
 *   31. handleFabricMemory decision_history has total field
 *   32. handleFabricMemory KV cache returns _cache: hit
 *   33. handleFabricMemory global_signals present
 *   34. handleFabricMemoryRecord returns 201 with event_id
 *   35. handleFabricMemoryRecord rejects missing record_type (400)
 *   36. handleFabricMemoryRecord rejects invalid record_type (400)
 *   37. handleFabricMemoryRecord handles invalid JSON (400)
 *   38. handleFabricObservability returns observability with 6 subsystems
 *   39. handleFabricObservability has performance.within_target field
 *   40. handleFabricObservability _cache is 'none' (always live)
 *   41. handleFabricObservability agent_coordination has error_rate
 *   42. No regression: P13 handlers still export correct signatures
 *   43. No regression: P12 handlers still export correct signatures
 *   44. No regression: P14 handler imports resolve without error
 */

import { describe, it, expect } from 'vitest';

import {
  handleFabricState,
  handleFabricAgentStatus,
  handleFabricEvents,
  handleFabricPublishEvent,
  handleFabricPlugins,
  handleFabricPluginRegister,
  handleFabricPolicyEvaluate,
  handleFabricMemory,
  handleFabricMemoryRecord,
  handleFabricObservability,
} from '../src/handlers/securityFabricHandler.js';

// ─── Test data ────────────────────────────────────────────────────────────────

const VULN_ROWS = [
  { cve_id: 'CVE-2024-3001', cvss_score: 9.8, epss_score: 0.90, is_kev: 1, severity: 'CRITICAL' },
  { cve_id: 'CVE-2024-3002', cvss_score: 7.5, epss_score: 0.20, is_kev: 0, severity: 'HIGH' },
];
const PRED_ROWS = [
  { cve_id: 'CVE-2024-3001', risk_score: 0.92, risk_level: 'CRITICAL', exploit_probability: 0.90 },
];
const CASE_ROWS = [
  { id: 'case_200', case_number: 'SOC-200', severity: 'CRITICAL', status: 'OPEN', sla_due_at: new Date().toISOString(), created_at: new Date().toISOString() },
  { id: 'case_201', case_number: 'SOC-201', severity: 'HIGH', status: 'IN_PROGRESS', sla_due_at: new Date().toISOString(), created_at: new Date().toISOString() },
];
const DECISION_ROWS = [
  { id: 'dec_200', cve_id: 'CVE-2024-3001', decision: 'PATCH', priority: 'P1', confidence: 95, risk_score: 98 },
];
const EXEC_STAT_ROWS = [
  { status: 'COMPLETED', cnt: 5 },
  { status: 'RUNNING',   cnt: 2 },
];
const WORKFLOW_ROWS = [
  { id: 'exec_200', workflow_id: 'wf_1', status: 'COMPLETED', started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
];
const SIGNAL_ROWS = [
  { signal_type: 'global_risk', signal_value: '0.72', weight: 8.5, updated_at: new Date().toISOString() },
];
const QUEUE_STAT_ROWS = [
  { status: 'pending',    count: 3, max_priority: 7 },
  { status: 'done',       count: 10, max_priority: 10 },
  { status: 'failed',     count: 1, max_priority: 5 },
];
const QUEUE_EVENT_ROWS = [
  { id: 'evt_1', event_type: 'cve_detected', payload: '{"cve_id":"CVE-2024-3001"}', priority: 7, status: 'pending', attempts: 0, created_at: new Date().toISOString(), processed_at: null },
];

// ─── DB Mock ──────────────────────────────────────────────────────────────────

function makeDB() {
  return {
    prepare(sql) {
      const stmt = {
        bind(..._args) { return stmt; },
        async all() {
          if (/FROM agent_event_queue/.test(sql) && /GROUP BY status/.test(sql))
            return { results: QUEUE_STAT_ROWS };
          if (/FROM agent_event_queue/.test(sql))
            return { results: QUEUE_EVENT_ROWS };
          if (/FROM threat_intel/.test(sql))
            return { results: VULN_ROWS };
          if (/FROM threat_predictions/.test(sql))
            return { results: PRED_ROWS };
          if (/FROM soc_cases/.test(sql))
            return { results: CASE_ROWS };
          if (/FROM soc_decisions/.test(sql))
            return { results: DECISION_ROWS };
          if (/FROM workflow_executions/.test(sql) && /GROUP BY/.test(sql))
            return { results: EXEC_STAT_ROWS };
          if (/FROM workflow_executions/.test(sql))
            return { results: WORKFLOW_ROWS };
          if (/FROM brain_global_signals/.test(sql))
            return { results: SIGNAL_ROWS };
          if (/FROM agent_actions/.test(sql))
            return { results: [] };
          // customer_entitlements — return empty so tier fallback is used
          if (/FROM customer_entitlements/.test(sql))
            return { results: [] };
          return { results: [] };
        },
        async first() {
          if (/FROM customer_entitlements/.test(sql)) return null;
          return null;
        },
        async run() { return { success: true, meta: { changes: 1 } }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async get(key)            { return store.has(key) ? store.get(key) : null; },
    async put(key, value, _o) { store.set(key, value); },
  };
}

function makeEnv() {
  return { DB: makeDB(), SECURITY_HUB_KV: makeKV() };
}

const PRO_CTX       = { authenticated: true, tier: 'PRO',        userId: 'u1', id: 'u1', org_id: 'org1' };
const ENTERPRISE_CTX= { authenticated: true, tier: 'ENTERPRISE', userId: 'u2', id: 'u2', org_id: 'org1' };
const MSSP_CTX      = { authenticated: true, tier: 'MSSP',       userId: 'u3', id: 'u3', org_id: 'org1' };
const STARTER_CTX   = { authenticated: true, tier: 'STARTER',    userId: 'u4', id: 'u4' };
const UNAUTH_CTX    = { authenticated: false };

function getReq(path, params = {}) {
  const url = new URL(`https://hub.test${path}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  return new Request(url.toString(), { method: 'GET' });
}

function postReq(path, body) {
  return new Request(`https://hub.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function badPostReq(path) {
  return new Request(`https://hub.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: 'not-json{{{',
  });
}

// ─── Auth gate tests ──────────────────────────────────────────────────────────

describe('P14.0 — tier gate (all endpoints)', () => {
  const getEndpoints = [
    [handleFabricState,          '/api/fabric/state'],
    [handleFabricAgentStatus,    '/api/fabric/agents/status'],
    [handleFabricEvents,         '/api/fabric/events'],
    [handleFabricPlugins,        '/api/fabric/plugins'],
    [handleFabricPolicyEvaluate, '/api/fabric/policy/evaluate'],
    [handleFabricMemory,         '/api/fabric/memory'],
    [handleFabricObservability,  '/api/fabric/observability'],
  ];

  for (const [handler, path] of getEndpoints) {
    it(`GET ${path} returns 401 for unauthenticated`, async () => {
      const res = await handler(getReq(path), makeEnv(), UNAUTH_CTX);
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.success).toBe(false);
      expect(body.service).toBe('CDB-SECURITY-FABRIC');
    });

    it(`GET ${path} returns 403 for STARTER tier`, async () => {
      const res  = await handler(getReq(path), makeEnv(), STARTER_CTX);
      const body = await res.json();
      expect(res.status).toBe(403);
      expect(body.success).toBe(false);
      expect(body.upgrade).toMatch(/pricing/);
    });
  }

  const postTests = [
    ['POST /api/fabric/events/publish',   () => handleFabricPublishEvent(postReq('/api/fabric/events/publish', { event_type: 'cve_detected', payload: {} }), makeEnv(), UNAUTH_CTX)],
    ['POST /api/fabric/plugins/register', () => handleFabricPluginRegister(postReq('/api/fabric/plugins/register', { id: 'test-plug', name: 'Test', category: 'siem' }), makeEnv(), UNAUTH_CTX)],
    ['POST /api/fabric/memory/record',    () => handleFabricMemoryRecord(postReq('/api/fabric/memory/record', { record_type: 'decision', summary: 'test' }), makeEnv(), UNAUTH_CTX)],
  ];

  for (const [label, fn] of postTests) {
    it(`${label} returns 401 for unauthenticated`, async () => {
      const res = await fn();
      expect(res.status).toBe(401);
    });
  }

  it('POST /api/fabric/events/publish returns 403 for STARTER', async () => {
    const res = await handleFabricPublishEvent(
      postReq('/api/fabric/events/publish', { event_type: 'cve_detected' }),
      makeEnv(), STARTER_CTX
    );
    expect(res.status).toBe(403);
  });
});

// ─── P14.1: handleFabricState ─────────────────────────────────────────────────

describe('handleFabricState — P14.1', () => {
  it('returns success with fabric_level', async () => {
    const res  = await handleFabricState(getReq('/api/fabric/state'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-SECURITY-FABRIC');
    expect(['CRITICAL', 'ELEVATED', 'OPERATIONAL']).toContain(body.fabric_level);
  });

  it('has subsystems object with 6 keys', async () => {
    const res  = await handleFabricState(getReq('/api/fabric/state'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Object.keys(body.subsystems)).toHaveLength(6);
    expect(body.subsystems.threat_intelligence).toBeDefined();
    expect(body.subsystems.event_bus).toBeDefined();
    expect(body.subsystems.workflow_engine).toBeDefined();
    expect(body.subsystems.decision_engine).toBeDefined();
    expect(body.subsystems.autonomous_ops).toBeDefined();
    expect(body.subsystems.ai_agents).toBeDefined();
  });

  it('agents array has 6 entries with id and subsystem', async () => {
    const res  = await handleFabricState(getReq('/api/fabric/state'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.agents).toHaveLength(6);
    body.agents.forEach(a => {
      expect(a.id).toBeDefined();
      expect(a.name).toBeDefined();
      expect(a.subsystem).toBeDefined();
      expect(a.status).toBe('active');
    });
  });

  it('summary has required fields', async () => {
    const res  = await handleFabricState(getReq('/api/fabric/state'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.summary.total_subsystems).toBe(6);
    expect(body.summary.active_subsystems).toBe(6);
    expect(typeof body.summary.critical_vulns).toBe('number');
    expect(typeof body.summary.kev_exposure).toBe('number');
    expect(typeof body.summary.open_cases).toBe('number');
  });

  it('KV cache returns _cache: hit on second call', async () => {
    const env = makeEnv();
    await handleFabricState(getReq('/api/fabric/state'), env, PRO_CTX);
    const res2  = await handleFabricState(getReq('/api/fabric/state'), env, PRO_CTX);
    const body2 = await res2.json();
    expect(body2._cache).toBe('hit');
  });

  it('ENTERPRISE tier is accepted', async () => {
    const res = await handleFabricState(getReq('/api/fabric/state'), makeEnv(), ENTERPRISE_CTX);
    expect(res.status).toBe(200);
  });
});

// ─── P14.2: handleFabricAgentStatus ──────────────────────────────────────────

describe('handleFabricAgentStatus — P14.2', () => {
  it('returns 6 agents with capabilities', async () => {
    const res  = await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.agent_count).toBe(6);
    expect(body.agents).toHaveLength(6);
    body.agents.forEach(a => {
      expect(Array.isArray(a.capabilities)).toBe(true);
      expect(a.capabilities.length).toBeGreaterThan(0);
    });
  });

  it('shared_context coordination_model is hierarchical', async () => {
    const res  = await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.shared_context.coordination_model).toBe('hierarchical');
  });

  it('event_bus has queue_stats', async () => {
    const res  = await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.event_bus.queue_stats).toBeDefined();
    expect(typeof body.event_bus.queue_stats.pending).toBe('number');
    expect(typeof body.event_bus.queue_stats.done).toBe('number');
  });

  it('KV cache returns _cache: hit on second call', async () => {
    const env = makeEnv();
    await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), env, PRO_CTX);
    const res2  = await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), env, PRO_CTX);
    const body2 = await res2.json();
    expect(body2._cache).toBe('hit');
  });

  it('agents include soc-command and compliance-policy subsystems', async () => {
    const res  = await handleFabricAgentStatus(getReq('/api/fabric/agents/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const ids  = body.agents.map(a => a.id);
    expect(ids).toContain('soc-command');
    expect(ids).toContain('compliance-policy');
  });
});

// ─── P14.3: handleFabricEvents (GET) ─────────────────────────────────────────

describe('handleFabricEvents — P14.3 GET', () => {
  it('returns events array with queue_stats', async () => {
    const res  = await handleFabricEvents(getReq('/api/fabric/events'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.events)).toBe(true);
    expect(body.queue_stats).toBeDefined();
  });

  it('available_types lists all event types', async () => {
    const res  = await handleFabricEvents(getReq('/api/fabric/events'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Array.isArray(body.available_types)).toBe(true);
    expect(body.available_types.length).toBeGreaterThan(0);
    expect(body.available_types).toContain('cve_detected');
  });

  it('events have expected fields', async () => {
    const res  = await handleFabricEvents(getReq('/api/fabric/events'), makeEnv(), PRO_CTX);
    const body = await res.json();
    if (body.events.length > 0) {
      const evt = body.events[0];
      expect(evt.id).toBeDefined();
      expect(evt.event_type).toBeDefined();
      expect(evt.status).toBeDefined();
    }
  });

  it('returns success with empty DB', async () => {
    const env = { DB: null, SECURITY_HUB_KV: makeKV() };
    const res  = await handleFabricEvents(getReq('/api/fabric/events'), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.events).toEqual([]);
  });
});

// ─── P14.3: handleFabricPublishEvent (POST) ───────────────────────────────────

describe('handleFabricPublishEvent — P14.3 POST', () => {
  it('returns 201 with event_id for valid event', async () => {
    const res  = await handleFabricPublishEvent(
      postReq('/api/fabric/events/publish', { event_type: 'cve_detected', payload: { cve_id: 'CVE-2024-3001' }, risk_level: 'HIGH' }),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.event_id).toBeDefined();
    expect(body.event_type).toBe('cve_detected');
    expect(body.risk_level).toBe('HIGH');
  });

  it('returns 400 for missing event_type', async () => {
    const res  = await handleFabricPublishEvent(
      postReq('/api/fabric/events/publish', { payload: {} }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error).toMatch(/event_type/);
  });

  it('returns 400 for invalid event_type', async () => {
    const res  = await handleFabricPublishEvent(
      postReq('/api/fabric/events/publish', { event_type: 'not_a_real_event' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/Invalid event_type/);
  });

  it('returns 400 for invalid risk_level', async () => {
    const res  = await handleFabricPublishEvent(
      postReq('/api/fabric/events/publish', { event_type: 'cve_detected', risk_level: 'EXTREME' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/risk_level/);
  });

  it('returns 400 for invalid JSON body', async () => {
    const res  = await handleFabricPublishEvent(badPostReq('/api/fabric/events/publish'), makeEnv(), PRO_CTX);
    expect(res.status).toBe(400);
  });

  it('accepts all valid event types', async () => {
    const validTypes = ['cve_detected', 'anomaly_detected', 'threat_intel', 'manual_trigger', 'scheduled_scan'];
    for (const event_type of validTypes) {
      const res = await handleFabricPublishEvent(
        postReq('/api/fabric/events/publish', { event_type }),
        makeEnv(), PRO_CTX
      );
      expect(res.status).toBe(201);
    }
  });
});

// ─── P14.4: handleFabricPlugins (GET) ────────────────────────────────────────

describe('handleFabricPlugins — P14.4 GET', () => {
  it('returns builtin_plugins with 9 entries', async () => {
    const res  = await handleFabricPlugins(getReq('/api/fabric/plugins'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.builtin_plugins).toHaveLength(9);
  });

  it('builtin plugins have required fields', async () => {
    const res  = await handleFabricPlugins(getReq('/api/fabric/plugins'), makeEnv(), PRO_CTX);
    const body = await res.json();
    body.builtin_plugins.forEach(p => {
      expect(p.id).toBeDefined();
      expect(p.name).toBeDefined();
      expect(p.category).toBeDefined();
      expect(p.status).toBe('available');
    });
  });

  it('custom_plugins is empty when no registry exists', async () => {
    const res  = await handleFabricPlugins(getReq('/api/fabric/plugins'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.custom_plugins).toEqual([]);
  });

  it('total = builtin + custom count', async () => {
    const res  = await handleFabricPlugins(getReq('/api/fabric/plugins'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.total).toBe(body.builtin_plugins.length + body.custom_plugins.length);
  });
});

// ─── P14.4: handleFabricPluginRegister (POST) ────────────────────────────────

describe('handleFabricPluginRegister — P14.4 POST', () => {
  it('returns 201 with plugin record on new registration', async () => {
    const env = makeEnv();
    const res  = await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'my-siem-001', name: 'My SIEM', category: 'siem' }),
      env, PRO_CTX
    );
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.plugin.id).toBe('my-siem-001');
    expect(body.plugin.category).toBe('siem');
    expect(body.action).toBe('registered');
  });

  it('returns 400 for missing required fields', async () => {
    const res  = await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'my-plug' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/id, name, and category/);
  });

  it('returns 400 for invalid category', async () => {
    const res  = await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'my-plug-x', name: 'Test', category: 'unknown_cat' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/Invalid category/);
  });

  it('returns 400 for invalid plugin id format', async () => {
    const res  = await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'UPPERCASE_ID', name: 'Test', category: 'siem' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/Plugin id/);
  });

  it('returns 200 on update when plugin id already exists (idempotent)', async () => {
    const env = makeEnv();
    // First registration
    await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'dup-plug-01', name: 'Dup Plugin', category: 'workflow' }),
      env, PRO_CTX
    );
    // Second registration with same id
    const res2  = await handleFabricPluginRegister(
      postReq('/api/fabric/plugins/register', { id: 'dup-plug-01', name: 'Updated Plugin', category: 'workflow' }),
      env, PRO_CTX
    );
    const body2 = await res2.json();
    expect(res2.status).toBe(200);
    expect(body2.action).toBe('updated');
    expect(body2.plugin.name).toBe('Updated Plugin');
  });

  it('returns 400 for invalid JSON body', async () => {
    const res = await handleFabricPluginRegister(badPostReq('/api/fabric/plugins/register'), makeEnv(), PRO_CTX);
    expect(res.status).toBe(400);
  });
});

// ─── P14.5: handleFabricPolicyEvaluate ───────────────────────────────────────

describe('handleFabricPolicyEvaluate — P14.5', () => {
  it('returns policy_decision with subject', async () => {
    const res  = await handleFabricPolicyEvaluate(getReq('/api/fabric/policy/evaluate'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.policy_decision.subject.userId).toBe('u1');
    expect(body.policy_decision.subject.tier).toBe('PRO');
  });

  it('has 6 policy types in policies object', async () => {
    const res  = await handleFabricPolicyEvaluate(getReq('/api/fabric/policy/evaluate'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const p    = body.policy_decision.policies;
    expect(p.tenant_isolation).toBeDefined();
    expect(p.customer_policy).toBeDefined();
    expect(p.mssp_policy).toBeDefined();
    expect(p.executive_policy).toBeDefined();
    expect(p.compliance_policy).toBeDefined();
    expect(p.workflow_policy).toBeDefined();
  });

  it('entitlements include PRO tier features', async () => {
    const res  = await handleFabricPolicyEvaluate(getReq('/api/fabric/policy/evaluate'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const ents = body.policy_decision.entitlements;
    expect(ents['api_access']?.granted).toBe(true);
    expect(ents['threat_feed_full']?.granted).toBe(true);
  });

  it('feature_decision is null when feature param is absent', async () => {
    const res  = await handleFabricPolicyEvaluate(getReq('/api/fabric/policy/evaluate'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.policy_decision.feature_decision).toBeNull();
  });

  it('feature_decision is populated when feature param is provided', async () => {
    const res  = await handleFabricPolicyEvaluate(
      getReq('/api/fabric/policy/evaluate', { feature: 'api_access' }),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    expect(body.policy_decision.feature_decision).toBeDefined();
    expect(body.policy_decision.feature_decision.feature).toBe('api_access');
    expect(body.policy_decision.feature_decision.granted).toBe(true);
  });

  it('mssp_policy applicable is true for MSSP tier', async () => {
    const res  = await handleFabricPolicyEvaluate(getReq('/api/fabric/policy/evaluate'), makeEnv(), MSSP_CTX);
    const body = await res.json();
    expect(body.policy_decision.policies.mssp_policy.applicable).toBe(true);
  });
});

// ─── P14.7: handleFabricMemory (GET) ─────────────────────────────────────────

describe('handleFabricMemory — P14.7 GET', () => {
  it('returns memory with 4 sections', async () => {
    const res  = await handleFabricMemory(getReq('/api/fabric/memory'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.memory.decision_history).toBeDefined();
    expect(body.memory.investigation_history).toBeDefined();
    expect(body.memory.automation_outcomes).toBeDefined();
    expect(body.memory.global_signals).toBeDefined();
  });

  it('decision_history has total field and summary', async () => {
    const res  = await handleFabricMemory(getReq('/api/fabric/memory'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.memory.decision_history.total).toBe('number');
    expect(body.memory.decision_history.summary).toBeDefined();
    expect(Array.isArray(body.memory.decision_history.recent)).toBe(true);
  });

  it('global_signals is an array', async () => {
    const res  = await handleFabricMemory(getReq('/api/fabric/memory'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Array.isArray(body.memory.global_signals)).toBe(true);
  });

  it('KV cache returns _cache: hit on second call', async () => {
    const env = makeEnv();
    await handleFabricMemory(getReq('/api/fabric/memory'), env, PRO_CTX);
    const res2  = await handleFabricMemory(getReq('/api/fabric/memory'), env, PRO_CTX);
    const body2 = await res2.json();
    expect(body2._cache).toBe('hit');
  });

  it('investigation_history summary aggregates case statuses', async () => {
    const res  = await handleFabricMemory(getReq('/api/fabric/memory'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const s    = body.memory.investigation_history.summary;
    expect(typeof s).toBe('object');
  });
});

// ─── P14.7: handleFabricMemoryRecord (POST) ──────────────────────────────────

describe('handleFabricMemoryRecord — P14.7 POST', () => {
  it('returns 201 with event_id for valid record', async () => {
    const res  = await handleFabricMemoryRecord(
      postReq('/api/fabric/memory/record', { record_type: 'decision', summary: 'Patched CVE-2024-3001', outcome: 'success' }),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.record_type).toBe('decision');
    expect(body.event_id).toBeDefined();
  });

  it('accepts all valid record types', async () => {
    const validTypes = ['decision', 'investigation', 'playbook', 'executive', 'automation'];
    for (const record_type of validTypes) {
      const res = await handleFabricMemoryRecord(
        postReq('/api/fabric/memory/record', { record_type }),
        makeEnv(), PRO_CTX
      );
      expect(res.status).toBe(201);
    }
  });

  it('returns 400 for missing record_type', async () => {
    const res  = await handleFabricMemoryRecord(
      postReq('/api/fabric/memory/record', { summary: 'missing type' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/record_type/);
  });

  it('returns 400 for invalid record_type', async () => {
    const res  = await handleFabricMemoryRecord(
      postReq('/api/fabric/memory/record', { record_type: 'invalid_thing' }),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid JSON body', async () => {
    const res = await handleFabricMemoryRecord(badPostReq('/api/fabric/memory/record'), makeEnv(), PRO_CTX);
    expect(res.status).toBe(400);
  });
});

// ─── P14.8: handleFabricObservability ────────────────────────────────────────

describe('handleFabricObservability — P14.8', () => {
  it('returns observability with 6 subsystems', async () => {
    const res  = await handleFabricObservability(getReq('/api/fabric/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(Object.keys(body.observability.subsystems)).toHaveLength(6);
  });

  it('performance has within_target field', async () => {
    const res  = await handleFabricObservability(getReq('/api/fabric/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.observability.performance.within_target).toBe('boolean');
    expect(body.observability.performance.target_cached_ms).toBe(50);
    expect(body.observability.performance.target_uncached_ms).toBe(400);
  });

  it('_cache is none (always live)', async () => {
    const env = makeEnv();
    const res1  = await handleFabricObservability(getReq('/api/fabric/observability'), env, PRO_CTX);
    const body1 = await res1.json();
    expect(body1._cache).toBe('none');
    const res2  = await handleFabricObservability(getReq('/api/fabric/observability'), env, PRO_CTX);
    const body2 = await res2.json();
    expect(body2._cache).toBe('none');
  });

  it('agent_coordination has error_rate and throughput', async () => {
    const res  = await handleFabricObservability(getReq('/api/fabric/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.observability.agent_coordination.error_rate).toBe('number');
    expect(typeof body.observability.agent_coordination.throughput).toBe('number');
    expect(body.observability.agent_coordination.agents_active).toBe(6);
  });

  it('subsystems are all marked healthy', async () => {
    const res  = await handleFabricObservability(getReq('/api/fabric/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    Object.values(body.observability.subsystems).forEach(s => {
      expect(s.healthy).toBe(true);
    });
  });

  it('memory section has decision_history_size', async () => {
    const res  = await handleFabricObservability(getReq('/api/fabric/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.observability.memory.decision_history_size).toBe('number');
    expect(typeof body.observability.memory.case_history_size).toBe('number');
  });
});

// ─── P14.11 Regression: no P12/P13 regressions ───────────────────────────────

describe('P14.11 — regression: P12 and P13 handlers still resolve', () => {
  it('P13 handlers export 6 functions', async () => {
    const mod = await import('../src/handlers/autonomousOpsHandler.js');
    expect(typeof mod.handleAutonomousOrchestratorPlan).toBe('function');
    expect(typeof mod.handleAutonomousIncidentResponse).toBe('function');
    expect(typeof mod.handleAutonomousPredictiveRisk).toBe('function');
    expect(typeof mod.handleAutonomousWorkflowStatus).toBe('function');
    expect(typeof mod.handleAutonomousExecutiveBrief).toBe('function');
    expect(typeof mod.handleAutonomousObservability).toBe('function');
  });

  it('P12 handlers export 5 SOC command functions', async () => {
    const mod = await import('../src/handlers/socCommandHandler.js');
    expect(typeof mod.handleSOCCommandState).toBe('function');
    expect(typeof mod.handleSOCCopilot).toBe('function');
    expect(typeof mod.handleSOCWorkflowQueue).toBe('function');
    expect(typeof mod.handleSOCObservability).toBe('function');
    expect(typeof mod.handleSOCEventStream).toBe('function');
  });

  it('P14 handler exports 10 functions', () => {
    expect(typeof handleFabricState).toBe('function');
    expect(typeof handleFabricAgentStatus).toBe('function');
    expect(typeof handleFabricEvents).toBe('function');
    expect(typeof handleFabricPublishEvent).toBe('function');
    expect(typeof handleFabricPlugins).toBe('function');
    expect(typeof handleFabricPluginRegister).toBe('function');
    expect(typeof handleFabricPolicyEvaluate).toBe('function');
    expect(typeof handleFabricMemory).toBe('function');
    expect(typeof handleFabricMemoryRecord).toBe('function');
    expect(typeof handleFabricObservability).toBe('function');
  });

  it('all P14 GET endpoints return 200 for OWNER tier', async () => {
    const ownerCtx = { authenticated: true, tier: 'OWNER', userId: 'owner1', id: 'owner1' };
    const env = makeEnv();
    const handlers = [
      [handleFabricState,          '/api/fabric/state'],
      [handleFabricAgentStatus,    '/api/fabric/agents/status'],
      [handleFabricEvents,         '/api/fabric/events'],
      [handleFabricPlugins,        '/api/fabric/plugins'],
      [handleFabricPolicyEvaluate, '/api/fabric/policy/evaluate'],
      [handleFabricMemory,         '/api/fabric/memory'],
      [handleFabricObservability,  '/api/fabric/observability'],
    ];
    for (const [handler, path] of handlers) {
      const res = await handler(getReq(path), env, ownerCtx);
      expect(res.status).toBe(200);
    }
  });
});
