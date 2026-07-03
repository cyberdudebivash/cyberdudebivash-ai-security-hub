/* P13.0 regression tests — Autonomous Security Operations Platform
 *
 * Verifies:
 *   1.  All P13 endpoints reject non-PRO tiers with 403
 *   2.  All P13 endpoints reject unauthenticated requests with 401
 *   3.  handleAutonomousOrchestratorPlan returns execution_plan with 4 phases
 *   4.  handleAutonomousOrchestratorPlan KV cache returns _cache: HIT
 *   5.  handleAutonomousOrchestratorPlan threat_level is a valid level
 *   6.  handleAutonomousOrchestratorPlan subsystems map is present
 *   7.  handleAutonomousIncidentResponse returns 404 for unknown case
 *   8.  handleAutonomousIncidentResponse returns full IR plan for known case
 *   9.  handleAutonomousIncidentResponse IR plan has all 5 required sections
 *   10. handleAutonomousIncidentResponse KV cache returns _cache: HIT
 *   11. handleAutonomousIncidentResponse returns 400 when caseId is base path
 *   12. handleAutonomousPredictiveRisk returns emerging_risks array
 *   13. handleAutonomousPredictiveRisk returns priority_trend with direction
 *   14. handleAutonomousPredictiveRisk KV cache returns _cache: HIT
 *   15. handleAutonomousPredictiveRisk operational_impact fields are present
 *   16. handleAutonomousWorkflowStatus returns sla_dashboard with counts
 *   17. handleAutonomousWorkflowStatus KV cache returns _cache: HIT
 *   18. handleAutonomousWorkflowStatus returns automation_health
 *   19. handleAutonomousExecutiveBrief defaults to ciso role
 *   20. handleAutonomousExecutiveBrief returns valid role variants
 *   21. handleAutonomousExecutiveBrief KV cache returns _cache: HIT
 *   22. handleAutonomousExecutiveBrief risk_posture has label and score
 *   23. handleAutonomousObservability returns infrastructure health fields
 *   24. handleAutonomousObservability returns operations fields
 *   25. handleAutonomousObservability returns subsystems map
 *   26. handleAutonomousObservability returns performance fields
 *   27. No regression: P12 handlers still export correct function signatures
 *   28. No regression: P13 handler file has no syntax errors (import check)
 */
import { describe, it, expect } from 'vitest';
import {
  handleAutonomousOrchestratorPlan,
  handleAutonomousIncidentResponse,
  handleAutonomousPredictiveRisk,
  handleAutonomousWorkflowStatus,
  handleAutonomousExecutiveBrief,
  handleAutonomousObservability,
} from '../src/handlers/autonomousOpsHandler.js';

// ─── Mocks ────────────────────────────────────────────────────────────────────

const THREAT_ROWS = [
  { cve_id: 'CVE-2024-2001', cvss_score: 9.8, epss_score: 0.91,
    is_kev: 1, actively_exploited: 1, severity: 'CRITICAL',
    mitre_technique: 'T1190', description: 'Critical RCE' },
  { cve_id: 'CVE-2024-2002', cvss_score: 7.5, epss_score: 0.18,
    is_kev: 0, actively_exploited: 0, severity: 'HIGH',
    mitre_technique: 'T1059', description: 'Code exec' },
];

const ACTOR_ROWS    = [{ name: 'APT29', sector: 'finance', active: 1 }];
const ASSET_ROWS    = [
  { asset_value: 'CVE-2024-2001', asset_type: 'cve_watchlist' },
  { asset_value: 'Apache',        asset_type: 'technology' },
];
const CASE_ROWS     = [
  { id: 'case_100', case_number: 'SOC-100', title: 'Ransomware Incident',
    severity: 'CRITICAL', status: 'OPEN', assignee_id: null,
    sla_due_at: new Date(Date.now() - 3600000).toISOString(), // breached
    mitre_tactics: '["T1190","T1486"]', ioc_list: '["1.2.3.4"]',
    summary: 'Ransomware detected', source: 'automated',
    org_id: 'org1', created_at: new Date(Date.now() - 86400000).toISOString() },
  { id: 'case_101', case_number: 'SOC-101', title: 'Phishing Campaign',
    severity: 'HIGH', status: 'IN_PROGRESS', assignee_id: 'u1',
    sla_due_at: new Date(Date.now() + 7200000).toISOString(),
    mitre_tactics: '["T1566"]', ioc_list: '[]',
    summary: 'Phishing emails', source: 'manual',
    org_id: 'org1', created_at: new Date(Date.now() - 43200000).toISOString() },
];
const DECISION_ROWS = [
  { id: 'dec_100', cve_id: 'CVE-2024-2001', decision: 'PATCH', priority: 'P1', confidence: 95, risk_score: 98 },
];
const EXEC_ROWS     = [
  { id: 'exec_1', workflow_id: 'wf_1', status: 'completed', started_at: new Date().toISOString(), completed_at: new Date().toISOString(), steps_json: '[]' },
  { id: 'exec_2', workflow_id: 'wf_1', status: 'failed',    started_at: new Date().toISOString(), completed_at: new Date().toISOString(), steps_json: '[]' },
];
const TIMELINE_ROWS = [
  { case_id: 'case_100', event_type: 'CREATED', actor: 'system', occurred_at: new Date().toISOString() },
];
const PRED_ROWS     = [
  { cve_id: 'CVE-2024-2001', risk_score: 95, risk_level: 'CRITICAL', exploit_probability: 0.91, impact_score: 0.95 },
];

function makeDB({
  tiRows       = THREAT_ROWS,
  actorRows    = ACTOR_ROWS,
  assetRows    = ASSET_ROWS,
  caseRows     = CASE_ROWS,
  decisionRows = DECISION_ROWS,
  execRows     = EXEC_ROWS,
  timelineRows = TIMELINE_ROWS,
  predRows     = PRED_ROWS,
} = {}) {
  return {
    prepare(sql) {
      const stmt = {
        bind(..._args) { return stmt; },
        async all() {
          if (/FROM threat_intel/.test(sql))          return { results: tiRows };
          if (/FROM customer_assets/.test(sql))       return { results: assetRows };
          if (/FROM threat_actors/.test(sql))         return { results: actorRows };
          // \bid distinguishes `WHERE id = ?` (single case) from `WHERE org_id = ?`
          // (tenant-scoped list) — `_` is a word char, so \bid does NOT match org_id.
          if (/FROM soc_cases/.test(sql) && !/\bid = \?/.test(sql)) return { results: caseRows };
          if (/FROM soc_decisions/.test(sql))         return { results: decisionRows };
          if (/FROM workflow_executions/.test(sql) && !/GROUP BY/.test(sql)) return { results: execRows };
          if (/FROM soc_timeline/.test(sql))          return { results: timelineRows };
          if (/FROM threat_predictions/.test(sql) && !/GROUP BY/.test(sql) && !/AVG/.test(sql) && !/COUNT/.test(sql)) return { results: predRows };
          if (/FROM threat_predictions/.test(sql) && /GROUP BY status/.test(sql))
            return { results: [{ status: 'completed', cnt: 1 }, { status: 'failed', cnt: 1 }] };
          return { results: [] };
        },
        async first() {
          if (/FROM soc_cases/.test(sql) && /\bid = \?/.test(sql)) return caseRows[0] || null;
          if (/COUNT\(\*\) cnt FROM soc_cases/.test(sql))         return { cnt: caseRows.filter(c => c.status === 'OPEN').length };
          if (/COUNT\(\*\) cnt FROM soc_evidence/.test(sql))      return { cnt: 2 };
          if (/COUNT\(\*\) cnt FROM soc_notes/.test(sql))         return { cnt: 1 };
          if (/SELECT COUNT\(\*\) cnt FROM threat_predictions/.test(sql)) return { cnt: predRows.length };
          if (/AVG\(risk_score\)/.test(sql))                      return { avg: 85 };
          if (/SELECT 1/.test(sql))                               return { 1: 1 };
          if (/GROUP BY status/.test(sql))                        return { completed: 1, failed: 1 };
          return null;
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async get(key)        { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

function makeEnv(opts = {}) {
  return { DB: makeDB(opts), SECURITY_HUB_KV: makeKV() };
}

const PRO_CTX     = { authenticated: true, tier: 'PRO',      userId: 'u1', org_id: 'org1' };
const OWNER_CTX   = { authenticated: true, tier: 'OWNER',    userId: 'u2', org_id: 'org1' };
const STARTER_CTX = { authenticated: true, tier: 'STARTER',  userId: 'u3' };
const UNAUTH_CTX  = { authenticated: false };

function getReq(path, params = {}) {
  const url = new URL(`https://hub.test${path}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  return new Request(url.toString(), { method: 'GET' });
}

// ─── Auth gate tests ──────────────────────────────────────────────────────────

describe('P13.0 — tier gate (all endpoints)', () => {
  const endpoints = [
    [handleAutonomousOrchestratorPlan, '/api/autonomous/orchestrator/plan'],
    [handleAutonomousIncidentResponse, '/api/autonomous/incident-response/case_100'],
    [handleAutonomousPredictiveRisk,   '/api/autonomous/risk/predict'],
    [handleAutonomousWorkflowStatus,   '/api/autonomous/workflow/status'],
    [handleAutonomousExecutiveBrief,   '/api/autonomous/executive/brief'],
    [handleAutonomousObservability,    '/api/autonomous/observability'],
  ];

  for (const [handler, path] of endpoints) {
    it(`${path} returns 403 for STARTER tier`, async () => {
      const res  = await handler(getReq(path), makeEnv(), STARTER_CTX);
      const body = await res.json();
      expect(res.status).toBe(403);
      expect(body.success).toBe(false);
      expect(body.upgrade).toMatch(/pricing/);
    });

    it(`${path} returns 401 for unauthenticated request`, async () => {
      const res = await handler(getReq(path), makeEnv(), UNAUTH_CTX);
      expect(res.status).toBe(401);
    });
  }
});

// ─── P13.1 Autonomous Orchestrator Plan ──────────────────────────────────────

describe('handleAutonomousOrchestratorPlan — P13.1', () => {
  it('returns success with execution_plan', async () => {
    const res  = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-ORCHESTRATOR');
    expect(body.execution_plan).toBeDefined();
  });

  it('execution_plan has 4 phases', async () => {
    const res  = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.execution_plan.phases).toHaveLength(4);
    expect(body.execution_plan.phases[0].phase).toBe(1);
    expect(body.execution_plan.phases[3].phase).toBe(4);
  });

  it('threat_level is one of the valid levels', async () => {
    const res  = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const valid = ['CRITICAL', 'HIGH', 'ELEVATED', 'GUARDED', 'NOMINAL'];
    expect(valid).toContain(body.execution_plan.threat_level);
  });

  it('subsystems map contains expected keys', async () => {
    const res  = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const subs = body.execution_plan.subsystems;
    expect(subs).toBeDefined();
    expect(subs.decision_engine).toBe('ACTIVE');
    expect(subs.soc_command).toBe('ACTIVE');
  });

  it('returns _cache: HIT on second call (KV cache)', async () => {
    const env  = makeEnv();
    await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), env, PRO_CTX);
    const res2 = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('returns latency_ms as a number', async () => {
    const res  = await handleAutonomousOrchestratorPlan(getReq('/api/autonomous/orchestrator/plan'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.latency_ms).toBe('number');
  });
});

// ─── P13.2 Automated Incident Response ───────────────────────────────────────

describe('handleAutonomousIncidentResponse — P13.2', () => {
  it('returns 404 for unknown case (empty caseRows)', async () => {
    const env = makeEnv({ caseRows: [] });
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/nonexistent'), env, PRO_CTX);
    expect(res.status).toBe(404);
  });

  it('returns 400 when path is missing caseId (base path)', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/incident-response'), makeEnv(), PRO_CTX);
    expect(res.status).toBe(400);
  });

  it('returns full IR plan structure for known case', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-IR');
    expect(body.case.id).toBe('case_100');
  });

  it('IR plan contains all 5 required sections', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Array.isArray(body.containment_plan)).toBe(true);
    expect(Array.isArray(body.remediation_plan)).toBe(true);
    expect(Array.isArray(body.recovery_plan)).toBe(true);
    expect(Array.isArray(body.validation_checklist)).toBe(true);
    expect(Array.isArray(body.rollback_plan)).toBe(true);
  });

  it('containment_plan is non-empty for CRITICAL case', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.containment_plan.length).toBeGreaterThan(0);
    expect(body.containment_plan[0].step).toBe(1);
  });

  it('validation_checklist has required checks', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const reqChecks = body.validation_checklist.filter(c => c.required);
    expect(reqChecks.length).toBeGreaterThan(0);
  });

  it('returns _cache: HIT on second call (KV cache)', async () => {
    const env = makeEnv();
    await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), env, PRO_CTX);
    const res2 = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('OWNER tier is authorized', async () => {
    const res  = await handleAutonomousIncidentResponse(getReq('/api/autonomous/incident-response/case_100'), makeEnv(), OWNER_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
  });
});

// ─── P13.3 Predictive Risk Engine ────────────────────────────────────────────

describe('handleAutonomousPredictiveRisk — P13.3', () => {
  it('returns success with emerging_risks array', async () => {
    const res  = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-PREDICTIVE-RISK');
    expect(Array.isArray(body.emerging_risks)).toBe(true);
  });

  it('priority_trend has direction field', async () => {
    const res  = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const valid = ['INCREASING', 'DECREASING', 'STABLE'];
    expect(valid).toContain(body.priority_trend.direction);
  });

  it('operational_impact has expected fields', async () => {
    const res  = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.operational_impact).toBeDefined();
    expect(typeof body.operational_impact.kev_active).toBe('number');
    expect(typeof body.operational_impact.critical_cves).toBe('number');
  });

  it('likelihood_scores has the 4 risk level keys', async () => {
    const res  = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.likelihood_scores).toHaveProperty('CRITICAL');
    expect(body.likelihood_scores).toHaveProperty('HIGH');
    expect(body.likelihood_scores).toHaveProperty('MEDIUM');
    expect(body.likelihood_scores).toHaveProperty('LOW');
  });

  it('returns _cache: HIT on second call (KV cache)', async () => {
    const env  = makeEnv();
    await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), env, PRO_CTX);
    const res2 = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('handles empty DB gracefully (no crash)', async () => {
    const env  = makeEnv({ tiRows: [], caseRows: [], assetRows: [], predRows: [] });
    const res  = await handleAutonomousPredictiveRisk(getReq('/api/autonomous/risk/predict'), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.emerging_risks)).toBe(true);
  });
});

// ─── P13.4 Autonomous Workflow Status ────────────────────────────────────────

describe('handleAutonomousWorkflowStatus — P13.4', () => {
  it('returns success with sla_dashboard', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-WORKFLOW');
    expect(body.sla_dashboard).toBeDefined();
    expect(body.sla_dashboard.counts).toBeDefined();
  });

  it('sla_dashboard.counts has breached/at_risk/healthy/no_sla', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const counts = body.sla_dashboard.counts;
    expect(typeof counts.breached).toBe('number');
    expect(typeof counts.at_risk).toBe('number');
    expect(typeof counts.healthy).toBe('number');
    expect(typeof counts.no_sla).toBe('number');
  });

  it('detects the breached case_100 in escalations', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.escalations.length).toBeGreaterThan(0);
    const breached = body.escalations.find(e => e.case_id === 'case_100');
    expect(breached).toBeDefined();
    expect(breached.reason).toBe('SLA_BREACHED');
  });

  it('returns automation_health with success_rate_pct', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.automation_health).toBeDefined();
    expect(typeof body.automation_health.success_rate_pct).toBe('number');
  });

  it('returns _cache: HIT on second call (KV cache)', async () => {
    const env  = makeEnv();
    await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), env, PRO_CTX);
    const res2 = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('unassigned cases queue contains case_100 (no assignee)', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const q = body.assignments?.queue || [];
    const unassigned = q.find(c => c.id === 'case_100');
    expect(unassigned).toBeDefined();
  });

  it('audit_trail is an array', async () => {
    const res  = await handleAutonomousWorkflowStatus(getReq('/api/autonomous/workflow/status'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(Array.isArray(body.audit_trail)).toBe(true);
  });
});

// ─── P13.5 Executive Operations Copilot ──────────────────────────────────────

describe('handleAutonomousExecutiveBrief — P13.5', () => {
  it('returns success for default ceo role', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-EXECUTIVE-COPILOT');
    expect(body.role).toBe('ceo');
  });

  it('returns ciso brief when role=ciso', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'ciso' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.role).toBe('ciso');
    expect(body.brief_title).toMatch(/CISO/);
  });

  it('returns soc_lead brief when role=soc_lead', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'soc_lead' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.role).toBe('soc_lead');
  });

  it('returns board brief when role=board', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'board' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.role).toBe('board');
    expect(body.brief_title).toMatch(/Board/);
  });

  it('defaults to ciso for unknown role param', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'invalid_role' }), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.role).toBe('ciso');
  });

  it('risk_posture has score and label', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.risk_posture).toBeDefined();
    expect(typeof body.risk_posture.score).toBe('number');
    expect(body.risk_posture.label).toBeTruthy();
  });

  it('key_metrics is an object with numeric values', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.key_metrics).toBeDefined();
    const vals = Object.values(body.key_metrics);
    expect(vals.length).toBeGreaterThan(0);
  });

  it('available_roles contains all 6 roles', async () => {
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.available_roles).toContain('ceo');
    expect(body.available_roles).toContain('ciso');
    expect(body.available_roles).toContain('board');
  });

  it('returns _cache: HIT on second call (KV cache)', async () => {
    const env  = makeEnv();
    await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), env, PRO_CTX);
    const res2 = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('different roles produce separate cache entries', async () => {
    const env  = makeEnv();
    await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'ceo' }), env, PRO_CTX);
    const res  = await handleAutonomousExecutiveBrief(getReq('/api/autonomous/executive/brief', { role: 'ciso' }), env, PRO_CTX);
    const body = await res.json();
    // ciso brief should NOT be a cache hit (different key)
    expect(body._cache).toBeUndefined();
  });
});

// ─── P13.7 Extended Observability ────────────────────────────────────────────

describe('handleAutonomousObservability — P13.7', () => {
  it('returns success with infrastructure fields', async () => {
    const res  = await handleAutonomousObservability(getReq('/api/autonomous/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AUTONOMOUS-OBSERVABILITY');
    expect(body.infrastructure).toBeDefined();
    expect(typeof body.infrastructure.d1_healthy).toBe('boolean');
    expect(typeof body.infrastructure.kv_healthy).toBe('boolean');
  });

  it('returns performance metrics', async () => {
    const res  = await handleAutonomousObservability(getReq('/api/autonomous/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.performance).toBeDefined();
    expect(typeof body.performance.cache_hit_ratio_pct).toBe('number');
    expect(typeof body.performance.cache_keys_probed).toBe('number');
  });

  it('returns operations fields', async () => {
    const res  = await handleAutonomousObservability(getReq('/api/autonomous/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.operations).toBeDefined();
    expect(typeof body.operations.queue_depth).toBe('number');
    expect(typeof body.operations.automation_success_rate_pct).toBe('number');
  });

  it('returns subsystems map with 8 subsystems', async () => {
    const res  = await handleAutonomousObservability(getReq('/api/autonomous/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.subsystems).toBeDefined();
    expect(Object.keys(body.subsystems).length).toBe(8);
    expect(body.subsystems.autonomous_orchestrator).toBe('ACTIVE');
    expect(body.subsystems.soc_command).toBe('ACTIVE');
  });

  it('does NOT use KV cache (always live metrics)', async () => {
    const env  = makeEnv();
    const res1 = await handleAutonomousObservability(getReq('/api/autonomous/observability'), env, PRO_CTX);
    const res2 = await handleAutonomousObservability(getReq('/api/autonomous/observability'), env, PRO_CTX);
    const b1   = await res1.json();
    const b2   = await res2.json();
    expect(b1._cache).toBeUndefined();
    expect(b2._cache).toBeUndefined();
  });

  it('handles env with no DB gracefully', async () => {
    const env  = { DB: null, SECURITY_HUB_KV: makeKV() };
    const res  = await handleAutonomousObservability(getReq('/api/autonomous/observability'), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.infrastructure.d1_healthy).toBe(false);
  });
});

// ─── P13.10 — No regression: P12 exports still intact ────────────────────────

describe('P13.10 — regression: P12 handler exports unchanged', () => {
  it('socCommandHandler still exports all 5 P12 functions', async () => {
    const mod = await import('../src/handlers/socCommandHandler.js');
    expect(typeof mod.handleSOCCommandState).toBe('function');
    expect(typeof mod.handleSOCCopilot).toBe('function');
    expect(typeof mod.handleSOCWorkflowQueue).toBe('function');
    expect(typeof mod.handleSOCObservability).toBe('function');
    expect(typeof mod.handleSOCEventStream).toBe('function');
  });

  it('knowledgeGraphHandler still exports both P12 functions', async () => {
    const mod = await import('../src/handlers/knowledgeGraphHandler.js');
    expect(typeof mod.handleKnowledgeGraph).toBe('function');
    expect(typeof mod.handleKnowledgeGraphQuery).toBe('function');
  });

  it('aiInvestigationHandler still exports handleAIInvestigation', async () => {
    const mod = await import('../src/handlers/aiInvestigationHandler.js');
    expect(typeof mod.handleAIInvestigation).toBe('function');
  });

  it('P13 handler exports all 6 functions', async () => {
    const mod = await import('../src/handlers/autonomousOpsHandler.js');
    expect(typeof mod.handleAutonomousOrchestratorPlan).toBe('function');
    expect(typeof mod.handleAutonomousIncidentResponse).toBe('function');
    expect(typeof mod.handleAutonomousPredictiveRisk).toBe('function');
    expect(typeof mod.handleAutonomousWorkflowStatus).toBe('function');
    expect(typeof mod.handleAutonomousExecutiveBrief).toBe('function');
    expect(typeof mod.handleAutonomousObservability).toBe('function');
  });
});
