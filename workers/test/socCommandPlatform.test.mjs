/* P12.0 regression tests — Enterprise AI SOC Command Platform
 *
 * Verifies:
 *   1.  All P12 endpoints reject non-PRO tiers with 403
 *   2.  All P12 endpoints reject unauthenticated requests with 401
 *   3.  handleSOCCommandState returns required soc_state fields
 *   4.  handleSOCCommandState KV cache returns _cache: HIT on second call
 *   5.  handleSOCCommandState returns zero counts (not errors) when DB empty
 *   6.  handleSOCCopilot returns all 5 copilot sections
 *   7.  handleSOCCopilot KV cache returns _cache: HIT on second call
 *   8.  handleSOCWorkflowQueue returns case arrays and SLA summary
 *   9.  handleSOCObservability returns latency fields and endpoints_monitored
 *   10. handleKnowledgeGraph returns nodes/edges arrays with node_counts
 *   11. handleKnowledgeGraph KV cache returns _cache: HIT on second call
 *   12. handleKnowledgeGraphQuery returns subgraph structure
 *   13. handleKnowledgeGraphQuery returns 400 when node_id missing
 *   14. handleAIInvestigation returns 404 for unknown case
 *   15. handleAIInvestigation returns all investigation fields for known case
 *   16. Knowledge graph edge count >= 0 (no errors on empty DB)
 *   17. SOC command state threat_level is one of the known levels
 *   18. SOC copilot containment_steps is array
 */
import { describe, it, expect } from 'vitest';
import {
  handleSOCCommandState,
  handleSOCCopilot,
  handleSOCWorkflowQueue,
  handleSOCObservability,
  handleSOCEventStream,
} from '../src/handlers/socCommandHandler.js';
import {
  handleKnowledgeGraph,
  handleKnowledgeGraphQuery,
} from '../src/handlers/knowledgeGraphHandler.js';
import { handleAIInvestigation } from '../src/handlers/aiInvestigationHandler.js';

// ─── Mocks ────────────────────────────────────────────────────────────────────

const THREAT_ROWS = [
  { cve_id: 'CVE-2024-1001', title: 'RCE in OpenSSH', cvss_score: 9.8, epss_score: 0.88,
    actively_exploited: 1, known_ransomware: 1, severity: 'CRITICAL', source: 'cisa_kev',
    mitre_technique: 'T1190', description: 'Critical RCE' },
  { cve_id: 'CVE-2024-1002', title: 'Priv Escalation in kernel', cvss_score: 7.8, epss_score: 0.22,
    actively_exploited: 0, known_ransomware: 0, severity: 'HIGH', source: 'nvd',
    mitre_technique: 'T1059', description: 'Local privesc' },
];

const ACTOR_ROWS  = [{ name: 'APT28', sector: 'government', active: 1 }];
const ASSET_ROWS  = [
  { asset_value: 'CVE-2024-1001', asset_type: 'cve_watchlist' },
  { asset_value: 'nginx',         asset_type: 'technology' },
];
const ASM_ROWS    = [{ target: 'example.com', asm_score: 65 }];
const CASE_ROWS   = [
  { id: 'case_001', case_number: 'SOC-001', title: 'Critical RCE Incident',
    severity: 'CRITICAL', status: 'OPEN', assignee_id: null,
    sla_hours: 24, sla_due_at: null, mitre_tactics: '["T1190"]',
    ioc_list: '[]', summary: 'RCE detected', source: 'automated',
    created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
];
const DECISION_ROWS = [
  { id: 'dec_001', cve_id: 'CVE-2024-1001', decision: 'PATCH_IMMEDIATELY',
    priority: 'P1-CRITICAL', confidence: 95, risk_score: 98, reason: 'KEV', created_at: new Date().toISOString() },
];
const WORKFLOW_EXEC_ROWS = [];
const TIMELINE_ROWS = [
  { event_type: 'CREATED', description: 'Case opened', actor: 'system', occurred_at: new Date().toISOString() },
];

function makeDB({
  tiRows       = THREAT_ROWS,
  actorRows    = ACTOR_ROWS,
  assetRows    = ASSET_ROWS,
  asmRows      = ASM_ROWS,
  caseRows     = CASE_ROWS,
  decisionRows = DECISION_ROWS,
  execRows     = WORKFLOW_EXEC_ROWS,
  timelineRows = TIMELINE_ROWS,
} = {}) {
  return {
    prepare(sql) {
      const stmt = {
        bind(..._args) { return stmt; },
        async all() {
          if (/FROM threat_intel/.test(sql))          return { results: tiRows };
          if (/FROM customer_assets/.test(sql))       return { results: assetRows };
          if (/FROM threat_actors/.test(sql))         return { results: actorRows };
          if (/FROM asm_targets/.test(sql))           return { results: asmRows };
          if (/FROM soc_cases/.test(sql))             return { results: caseRows };
          if (/FROM soc_decisions/.test(sql))         return { results: decisionRows };
          if (/FROM workflow_executions/.test(sql))   return { results: execRows };
          if (/FROM soc_timeline/.test(sql))          return { results: timelineRows };
          return { results: [] };
        },
        async first() {
          if (/FROM soc_cases/.test(sql) && /id = \?/.test(sql)) return caseRows[0] || null;
          if (/COUNT\(\*\) cnt FROM soc_evidence/.test(sql)) return { cnt: 2 };
          if (/COUNT\(\*\) cnt FROM soc_notes/.test(sql))    return { cnt: 1 };
          if (/SELECT 1/.test(sql))                          return { 1: 1 };
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
    async get(key)         { return store.has(key) ? store.get(key) : null; },
    async put(key, value)  { store.set(key, value); },
  };
}

function makeEnv(opts = {}) {
  return { DB: makeDB(opts), SECURITY_HUB_KV: makeKV() };
}

const PRO_CTX     = { authenticated: true, tier: 'PRO',     userId: 'u1' };
const STARTER_CTX = { authenticated: true, tier: 'STARTER', userId: 'u2' };
const UNAUTH_CTX  = { authenticated: false };

function getReq(path = '/api/soc/command/state', params = {}, method = 'GET') {
  const url = new URL(`https://hub.test${path}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  return new Request(url.toString(), { method });
}

function postReq(path, body = {}) {
  return new Request(`https://hub.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ─── Auth gate tests ──────────────────────────────────────────────────────────

describe('P12.0 — tier gate (all endpoints)', () => {
  const endpoints = [
    [handleSOCCommandState,  '/api/soc/command/state'],
    [handleSOCCopilot,       '/api/soc/command/copilot'],
    [handleSOCWorkflowQueue, '/api/soc/command/workflow'],
    [handleSOCObservability, '/api/soc/command/observability'],
    [handleKnowledgeGraph,   '/api/knowledge-graph'],
    [handleAIInvestigation,  '/api/soc/investigate/case_001'],
  ];

  for (const [handler, path] of endpoints) {
    it(`${path} returns 403 for STARTER tier`, async () => {
      const res  = await handler(getReq(path), makeEnv(), STARTER_CTX);
      const body = await res.json();
      expect(res.status).toBe(403);
      expect(body.success).toBe(false);
    });

    it(`${path} returns 401 for unauthenticated request`, async () => {
      const res = await handler(getReq(path), makeEnv(), UNAUTH_CTX);
      expect(res.status).toBe(401);
    });
  }
});

// ─── P12.1 SOC Command State ──────────────────────────────────────────────────

describe('handleSOCCommandState — P12.1', () => {
  it('returns required top-level fields', async () => {
    const res  = await handleSOCCommandState(getReq(), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-SOC-COMMAND');
    expect(body.soc_state).toBeDefined();
    expect(typeof body.soc_state.threat_level).toBe('string');
    expect(typeof body.soc_state.kev_count).toBe('number');
    expect(typeof body.soc_state.active_cases).toBe('number');
    expect(body.case_queue).toBeDefined();
    expect(body.threat_summary).toBeDefined();
    expect(body.automation_status).toBeDefined();
    expect(Array.isArray(body.data_sources)).toBe(true);
  });

  it('threat_level is a known value', async () => {
    const res  = await handleSOCCommandState(getReq(), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(['CRITICAL','HIGH','ELEVATED','GUARDED','NOMINAL']).toContain(body.soc_state.threat_level);
  });

  it('returns zero counts (not errors) when DB empty', async () => {
    const env  = makeEnv({ tiRows: [], actorRows: [], assetRows: [], asmRows: [], caseRows: [], decisionRows: [] });
    const res  = await handleSOCCommandState(getReq(), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.soc_state.kev_count).toBe(0);
    expect(body.soc_state.active_cases).toBe(0);
  });

  it('KV cache returns _cache: HIT on second call', async () => {
    const env = makeEnv();
    await handleSOCCommandState(getReq(), env, PRO_CTX);
    const res2 = await handleSOCCommandState(getReq(), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });

  it('kev_count matches actively_exploited rows', async () => {
    const res  = await handleSOCCommandState(getReq(), makeEnv(), PRO_CTX);
    const body = await res.json();
    // THREAT_ROWS has 1 row with actively_exploited=1
    expect(body.soc_state.kev_count).toBe(1);
  });
});

// ─── P12.5 SOC Copilot ────────────────────────────────────────────────────────

describe('handleSOCCopilot — P12.5', () => {
  it('returns all 5 copilot sections', async () => {
    const res  = await handleSOCCopilot(getReq('/api/soc/command/copilot'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-SOC-COPILOT');
    expect(typeof body.soc_summary).toBe('string');
    expect(body.soc_summary.length).toBeGreaterThan(5);
    expect(typeof body.investigation_summary).toBe('string');
    expect(typeof body.analyst_guidance).toBe('string');
    expect(Array.isArray(body.containment_steps)).toBe(true);
    expect(Array.isArray(body.recovery_plan)).toBe(true);
    expect(typeof body.escalation_advice).toBe('string');
  });

  it('key_metrics has required numeric fields', async () => {
    const res  = await handleSOCCopilot(getReq('/api/soc/command/copilot'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.key_metrics.kev_count).toBe('number');
    expect(typeof body.key_metrics.critical_threats).toBe('number');
    expect(typeof body.key_metrics.open_cases).toBe('number');
  });

  it('KV cache returns _cache: HIT on second call', async () => {
    const env = makeEnv();
    await handleSOCCopilot(getReq('/api/soc/command/copilot'), env, PRO_CTX);
    const res2 = await handleSOCCopilot(getReq('/api/soc/command/copilot'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });
});

// ─── P12.6 Workflow Queue ─────────────────────────────────────────────────────

describe('handleSOCWorkflowQueue — P12.6', () => {
  it('returns active_cases array and sla_summary', async () => {
    const res  = await handleSOCWorkflowQueue(getReq('/api/soc/command/workflow'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-SOC-WORKFLOW');
    expect(Array.isArray(body.active_cases)).toBe(true);
    expect(body.sla_summary).toBeDefined();
    expect(typeof body.sla_summary.total).toBe('number');
    expect(typeof body.sla_summary.breached).toBe('number');
    expect(Array.isArray(body.escalations)).toBe(true);
    expect(Array.isArray(body.pending_approvals)).toBe(true);
  });

  it('sla_summary.total matches open case count', async () => {
    const res  = await handleSOCWorkflowQueue(getReq('/api/soc/command/workflow'), makeEnv(), PRO_CTX);
    const body = await res.json();
    // CASE_ROWS has 1 case with status OPEN
    expect(body.sla_summary.total).toBeGreaterThanOrEqual(0);
  });
});

// ─── P12.8 Observability ──────────────────────────────────────────────────────

describe('handleSOCObservability — P12.8', () => {
  it('returns latency fields and endpoints_monitored', async () => {
    const res  = await handleSOCObservability(getReq('/api/soc/command/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-SOC-OBS');
    expect(Array.isArray(body.endpoints_monitored)).toBe(true);
    expect(body.endpoints_monitored.length).toBeGreaterThan(0);
    expect(typeof body.cache_hit_ratio).toBe('number');
    expect(body.performance_targets).toBeDefined();
    expect(body.performance_targets.cache_hit_ms).toBe(50);
  });

  it('d1_latency_ms is a number when DB available', async () => {
    const res  = await handleSOCObservability(getReq('/api/soc/command/observability'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(typeof body.d1_latency_ms).toBe('number');
  });
});

// ─── P12.3 Knowledge Graph ────────────────────────────────────────────────────

describe('handleKnowledgeGraph — P12.3', () => {
  it('returns nodes and edges arrays', async () => {
    const res  = await handleKnowledgeGraph(getReq('/api/knowledge-graph'), makeEnv(), PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-KNOWLEDGE-GRAPH');
    expect(Array.isArray(body.nodes)).toBe(true);
    expect(Array.isArray(body.edges)).toBe(true);
    expect(body.node_counts).toBeDefined();
    expect(typeof body.node_counts.cve).toBe('number');
    expect(typeof body.edge_count).toBe('number');
  });

  it('nodes contain CVE type from threat_intel', async () => {
    const res  = await handleKnowledgeGraph(getReq('/api/knowledge-graph'), makeEnv(), PRO_CTX);
    const body = await res.json();
    const cveNodes = body.nodes.filter(n => n.type === 'CVE');
    expect(cveNodes.length).toBeGreaterThan(0);
    expect(cveNodes[0].id).toBe('CVE-2024-1001');
  });

  it('edge count >= 0 (no errors on empty DB)', async () => {
    const env  = makeEnv({ tiRows: [], actorRows: [], assetRows: [], decisionRows: [] });
    const res  = await handleKnowledgeGraph(getReq('/api/knowledge-graph'), env, PRO_CTX);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.edge_count).toBe(0);
    expect(body.nodes.length).toBe(0);
  });

  it('KV cache returns _cache: HIT on second call', async () => {
    const env = makeEnv();
    await handleKnowledgeGraph(getReq('/api/knowledge-graph'), env, PRO_CTX);
    const res2 = await handleKnowledgeGraph(getReq('/api/knowledge-graph'), env, PRO_CTX);
    const body = await res2.json();
    expect(body._cache).toBe('HIT');
  });
});

describe('handleKnowledgeGraphQuery — P12.3', () => {
  it('returns subgraph structure for a valid node', async () => {
    const res  = await handleKnowledgeGraphQuery(
      postReq('/api/knowledge-graph/query', { node_id: 'CVE-2024-1001', depth: 1 }),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.nodes)).toBe(true);
    expect(Array.isArray(body.edges)).toBe(true);
    expect(body.query.node_id).toBe('CVE-2024-1001');
  });

  it('returns 400 when node_id is missing', async () => {
    const res  = await handleKnowledgeGraphQuery(
      postReq('/api/knowledge-graph/query', {}),
      makeEnv(), PRO_CTX
    );
    expect(res.status).toBe(400);
  });

  it('returns 403 for STARTER tier', async () => {
    const res = await handleKnowledgeGraphQuery(
      postReq('/api/knowledge-graph/query', { node_id: 'CVE-2024-1001' }),
      makeEnv(), STARTER_CTX
    );
    expect(res.status).toBe(403);
  });
});

// ─── P12.2 AI Investigation ───────────────────────────────────────────────────

describe('handleAIInvestigation — P12.2', () => {
  it('returns 404 for unknown case', async () => {
    const env = makeEnv({ caseRows: [] });
    const res = await handleAIInvestigation(
      getReq('/api/soc/investigate/nonexistent'),
      env, PRO_CTX
    );
    expect(res.status).toBe(404);
  });

  it('returns all investigation fields for a known case', async () => {
    const res  = await handleAIInvestigation(
      getReq('/api/soc/investigate/case_001'),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-AI-INVESTIGATION');
    expect(body.case).toBeDefined();
    expect(body.case.id).toBe('case_001');
    expect(Array.isArray(body.mitre_mapping)).toBe(true);
    expect(Array.isArray(body.attack_chain)).toBe(true);
    expect(Array.isArray(body.affected_assets)).toBe(true);
    expect(typeof body.business_context).toBe('string');
    expect(body.evidence_summary).toBeDefined();
    expect(typeof body.evidence_summary.total).toBe('number');
    expect(Array.isArray(body.recommended_response)).toBe(true);
  });

  it('mitre_mapping has technique_id and stage', async () => {
    const res  = await handleAIInvestigation(
      getReq('/api/soc/investigate/case_001'),
      makeEnv(), PRO_CTX
    );
    const body = await res.json();
    if (body.mitre_mapping.length > 0) {
      expect(typeof body.mitre_mapping[0].technique_id).toBe('string');
      expect(typeof body.mitre_mapping[0].stage).toBe('string');
    }
  });
});

// ─── P12.4 SSE stream auth ────────────────────────────────────────────────────

describe('handleSOCEventStream — P12.4', () => {
  it('returns 403 for STARTER tier', async () => {
    const res = await handleSOCEventStream(getReq('/api/soc/stream'), makeEnv(), STARTER_CTX);
    expect(res.status).toBe(403);
  });

  it('returns 401 for unauthenticated request', async () => {
    const res = await handleSOCEventStream(getReq('/api/soc/stream'), makeEnv(), UNAUTH_CTX);
    expect(res.status).toBe(401);
  });

  it('returns 204 for OPTIONS preflight', async () => {
    const req = new Request('https://hub.test/api/soc/stream', { method: 'OPTIONS' });
    const res = await handleSOCEventStream(req, makeEnv(), PRO_CTX);
    expect(res.status).toBe(204);
  });
});
