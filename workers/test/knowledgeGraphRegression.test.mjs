// Permanent regression protection — P12.3 Knowledge Graph production outage.
//
// Root cause (confirmed live against a local D1 replica of production):
//   knowledgeGraphHandler.js queried `cve_id`, `cvss_score`, `mitre_technique`
//   (threat_intel) and `sector` (threat_actors) — column names that exist
//   ONLY in workers/schema_master.sql, a migration gated behind a manual,
//   typed-"APPLY" workflow_dispatch (.github/workflows/db-migrate.yml) that
//   has never been run against production. Every query threw "no such
//   column", was swallowed by `.catch(() => [])`, and the handler still
//   returned `success: true` with an empty or partial graph. threat_actors
//   and soc_decisions additionally had no self-healing schema at all, so
//   actor seeding and decision persistence silently no-op'd forever even
//   though their callers reported success.
//
// A second, related defect surfaced while building this suite: threat_actors
// .target_sectors is a JSON array (an actor can target several industries),
// but buildGraph() treated it as a single plain string — even after fixing
// the column name, this produced a garbled node label like
// '["Government","Defense",...]' instead of clean per-sector INDUSTRY nodes.
// Both are fixed in knowledgeGraphHandler.js / threatActorEngine.js /
// decisionEngine.js; this suite locks in both fixes.
//
// This suite deliberately runs against a REAL SQL engine (node:sqlite),
// never workers/schema_master.sql — only the platform's own self-healing
// code paths, exactly replicating production's actual, never-migrated
// state. A hand-rolled string-matching mock would NOT catch a column-name
// regression (it doesn't know what columns exist); only a real, schema-
// validating engine throws "no such column" the way production D1 does,
// which is the exact failure mode that shipped undetected.
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { storeInD1 } from '../src/services/threatIngestion.js';
import { seedThreatActors } from '../src/services/threatActorEngine.js';
import { runDecisionEngine, storeDecisions } from '../src/services/decisionEngine.js';
import { handleKnowledgeGraph, handleKnowledgeGraphQuery } from '../src/handlers/knowledgeGraphHandler.js';

// ─── Real-SQLite D1 shim ──────────────────────────────────────────────────────
// Implements only the subset of the D1 API this codebase actually calls
// (.prepare().bind().all()/.first()/.run(), .batch()), backed by a real
// SQLite engine so schema errors behave like production, not like a mock.
function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');

  function wrap(sql) {
    let bound = [];
    return {
      bind(...args) { bound = args; return this; },
      async all() {
        const rows = sqlite.prepare(sql).all(...bound);
        return { results: rows };
      },
      async first() {
        const row = sqlite.prepare(sql).get(...bound);
        return row ?? null;
      },
      async run() {
        const info = sqlite.prepare(sql).run(...bound);
        return { success: true, meta: { changes: info.changes } };
      },
    };
  }

  return {
    _sqlite: sqlite,
    prepare(sql) { return wrap(sql); },
    async batch(stmts) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
  };
}

function tableNames(db) {
  return db._sqlite.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all().map(r => r.name);
}

function columnNames(db, table) {
  return db._sqlite.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
}

const AUTH_ENTERPRISE = { authenticated: true, tier: 'ENTERPRISE', userId: 'u1', isAdmin: false };

function req(url, method = 'GET', body) {
  return new Request(url, {
    method,
    ...(body ? { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } } : {}),
  });
}

describe('Knowledge Graph — production self-healing schema regression (no schema_master.sql)', () => {
  let env;

  beforeEach(() => {
    env = { DB: makeRealD1() };
    // schema_master.sql is never loaded anywhere in this suite. Everything
    // below must come only from the platform's own self-healing code paths —
    // exactly like the real, never-migrated production database.
  });

  it('starts with zero tables — proves no schema_master.sql dependency exists anywhere in setup', () => {
    expect(tableNames(env.DB)).toEqual([]);
  });

  it('a completely empty, never-seeded platform returns success:true with an honest empty graph (no crash)', async () => {
    const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.node_counts).toEqual({ cve: 0, actor: 0, asset: 0, decision: 0, industry: 0, campaign: 0 });
    expect(body.edge_count).toBe(0);
  });

  describe('once real data flows through the real production write paths', () => {
    const CVE_ALPHA = {
      id: 'CVE-2026-30001', title: 'SQL Injection in Acme Portal Login', severity: 'CRITICAL',
      cvss: 9.8, description: 'Unauthenticated SQL injection in the login endpoint.',
      source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-30001',
      published_at: '2026-06-01T00:00:00Z', exploit_status: 'confirmed', known_ransomware: 0,
      tags: '[]', iocs: '[]', affected_products: '["Acme Portal 3.x"]', weakness_types: '["CWE-89"]',
      epss_score: 0.92, epss_percentile: 0.98, actively_exploited: 1, exploit_available: 1,
    };
    const CVE_BETA = {
      ...CVE_ALPHA, id: 'CVE-2026-30002', title: 'SQL Injection in Beta Corp Admin Panel',
      source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-30002',
    };
    const CVE_GAMMA_UNMAPPED = {
      id: 'CVE-2026-30003', title: 'Unspecified issue', severity: 'LOW', cvss: 2.1,
      description: '', source: 'nvd', source_url: null, published_at: '2026-06-01T00:00:00Z',
      exploit_status: null, known_ransomware: 0, tags: '[]', iocs: '[]',
      affected_products: '[]', weakness_types: '[]', epss_score: 0.01, epss_percentile: 0.1,
      actively_exploited: 0, exploit_available: 0,
    };

    beforeEach(async () => {
      // 1. Real CVE ingestion — the same storeInD1() the live hourly cron calls.
      await storeInD1(env.DB, [CVE_ALPHA, CVE_BETA, CVE_GAMMA_UNMAPPED]);
      // 2. Real threat actor seeding — the same seedThreatActors() the admin
      //    POST /seed-threat-actors endpoint calls.
      await seedThreatActors(env);
      // 3. Real decision engine — the same runDecisionEngine()/storeDecisions()
      //    pair the ingestion cron calls (index.js: runDecisionEngine(enriched, detResult)).
      const decisionResult = runDecisionEngine([CVE_ALPHA, CVE_BETA, CVE_GAMMA_UNMAPPED]);
      await storeDecisions(env, decisionResult);
    });

    it('self-heals threat_intel, threat_actors, and soc_decisions from nothing', () => {
      expect(tableNames(env.DB)).toEqual(expect.arrayContaining(['threat_intel', 'threat_actors', 'soc_decisions']));
    });

    it('seeds the real APT database (was: silent seeded:0 forever — no such table)', async () => {
      const result = await seedThreatActors(env); // idempotent re-run via INSERT OR IGNORE
      // NOTE: result.total is APT_DATABASE.length — a static constant that's
      // always 20 regardless of whether the writes actually landed. The only
      // signal that proves persistence is result.seeded plus a direct COUNT.
      expect(result.seeded).toBeGreaterThanOrEqual(20);
      const row = env.DB._sqlite.prepare(`SELECT COUNT(*) AS n FROM threat_actors`).get();
      expect(row.n).toBeGreaterThanOrEqual(20);
    });

    it('persists only the CVEs that actually warrant P1/P2 escalation (was: silent no-op for all of them)', () => {
      const rows = env.DB._sqlite.prepare('SELECT * FROM soc_decisions').all();
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.some(r => r.cve_id === 'CVE-2026-30001')).toBe(true);
      expect(rows.some(r => r.cve_id === 'CVE-2026-30002')).toBe(true);
      // The low-severity, unmapped CVE must NOT produce a stored decision — no fabrication.
      expect(rows.some(r => r.cve_id === 'CVE-2026-30003')).toBe(false);
    });

    it('GET /api/knowledge-graph populates every mandated node type end-to-end', async () => {
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.node_counts.cve).toBe(3);
      expect(body.node_counts.actor).toBeGreaterThanOrEqual(20);
      expect(body.node_counts.industry).toBeGreaterThan(0);
      expect(body.node_counts.decision).toBe(2);
      expect(body.node_counts.campaign).toBeGreaterThan(0);
      // customer_assets was never seeded in this suite — must stay honestly 0, not fabricated.
      expect(body.node_counts.asset).toBe(0);
      expect(body.edge_count).toBeGreaterThan(0);
    });

    it('correlates CVEs sharing a live-computed ATT&CK technique into a CAMPAIGN node (not a phantom mitre_technique column)', async () => {
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
      const body = await res.json();
      const campaign = body.nodes.find(n => n.type === 'CAMPAIGN' && n.technique === 'T1190');
      expect(campaign).toBeDefined();
      const campaignTargets = body.edges.filter(e => e.source === campaign.id).map(e => e.target);
      expect(campaignTargets).toEqual(expect.arrayContaining(['CVE-2026-30001', 'CVE-2026-30002']));
      // The unmapped CVE has no attributable technique and must not be swept in.
      expect(campaignTargets).not.toContain('CVE-2026-30003');
    });

    it('links a DECISION node to its CVE via a mitigates edge', async () => {
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
      const body = await res.json();
      const decisionNode = body.nodes.find(n => n.type === 'DECISION' && n.cve_id === 'CVE-2026-30001');
      expect(decisionNode).toBeDefined();
      expect(decisionNode.priority).toBe('P1-CRITICAL');
      expect(body.edges.some(e =>
        e.source === decisionNode.id && e.target === 'CVE-2026-30001' && e.type === 'mitigates'
      )).toBe(true);
    });

    it('creates one clean INDUSTRY node per real target sector (was: garbled JSON-array-as-string label, or nothing at all)', async () => {
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
      const body = await res.json();
      const actorNode = body.nodes.find(n => n.type === 'ACTOR' && n.label.includes('APT28'));
      expect(actorNode).toBeDefined();
      expect(actorNode.sector).toContain('Government');
      expect(actorNode.sector).not.toContain('['); // must never leak raw JSON into a display field

      const govIndustry = body.nodes.find(n => n.type === 'INDUSTRY' && n.label === 'Government');
      expect(govIndustry).toBeDefined();
      const defenseIndustry = body.nodes.find(n => n.type === 'INDUSTRY' && n.label === 'Defense');
      expect(defenseIndustry).toBeDefined();
      expect(body.edges.some(e => e.source === actorNode.id && e.target === govIndustry.id)).toBe(true);
      expect(body.edges.some(e => e.source === actorNode.id && e.target === defenseIndustry.id)).toBe(true);
    });

    it('POST /api/knowledge-graph/query expands a real subgraph from a seeded CVE', async () => {
      const res = await handleKnowledgeGraphQuery(
        req('https://x/api/knowledge-graph/query', 'POST', { node_id: 'CVE-2026-30001', depth: 2 }),
        env, AUTH_ENTERPRISE
      );
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.nodes.some(n => n.id === 'CVE-2026-30001')).toBe(true);
      expect(body.node_count).toBeGreaterThan(1);
    });

    it('rejects unauthenticated/under-tier callers before touching the database (tier gate still enforced)', async () => {
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, { authenticated: true, tier: 'FREE', userId: 'u2' });
      expect(res.status).toBe(403);
    });
  });

  describe('regression guard — the exact production bug must not silently return', () => {
    it('pins the real self-healed schema: legacy buggy column names do not exist, real ones do', async () => {
      await storeInD1(env.DB, [{ id: 'CVE-2026-40000', title: 'x', severity: 'LOW', cvss: 1, source: 'nvd' }]);
      await seedThreatActors(env);
      await storeDecisions(env, runDecisionEngine([
        { id: 'CVE-2026-40000', severity: 'CRITICAL', cvss: 9.8, exploit_status: 'confirmed', source: 'cisa_kev', known_ransomware: 0, tags: '[]' },
      ]));

      const intelCols = columnNames(env.DB, 'threat_intel');
      // cve_id/cvss_score are now real, intentionally self-healed columns (see
      // threatIntelCanonicalColumns.test.mjs) — a separate fix for the 30+
      // other readers keyed on those names. That doesn't change this handler's
      // own behavior: fetchVulnRows() still aliases FROM the canonical id/cvss
      // fields regardless of whether cve_id/cvss_score also exist alongside
      // them, so both fixes are independently correct and compatible.
      expect(intelCols).not.toContain('mitre_technique');
      expect(intelCols).toEqual(expect.arrayContaining(['id', 'cvss', 'cve_id', 'cvss_score', 'severity', 'source']));

      const actorCols = columnNames(env.DB, 'threat_actors');
      expect(actorCols).not.toContain('sector');
      expect(actorCols).toContain('target_sectors');

      const decisionCols = columnNames(env.DB, 'soc_decisions');
      expect(decisionCols).toEqual(expect.arrayContaining(['id', 'cve_id', 'decision', 'priority']));
    });

    it('proves why the original bug was silent: the exact original query throws against this real schema', async () => {
      await storeInD1(env.DB, [{ id: 'CVE-2026-40001', title: 'x', severity: 'LOW', cvss: 1, source: 'nvd' }]);

      await expect(
        env.DB.prepare(
          `SELECT cve_id, cvss_score, severity, actively_exploited, source, mitre_technique FROM threat_intel`
        ).all()
      ).rejects.toThrow(/no such column/i);

      await seedThreatActors(env);
      await expect(
        env.DB.prepare(`SELECT name, sector, active FROM threat_actors`).all()
      ).rejects.toThrow(/no such column/i);
    });

    it('the graph is populated immediately after ingestion — first request after a cold start, matching the real production request pattern', async () => {
      await storeInD1(env.DB, [{
        id: 'CVE-2026-50000', title: 'SQL Injection in Gamma Ltd', severity: 'CRITICAL', cvss: 9.9,
        description: '', source: 'cisa_kev', exploit_status: 'confirmed', known_ransomware: 0,
        tags: '[]', weakness_types: '["CWE-89"]', actively_exploited: 1,
      }]);
      const res = await handleKnowledgeGraph(req('https://x/api/knowledge-graph'), env, AUTH_ENTERPRISE);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.node_counts.cve).toBe(1); // was: 0, silently, forever
    });
  });
});
