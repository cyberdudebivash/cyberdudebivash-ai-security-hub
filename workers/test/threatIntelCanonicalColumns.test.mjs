// Permanent regression protection — threat_intel canonical column drift.
//
// cve_id and cvss_score are the platform's canonical, widely-queried column
// names on threat_intel: 30+ read paths across vulnerability management,
// the threat graph, executive reporting, threat hunting, SOC command,
// autonomous ops, IOC enrichment, and paid report downloads key on them
// directly. They were never part of ensureThreatIntelColumns()'s self-healing
// list, though — only workers/schema_master.sql defines them, and that
// migration is gated behind a manual, typed-"APPLY" workflow_dispatch
// (.github/workflows/db-migrate.yml) confirmed to have zero runs against
// production. Every one of those 30+ readers threw "no such column", and the
// self-heal UPDATE statements meant to backfill these columns (added in an
// earlier commit, 04c7006) threw for the same reason and were silently
// swallowed by their own try/catch — so the "fix" never actually ran either.
//
// That earlier commit's own regression test (businessTruthCvss.test.mjs)
// could not have caught this: its D1 mock just records which SQL strings ran,
// with no schema validation, so it can never produce a "no such column"
// error. This suite deliberately runs against a real SQL engine (node:
// sqlite), seeded only through the platform's own self-healing ingestion
// path (storeInD1), exactly replicating production's real, never-migrated
// state — the only way to catch this class of bug.
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { storeInD1 } from '../src/services/threatIngestion.js';
import { handleListVulns, handleGetVuln } from '../src/handlers/vulnManagement.js';
import { handleGetThreatGraph } from '../src/handlers/threatGraph.js';

// ─── Real-SQLite D1 shim (see knowledgeGraphRegression.test.mjs for rationale) ─
function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  function wrap(sql) {
    let bound = [];
    return {
      bind(...a) { bound = a; return this; },
      async all() { return { results: sqlite.prepare(sql).all(...bound) }; },
      async first() { return sqlite.prepare(sql).get(...bound) ?? null; },
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

function columnNames(db, table) {
  return db._sqlite.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
}

function req(url) { return new Request(url); }

const CVE_A = {
  id: 'CVE-2026-88001', title: 'SQL Injection in Delta Systems Login', severity: 'CRITICAL',
  cvss: 9.8, description: 'Unauthenticated SQL injection in the login endpoint.',
  source: 'cisa_kev', published_at: '2026-06-01T00:00:00Z', exploit_status: 'confirmed',
  known_ransomware: 0, tags: '[]', epss_score: 0.9, actively_exploited: 1,
};
const CVE_B_LOW = {
  id: 'CVE-2026-88002', title: 'Low severity configuration issue', severity: 'LOW', cvss: 2.0,
  description: '', source: 'nvd', published_at: '2026-06-01T00:00:00Z',
  exploit_status: null, known_ransomware: 0, tags: '[]', epss_score: 0.01, actively_exploited: 0,
};

describe('threat_intel canonical columns (cve_id, cvss_score) — production self-heal regression', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  it('self-heals cve_id and cvss_score from a zero-table start (no schema_master.sql)', async () => {
    expect(columnNames(env.DB, 'threat_intel')).toEqual([]); // table doesn't exist yet
    await storeInD1(env.DB, [CVE_A]);
    const cols = columnNames(env.DB, 'threat_intel');
    expect(cols).toContain('cve_id');
    expect(cols).toContain('cvss_score');
  });

  it('backfills cve_id = id and cvss_score = cvss on every ingestion cycle (the self-heal UPDATEs added in 04c7006, now actually able to run)', async () => {
    await storeInD1(env.DB, [CVE_A]);
    const row = env.DB._sqlite.prepare('SELECT cve_id, cvss_score FROM threat_intel WHERE id = ?').get(CVE_A.id);
    expect(row.cve_id).toBe(CVE_A.id);
    expect(row.cvss_score).toBe(CVE_A.cvss);
  });

  it('creates idx_ti_cvss — the index name 30+ readers\' query comments already assume exists', async () => {
    await storeInD1(env.DB, [CVE_A]);
    const indexes = env.DB._sqlite.prepare(`SELECT name FROM sqlite_master WHERE type='index'`).all().map(r => r.name);
    expect(indexes).toContain('idx_ti_cvss');
  });

  describe('GET /api/vulns — the exact query that threw "no such column: cve_id"', () => {
    beforeEach(async () => { await storeInD1(env.DB, [CVE_A, CVE_B_LOW]); });

    it('returns real CVE data (was: silently empty, forcing a fallback to NVD/hardcoded seed data)', async () => {
      const res = await handleListVulns(req('https://x/api/vulns'), env, {});
      const body = await res.json();
      expect(res.status).toBe(200);
      const found = body.vulns.find(v => v.id === CVE_A.id);
      expect(found).toBeDefined();
      expect(found.cvss_score).toBe(9.8);
      expect(found.source).toBe('threat_intel');
    });

    it('the ?kev=true filter works (depends on the same previously-broken query)', async () => {
      const res = await handleListVulns(req('https://x/api/vulns?kev=true'), env, {});
      const body = await res.json();
      expect(body.vulns.length).toBeGreaterThan(0);
      expect(body.vulns.every(v => v.in_kev)).toBe(true);
      expect(body.vulns.some(v => v.id === CVE_A.id)).toBe(true);
    });
  });

  describe('GET /api/vulns/:id — single CVE lookup keyed on cve_id', () => {
    it('finds a real ingested CVE by id (was: always 404 "Vulnerability not found")', async () => {
      await storeInD1(env.DB, [CVE_A]);
      const res = await handleGetVuln(req(`https://x/api/vulns/${CVE_A.id}`), env, {}, CVE_A.id);
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.vuln.cve_id).toBe(CVE_A.id);
      expect(body.vuln.cvss_score).toBe(9.8);
    });
  });

  describe('GET /api/threat-graph — D1 CVE-node augmentation keyed on cve_id/cvss_score', () => {
    it('augments the graph with real high-severity CVE nodes from D1 (was: silently skipped, static nodes only)', async () => {
      await storeInD1(env.DB, [CVE_A, CVE_B_LOW]);
      const res = await handleGetThreatGraph(req('https://x/api/threat-graph?live=false'), env, {});
      const body = await res.json(); // ok() wraps the payload as {success, data, error}
      const nodes = body.data.nodes;
      const cveNode = nodes.find(n => n.id === CVE_A.id);
      expect(cveNode).toBeDefined();
      expect(cveNode.source).toBe('live_d1');
      expect(cveNode.properties.cvss).toBe(9.8);
      // Below the >= 8.0 threshold in the handler's own query — must not appear.
      expect(nodes.some(n => n.id === CVE_B_LOW.id)).toBe(false);
    });
  });

  describe('regression guard — pins the real schema shape', () => {
    it('cve_id/cvss_score are real, populated table columns, not just JS-side aliases', async () => {
      await storeInD1(env.DB, [CVE_A]);
      const row = env.DB._sqlite.prepare(`SELECT cve_id, cvss_score FROM threat_intel`).get();
      expect(row).toBeDefined();
      expect(row.cve_id).toBe(CVE_A.id);
      expect(row.cvss_score).toBe(9.8);
    });
  });
});
