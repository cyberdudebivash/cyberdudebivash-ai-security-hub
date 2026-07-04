/* Phase IX RC blocker lock: org dashboard + org scans vs the REAL schema.
 *
 * Found in live production (RC-B1): GET /api/orgs/{id}/dashboard and
 * GET /api/orgs/{id}/scans returned 500 ERR_UNHANDLED because both queried
 * scan_history.created_at — a column that does not exist. The canonical time
 * column is scanned_at (schema.sql, history.js, all indexes). The lab only
 * masked this because a heal-pass had added a stray created_at column.
 *
 * This suite runs the real handlers against a production-faithful schema —
 * scan_history WITH scanned_at and deliberately WITHOUT created_at — so any
 * regression back to created_at fails here, not in production.
 *
 * Runs the real handlers against a real SQL engine (node:sqlite).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleOrgDashboard, handleOrgScans } from '../src/handlers/orgManagement.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}
const U = (id) => ({ authenticated: true, userId: id, user_id: id });
const owner = U('owner1'), outsider = U('outsider1');
const get = (url) => new Request(url, { method: 'GET' });

describe('Phase IX: org dashboard + scans against the production schema', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, plan TEXT, created_at TEXT DEFAULT (datetime('now')))`);
    db.exec(`CREATE TABLE org_members (org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active')`);
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT)`);
    // Production-faithful scan_history: scanned_at is the ONLY time column.
    db.exec(`CREATE TABLE scan_history (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      user_id TEXT NOT NULL, job_id TEXT, scan_id TEXT, target TEXT NOT NULL,
      module TEXT NOT NULL, risk_score INTEGER, risk_level TEXT, grade TEXT,
      data_source TEXT, status TEXT NOT NULL DEFAULT 'completed',
      scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
    db.exec(`CREATE TABLE monitor_configs (id TEXT PRIMARY KEY, org_id TEXT, enabled INTEGER DEFAULT 1)`);
    db.prepare(`INSERT INTO organizations (id, name, plan) VALUES ('org1','Acme Corp','ENTERPRISE')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role) VALUES ('org1','owner1','OWNER')`).run();
    db.prepare(`INSERT INTO users (id, email, full_name) VALUES ('owner1','o@acme.com','Org Owner')`).run();
    db.prepare(`INSERT INTO scan_history (user_id, target, module, risk_score, risk_level) VALUES ('owner1','acme.com','domain',72,'HIGH')`).run();
    db.prepare(`INSERT INTO scan_history (user_id, target, module, risk_score, risk_level) VALUES ('owner1','shop.acme.com','domain',95,'CRITICAL')`).run();
    db.prepare(`INSERT INTO monitor_configs (id, org_id, enabled) VALUES ('m1','org1',1)`).run();
  });

  it('dashboard returns 200 with real aggregates (was 500 in production)', async () => {
    const res = await handleOrgDashboard(get('https://x/api/orgs/org1/dashboard'), env, owner, 'org1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.summary.total_scans_30d).toBe(2);
    expect(body.summary.critical_count_30d).toBe(1);
    expect(body.summary.active_monitors).toBe(1);
    expect(body.recent_scans.length).toBe(2);
    expect(body.recent_scans[0].scanned_at).toBeTruthy();
  });

  it('org scan history returns 200 with rows (was 500 in production)', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans'), env, owner, 'org1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBe(2);
    expect(body.scans[0].scanned_at).toBeTruthy();
  });

  it('non-member is still denied (403) — fix opened no access hole', async () => {
    const res = await handleOrgDashboard(get('https://x/api/orgs/org1/dashboard'), env, outsider, 'org1');
    expect(res.status).toBe(403);
  });

  it('dashboard degrades instead of 500 when one aggregate table is missing', async () => {
    db.exec(`DROP TABLE monitor_configs`);
    const res = await handleOrgDashboard(get('https://x/api/orgs/org1/dashboard'), env, owner, 'org1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.summary.total_scans_30d).toBe(2);   // scan aggregates intact
    expect(body.summary.total_monitors).toBe(0);    // failed aggregate degraded
  });

  it('no scan_history query in orgManagement references created_at (schema truth)', async () => {
    const src = await import('node:fs').then(fs =>
      fs.readFileSync(new URL('../src/handlers/orgManagement.js', import.meta.url), 'utf8'));
    // Every scan_history SELECT must use the canonical scanned_at column.
    const shBlocks = src.split('FROM scan_history').slice(1);
    for (const block of shBlocks) {
      const clause = src.slice(Math.max(0, src.indexOf(block) - 400), src.indexOf(block) + 400);
      expect(clause.includes('sh.created_at') || /scan_history[^;]*created_at/.test(clause)).toBe(false);
    }
  });
});
