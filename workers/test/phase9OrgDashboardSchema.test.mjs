/* Phase IX RC defect — org security dashboard 500'd in production.
 *
 * Live-reproduced against production (RC governance, HTTP only): a customer
 * signs up, creates an organization, opens GET /api/orgs/:id/dashboard, and
 * receives 500 ERR_UNHANDLED — while GET /api/orgs/:id and GET /api/orgs both
 * return 200.
 *
 * Root cause: handleOrgDashboard aggregated scan_history by a NON-EXISTENT
 * column `created_at`. The canonical column is `scanned_at` (base schema +
 * indexes + history.js all use it). Production has the correct schema, so the
 * `created_at` reference threw "no such column"; a freshly-bootstrapped lab
 * masked the bug because its bootstrap had accidentally added a `created_at`
 * column. The mistake only surfaced by testing against real production.
 *
 * This test runs handleOrgDashboard against a PRODUCTION-FAITHFUL schema
 * (scan_history has scanned_at and deliberately NO created_at) backed by a real
 * SQL engine, so the pre-fix code would throw "no such column: created_at" and
 * the fix returns a 200 dashboard. It also asserts per-aggregate resilience.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleOrgDashboard } from '../src/handlers/orgManagement.js';

// Minimal D1-over-node:sqlite adapter: prepare(sql).bind(...).first()/all()/run().
function d1(db) {
  return {
    prepare(sql) {
      return {
        _args: [],
        bind(...args) { this._args = args; return this; },
        async first() { return db.prepare(sql).get(...this._args) ?? null; },
        async all() { return { results: db.prepare(sql).all(...this._args) }; },
        async run() { db.prepare(sql).run(...this._args); return { success: true }; },
      };
    },
  };
}

// Production-faithful subset: scan_history uses scanned_at, NOT created_at.
function seed() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, full_name TEXT);
    CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, plan TEXT);
    CREATE TABLE org_members (id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, role TEXT, status TEXT);
    CREATE TABLE scan_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, target TEXT, module TEXT,
      risk_score REAL, risk_level TEXT, scanned_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE monitor_configs (id TEXT PRIMARY KEY, org_id TEXT, enabled INTEGER);
    INSERT INTO users VALUES ('u_owner','Owner One');
    INSERT INTO organizations VALUES ('org_1','RC Enterprise','STARTER');
    INSERT INTO org_members VALUES ('m1','org_1','u_owner','owner','active');
    INSERT INTO scan_history (user_id,target,module,risk_score,risk_level,scanned_at)
      VALUES ('u_owner','example.com','domain',70,'HIGH',datetime('now')),
             ('u_owner','iana.org','domain',20,'LOW',datetime('now','-2 days'));
    INSERT INTO monitor_configs VALUES ('mon1','org_1',1);
  `);
  return db;
}

const authOwner = { userId: 'u_owner', user_id: 'u_owner', authenticated: true, method: 'jwt' };

describe('org dashboard works on the production schema (scanned_at, no created_at)', () => {
  let env;
  beforeEach(() => { env = { DB: d1(seed()) }; });

  it('returns 200 with aggregates (was 500 ERR_UNHANDLED in production)', async () => {
    const res = await handleOrgDashboard(new Request('https://x/api/orgs/org_1/dashboard'), env, authOwner, 'org_1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.org_id).toBe('org_1');
    expect(body.member_count).toBe(1);
    expect(body.summary.total_scans_30d).toBe(2);      // both scans within 30d, via scanned_at
    expect(Array.isArray(body.recent_scans)).toBe(true);
    expect(body.recent_scans.length).toBe(2);
    expect(body.summary.total_monitors).toBe(1);
    expect(body.summary.active_monitors).toBe(1);
  });

  it('an org with a member but no scans returns 200 zeros (empty-state, not 500)', async () => {
    const db = seed(); db.exec("DELETE FROM scan_history");
    env = { DB: d1(db) };
    const res = await handleOrgDashboard(new Request('https://x/api/orgs/org_1/dashboard'), env, authOwner, 'org_1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.summary.total_scans_30d).toBe(0);
    expect(body.recent_scans).toEqual([]);
  });

  it('degrades gracefully if the monitors table is absent (no hard 500)', async () => {
    const db = seed(); db.exec("DROP TABLE monitor_configs");
    env = { DB: d1(db) };
    const res = await handleOrgDashboard(new Request('https://x/api/orgs/org_1/dashboard'), env, authOwner, 'org_1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.summary.total_monitors).toBe(0);        // degraded default, dashboard still served
    expect(body.summary.total_scans_30d).toBe(2);       // other aggregates unaffected
  });

  it('non-members are denied (403), not 500', async () => {
    const res = await handleOrgDashboard(new Request('https://x/api/orgs/org_1/dashboard'), env,
      { userId: 'u_outsider', user_id: 'u_outsider', authenticated: true, method: 'jwt' }, 'org_1');
    expect(res.status).toBe(403);
  });
});
