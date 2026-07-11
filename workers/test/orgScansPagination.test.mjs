/* CAP-ORG-001 — wired up the one backend handler deliberately left without a
 * UI in the 2026-07-09 org-management build: GET /api/orgs/:id/scans
 * (org-wide scan history across every active member).
 *
 * Found while wiring it up: `total` in the response was `results?.length`,
 * i.e. capped at whatever `limit` the caller passed (default 20) — never the
 * real row count. A pager built against it would work fine on page 1 and
 * then be unable to tell "more pages exist" from "this is everything" the
 * moment an org had more scans than one page. Fixed with a real COUNT(*)
 * over the same WHERE clause (member ids + optional module filter).
 *
 * These tests seed more scan_history rows than the default page size to
 * make the old bug and the fix diverge — with only 2 rows (the pre-existing
 * phase9OrgDashboardSchema.test.mjs fixture), old and new code return the
 * same number by coincidence.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleOrgScans } from '../src/handlers/orgManagement.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}
const U = (id) => ({ authenticated: true, userId: id, user_id: id });
const owner = U('owner1'), outsider = U('outsider1'), otherOrgMember = U('other1');
const get = (url) => new Request(url, { method: 'GET' });

describe('GET /api/orgs/:id/scans — pagination total is a real count, not the page size', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, plan TEXT)`);
    db.exec(`CREATE TABLE org_members (org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active')`);
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT)`);
    db.exec(`CREATE TABLE scan_history (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      user_id TEXT NOT NULL, target TEXT NOT NULL, module TEXT NOT NULL,
      risk_score INTEGER, risk_level TEXT,
      scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
    db.prepare(`INSERT INTO organizations (id, name, plan) VALUES ('org1','Acme','ENTERPRISE')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role) VALUES ('org1','owner1','OWNER')`).run();
    db.prepare(`INSERT INTO users (id, email, full_name) VALUES ('owner1','o@acme.com','Org Owner')`).run();
    // 25 domain scans + 3 ai scans — more than the 20-row default page size.
    for (let i = 0; i < 25; i++) {
      db.prepare(`INSERT INTO scan_history (user_id, target, module, risk_score, risk_level) VALUES ('owner1', ?, 'domain', 50, 'MEDIUM')`).run(`site${i}.acme.com`);
    }
    for (let i = 0; i < 3; i++) {
      db.prepare(`INSERT INTO scan_history (user_id, target, module, risk_score, risk_level) VALUES ('owner1', ?, 'ai', 30, 'LOW')`).run(`ai-target-${i}`);
    }
    // A second org + member, to prove no cross-org leak.
    db.prepare(`INSERT INTO organizations (id, name, plan) VALUES ('org2','Other Co','FREE')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role) VALUES ('org2','other1','OWNER')`).run();
  });

  it('total reflects the real row count across the org, not just this page (the bug)', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans'), env, owner, 'org1');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.scans.length).toBe(20);   // default limit still caps the page
    expect(body.total).toBe(28);          // but total is the real count (25+3), not 20
  });

  it('a second page correctly returns the remaining rows, and total stays the same', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans?limit=20&offset=20'), env, owner, 'org1');
    const body = await res.json();
    expect(body.scans.length).toBe(8);
    expect(body.total).toBe(28);
  });

  it('the module filter narrows both scans and total consistently', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans?module=ai'), env, owner, 'org1');
    const body = await res.json();
    expect(body.scans.length).toBe(3);
    expect(body.total).toBe(3);
    expect(body.scans.every(s => s.module === 'ai')).toBe(true);
  });

  it('a non-member of the org is rejected (403), not shown any scans', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans'), env, outsider, 'org1');
    expect(res.status).toBe(403);
  });

  it('a real member of a DIFFERENT org cannot see org1\'s scans (no cross-org leak)', async () => {
    const res = await handleOrgScans(get('https://x/api/orgs/org1/scans'), env, otherOrgMember, 'org1');
    expect(res.status).toBe(403);
  });
});

const { readFileSync } = await import('node:fs');
const { resolve } = await import('node:path');
const repoRoot = resolve(import.meta.dirname, '..', '..');
const html = readFileSync(resolve(repoRoot, 'frontend/user-dashboard.html'), 'utf8');
function fnBody(name, windowSize = 2200) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) return '';
  return html.slice(start, start + windowSize);
}

describe('CAP-ORG-001 frontend wiring — loadOrgScans()/orgScansPage() match the real backend contract', () => {
  it('loadOrgScans() calls the real endpoint with limit/offset/module and reads the real response fields', () => {
    const body = fnBody('loadOrgScans');
    expect(body).not.toBe('');
    expect(body).toContain("'/api/orgs/' + encodeURIComponent(orgId) + '/scans?limit=' + ORG_SCANS_LIMIT + '&offset=' + offset");
    expect(body).toContain('d.scans');
    expect(body).toContain('d.total');
    expect(body).toContain('s.target_summary');
    expect(body).toContain('s.scanned_by');
    expect(body).toContain('s.risk_score');
    expect(body).toContain('s.scanned_at');
    expect(body).toContain('s.module');
  });

  it('pagination controls are disabled at the correct boundaries, not always-enabled', () => {
    const body = fnBody('loadOrgScans');
    expect(body).toContain("'org-scans-prev').disabled = offset <= 0");
    expect(body).toContain("'org-scans-next').disabled = offset + scans.length >= total");
  });

  it('openOrgDetail() loads scan history for the org being opened', () => {
    const body = fnBody('openOrgDetail', 1300);
    expect(body).toContain('loadOrgScans(d.id, 0)');
  });
});
