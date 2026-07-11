/* Organization Activity Log — every enterprise competitor researched
 * (CrowdStrike, SentinelOne, Palo Alto, ThreatConnect) documents some form
 * of admin-visible audit trail; this platform had one for platform STAFF
 * (handleAdminAudit) but nothing an org OWNER/ADMIN could see for their own
 * organization — an OWNER had no way to know who invited a member, changed
 * a role, or removed someone from their own org.
 *
 * Reuses the existing, already-migrated D1 audit_log table (the same one
 * aiSecurityCopilot.js's writeCopilotAuditLog() and the SSO handler already
 * write to, and the staff console's handleAdminAudit already merges into
 * its own view) — zero new schema, zero migration dependency.
 *
 * Runs the real handlers against a real SQL engine (node:sqlite), same
 * convention as orgRbacIsolation.test.mjs.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  handleInviteMember, handleUpdateMemberRole, handleRemoveMember,
  handleUpdateOrg, handleDeleteOrg, handleGetOrgAuditLog,
} from '../src/handlers/orgManagement.js';

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
const owner = U('owner1'), admin = U('admin1'), member = U('member1'), outsider = U('outsider1');
const post = (body) => new Request('https://x/api/orgs/org1/members', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const put  = (body, path = '/api/orgs/org1/members/x') => new Request('https://x' + path, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const del  = () => new Request('https://x/api/orgs/org1/members/x', { method: 'DELETE' });
const getAudit = () => new Request('https://x/api/orgs/org1/audit');

describe('org audit log', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, domain TEXT, industry TEXT, plan TEXT, max_members INTEGER, owner_id TEXT, settings_json TEXT DEFAULT '{}', updated_at TEXT)`);
    db.exec(`CREATE TABLE org_members (id TEXT DEFAULT (lower(hex(randomblob(8)))), org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active', invited_by TEXT, invite_email TEXT, joined_at TEXT)`);
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT, tier TEXT)`);
    db.exec(`CREATE TABLE audit_log (id TEXT DEFAULT (lower(hex(randomblob(8)))), user_id TEXT, api_key_id TEXT, action TEXT NOT NULL, resource TEXT, resource_id TEXT, ip TEXT, user_agent TEXT, status TEXT DEFAULT 'ok', metadata TEXT DEFAULT '{}', details TEXT DEFAULT '{}', severity TEXT DEFAULT 'info', created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    db.prepare(`INSERT INTO organizations (id, name, plan, max_members, owner_id) VALUES ('org1','Acme','ENTERPRISE',50,'owner1')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org1','owner1','OWNER','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org1','admin1','ADMIN','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org1','member1','MEMBER','active')`).run();
    db.prepare(`INSERT INTO users (id, email, full_name, tier) VALUES ('owner1','owner@x.com','Owner One','ENTERPRISE')`).run();
    db.prepare(`INSERT INTO users (id, email, full_name, tier) VALUES ('cand','cand@x.com','Candidate','FREE')`).run();
  });

  it('invite writes an audit row with the org, actor, and invite details', async () => {
    const res = await handleInviteMember(post({ email: 'cand@x.com', role: 'ANALYST' }), env, owner, 'org1');
    expect(res.status).toBe(201);
    const row = db.prepare(`SELECT * FROM audit_log WHERE resource='organization' AND resource_id='org1'`).get();
    expect(row.action).toBe('member_invited');
    expect(row.user_id).toBe('owner1');
    const meta = JSON.parse(row.metadata);
    expect(meta.email).toBe('cand@x.com');
    expect(meta.role).toBe('ANALYST');
  });

  it('role change writes an audit row', async () => {
    const res = await handleUpdateMemberRole(put({ role: 'ADMIN' }, '/api/orgs/org1/members/member1'), env, owner, 'org1', 'member1');
    expect(res.status).toBe(200);
    const row = db.prepare(`SELECT * FROM audit_log WHERE action='member_role_changed'`).get();
    expect(row.user_id).toBe('owner1');
    expect(JSON.parse(row.metadata).new_role).toBe('ADMIN');
  });

  it('member removal writes an audit row distinguishing removed-by-admin from self-leave', async () => {
    await handleRemoveMember(del(), env, owner, 'org1', 'member1');
    const removedRow = db.prepare(`SELECT * FROM audit_log WHERE action='member_removed'`).get();
    expect(removedRow).toBeTruthy();

    db.prepare(`INSERT OR REPLACE INTO org_members (org_id, user_id, role, status) VALUES ('org1','admin1','ADMIN','active')`).run();
    await handleRemoveMember(new Request('https://x/api/orgs/org1/members/admin1', { method: 'DELETE' }), env, admin, 'org1', 'admin1');
    const leftRow = db.prepare(`SELECT * FROM audit_log WHERE action='member_left'`).get();
    expect(leftRow).toBeTruthy();
  });

  it('org settings update writes an audit row listing which fields changed', async () => {
    const res = await handleUpdateOrg(put({ name: 'New Name', domain: 'acme.com' }, '/api/orgs/org1'), env, owner, 'org1');
    expect(res.status).toBe(200);
    const row = db.prepare(`SELECT * FROM audit_log WHERE action='org_updated'`).get();
    const fields = JSON.parse(row.metadata).fields;
    expect(fields).toContain('name');
    expect(fields).toContain('domain');
  });

  it('org deletion writes an audit row before the org disappears', async () => {
    const res = await handleDeleteOrg(new Request('https://x/api/orgs/org1', { method: 'DELETE' }), env, owner, 'org1');
    expect(res.status).toBe(200);
    const row = db.prepare(`SELECT * FROM audit_log WHERE action='org_deleted'`).get();
    expect(JSON.parse(row.metadata).name).toBe('Acme');
  });

  it('audit writing never blocks the underlying action even if audit_log is unavailable', async () => {
    db.exec('DROP TABLE audit_log');
    const res = await handleInviteMember(post({ email: 'cand@x.com', role: 'ANALYST' }), env, owner, 'org1');
    expect(res.status).toBe(201);
    expect(db.prepare(`SELECT role FROM org_members WHERE user_id='cand'`).get().role).toBe('ANALYST');
  });

  describe('GET /api/orgs/:id/audit', () => {
    beforeEach(async () => {
      await handleInviteMember(post({ email: 'cand@x.com', role: 'ANALYST' }), env, owner, 'org1');
    });

    it('OWNER can view the org audit log', async () => {
      const res = await handleGetOrgAuditLog(getAudit(), env, owner, 'org1');
      expect(res.status).toBe(200);
      const d = await res.json();
      expect(d.entries).toHaveLength(1);
      expect(d.entries[0].action).toBe('member_invited');
      expect(d.entries[0].actor_name).toBe('Owner One');
    });

    it('ADMIN can view the org audit log', async () => {
      const res = await handleGetOrgAuditLog(getAudit(), env, admin, 'org1');
      expect(res.status).toBe(200);
    });

    it('a plain MEMBER cannot view the audit log (403)', async () => {
      const res = await handleGetOrgAuditLog(getAudit(), env, member, 'org1');
      expect(res.status).toBe(403);
    });

    it('an outsider with no membership in this org cannot view it (403, not an existence leak)', async () => {
      const res = await handleGetOrgAuditLog(getAudit(), env, outsider, 'org1');
      expect(res.status).toBe(403);
    });

    it('a real member of a DIFFERENT org cannot read this org\'s audit log by passing this org\'s id', async () => {
      db.prepare(`INSERT INTO organizations (id, name, plan, max_members, owner_id) VALUES ('org2','Other','STARTER',5,'outsider1')`).run();
      db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org2','outsider1','OWNER','active')`).run();
      // outsider1 IS a real OWNER — just not of org1
      const res = await handleGetOrgAuditLog(getAudit(), env, outsider, 'org1');
      expect(res.status).toBe(403);
    });

    it('unauthenticated caller is rejected (401)', async () => {
      const res = await handleGetOrgAuditLog(getAudit(), env, {}, 'org1');
      expect(res.status).toBe(401);
    });
  });
});

describe('GET /api/orgs/:id/audit route registration', () => {
  const root = resolve(import.meta.dirname, '..');
  const src = readFileSync(resolve(root, 'src/index.js'), 'utf8');

  it('imports handleGetOrgAuditLog from orgManagement.js', () => {
    expect(src).toMatch(/handleGetOrgAuditLog/);
    const importBlock = src.slice(src.indexOf("from './handlers/orgManagement.js'") - 400, src.indexOf("from './handlers/orgManagement.js'"));
    expect(importBlock).toContain('handleGetOrgAuditLog');
  });

  it('registers GET /api/orgs/:id/audit dispatching to handleGetOrgAuditLog', () => {
    const idx = src.indexOf("/^\\/api\\/orgs\\/[^/]+\\/audit$/");
    expect(idx).toBeGreaterThan(-1);
    const block = src.slice(idx, idx + 350);
    expect(block).toContain("method === 'GET'");
    expect(block).toContain('handleGetOrgAuditLog(request, env, authCtx, orgId)');
  });
});

describe('Org detail view — Activity Log card (frontend)', () => {
  const root = resolve(import.meta.dirname, '..');
  const html = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

  function fnBody(name, window = 1500) {
    const start = html.indexOf(`function ${name}`);
    return start === -1 ? '' : html.slice(start, start + window);
  }

  it('renders an org-audit-card, hidden by default, shown only for OWNER/ADMIN like org-settings-card', () => {
    expect(html).toContain('id="org-audit-card"');
    const body = fnBody('renderOrgDetail', 2000);
    const settingsIdx = body.indexOf("getElementById('org-settings-card').style.display = canManage");
    const auditIdx    = body.indexOf("getElementById('org-audit-card').style.display    = canManage");
    expect(settingsIdx).toBeGreaterThan(-1);
    expect(auditIdx).toBeGreaterThan(-1);
  });

  it('loads the audit log via the real endpoint when the detail view opens for a manager', () => {
    const body = fnBody('renderOrgDetail', 2000);
    expect(body).toContain('loadOrgAudit(org.id)');
    const loadBody = fnBody('loadOrgAudit', 1200);
    expect(loadBody).toContain("apiFetch('/api/orgs/' + encodeURIComponent(orgId) + '/audit')");
  });

  it('renders actor, human-readable action label, and detail for each entry, HTML-escaped', () => {
    const loadBody = fnBody('loadOrgAudit', 1200);
    expect(loadBody).toContain('orgEsc(e.actor_name || e.actor_email');
    expect(loadBody).toContain('ORG_AUDIT_LABELS[e.action]');
    expect(loadBody).toContain('orgAuditDetail(e.action, e.metadata)');
  });
});
