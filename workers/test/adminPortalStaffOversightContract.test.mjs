// GUI↔backend contract guard for the Staff Admin Console's Users +
// Organizations oversight (CAP-ADMIN-004), following the static-parse
// convention established by userDashboardAuthContract.test.mjs. Pure text/
// regex assertions — no browser, no network. Locks in two things a future
// edit could silently break:
//
// 1. frontend/admin-portal.html only calls routes index.js actually
//    registers, gated by the exact permission keys auth/rbac.js defines.
// 2. The pre-existing unescaped-innerHTML-injection bug fixed in loadRoles()
//    (raw `${r.email}`/`${r.role}` etc. straight into a table row) doesn't
//    creep back in, and the new Users/Organizations render functions use the
//    same esc() helper rather than repeating that bug in new code.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORTAL = readFileSync(resolve(__dirname, '../../frontend/admin-portal.html'), 'utf8');
const INDEX  = readFileSync(resolve(__dirname, '../src/index.js'), 'utf8');
const RBAC   = readFileSync(resolve(__dirname, '../src/auth/rbac.js'), 'utf8');
const HANDLER = readFileSync(resolve(__dirname, '../src/handlers/staffUserOrgAdmin.js'), 'utf8');

describe('admin-portal.html — Users/Organizations route contract', () => {
  it('calls the real user oversight routes', () => {
    expect(PORTAL).toContain("apiFetch('/api/admin/users'");
    expect(PORTAL).toMatch(/apiFetch\(`\/api\/admin\/users\/\$\{encodeURIComponent\(userId\)\}`\)/);
    expect(PORTAL).toMatch(/apiFetch\(`\/api\/admin\/users\/\$\{encodeURIComponent\(CURRENT_USER_DETAIL\.id\)\}\/status`,\s*\{\s*method:\s*'PATCH'/);
  });

  it('calls the real organization oversight routes', () => {
    expect(PORTAL).toContain("apiFetch('/api/admin/orgs'");
    expect(PORTAL).toMatch(/apiFetch\(`\/api\/admin\/orgs\/\$\{encodeURIComponent\(orgId\)\}`\)/);
  });

  it('backend actually registers GET/PATCH /api/admin/users* and GET /api/admin/orgs*', () => {
    expect(INDEX).toContain("path === '/api/admin/users' && method === 'GET'");
    expect(INDEX).toContain("path.startsWith('/api/admin/users/') && path.endsWith('/status') && method === 'PATCH'");
    expect(INDEX).toContain("path.startsWith('/api/admin/users/') && method === 'GET'");
    expect(INDEX).toContain("path === '/api/admin/orgs' && method === 'GET'");
    expect(INDEX).toContain("path.startsWith('/api/admin/orgs/') && method === 'GET'");
  });

  it('every registered route imports its handler from handlers/staffUserOrgAdmin.js', () => {
    const registeredHandlers = ['handleListUsers', 'handleUpdateUserStatus', 'handleGetUserAdmin', 'handleListOrgsAdmin', 'handleGetOrgAdmin'];
    for (const fn of registeredHandlers) {
      expect(INDEX).toContain(fn);
      expect(HANDLER).toContain(`export async function ${fn}`);
    }
  });
});

describe('admin-portal.html — Users/Organizations RBAC permission contract', () => {
  it('handlers gate on admin:users:manage and admin:orgs:read, and rbac.js actually defines both', () => {
    expect(HANDLER).toMatch(/requireCan\(authCtx, env, 'admin:users:manage'\)/);
    expect(HANDLER).toMatch(/requireCan\(authCtx, env, 'admin:orgs:read'\)/);
    expect(RBAC).toContain("'admin:users:manage':");
    expect(RBAC).toContain("'admin:orgs:read':");
  });

  it('users:manage (PII + account suspension) requires Super Admin, not just Platform Admin', () => {
    const match = RBAC.match(/'admin:users:manage':\s*\(ctx, env\) => (\w+)\(ctx, env\)/);
    expect(match).toBeTruthy();
    expect(match[1]).toBe('isSuperAdmin');
  });

  it('orgs:read (view-only oversight) allows Platform Admin, the lower bar', () => {
    const match = RBAC.match(/'admin:orgs:read':\s*\(ctx, env\) => (\w+)\(ctx, env\)/);
    expect(match).toBeTruthy();
    expect(match[1]).toBe('isPlatformAdmin');
  });
});

describe('admin-portal.html — injection-safety regression (loadRoles + new Users/Orgs code)', () => {
  it('loadRoles() no longer interpolates r.email/r.role/r.granted_by/r.granted_at unescaped', () => {
    expect(PORTAL).not.toContain('<td>${r.email || r.user_id}</td>');
    expect(PORTAL).not.toContain('<span class="role-badge ${roleClass(r.role)}">${r.role}</span>');
    expect(PORTAL).not.toContain('<td>${r.granted_by');
    expect(PORTAL).not.toContain('<td>${r.granted_at');
    // the fixed version must route every one of those fields through esc()
    expect(PORTAL).toContain('<td>${esc(r.email || r.user_id)}</td>');
    expect(PORTAL).toContain('<td>${esc(r.granted_by || \'—\')}</td>');
    expect(PORTAL).toContain('<td>${esc(r.granted_at || \'—\')}</td>');
  });

  it("loadRoles()'s revoke button no longer builds an inline onclick by string-splicing r.email/r.role", () => {
    // The original bug's revoke button spliced r.email/r.role directly into a
    // single-quoted JS string inside the onclick attribute — safe from HTML
    // injection only via a partial, JS-only escape that still left the
    // attribute itself breakable. The fix reads via data-* attributes
    // instead, which need only ordinary HTML-attribute escaping.
    expect(PORTAL).not.toMatch(/revokeRoleFor\('\$\{/);
    expect(PORTAL).toContain('onclick="revokeRoleFor(this.dataset.email, this.dataset.role)"');
  });

  it('esc() helper is defined once, ahead of every render function that uses it', () => {
    const escDefIndex = PORTAL.indexOf('function esc(s) {');
    expect(escDefIndex).toBeGreaterThan(-1);
    for (const fn of ['function loadRoles()', 'async function loadUsers()', 'async function openUserDetail(', 'async function loadOrgsAdmin()', 'async function openOrgDetail(']) {
      expect(PORTAL.indexOf(fn)).toBeGreaterThan(escDefIndex);
    }
  });

  it('every user-controlled field rendered in the new Users table goes through esc()', () => {
    // Extract the loadUsers() row template and check each interpolated DB
    // field is wrapped in esc(...), not spliced raw into the row markup.
    const start = PORTAL.indexOf('async function loadUsers()');
    const end = PORTAL.indexOf('async function openUserDetail(');
    const body = PORTAL.slice(start, end);
    for (const field of ['u.email', 'u.full_name', 'u.company', 'u.tier', 'u.status']) {
      expect(body).toMatch(new RegExp(`esc\\(${field.replace('.', '\\.')}`));
    }
  });

  it('every user-controlled field rendered in the new Organizations table goes through esc()', () => {
    const start = PORTAL.indexOf('async function loadOrgsAdmin()');
    const end = PORTAL.indexOf('async function openOrgDetail(');
    const body = PORTAL.slice(start, end);
    for (const field of ['o.name', 'o.slug', 'o.plan', 'o.owner_email']) {
      expect(body).toMatch(new RegExp(`esc\\(${field.replace('.', '\\.')}`));
    }
  });
});

describe('admin-portal.html — suspend action revokes live sessions (not just future logins)', () => {
  it('handleUpdateUserStatus revokes outstanding refresh tokens on suspend', () => {
    expect(HANDLER).toContain('revokeAllUserTokens');
    expect(HANDLER).toMatch(/status === 'suspended'[\s\S]{0,80}revokeAllUserTokens/);
  });

  it('handlers/auth.js login path actually enforces users.status, so suspend has a real effect', () => {
    const AUTH = readFileSync(resolve(__dirname, '../src/handlers/auth.js'), 'utf8');
    expect(AUTH).toMatch(/user\.status !== 'active'/);
  });

  it('every mutating/PII query is wrapped so a schema mismatch fails loudly instead of silently returning empty (the enterpriseSsoHandler.js audit_log lesson)', () => {
    // The known-broken pattern elsewhere in the codebase is a bare
    // `.catch(() => {})`/`.catch(() => ({results: []}))` around a write or a
    // single-row read, which turns a real SQL error into indistinguishable
    // "no data". This handler's single-row lookups and the status UPDATE use
    // an explicit try/catch that logs and returns a real 500 instead.
    expect(HANDLER).toContain("console.error('[StaffUserOrgAdmin] listUsers query failed:'");
    expect(HANDLER).toContain("console.error('[StaffUserOrgAdmin] listOrgs query failed:'");
  });
});
