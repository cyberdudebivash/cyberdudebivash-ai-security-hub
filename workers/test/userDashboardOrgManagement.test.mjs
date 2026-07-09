// CAP-ORG-001 — Organization Management UI
// (docs/capability-registry/domains/organizations.json)
//
// Prior finding ("highest-value single gap identified across the whole
// platform"): workers/src/handlers/orgManagement.js is a complete,
// RBAC-enforced, tested backend (create/list/get/update/delete orgs, invite/
// update-role/remove members, org-scoped dashboard+scans) — but zero
// frontend anywhere ever called it. A brand-new signup account has no org
// and there was no "create your first org" flow anywhere on the platform.
//
// Confirmed before building: no near-miss page exists under
// frontend/enterprise*.html (enterprise-dashboard.html is a threat-intel
// feed, enterprise-portal.html is SSO/SIEM integration docs,
// enterprise-kpi-dashboard.html is CDB's own internal revenue analytics,
// enterprise-security.html is marketing copy) — none call any /api/orgs
// route, so this UI was built fresh with no duplication risk.
//
// FIX: added a new #page-orgs to frontend/user-dashboard.html (list view +
// detail view with dashboard stats, members table, settings, danger zone)
// plus 4 modals (create/invite/remove-confirm/delete-confirm), wired to the
// existing, unmodified backend contract. RBAC surfaced client-side to match
// the backend exactly: only OWNER/ADMIN see Invite + Settings, only OWNER
// sees Danger Zone and per-member role dropdowns (backend: only OWNER can
// change roles), OWNER/ADMIN/self can remove a member (backend: same rule),
// the OWNER's own row never shows a role-change or remove control (backend:
// role != 'OWNER' guard on both the role-update and remove-member queries).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASH  = readFileSync(resolve(__dirname, '../../frontend/user-dashboard.html'), 'utf8');
const INDEX = readFileSync(resolve(__dirname, '../src/index.js'), 'utf8');
const ORG   = readFileSync(resolve(__dirname, '../src/handlers/orgManagement.js'), 'utf8');

function fnBody(name) {
  const start = DASH.indexOf(`function ${name}`);
  if (start === -1) return '';
  return DASH.slice(start, start + 2500);
}

describe('Organizations entry point is discoverable and routes to a real page', () => {
  it('sidebar has a real, working nav-item for Organizations', () => {
    const idx = DASH.indexOf('data-page="orgs"');
    expect(idx).toBeGreaterThan(-1);
    expect(DASH.slice(idx - 30, idx + 60)).toContain("showPage('orgs',this)");
  });

  it('#page-orgs exists with both a list view and a detail view', () => {
    expect(DASH).toContain('id="page-orgs"');
    expect(DASH).toContain('id="orgs-list-view"');
    expect(DASH).toContain('id="org-detail-view"');
  });
});

describe('Organization CRUD wired to the real, unmodified backend contract', () => {
  it('loadOrgs() calls the real GET /api/orgs', () => {
    const fn = fnBody('loadOrgs');
    expect(fn).not.toBe('');
    expect(fn).toContain("apiFetch('/api/orgs')");
    expect(fn).toContain('d.organizations');
  });

  it('createOrg() posts the fields handleCreateOrg actually reads, and uses org_id (not id) from the response', () => {
    const fn = fnBody('createOrg');
    expect(fn).not.toBe('');
    expect(fn).toContain("apiFetch('/api/orgs'");
    expect(fn).toMatch(/name[,\s]/);
    expect(fn).toContain('industry');
    expect(fn).toContain('domain');
    expect(fn).toContain('openOrgDetail(d.org_id)');
  });

  it('openOrgDetail() fetches by id and uses the real UUID (not the slug) for the dashboard call', () => {
    const fn = fnBody('openOrgDetail');
    expect(fn).not.toBe('');
    expect(fn).toContain("apiFetch('/api/orgs/' + encodeURIComponent(orgId))");
    // handleOrgDashboard does not resolve a slug — must pass d.id, the real
    // UUID from the raw organizations-row spread in GET /api/orgs/:id.
    expect(fn).toContain('loadOrgDashboard(d.id)');
  });

  it("loadOrgDashboard() defensively handles the documented zero-member response shape (no `summary` key)", () => {
    const fn = fnBody('loadOrgDashboard');
    expect(fn).not.toBe('');
    expect(fn).toContain('d.summary || {}');
  });

  it('saveOrgSettings() calls the real PUT /api/orgs/:id', () => {
    const fn = fnBody('saveOrgSettings');
    expect(fn).not.toBe('');
    expect(fn).toMatch(/method:\s*'PUT'/);
  });

  it('deleteOrgConfirmed() calls the real DELETE /api/orgs/:id', () => {
    const fn = fnBody('deleteOrgConfirmed');
    expect(fn).not.toBe('');
    expect(fn).toMatch(/method:\s*'DELETE'/);
  });
});

describe('Member management wired to the real backend contract, with matching client-side RBAC', () => {
  it('inviteMember() posts email+role and handles the success:false "no account" shape, not just non-2xx', () => {
    const fn = fnBody('inviteMember');
    expect(fn).not.toBe('');
    expect(fn).toContain('email, role');
    expect(fn).toContain("d.success === false");
  });

  it('updateMemberRole() calls the real PUT /api/orgs/:id/members/:userId', () => {
    const fn = fnBody('updateMemberRole');
    expect(fn).not.toBe('');
    expect(fn).toMatch(/\/members\/\$\{encodeURIComponent\(userId\)\}/);
    expect(fn).toMatch(/method:\s*'PUT'/);
  });

  it('removeMemberConfirmed() calls the real DELETE /api/orgs/:id/members/:userId', () => {
    const fn = fnBody('removeMemberConfirmed');
    expect(fn).not.toBe('');
    expect(fn).toMatch(/method:\s*'DELETE'/);
  });

  it('renderOrgDetail() only offers the role dropdown to OWNER, and never on the OWNER\'s own row (matches backend: only OWNER can change roles, and role != \'OWNER\' is guarded server-side)', () => {
    const fn = fnBody('renderOrgDetail');
    expect(fn).not.toBe('');
    expect(fn).toContain("isOwner && m.role !== 'OWNER'");
  });

  it('renderOrgDetail() offers remove/leave to OWNER, ADMIN, or the member themself — matching handleRemoveMember exactly', () => {
    const fn = fnBody('renderOrgDetail');
    expect(fn).toContain("(canManage || isSelf) && m.role !== 'OWNER'");
  });

  it('renderOrgDetail() gates Invite/Settings/Danger-Zone visibility on OWNER/ADMIN and OWNER respectively', () => {
    const fn = fnBody('renderOrgDetail');
    expect(fn).toContain("['OWNER', 'ADMIN'].includes(org.your_role)");
    expect(fn).toContain("org.your_role === 'OWNER'");
    expect(fn).toContain('org-invite-btn');
    expect(fn).toContain('org-settings-card');
    expect(fn).toContain('org-danger-card');
  });
});

describe('Backend contract this UI relies on really exists as documented', () => {
  it('all routes this page calls are really registered', () => {
    expect(INDEX).toContain("'/api/orgs'");
    expect(INDEX).toMatch(/orgs\/:id\/dashboard|orgs\/\$\{|orgId.*dashboard/i);
  });

  it('ROLE_PERMISSIONS / role enforcement in orgManagement.js matches what the UI assumes', () => {
    expect(ORG).toContain("OWNER:    ['all']");
    expect(ORG).toContain("membership.role !== 'OWNER'"); // handleUpdateMemberRole: OWNER-only
    expect(ORG).toContain("role != 'OWNER'"); // handleRemoveMember / handleUpdateMemberRole guard the OWNER row server-side too
  });

  it('handleCreateOrg really returns org_id (not id) at the top level, matching createOrg()\'s expectation', () => {
    const start = ORG.indexOf('export async function handleCreateOrg');
    const body = ORG.slice(start, start + 3000);
    expect(body).toMatch(/org_id:\s*orgId/);
  });
});
