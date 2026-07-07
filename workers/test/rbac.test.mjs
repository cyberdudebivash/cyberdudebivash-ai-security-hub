/* Regression tests — auth/rbac.js (RBAC-0: central platform-staff RBAC
 * foundation). Before this, "admin" access had exactly one path — the
 * shared ADMIN_KEY secret or a single hardcoded owner email — with no way
 * to have a second real admin user. This wires the previously-unused
 * user_roles table (schema_master.sql) into real, multi-user Platform
 * Admin / Super Admin roles, role-cached in KV, without touching
 * isOwner()/ownerEmails() at all. */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  getPlatformRoles, isSuperAdmin, isPlatformAdmin, can, requireCan,
  handleGrantRole, handleRevokeRole, handleListRoles,
} from '../src/auth/rbac.js';

function makeEnv({ users = [], roles = [] } = {}) {
  const usersById = new Map(users.map(u => [u.id, u]));
  const roleRows = [...roles]; // [{user_id, role}]
  const kv = new Map();

  const env = {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT id, email FROM users WHERE id/.test(sql)) {
              return usersById.get(b[0]) || null;
            }
            return null;
          },
          async all() {
            if (/SELECT role FROM user_roles WHERE user_id/.test(sql)) {
              const [uid] = b;
              return { results: roleRows.filter(r => r.user_id === uid).map(r => ({ role: r.role })) };
            }
            if (/FROM user_roles ur JOIN users u/.test(sql)) {
              return {
                results: roleRows.map(r => ({ user_id: r.user_id, role: r.role, granted_by: r.granted_by || null, granted_at: 'now', email: usersById.get(r.user_id)?.email })),
              };
            }
            return { results: [] };
          },
          async run() {
            if (/INSERT INTO user_roles/.test(sql)) {
              const [user_id, role, granted_by] = b;
              const existing = roleRows.find(r => r.user_id === user_id && r.role === role);
              if (existing) existing.granted_by = granted_by;
              else roleRows.push({ user_id, role, granted_by });
              return { success: true };
            }
            if (/DELETE FROM user_roles/.test(sql)) {
              const [user_id, role] = b;
              const idx = roleRows.findIndex(r => r.user_id === user_id && r.role === role);
              if (idx >= 0) roleRows.splice(idx, 1);
              return { success: true };
            }
            return { success: true };
          },
        };
      },
    },
    KV: {
      async get(k, type) { const v = kv.get(k); if (v === undefined) return null; return type === 'json' ? JSON.parse(v) : v; },
      async put(k, v) { kv.set(k, v); },
      async delete(k) { kv.delete(k); },
    },
    _roleRows: roleRows,
    _kv: kv,
  };
  return env;
}

describe('getPlatformRoles — reads user_roles, KV-cached', () => {
  it('returns [] for a user with no granted roles', async () => {
    const env = makeEnv({ users: [{ id: 'u1', email: 'a@x.com' }] });
    expect(await getPlatformRoles(env, 'u1')).toEqual([]);
  });

  it('returns granted roles', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u1', role: 'ADMIN' }, { user_id: 'u1', role: 'SOC_ANALYST' }] });
    expect((await getPlatformRoles(env, 'u1')).sort()).toEqual(['ADMIN', 'SOC_ANALYST']);
  });

  it('caches in KV so a second call does not re-hit D1', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u1', role: 'ADMIN' }] });
    await getPlatformRoles(env, 'u1');
    // Mutate the underlying D1 rows directly (bypassing the cache) — a
    // cached second read should still return the stale (cached) value.
    env._roleRows.push({ user_id: 'u1', role: 'SUPERADMIN' });
    const second = await getPlatformRoles(env, 'u1');
    expect(second).toEqual(['ADMIN']);
  });
});

describe('isSuperAdmin / isPlatformAdmin — role hierarchy + legacy paths preserved', () => {
  it('ADMIN_KEY bypass (authCtx.isAdmin) is super admin — unchanged legacy path', async () => {
    const env = makeEnv();
    expect(await isSuperAdmin({ isAdmin: true }, env)).toBe(true);
  });

  it('the legacy owner email (isOwner()) is super admin — unchanged legacy path', async () => {
    const env = makeEnv();
    expect(await isSuperAdmin({ email: 'bivash@cyberdudebivash.com' }, env)).toBe(true);
  });

  it('a real SUPERADMIN user_roles grant is super admin', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u1', role: 'SUPERADMIN' }] });
    expect(await isSuperAdmin({ user_id: 'u1' }, env)).toBe(true);
  });

  it('an ordinary user is neither super admin nor platform admin', async () => {
    const env = makeEnv();
    expect(await isSuperAdmin({ user_id: 'u2', tier: 'PRO' }, env)).toBe(false);
    expect(await isPlatformAdmin({ user_id: 'u2', tier: 'PRO' }, env)).toBe(false);
  });

  it('a real ADMIN user_roles grant is platform admin but NOT super admin (least privilege)', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u3', role: 'ADMIN' }] });
    expect(await isPlatformAdmin({ user_id: 'u3' }, env)).toBe(true);
    expect(await isSuperAdmin({ user_id: 'u3' }, env)).toBe(false);
  });

  it('role inheritance: SUPERADMIN also satisfies isPlatformAdmin', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u4', role: 'SUPERADMIN' }] });
    expect(await isPlatformAdmin({ user_id: 'u4' }, env)).toBe(true);
  });

  it('an already-resolved staff session (authCtx.platformRoles) is honored without a DB round-trip', async () => {
    const env = makeEnv();
    expect(await isPlatformAdmin({ platformRoles: ['ADMIN'] }, env)).toBe(true);
    expect(await isSuperAdmin({ platformRoles: ['ADMIN'] }, env)).toBe(false);
    expect(await isSuperAdmin({ platformRoles: ['SUPERADMIN'] }, env)).toBe(true);
  });
});

describe('can() / requireCan() — declarative permission registry, fail-closed', () => {
  it('denies an unknown permission name by default', async () => {
    const env = makeEnv();
    expect(await can({ isAdmin: true }, env, 'not:a:real:permission')).toBe(false);
  });

  it('requireCan returns null (allowed) for a super admin on any permission', async () => {
    const env = makeEnv();
    expect(await requireCan({ isAdmin: true }, env, 'admin:business:read')).toBeNull();
  });

  it('requireCan returns a 403 Response for a denied caller', async () => {
    const env = makeEnv();
    const res = await requireCan({ tier: 'FREE' }, env, 'admin:business:read');
    expect(res).not.toBeNull();
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.permission).toBe('admin:business:read');
  });

  it('admin:analytics:read admits a platform admin but admin:business:read does not', async () => {
    const env = makeEnv({ roles: [{ user_id: 'u5', role: 'ADMIN' }] });
    const ctx = { user_id: 'u5' };
    expect(await requireCan(ctx, env, 'admin:analytics:read')).toBeNull();
    const denied = await requireCan(ctx, env, 'admin:business:read');
    expect(denied.status).toBe(403);
  });
});

describe('Role management endpoints — Super Admin only', () => {
  it('a non-super-admin cannot grant roles', async () => {
    const env = makeEnv({ users: [{ id: 'u6', email: 'target@x.com' }] });
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ user_id: 'u6', role: 'ADMIN' }) });
    const res = await handleGrantRole(req, env, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('a super admin can grant a role, and it is invalidated from cache immediately', async () => {
    const env = makeEnv({ users: [{ id: 'u7', email: 'target@x.com' }] });
    await getPlatformRoles(env, 'u7'); // warm the cache to []
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ user_id: 'u7', role: 'ADMIN' }) });
    const res = await handleGrantRole(req, env, { isAdmin: true, email: 'owner@x.com' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    // Cache was invalidated by the grant — a fresh read reflects the new role.
    expect(await getPlatformRoles(env, 'u7')).toEqual(['ADMIN']);
  });

  it('rejects granting a role to a nonexistent user', async () => {
    const env = makeEnv();
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ user_id: 'ghost', role: 'ADMIN' }) });
    const res = await handleGrantRole(req, env, { isAdmin: true });
    expect(res.status).toBe(404);
  });

  it('rejects an invalid role name', async () => {
    const env = makeEnv({ users: [{ id: 'u8', email: 'x@x.com' }] });
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ user_id: 'u8', role: 'NOT_A_ROLE' }) });
    const res = await handleGrantRole(req, env, { isAdmin: true });
    expect(res.status).toBe(400);
  });

  it('a super admin can revoke a role', async () => {
    const env = makeEnv({ users: [{ id: 'u9', email: 'x@x.com' }], roles: [{ user_id: 'u9', role: 'ADMIN' }] });
    const req = new Request('https://x', { method: 'DELETE', body: JSON.stringify({ user_id: 'u9', role: 'ADMIN' }) });
    const res = await handleRevokeRole(req, env, { isAdmin: true });
    expect(res.status).toBe(200);
    expect(await getPlatformRoles(env, 'u9')).toEqual([]);
  });

  it('listing roles requires super admin', async () => {
    const env = makeEnv({ users: [{ id: 'u10', email: 'x@x.com' }], roles: [{ user_id: 'u10', role: 'ADMIN' }] });
    const denied = await handleListRoles(new Request('https://x'), env, { tier: 'FREE' });
    expect(denied.status).toBe(403);
    const ok = await handleListRoles(new Request('https://x'), env, { isAdmin: true });
    expect(ok.status).toBe(200);
    const body = await ok.json();
    expect(body.roles.length).toBe(1);
  });
});
