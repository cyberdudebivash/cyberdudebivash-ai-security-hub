/* Regression test — workers/src/handlers/enterpriseTransformHandler.js's
 * adminGuard(). Before this fix, adminGuard() checked authCtx.tier against
 * {OWNER, ADMIN} — values no auth path in the system ever produces (real
 * subscription tiers are FREE/STARTER/PRO/ENTERPRISE/MSSP, and staff
 * sessions from handlers/staffAuth.js hardcode tier:'ENTERPRISE'). That 403'd
 * every caller including the real platform owner and real platform admins,
 * on all 5 routes this guard protects: GET /api/platform/kpi,
 * GET /api/platform/overage/report, POST /api/platform/overage/charge,
 * GET /api/platform/kpi/executive, GET /api/platform/transform/observability.
 * adminGuard() now delegates to auth/rbac.js's isPlatformAdmin(), the same
 * predicate already used correctly elsewhere in the codebase. */
import { describe, it, expect } from 'vitest';
import {
  handlePlatformKPI, handleOverageReport, handleOverageCharge,
  handleExecutiveKPI, handleTransformObservability,
} from '../src/handlers/enterpriseTransformHandler.js';

function makeEnv({ roles = [] } = {}) {
  const roleRows = [...roles]; // [{user_id, role}]
  const kv = new Map();
  return {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() { return null; },
          async all() {
            if (/SELECT role FROM user_roles WHERE user_id/.test(sql)) {
              const [uid] = b;
              return { results: roleRows.filter(r => r.user_id === uid).map(r => ({ role: r.role })) };
            }
            return { results: [] };
          },
          async run() { return { success: true }; },
        };
      },
    },
    KV: {
      async get(k, type) { const v = kv.get(k); if (v === undefined) return null; return type === 'json' ? JSON.parse(v) : v; },
      async put(k, v) { kv.set(k, v); },
      async delete(k) { kv.delete(k); },
    },
    SECURITY_HUB_KV: {
      async get() { return null; },
      async put() {},
    },
  };
}

const anon = { authenticated: false };
const ordinaryCustomer = { authenticated: true, user_id: 'cust1', email: 'cust@x.com', tier: 'ENTERPRISE' };
const roleGrantedAdmin = { authenticated: true, user_id: 'admin1', email: 'admin1@x.com', tier: 'ENTERPRISE' };
const adminKeyBypass = { authenticated: true, user_id: 'bypass1', isAdmin: true };
const ownerEmailCaller = { authenticated: true, user_id: 'owner1', email: 'bivash@cyberdudebivash.com' };
// Exact shape resolveStaffSession() (handlers/staffAuth.js) produces for a
// plain ADMIN (Platform Administrator) staff-console login — tier is always
// 'ENTERPRISE', never 'ADMIN'; the real signal is platformRoles.
const staffAdminSession = { authenticated: true, user_id: 'staff1', email: 'staff@x.com', tier: 'ENTERPRISE', platformRoles: ['ADMIN'], isAdmin: false };
const staffSuperAdminSession = { authenticated: true, user_id: 'staff2', email: 'staff2@x.com', tier: 'ENTERPRISE', platformRoles: ['SUPERADMIN'], isAdmin: true };

describe('handlePlatformKPI (GET /api/platform/kpi) — admin gate', () => {
  it('rejects an anonymous caller with 401', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), anon);
    expect(res.status).toBe(401);
  });

  it('rejects an ordinary authenticated customer (any tier) with 403 — not an open leak', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), ordinaryCustomer);
    expect(res.status).toBe(403);
  });

  it('admits a real platform admin granted via user_roles', async () => {
    const env = makeEnv({ roles: [{ user_id: 'admin1', role: 'ADMIN' }] });
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), env, roleGrantedAdmin);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  it('admits the ADMIN_KEY bypass (authCtx.isAdmin)', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), adminKeyBypass);
    expect((await res.json()).success).toBe(true);
  });

  it('admits the legacy owner-email caller', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), ownerEmailCaller);
    expect((await res.json()).success).toBe(true);
  });

  it('admits a real staff-console ADMIN session despite tier:"ENTERPRISE" (the exact bug scenario)', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), staffAdminSession);
    expect(res.status).toBe(200);
  });

  it('admits a real staff-console SUPERADMIN session', async () => {
    const res = await handlePlatformKPI(new Request('https://x/api/platform/kpi'), makeEnv(), staffSuperAdminSession);
    expect(res.status).toBe(200);
  });
});

describe('The other 4 routes sharing adminGuard() are fixed the same way', () => {
  it('GET /api/platform/overage/report: 403 for ordinary user, 200 for platform admin', async () => {
    const denied = await handleOverageReport(new Request('https://x/api/platform/overage/report'), makeEnv(), ordinaryCustomer);
    expect(denied.status).toBe(403);
    const allowed = await handleOverageReport(new Request('https://x/api/platform/overage/report'), makeEnv(), staffAdminSession);
    expect(allowed.status).toBe(200);
  });

  it('POST /api/platform/overage/charge: 403 for ordinary user, processes for platform admin', async () => {
    const body = JSON.stringify({ user_id: 'u9', amount_usd: 5 });
    const denied = await handleOverageCharge(new Request('https://x/api/platform/overage/charge', { method: 'POST', body }), makeEnv(), ordinaryCustomer);
    expect(denied.status).toBe(403);
    const allowed = await handleOverageCharge(new Request('https://x/api/platform/overage/charge', { method: 'POST', body }), makeEnv(), staffAdminSession);
    expect(allowed.status).toBe(200);
  });

  it('GET /api/platform/kpi/executive: 403 for ordinary user, 200 for platform admin', async () => {
    const denied = await handleExecutiveKPI(new Request('https://x/api/platform/kpi/executive'), makeEnv(), ordinaryCustomer);
    expect(denied.status).toBe(403);
    const allowed = await handleExecutiveKPI(new Request('https://x/api/platform/kpi/executive'), makeEnv(), staffAdminSession);
    expect(allowed.status).toBe(200);
  });

  it('GET /api/platform/transform/observability: 403 for ordinary user, 200 for platform admin', async () => {
    const denied = await handleTransformObservability(new Request('https://x/api/platform/transform/observability'), makeEnv(), ordinaryCustomer);
    expect(denied.status).toBe(403);
    const allowed = await handleTransformObservability(new Request('https://x/api/platform/transform/observability'), makeEnv(), staffAdminSession);
    expect(allowed.status).toBe(200);
  });
});
