/* Regression tests — real platform-staff login (RBAC-0), replacing the
 * hardcoded shared password that used to gate
 * mssp-command-center.html, revenue-command-center.html, and
 * proposal-generator.html. Modeled directly on partnerAuth.test.mjs's
 * conventions — same anti-enumeration, single-use-token, and session-
 * resolution guarantees, adapted for the users/user_roles identity model
 * instead of mssp_partners. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import {
  handleStaffLoginRequest, handleStaffLoginVerify, handleStaffLogout, handleStaffMe,
  resolveStaffSession,
} from '../src/handlers/staffAuth.js';
import { resolveAuthV5 } from '../src/auth/middleware.js';

function makeEnv({ users = [], roles = [] } = {}) {
  const usersByEmail = new Map(users.map(u => [u.email, u]));
  const roleRows = [...roles];
  const kv = new Map();

  const env = {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT id FROM users WHERE email/.test(sql)) {
              const u = usersByEmail.get(b[0]);
              return u ? { id: u.id } : null;
            }
            return null;
          },
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
      async get(k) { return kv.has(k) ? kv.get(k) : null; },
      async put(k, v) { kv.set(k, v); return true; },
      async delete(k) { kv.delete(k); return true; },
    },
    _kv: kv,
  };
  return env;
}

function req(body, method = 'POST') {
  return new Request('https://x', { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
}

const realFetch = globalThis.fetch;
beforeEach(() => { globalThis.fetch = async () => new Response('', { status: 202 }); }); // stub email transport
afterAll(() => { globalThis.fetch = realFetch; });

describe('POST /api/staff/login — no account enumeration', () => {
  it('returns the same generic message for an eligible staff member and an ineligible one', async () => {
    const env = makeEnv({
      users: [{ id: 'u1', email: 'staff@cyberdudebivash.com' }],
      roles: [{ user_id: 'u1', role: 'ADMIN' }],
    });
    const eligible = await handleStaffLoginRequest(req({ email: 'staff@cyberdudebivash.com' }), env);
    const ineligible = await handleStaffLoginRequest(req({ email: 'random@nowhere.com' }), env);
    const b1 = await eligible.json();
    const b2 = await ineligible.json();
    expect(b1.message).toBe(b2.message);
    expect(b1.success).toBe(true);
  });

  it('the configured owner email is always eligible, even with no users row', async () => {
    const env = makeEnv();
    await handleStaffLoginRequest(req({ email: 'bivash@cyberdudebivash.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('staff:login_token:'));
    expect(tokenKey).toBeTruthy();
    const stored = JSON.parse(env._kv.get(tokenKey));
    expect(stored.roles).toEqual(['SUPERADMIN']);
  });

  it('does NOT issue a login token for a real user with zero granted roles', async () => {
    const env = makeEnv({ users: [{ id: 'u2', email: 'nobody@x.com' }] });
    await handleStaffLoginRequest(req({ email: 'nobody@x.com' }), env);
    const anyToken = [...env._kv.keys()].some(k => k.startsWith('staff:login_token:'));
    expect(anyToken).toBe(false);
  });

  it('rejects an invalid email with a real 400 (input validation, not enumeration)', async () => {
    const env = makeEnv();
    const res = await handleStaffLoginRequest(req({ email: 'not-an-email' }), env);
    expect(res.status).toBe(400);
  });
});

describe('POST /api/staff/verify — single-use token exchange', () => {
  it('rejects an invalid/unknown token', async () => {
    const env = makeEnv();
    const res = await handleStaffLoginVerify(req({ token: 'garbage' }), env);
    expect(res.status).toBe(401);
  });

  it('issues a session and the login token cannot be reused', async () => {
    const env = makeEnv({ users: [{ id: 'u3', email: 'analyst@x.com' }], roles: [{ user_id: 'u3', role: 'SOC_ANALYST' }] });
    await handleStaffLoginRequest(req({ email: 'analyst@x.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('staff:login_token:'));
    const token = tokenKey.replace('staff:login_token:', '');

    const res1 = await handleStaffLoginVerify(req({ token }), env);
    const body1 = await res1.json();
    expect(res1.status).toBe(200);
    expect(body1.roles).toEqual(['SOC_ANALYST']);
    expect(body1.session_token).toBeTruthy();

    const res2 = await handleStaffLoginVerify(req({ token }), env);
    expect(res2.status).toBe(401);
  });
});

describe('resolveStaffSession + resolveAuthV5 — least privilege by role', () => {
  it('a SUPERADMIN session gets isAdmin:true (isOwner()-equivalent reach)', async () => {
    const env = makeEnv();
    await handleStaffLoginRequest(req({ email: 'bivash@cyberdudebivash.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('staff:login_token:'));
    const loginToken = tokenKey.replace('staff:login_token:', '');
    const verifyRes = await handleStaffLoginVerify(req({ token: loginToken }), env);
    const { session_token } = await verifyRes.json();

    const authedReq = new Request('https://x', { headers: { Authorization: `Bearer ${session_token}` } });
    const authCtx = await resolveAuthV5(authedReq, env);
    expect(authCtx.isAdmin).toBe(true);
    expect(authCtx.platformRoles).toEqual(['SUPERADMIN']);
    expect(authCtx.role).toBe('admin'); // derived by withAuthAliases from isAdmin, unchanged logic
  });

  it('a plain ADMIN (Platform Administrator) session does NOT get isAdmin:true — least privilege', async () => {
    const env = makeEnv({ users: [{ id: 'u4', email: 'admin2@x.com' }], roles: [{ user_id: 'u4', role: 'ADMIN' }] });
    await handleStaffLoginRequest(req({ email: 'admin2@x.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('staff:login_token:'));
    const loginToken = tokenKey.replace('staff:login_token:', '');
    const verifyRes = await handleStaffLoginVerify(req({ token: loginToken }), env);
    const { session_token } = await verifyRes.json();

    const authedReq = new Request('https://x', { headers: { Authorization: `Bearer ${session_token}` } });
    const authCtx = await resolveAuthV5(authedReq, env);
    expect(authCtx.isAdmin).toBeFalsy();
    expect(authCtx.platformRoles).toEqual(['ADMIN']);
  });

  it('an unauthenticated request never resolves platformRoles', async () => {
    const env = makeEnv();
    const authCtx = await resolveAuthV5(new Request('https://x'), env);
    expect(authCtx.platformRoles).toBeUndefined();
  });

  it('resolveStaffSession ignores a short/garbage bearer token without a KV lookup', async () => {
    const env = makeEnv();
    const ctx = await resolveStaffSession(new Request('https://x', { headers: { Authorization: 'Bearer short' } }), env);
    expect(ctx).toBeNull();
  });
});

describe('GET /api/staff/me', () => {
  it('401s without a resolved staff session', async () => {
    const res = await handleStaffMe(new Request('https://x'), {}, {});
    expect(res.status).toBe(401);
  });

  it('returns the resolved roles for a real session', async () => {
    const res = await handleStaffMe(new Request('https://x'), {}, { email: 'x@x.com', platformRoles: ['ADMIN'] });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.roles).toEqual(['ADMIN']);
  });
});

describe('POST /api/staff/logout', () => {
  it('invalidates the session so it no longer resolves', async () => {
    const env = makeEnv();
    await handleStaffLoginRequest(req({ email: 'bivash@cyberdudebivash.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('staff:login_token:'));
    const loginToken = tokenKey.replace('staff:login_token:', '');
    const verifyRes = await handleStaffLoginVerify(req({ token: loginToken }), env);
    const { session_token } = await verifyRes.json();

    const logoutReq = new Request('https://x', { method: 'POST', headers: { Authorization: `Bearer ${session_token}` } });
    await handleStaffLogout(logoutReq, env);

    const ctx = await resolveStaffSession(new Request('https://x', { headers: { Authorization: `Bearer ${session_token}` } }), env);
    expect(ctx).toBeNull();
  });
});
