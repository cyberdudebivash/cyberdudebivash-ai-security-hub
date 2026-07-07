/* Regression tests — a real MSSP partner session (role:'partner') managing
 * their own white-label branding is the actual intended use of this file
 * (its own header comment: "PUT/DELETE theme (mssp_admin|admin)" — a partner
 * customizing their OWN org's theme is that same "own-org" case, not a
 * platform-admin action). Also locks the org_id derivation fix in
 * auth/middleware.js: a partner session has no user_id at all, so without
 * that fix every partner would collapse onto the shared 'default' tenant_themes
 * row instead of getting their own. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { handleUpdateTheme, handleDeleteTheme, handleGetThemeByOrg } from '../src/handlers/whiteLabelMSSP.js';
import { resolveAuthV5 } from '../src/auth/middleware.js';
import { handlePartnerLoginRequest, handlePartnerLoginVerify } from '../src/handlers/partnerAuth.js';

// Real end-to-end partner env: mssp_partners row + KV, enough to drive the
// actual login -> verify -> resolveAuthV5 chain (same as partnerAuth.test.mjs).
function makePartnerAuthEnv(partners) {
  const partnersById = new Map(partners.map(p => [p.id, p]));
  const partnersByEmail = new Map(partners.map(p => [p.contact_email, p]));
  const kv = new Map();
  return {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT id, company, contact_email, status FROM mssp_partners WHERE contact_email/.test(sql)) return partnersByEmail.get(b[0]) || null;
            if (/FROM mssp_partners WHERE id/.test(sql)) return partnersById.get(b[0]) || null;
            return null;
          },
          async run() { return { success: true }; },
          async all() { return { results: [] }; },
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
}

const realFetch = globalThis.fetch;

function makeEnv() {
  const themes = new Map();
  const kv = new Map();
  return {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT \* FROM tenant_themes WHERE org_id/.test(sql)) return themes.get(b[0]) || null;
            return null;
          },
          async run() {
            if (/INSERT INTO tenant_themes/.test(sql)) {
              // cols: org_id, ...safe fields..., updated_at
              const existing = themes.get(b[0]) || {};
              themes.set(b[0], { ...existing, org_id: b[0] });
              return { success: true };
            }
            if (/DELETE FROM tenant_themes/.test(sql)) { themes.delete(b[0]); return { success: true }; }
            return { success: true };
          },
        };
      },
    },
    KV: {
      async get() { return null; },
      async put(k, v) { kv.set(k, v); },
      async delete(k) { kv.delete(k); },
    },
    _themes: themes,
  };
}

function req(url = 'https://x', method = 'GET', body) {
  return new Request(url, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
}

describe('White-label theme — partner session org_id isolation (auth/middleware.js)', () => {
  beforeEach(() => { globalThis.fetch = async () => new Response('', { status: 202 }); }); // stub email transport
  afterAll(() => { globalThis.fetch = realFetch; });

  it('a real, logged-in partner session resolves with a distinct partner:<id> org_id, not the shared "default" tenant', async () => {
    const env = makePartnerAuthEnv([{ id: 'mp_iso_1', company: 'Acme', contact_email: 'iso@acme.com', tier: 'GOLD', status: 'active' }]);
    await handlePartnerLoginRequest(new Request('https://x', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'iso@acme.com' }) }), env);
    const loginTokenKey = [...env._kv.keys()].find(k => k.startsWith('partner:login_token:'));
    const loginToken = loginTokenKey.replace('partner:login_token:', '');
    const verifyRes = await handlePartnerLoginVerify(new Request('https://x', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: loginToken }) }), env);
    const { session_token } = await verifyRes.json();

    const authedReq = new Request('https://x', { headers: { Authorization: `Bearer ${session_token}` } });
    const authCtx = await resolveAuthV5(authedReq, env);
    expect(authCtx.org_id).toBe('partner:mp_iso_1');
    expect(authCtx.org_id).not.toBe('default');
  });
});

describe('White-label theme — role gating admits a real partner session', () => {
  it('PUT is rejected for an unauthenticated/no-role caller', async () => {
    const env = makeEnv();
    const request = req('https://x', 'PUT', { brand_name: 'Acme' });
    request.user = { authenticated: true, tier: 'FREE' };
    const res = await handleUpdateTheme(request, env);
    expect(res.status).toBe(403);
  });

  it('PUT succeeds for a real partner session, scoped to their own org_id', async () => {
    const env = makeEnv();
    const request = req('https://x', 'PUT', { brand_name: 'Acme MSSP' });
    request.user = { authenticated: true, role: 'partner', partnerId: 'mp_1', org_id: 'partner:mp_1' };
    const res = await handleUpdateTheme(request, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.org_id).toBe('partner:mp_1');
    expect(env._themes.has('partner:mp_1')).toBe(true);
  });

  it('DELETE succeeds for a real partner session', async () => {
    const env = makeEnv();
    const putReq = req('https://x', 'PUT', { brand_name: 'Acme MSSP' });
    putReq.user = { authenticated: true, role: 'partner', partnerId: 'mp_2', org_id: 'partner:mp_2' };
    await handleUpdateTheme(putReq, env);

    const delReq = req('https://x', 'DELETE');
    delReq.user = { authenticated: true, role: 'partner', partnerId: 'mp_2', org_id: 'partner:mp_2' };
    const res = await handleDeleteTheme(delReq, env);
    expect(res.status).toBe(200);
    expect(env._themes.has('partner:mp_2')).toBe(false);
  });

  it('a partner session can fetch their OWN org via GET /theme/:orgId', async () => {
    const env = makeEnv();
    const getReq = req('https://x');
    getReq.user = { authenticated: true, role: 'partner', partnerId: 'mp_3', org_id: 'partner:mp_3' };
    const res = await handleGetThemeByOrg(getReq, env, 'partner:mp_3');
    expect(res.status).toBe(200);
  });

  it('a partner session CANNOT fetch a DIFFERENT org via GET /theme/:orgId', async () => {
    const env = makeEnv();
    const getReq = req('https://x');
    getReq.user = { authenticated: true, role: 'partner', partnerId: 'mp_3', org_id: 'partner:mp_3' };
    const res = await handleGetThemeByOrg(getReq, env, 'partner:someone-else');
    expect(res.status).toBe(403);
  });

  it('admin/mssp_admin can still fetch any org via GET /theme/:orgId (unchanged)', async () => {
    const env = makeEnv();
    const getReq = req('https://x');
    getReq.user = { authenticated: true, role: 'admin', isAdmin: true };
    const res = await handleGetThemeByOrg(getReq, env, 'partner:mp_9');
    expect(res.status).toBe(200);
  });
});
