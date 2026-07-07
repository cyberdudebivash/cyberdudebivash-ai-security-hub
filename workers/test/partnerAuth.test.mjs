/* Regression tests — real MSSP partner self-serve login (2026-07-07 Partner/
 * White-label infra follow-up). mssp_partners has no password column, so this
 * is a passwordless magic-link flow: request a link (generic response, no
 * account enumeration) -> exchange the one-time token for a session -> the
 * session resolves through resolveAuthV5 like any other auth method. Locks:
 *  1. Login request never reveals whether an email is a real partner.
 *  2. Only an active/trial partner (not 'pending') actually gets an emailed link.
 *  3. The one-time login token is single-use and short-lived.
 *  4. A verified session resolves via resolveAuthV5 with authCtx.partnerId
 *     and authCtx.role === 'partner' — not 'mssp_admin' or 'admin'.
 *  5. Logout invalidates the session immediately. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import {
  handlePartnerLoginRequest,
  handlePartnerLoginVerify,
  handlePartnerLogout,
  handlePartnerMe,
  resolvePartnerSession,
} from '../src/handlers/partnerAuth.js';
import { resolveAuthV5 } from '../src/auth/middleware.js';

function makeEnv({ partners = [] } = {}) {
  const partnersById = new Map(partners.map(p => [p.id, { ...p }]));
  const partnersByEmail = new Map(partners.map(p => [p.contact_email, { ...p }]));
  const kv = new Map();

  const env = {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT id, company, contact_email, status FROM mssp_partners WHERE contact_email/.test(sql)) {
              return partnersByEmail.get(b[0]) || null;
            }
            if (/FROM mssp_partners WHERE id/.test(sql)) {
              return partnersById.get(b[0]) || null;
            }
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
  return { env, partnersById, partnersByEmail };
}

function req(url, body) {
  return new Request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

const realFetch = globalThis.fetch;
beforeEach(() => {
  globalThis.fetch = async () => new Response('', { status: 202 }); // stub MailChannels/Resend
});
afterAll(() => { globalThis.fetch = realFetch; });

describe('POST /api/partners/login — no account enumeration', () => {
  it('returns the same generic message for a real active partner and an unknown email', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_1', company: 'Acme', contact_email: 'real@acme.com', status: 'active' }],
    });
    const resReal = await handlePartnerLoginRequest(req('https://x', { email: 'real@acme.com' }), env);
    const resFake = await handlePartnerLoginRequest(req('https://x', { email: 'ghost@nowhere.com' }), env);
    const bodyReal = await resReal.json();
    const bodyFake = await resFake.json();
    expect(resReal.status).toBe(200);
    expect(resFake.status).toBe(200);
    expect(bodyReal.message).toBe(bodyFake.message);
    expect(bodyReal.success).toBe(true);
  });

  it('rejects an invalid email with 400 (this is real input validation, not enumeration)', async () => {
    const { env } = makeEnv();
    const res = await handlePartnerLoginRequest(req('https://x', { email: 'not-an-email' }), env);
    expect(res.status).toBe(400);
  });

  it('does NOT send a login link for a pending (never-activated) partner', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_2', company: 'Pending Co', contact_email: 'pending@co.com', status: 'pending' }],
    });
    await handlePartnerLoginRequest(req('https://x', { email: 'pending@co.com' }), env);
    const anyLoginToken = [...env._kv.keys()].some(k => k.startsWith('partner:login_token:'));
    expect(anyLoginToken).toBe(false);
  });

  it('does issue a one-time login token (in KV) for a real active partner', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_3', company: 'Acme', contact_email: 'active@acme.com', status: 'active' }],
    });
    await handlePartnerLoginRequest(req('https://x', { email: 'active@acme.com' }), env);
    const tokenKey = [...env._kv.keys()].find(k => k.startsWith('partner:login_token:'));
    expect(tokenKey).toBeTruthy();
    const stored = JSON.parse(env._kv.get(tokenKey));
    expect(stored.partnerId).toBe('mp_3');
  });
});

describe('POST /api/partners/verify — exchanges the one-time token for a session', () => {
  it('rejects an invalid/unknown token', async () => {
    const { env } = makeEnv();
    const res = await handlePartnerLoginVerify(req('https://x', { token: 'garbage' }), env);
    expect(res.status).toBe(401);
  });

  it('issues a real session token tied to the partner, and the login token is single-use', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_4', company: 'Acme', contact_email: 'buyer@acme.com', tier: 'GOLD', plan: 'gold', status: 'active' }],
    });
    await handlePartnerLoginRequest(req('https://x', { email: 'buyer@acme.com' }), env);
    const loginTokenKey = [...env._kv.keys()].find(k => k.startsWith('partner:login_token:'));
    const loginToken = loginTokenKey.replace('partner:login_token:', '');

    const res1 = await handlePartnerLoginVerify(req('https://x', { token: loginToken }), env);
    const body1 = await res1.json();
    expect(res1.status).toBe(200);
    expect(body1.success).toBe(true);
    expect(body1.session_token).toBeTruthy();
    expect(body1.partner.id).toBe('mp_4');
    expect(body1.partner.tier).toBe('GOLD');

    // Re-using the same one-time token must fail (single-use)
    const res2 = await handlePartnerLoginVerify(req('https://x', { token: loginToken }), env);
    expect(res2.status).toBe(401);
  });
});

describe('resolvePartnerSession + resolveAuthV5 — session resolves as its own role', () => {
  it('a verified session resolves through resolveAuthV5 with partnerId and role=partner', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_5', company: 'Acme', contact_email: 'ceo@acme.com', tier: 'SILVER', status: 'active' }],
    });
    await handlePartnerLoginRequest(req('https://x', { email: 'ceo@acme.com' }), env);
    const loginTokenKey = [...env._kv.keys()].find(k => k.startsWith('partner:login_token:'));
    const loginToken = loginTokenKey.replace('partner:login_token:', '');
    const verifyRes = await handlePartnerLoginVerify(req('https://x', { token: loginToken }), env);
    const { session_token } = await verifyRes.json();

    const authedReq = new Request('https://x/api/partners/me', { headers: { Authorization: `Bearer ${session_token}` } });
    const authCtx = await resolveAuthV5(authedReq, env);
    expect(authCtx.authenticated).toBe(true);
    expect(authCtx.partnerId).toBe('mp_5');
    expect(authCtx.partner_id).toBe('mp_5'); // snake_case alias
    expect(authCtx.role).toBe('partner');
    expect(authCtx.tier).toBe('SILVER');
  });

  it('an unauthenticated request does not get a partner role', async () => {
    const { env } = makeEnv();
    const authCtx = await resolveAuthV5(new Request('https://x/api/partners/me'), env);
    expect(authCtx.role).not.toBe('partner');
  });

  it('resolvePartnerSession ignores short/garbage bearer tokens without a KV lookup', async () => {
    const { env } = makeEnv();
    const ctx = await resolvePartnerSession(new Request('https://x', { headers: { Authorization: 'Bearer short' } }), env);
    expect(ctx).toBeNull();
  });
});

describe('GET /api/partners/me', () => {
  it('401s without a partner session', async () => {
    const { env } = makeEnv();
    const res = await handlePartnerMe(new Request('https://x'), env, {});
    expect(res.status).toBe(401);
  });

  it('returns the full partner profile for a resolved session', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_6', company: 'Acme', contact_email: 'ceo@acme.com', tier: 'RESELLER', plan: 'reseller', status: 'active', client_count: 2, max_clients: 10, margin_pct: 30 }],
    });
    const res = await handlePartnerMe(new Request('https://x'), env, { partnerId: 'mp_6' });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.partner.company).toBe('Acme');
    expect(body.partner.client_count).toBe(2);
  });
});

describe('POST /api/partners/logout', () => {
  it('invalidates the session so it no longer resolves', async () => {
    const { env } = makeEnv({
      partners: [{ id: 'mp_7', company: 'Acme', contact_email: 'ceo@acme.com', tier: 'GOLD', status: 'active' }],
    });
    await handlePartnerLoginRequest(req('https://x', { email: 'ceo@acme.com' }), env);
    const loginTokenKey = [...env._kv.keys()].find(k => k.startsWith('partner:login_token:'));
    const loginToken = loginTokenKey.replace('partner:login_token:', '');
    const verifyRes = await handlePartnerLoginVerify(req('https://x', { token: loginToken }), env);
    const { session_token } = await verifyRes.json();

    const logoutReq = new Request('https://x', { method: 'POST', headers: { Authorization: `Bearer ${session_token}` } });
    await handlePartnerLogout(logoutReq, env);

    const ctx = await resolvePartnerSession(new Request('https://x', { headers: { Authorization: `Bearer ${session_token}` } }), env);
    expect(ctx).toBeNull();
  });
});
