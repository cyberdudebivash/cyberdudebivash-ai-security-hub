/* MFA (TOTP) and Enterprise SSO (OIDC) — full round-trip acceptance tests.
 *
 * MFA: setup → authenticator-computed TOTP → enable (backup codes) → status →
 *      login challenge → authenticate (TOTP and backup-code paths) → burned
 *      codes can't be replayed. The test computes codes from the returned
 *      secret with the same RFC-6238 math an authenticator app uses.
 *
 * SSO: org IdP config in D1 → /login issues PKCE+state and redirects to the
 *      IdP → /callback exchanges the code at a stubbed IdP that RS256-signs a
 *      real id_token (nonce/aud/iss enforced) → user provisioned at org plan →
 *      platform JWT issued in the redirect fragment. State replay fails.
 *
 * Everything runs through the real exported worker.fetch(); only the D1/KV
 * bindings and the external IdP HTTP endpoints are stubbed.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import worker from '../src/index.js';
import { generateTOTP } from '../src/lib/totp.js';
import { createAccessToken } from '../src/auth/jwt.js';

const JWT_SECRET = 'roundtrip_test_jwt_secret';

function kvStub() {
  const m = new Map();
  return {
    _map: m,
    async put(k, v) { m.set(k, v); },
    async get(k, type) {
      if (!m.has(k)) return null;
      const v = m.get(k);
      return type === 'json' ? JSON.parse(v) : v;
    },
    async delete(k) { m.delete(k); },
    async list() { return { keys: [] }; },
  };
}
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }

// Minimal stateful D1 stub for the tables MFA/SSO touch.
function makeDB(state) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...a) { bound = a; return stmt; },
        async first() {
          if (/FROM mfa_secrets WHERE user_id = \? AND enabled = 1/.test(sql)) {
            const r = state.mfa.get(bound[0]);
            return r?.enabled ? r : null;
          }
          if (/FROM mfa_secrets WHERE user_id/.test(sql)) return state.mfa.get(bound[0]) || null;
          if (/SELECT id, email, tier, full_name FROM users WHERE id/.test(sql)) return state.users.get(bound[0]) || null;
          if (/SELECT id, tier FROM users WHERE email/.test(sql)) {
            for (const u of state.users.values()) if (u.email === bound[0]) return u;
            return null;
          }
          if (/FROM organizations WHERE slug/.test(sql)) return state.orgs.find(o => o.slug === bound[0]) || null;
          if (/FROM organizations WHERE id/.test(sql)) return state.orgs.find(o => o.id === bound[0]) || null;
          if (/FROM sso_configs WHERE org_id/.test(sql)) {
            const c = state.ssoConfigs.get(bound[0]);
            return c?.enabled ? c : null;
          }
          return null;
        },
        async run() {
          if (/INSERT INTO mfa_secrets/.test(sql)) {
            state.mfa.set(bound[0], { user_id: bound[0], secret: bound[1], backup_codes: bound[2], enabled: 1, created_at: 'now' });
          }
          if (/UPDATE mfa_secrets SET backup_codes/.test(sql)) {
            const r = state.mfa.get(bound[1]); if (r) r.backup_codes = bound[0];
          }
          if (/UPDATE mfa_secrets SET enabled = 0/.test(sql)) {
            const r = state.mfa.get(bound[0]); if (r) r.enabled = 0;
          }
          if (/INSERT INTO users/.test(sql)) {
            state.users.set(bound[0], { id: bound[0], email: bound[1], full_name: bound[2], tier: bound[3] });
            state.writes.userInserts.push({ id: bound[0], email: bound[1], tier: bound[3] });
          }
          if (/INSERT INTO org_members/.test(sql)) state.writes.orgMembers.push(bound);
          if (/refresh_tokens/.test(sql)) state.writes.refreshTokens.push(bound);
          return { success: true, meta: { changes: 1 } };
        },
        async all() { return { results: [] }; },
      };
      return stmt;
    },
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
}

function freshState() {
  return {
    mfa: new Map(), users: new Map(), orgs: [], ssoConfigs: new Map(),
    writes: { userInserts: [], orgMembers: [], refreshTokens: [] },
  };
}
function makeEnv(state) {
  const kv = kvStub();
  const db = makeDB(state);
  return { DB: db, SECURITY_HUB_DB: db, KV: kv, SECURITY_HUB_KV: kv, JWT_SECRET };
}
const B = 'https://cyberdudebivash.in';

describe('MFA TOTP — full enrollment → login round-trip', () => {
  let state, env, bearer;

  beforeEach(async () => {
    state = freshState();
    state.users.set('u_mfa_1', { id: 'u_mfa_1', email: 'ciso@acme.test', tier: 'ENTERPRISE', full_name: 'ACME CISO' });
    env = makeEnv(state);
    const token = await createAccessToken({ id: 'u_mfa_1', email: 'ciso@acme.test', tier: 'ENTERPRISE' }, JWT_SECRET);
    bearer = { Authorization: `Bearer ${token}` };
  });

  it('setup → enable with a computed TOTP → status → challenge login → tokens', async () => {
    // 1) Enroll: get a fresh secret
    const setup = await worker.fetch(new Request(`${B}/api/auth/mfa/setup`, { method: 'POST', headers: bearer }), env, ctxStub());
    expect(setup.status).toBe(200);
    const { secret, otpauth_url } = await setup.json();
    expect(secret).toBeTruthy();
    expect(otpauth_url).toContain('ciso%40acme.test');
    expect(otpauth_url).not.toContain('null');

    // 2) Confirm with a code computed exactly like an authenticator app
    const code = await generateTOTP(secret);
    const enable = await worker.fetch(new Request(`${B}/api/auth/mfa/enable`, {
      method: 'POST', headers: { ...bearer, 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp_code: code }),
    }), env, ctxStub());
    expect(enable.status).toBe(200);
    const enBody = await enable.json();
    expect(enBody.success).toBe(true);
    expect(enBody.backup_codes).toHaveLength(8);
    expect(state.mfa.get('u_mfa_1')?.enabled).toBe(1);

    // 3) Status reflects enrollment
    const status = await worker.fetch(new Request(`${B}/api/auth/mfa/status`, { headers: bearer }), env, ctxStub());
    expect((await status.json()).mfa_enabled).toBe(true);

    // 4) Login-time challenge → authenticate with a fresh TOTP → real tokens
    const { issueMFAChallenge } = await import('../src/handlers/mfa.js');
    const challenge = await issueMFAChallenge(env, 'u_mfa_1', 'ciso@acme.test', 'ENTERPRISE');
    expect(challenge).toBeTruthy();

    const authRes = await worker.fetch(new Request(`${B}/api/auth/mfa/authenticate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_challenge_token: challenge, totp_code: await generateTOTP(secret) }),
    }), env, ctxStub());
    expect(authRes.status).toBe(200);
    const authBody = await authRes.json();
    expect(authBody.access_token).toBeTruthy();
    expect(authBody.refresh_token).toBeTruthy();
    expect(authBody.user.tier).toBe('ENTERPRISE');

    // 5) Challenge is one-time — replay with a valid code still fails
    const replay = await worker.fetch(new Request(`${B}/api/auth/mfa/authenticate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_challenge_token: challenge, totp_code: await generateTOTP(secret) }),
    }), env, ctxStub());
    expect(replay.status).toBe(401);
  });

  it('rejects a wrong TOTP at enable, and burns backup codes after one use', async () => {
    const setup = await worker.fetch(new Request(`${B}/api/auth/mfa/setup`, { method: 'POST', headers: bearer }), env, ctxStub());
    const { secret } = await setup.json();

    // Wrong code → 401, MFA stays off
    const bad = await worker.fetch(new Request(`${B}/api/auth/mfa/enable`, {
      method: 'POST', headers: { ...bearer, 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp_code: '000000' }),
    }), env, ctxStub());
    expect(bad.status).toBe(401);
    expect(state.mfa.get('u_mfa_1')).toBeUndefined();

    // Enable properly, then log in with a backup code
    const good = await worker.fetch(new Request(`${B}/api/auth/mfa/enable`, {
      method: 'POST', headers: { ...bearer, 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp_code: await generateTOTP(secret) }),
    }), env, ctxStub());
    const { backup_codes } = await good.json();

    const { issueMFAChallenge } = await import('../src/handlers/mfa.js');
    const c1 = await issueMFAChallenge(env, 'u_mfa_1', 'ciso@acme.test', 'ENTERPRISE');
    const useBackup = await worker.fetch(new Request(`${B}/api/auth/mfa/authenticate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_challenge_token: c1, backup_code: backup_codes[0] }),
    }), env, ctxStub());
    expect(useBackup.status).toBe(200);
    expect((await useBackup.json()).warning).toContain('burned');

    // The same backup code is burned — a second login with it fails
    const c2 = await issueMFAChallenge(env, 'u_mfa_1', 'ciso@acme.test', 'ENTERPRISE');
    const reuse = await worker.fetch(new Request(`${B}/api/auth/mfa/authenticate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_challenge_token: c2, backup_code: backup_codes[0] }),
    }), env, ctxStub());
    expect(reuse.status).toBe(401);
  });
});

// ─── SSO (OIDC) round-trip with a stubbed enterprise IdP ──────────────────────

const IDP = 'https://idp.acme.test';
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function makeIdP() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return {
    jwks: { keys: [{ ...jwk, kid: 'test-key-1', use: 'sig', alg: 'RS256' }] },
    async signIdToken(claims) {
      const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', kid: 'test-key-1', typ: 'JWT' })));
      const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
      const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(`${header}.${payload}`));
      return `${header}.${payload}.${b64url(sig)}`;
    },
  };
}

describe('Enterprise SSO (OIDC) — login → IdP → callback → platform JWT', () => {
  let state, env, idp, lastNonce;

  beforeEach(async () => {
    state = freshState();
    state.orgs = [{ id: 'org_acme', slug: 'acme', name: 'ACME Corp', plan: 'ENTERPRISE' }];
    state.ssoConfigs.set('org_acme', {
      org_id: 'org_acme', enabled: 1, issuer: IDP,
      client_id: 'acme-client-id', client_secret: 'acme-client-secret',
      allowed_domains: JSON.stringify(['acme.test']),
    });
    env = makeEnv(state);
    idp = await makeIdP();

    vi.stubGlobal('fetch', vi.fn(async (input, init) => {
      const u = String(input instanceof Request ? input.url : input);
      if (u === `${IDP}/.well-known/openid-configuration`) {
        return Response.json({
          issuer: IDP,
          authorization_endpoint: `${IDP}/authorize`,
          token_endpoint: `${IDP}/token`,
          jwks_uri: `${IDP}/jwks`,
        });
      }
      if (u === `${IDP}/token`) {
        const idToken = await idp.signIdToken({
          iss: IDP, aud: 'acme-client-id', sub: 'idp-user-42',
          email: 'engineer@acme.test', name: 'ACME Engineer',
          nonce: lastNonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300,
        });
        return Response.json({ id_token: idToken, access_token: 'idp-opaque', token_type: 'Bearer' });
      }
      if (u === `${IDP}/jwks`) return Response.json(idp.jwks);
      return new Response('unexpected external call: ' + u, { status: 500 });
    }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('full code flow: PKCE login redirect → signed id_token → provisioned user + platform JWT', async () => {
    // 1) Login: platform discovers the IdP and redirects with state + PKCE + nonce
    const login = await worker.fetch(new Request(`${B}/api/auth/sso/login?org=acme`), env, ctxStub());
    expect(login.status).toBe(302);
    const loc = new URL(login.headers.get('Location'));
    expect(loc.origin + loc.pathname).toBe(`${IDP}/authorize`);
    expect(loc.searchParams.get('code_challenge')).toBeTruthy();
    const stateParam = loc.searchParams.get('state');
    lastNonce = loc.searchParams.get('nonce');
    expect(stateParam).toBeTruthy();
    expect(lastNonce).toBeTruthy();

    // 2) Callback: IdP "returns" the user with an auth code
    const cb = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=authcode-xyz&state=${stateParam}`), env, ctxStub());
    expect(cb.status).toBe(302);
    const dest = cb.headers.get('Location');
    expect(dest).toContain('access_token=');
    expect(dest).toContain('tier=ENTERPRISE');
    expect(dest).toContain('sso=oidc');
    expect(dest).not.toContain('reason='); // no failure redirect

    // 3) User provisioned at the org's plan + membership recorded
    expect(state.writes.userInserts).toEqual([expect.objectContaining({ email: 'engineer@acme.test', tier: 'ENTERPRISE' })]);
    expect(state.writes.orgMembers.length).toBe(1);

    // 4) The issued platform JWT actually authenticates against the platform
    const token = new URL(dest.replace('#', '?')).searchParams.get('access_token');
    const who = await worker.fetch(new Request(`${B}/api/auth/status`, { headers: { Authorization: `Bearer ${token}` } }), env, ctxStub());
    const whoBody = await who.json();
    expect(whoBody.authenticated).toBe(true);
    expect(whoBody.tier).toBe('ENTERPRISE');
  });

  it('state is one-time: replaying the callback fails closed', async () => {
    const login = await worker.fetch(new Request(`${B}/api/auth/sso/login?org=acme`), env, ctxStub());
    const loc = new URL(login.headers.get('Location'));
    const stateParam = loc.searchParams.get('state');
    lastNonce = loc.searchParams.get('nonce');

    const first = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=c1&state=${stateParam}`), env, ctxStub());
    expect(first.headers.get('Location')).toContain('access_token=');

    const replay = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=c2&state=${stateParam}`), env, ctxStub());
    expect(replay.headers.get('Location')).toContain('reason=invalid_or_expired_state');
  });

  it('rejects an id_token for a user outside the allowed email domains', async () => {
    const login = await worker.fetch(new Request(`${B}/api/auth/sso/login?org=acme`), env, ctxStub());
    const loc = new URL(login.headers.get('Location'));
    const stateParam = loc.searchParams.get('state');
    lastNonce = loc.searchParams.get('nonce');

    // Re-point the IdP stub to return an out-of-domain identity
    const orig = idp.signIdToken.bind(idp);
    idp.signIdToken = (claims) => orig({ ...claims, email: 'intruder@evil.example' });

    const cb = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=c9&state=${stateParam}`), env, ctxStub());
    expect(cb.headers.get('Location')).toContain('reason=domain_not_allowed');
    expect(state.writes.userInserts).toEqual([]);
  });
});
