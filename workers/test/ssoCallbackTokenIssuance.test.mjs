/* enterpriseSsoHandler.js's SSO callback minted unusable session tokens: it
 * called createAccessToken(env, {...}) and storeRefreshToken(env, userId,
 * refreshToken) with the wrong argument shapes compared to every other real
 * caller (auth.js:106-110, googleAuth.js:165-171, mfa.js:192-194).
 *
 * createAccessToken(user, secret)'s 2nd arg is the HMAC signing secret — with
 * `env` passed there instead, TextEncoder coerces the whole env object to the
 * literal string "[object Object]", so every SSO-issued JWT was silently
 * signed with a constant, not env.JWT_SECRET. No exception was thrown (the
 * bug is data-shaped, not a crash), so the flow "succeeded" — the resulting
 * token simply failed verifyJWT() everywhere else in the app.
 *
 * storeRefreshToken(db, ...)'s 1st arg is a D1 database (env.DB) — with `env`
 * passed instead, env.prepare doesn't exist, the INSERT threw, and the
 * failure was swallowed by an inline `.catch(() => {})`, so the refresh token
 * was never persisted. The redirect also embedded the whole {token,hash,
 * expires} object as `refresh_token`, which stringifies to "[object Object]".
 *
 * This file deliberately does NOT mock ../src/auth/jwt.js (unlike
 * ssoAuditLogWrite.test.mjs, which does and therefore could not have caught
 * this — a mock that always "succeeds" regardless of what arguments it's
 * called with can't detect a wrong-argument-shape bug). Driving the real
 * jwt.js is what actually proves the token this handler mints is usable.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

import { handleEnterpriseSSoCallback } from '../src/handlers/enterpriseSsoHandler.js';
import { verifyJWT, hashToken } from '../src/auth/jwt.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE users (
    id TEXT PRIMARY KEY, email TEXT, name TEXT, tier TEXT, org_name TEXT,
    sso_provider TEXT, sso_sub TEXT, created_at TEXT, updated_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE audit_log (
    id TEXT DEFAULT (lower(hex(randomblob(8)))), user_id TEXT, api_key_id TEXT,
    action TEXT NOT NULL, resource TEXT, resource_id TEXT, ip TEXT, user_agent TEXT,
    status TEXT DEFAULT 'ok', metadata TEXT DEFAULT '{}', details TEXT DEFAULT '{}',
    severity TEXT DEFAULT 'info', created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE refresh_tokens (
    user_id TEXT, token_hash TEXT, expires_at TEXT, ip_address TEXT, user_agent TEXT, revoked INTEGER DEFAULT 0
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeKV(entries = {}) {
  const store = new Map(Object.entries(entries));
  return {
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  };
}

function mockOidcFetch({ discoveryUrl, tokenEndpoint, userinfoEndpoint, userinfo }) {
  return async (url, init = {}) => {
    const href = typeof url === 'string' ? url : url.toString();
    if (href === discoveryUrl) {
      return new Response(JSON.stringify({ token_endpoint: tokenEndpoint, userinfo_endpoint: userinfoEndpoint }), { status: 200 });
    }
    if (href === tokenEndpoint && init.method === 'POST') {
      return new Response(JSON.stringify({ access_token: 'idp-access-token' }), { status: 200 });
    }
    if (href === userinfoEndpoint) {
      return new Response(JSON.stringify(userinfo), { status: 200 });
    }
    throw new Error(`unexpected fetch to ${href}`);
  };
}

const DISCOVERY_URL     = 'https://idp.example.com/.well-known/openid-configuration';
const TOKEN_ENDPOINT    = 'https://idp.example.com/oauth2/token';
const USERINFO_ENDPOINT = 'https://idp.example.com/oauth2/userinfo';
const JWT_SECRET        = 'test-jwt-secret-for-sso-callback';

function makeEnv({ db, kv }) {
  return {
    DB: db,
    SECURITY_HUB_KV: kv,
    WEBSITE: 'https://cyberdudebivash.in',
    WORKER_URL: 'https://worker.example.dev',
    JWT_SECRET,
  };
}

function kvFor(orgSlug, orgConfig) {
  return makeKV({
    [`enterprise_sso:state:teststate123`]: JSON.stringify({ orgSlug }),
    [`enterprise_sso:org:${orgSlug}`]: JSON.stringify(orgConfig),
  });
}

async function runCallback(env) {
  const request = new Request('https://worker.example.dev/api/auth/enterprise/callback?code=authcode123&state=teststate123');
  return handleEnterpriseSSoCallback(request, env);
}

function parseFragment(location) {
  const hash = location.split('#')[1] || '';
  return Object.fromEntries(new URLSearchParams(hash));
}

describe('enterpriseSsoHandler — SSO callback token issuance (regression for wrong createAccessToken/storeRefreshToken call shapes)', () => {
  it('mints an access token that verifyJWT() actually accepts with env.JWT_SECRET', async () => {
    const db = makeRealD1();
    const kv = kvFor('acme', {
      idp_type: 'generic_oidc', discovery_url: DISCOVERY_URL,
      client_id: 'c', client_secret: 's', default_tier: 'ENTERPRISE', org_name: 'Acme Corp',
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL, tokenEndpoint: TOKEN_ENDPOINT, userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    const env = makeEnv({ db, kv });

    const res = await runCallback(env);
    expect(res.status).toBe(302);
    const location = res.headers.get('Location') || '';
    expect(location).not.toContain('sso_error');

    const { access_token } = parseFragment(location);
    expect(access_token).toBeTruthy();

    // The actual regression assertion: the old bug signed every token with
    // the constant "[object Object]" instead of env.JWT_SECRET — verifying
    // against the real secret would fail. This must succeed.
    const payload = await verifyJWT(access_token, JWT_SECRET);
    expect(payload).toBeTruthy();
    expect(payload.email).toBe('jane@acme.com');
    expect(payload.tier).toBe('ENTERPRISE');
    expect(payload.sub).toBeTruthy();

    // Verifying against a wrong secret (simulating the old constant-string
    // key) must fail — confirms the token is genuinely secret-bound, not
    // accidentally verifiable against anything.
    expect(await verifyJWT(access_token, '[object Object]')).toBeNull();
  });

  it('persists a real refresh_tokens row, not a silently-swallowed failure', async () => {
    const db = makeRealD1();
    const kv = kvFor('acme', {
      idp_type: 'generic_oidc', discovery_url: DISCOVERY_URL,
      client_id: 'c', client_secret: 's', default_tier: 'ENTERPRISE', org_name: 'Acme Corp',
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL, tokenEndpoint: TOKEN_ENDPOINT, userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    const env = makeEnv({ db, kv });

    const res = await runCallback(env);
    const location = res.headers.get('Location') || '';
    const { refresh_token } = parseFragment(location);

    // The old bug embedded the whole {token,hash,expires} object in the URL,
    // which stringifies to the literal "[object Object]".
    expect(refresh_token).not.toBe('[object Object]');
    expect(refresh_token.length).toBeGreaterThan(20);

    const expectedHash = await hashToken(refresh_token);
    const row = db._sqlite.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(expectedHash);
    expect(row).toBeTruthy();
    expect(row.user_id).toBeTruthy();
    expect(row.expires_at).toBeTruthy();
  });

  it('a genuine storeRefreshToken failure now surfaces as sso_error instead of a silently-broken success redirect', async () => {
    const kv = kvFor('acme', {
      idp_type: 'generic_oidc', discovery_url: DISCOVERY_URL,
      client_id: 'c', client_secret: 's', default_tier: 'ENTERPRISE', org_name: 'Acme Corp',
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL, tokenEndpoint: TOKEN_ENDPOINT, userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    // env.DB present but missing the refresh_tokens table — storeRefreshToken's
    // INSERT will throw. With the old inline `.catch(() => {})` this would
    // have been swallowed and the handler would still redirect as if
    // successful; it must now propagate to the outer error handler.
    const sqlite = new DatabaseSync(':memory:');
    sqlite.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, name TEXT, tier TEXT, org_name TEXT, sso_provider TEXT, sso_sub TEXT, created_at TEXT, updated_at TEXT)`);
    const wrap = (sql) => { let b = []; return {
      bind(...a) { b = a; return this; },
      async all() { return { results: sqlite.prepare(sql).all(...b) }; },
      async first() { return sqlite.prepare(sql).get(...b) ?? null; },
      async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
    }; };
    const db = { _sqlite: sqlite, prepare: wrap };
    const env = makeEnv({ db, kv });

    const res = await runCallback(env);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location') || '').toContain('sso_error=jwt_issue_failed');
  });
});
