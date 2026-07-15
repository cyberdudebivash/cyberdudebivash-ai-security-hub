/* SSO Consolidation (Phase 5, Customer Lifecycle Completion Program).
 *
 * ssoAuth.js (/api/auth/sso/*) is now the sole canonical enterprise SSO
 * system — chosen over enterpriseSsoHandler.js because it already did a
 * real, cryptographically-verified OIDC round-trip (PKCE + nonce + RS256
 * id_token signature check) and real org_members provisioning, while
 * enterpriseSsoHandler.js trusted the IdP's userinfo response with zero
 * verification and never provisioned org membership. See
 * docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md's Domain 1 gap-matrix row for
 * the full reconciliation record.
 *
 * This file proves the three pieces of that consolidation:
 *  1. ssoAuth.js's callback now writes a real audit_log row (it previously
 *     wrote none at all) — verified against a real node:sqlite D1, not the
 *     permissive always-succeeds DB stub mfaSsoRoundTrip.test.mjs uses for
 *     its own (unrelated) round-trip assertions.
 *  2. handleSSOConfigUpsert accepts the friendly named idp_type (azure_ad /
 *     okta) convenience ported from enterpriseSsoHandler.js's
 *     buildDiscoveryURL(), building the correct issuer automatically,
 *     while the original raw `issuer` field keeps working unchanged.
 *  3. enterpriseSsoHandler.js's retired customer-facing routes
 *     (index.js's /api/auth/enterprise/* block) now redirect/410 to the
 *     canonical routes instead of running the unverified-identity code path.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';
import { handleSSOConfigUpsert } from '../src/handlers/ssoAuth.js';

function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }
function kvStub() {
  const m = new Map();
  return {
    async put(k, v, opts) { m.set(k, { v, expires: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : null }); },
    async get(k, type) {
      const e = m.get(k);
      if (!e) return null;
      if (e.expires && e.expires < Date.now()) { m.delete(k); return null; }
      return type === 'json' ? JSON.parse(e.v) : e.v;
    },
    async delete(k) { m.delete(k); },
  };
}

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, slug TEXT UNIQUE, plan TEXT, owner_id TEXT)`);
  sqlite.exec(`CREATE TABLE sso_configs (
    id TEXT PRIMARY KEY, org_id TEXT UNIQUE, provider_name TEXT, issuer TEXT,
    client_id TEXT, client_secret TEXT, allowed_domains TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT, tier TEXT, status TEXT, email_verified INTEGER, created_at TEXT)`);
  sqlite.exec(`CREATE TABLE org_members (id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, role TEXT, status TEXT, joined_at TEXT)`);
  sqlite.exec(`CREATE TABLE refresh_tokens (user_id TEXT, token_hash TEXT, expires_at TEXT, ip_address TEXT, user_agent TEXT, revoked INTEGER DEFAULT 0)`);
  sqlite.exec(`CREATE TABLE audit_log (
    id TEXT DEFAULT (lower(hex(randomblob(8)))), user_id TEXT, api_key_id TEXT,
    action TEXT NOT NULL, resource TEXT, resource_id TEXT, ip TEXT, user_agent TEXT,
    status TEXT DEFAULT 'ok', metadata TEXT DEFAULT '{}', details TEXT DEFAULT '{}',
    severity TEXT DEFAULT 'info', created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeEnv(db) {
  return { DB: db, SECURITY_HUB_KV: kvStub(), WEBSITE: 'https://cyberdudebivash.in', JWT_SECRET: 'test-secret' };
}

const B = 'https://cyberdudebivash.in';

// ─── Real RSA-signed IdP stub (same convention as mfaSsoRoundTrip.test.mjs) ──
const IDP = 'https://idp.example.com';
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function makeIdP() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return {
    jwks: { keys: [{ ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' }] },
    async signIdToken(claims) {
      const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' })));
      const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
      const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(`${header}.${payload}`));
      return `${header}.${payload}.${b64url(sig)}`;
    },
  };
}

function stubIdpFetch(idp, { discoveryUrl = `${IDP}/.well-known/openid-configuration`, tokenUrl = `${IDP}/token`, jwksUrl = `${IDP}/jwks`, claimsFor }) {
  return vi.fn(async (input) => {
    const u = String(input instanceof Request ? input.url : input);
    if (u === discoveryUrl) {
      return Response.json({ issuer: IDP, authorization_endpoint: `${IDP}/authorize`, token_endpoint: tokenUrl, jwks_uri: jwksUrl });
    }
    if (u === tokenUrl) {
      const idToken = await idp.signIdToken(claimsFor());
      return Response.json({ id_token: idToken, access_token: 'idp-opaque', token_type: 'Bearer' });
    }
    if (u === jwksUrl) return Response.json(idp.jwks);
    return new Response('unexpected external call: ' + u, { status: 500 });
  });
}

describe('ssoAuth.js — audit log write (previously missing entirely)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('writes a real audit_log row on successful SSO login', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u_owner')`).run();
    db._sqlite.prepare(`INSERT INTO sso_configs (id, org_id, provider_name, issuer, client_id, client_secret, enabled) VALUES ('c1','org_1','custom','${IDP}','client-1','secret-1',1)`).run();
    const env = makeEnv(db);

    let lastNonce;
    const idp = await makeIdP();
    vi.stubGlobal('fetch', stubIdpFetch(idp, { claimsFor: () => ({
      iss: IDP, aud: 'client-1', sub: 'idp-sub-1', email: 'engineer@acme.test', name: 'Acme Engineer',
      nonce: lastNonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300,
    }) }));

    const login = await worker.fetch(new Request(`${B}/api/auth/sso/login?org=acme`), env, ctxStub());
    const loc = new URL(login.headers.get('Location'));
    const stateParam = loc.searchParams.get('state');
    lastNonce = loc.searchParams.get('nonce');

    const cb = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=c1&state=${stateParam}`), env, ctxStub());
    expect(cb.headers.get('Location')).toContain('access_token=');

    const row = db._sqlite.prepare(`SELECT * FROM audit_log WHERE action = 'sso.login'`).get();
    expect(row).toBeTruthy();
    expect(row.resource).toBe('sso');
    expect(row.resource_id).toBe('org_1');
    expect(row.status).toBe('ok');
    const metadata = JSON.parse(row.metadata);
    expect(metadata.email).toBe('engineer@acme.test');
    expect(metadata.org_id).toBe('org_1');
  });

  it('never blocks the login itself if the audit write fails (e.g. missing table)', async () => {
    const sqlite = new DatabaseSync(':memory:');
    sqlite.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, slug TEXT UNIQUE, plan TEXT, owner_id TEXT)`);
    sqlite.exec(`CREATE TABLE sso_configs (id TEXT PRIMARY KEY, org_id TEXT UNIQUE, provider_name TEXT, issuer TEXT, client_id TEXT, client_secret TEXT, allowed_domains TEXT DEFAULT '[]', enabled INTEGER DEFAULT 1)`);
    sqlite.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT, tier TEXT, status TEXT, email_verified INTEGER, created_at TEXT)`);
    sqlite.exec(`CREATE TABLE org_members (id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, role TEXT, status TEXT, joined_at TEXT)`);
    sqlite.exec(`CREATE TABLE refresh_tokens (user_id TEXT, token_hash TEXT, expires_at TEXT, ip_address TEXT, user_agent TEXT, revoked INTEGER DEFAULT 0)`);
    // Deliberately no audit_log table.
    sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u_owner')`).run();
    sqlite.prepare(`INSERT INTO sso_configs (id, org_id, provider_name, issuer, client_id, client_secret, enabled) VALUES ('c1','org_1','custom','${IDP}','client-1','secret-1',1)`).run();
    const wrap = (sql) => { let b = []; return {
      bind(...a) { b = a; return this; },
      async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
      async first() { return sqlite.prepare(sql).get(...b) ?? null; },
      async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
    }; };
    const env = makeEnv({ _sqlite: sqlite, prepare: wrap });

    let lastNonce;
    const idp = await makeIdP();
    vi.stubGlobal('fetch', stubIdpFetch(idp, { claimsFor: () => ({
      iss: IDP, aud: 'client-1', sub: 'idp-sub-2', email: 'engineer2@acme.test', name: 'Acme Engineer 2',
      nonce: lastNonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300,
    }) }));

    const login = await worker.fetch(new Request(`${B}/api/auth/sso/login?org=acme`), env, ctxStub());
    const loc = new URL(login.headers.get('Location'));
    const stateParam = loc.searchParams.get('state');
    lastNonce = loc.searchParams.get('nonce');

    const cb = await worker.fetch(new Request(`${B}/api/auth/sso/callback?code=c1&state=${stateParam}`), env, ctxStub());
    // Login still succeeds even though the audit_log table doesn't exist.
    expect(cb.headers.get('Location')).toContain('access_token=');
  });
});

describe('handleSSOConfigUpsert — named idp_type convenience (ported from enterpriseSsoHandler.js)', () => {
  function req(body) {
    return new Request('https://x/api/admin/sso/config', { method: 'POST', body: JSON.stringify(body) });
  }
  const owner = { isAdmin: true, email: 'owner@x.com' };

  function envWithDiscoveryStub(db, expectedIssuer) {
    vi.stubGlobal('fetch', vi.fn(async (input) => {
      const u = String(input instanceof Request ? input.url : input);
      expect(u).toBe(`${expectedIssuer}/.well-known/openid-configuration`);
      return Response.json({ authorization_endpoint: 'https://idp/authorize', token_endpoint: 'https://idp/token', jwks_uri: 'https://idp/jwks' });
    }));
    return makeEnv(db);
  }

  afterEach(() => vi.unstubAllGlobals());

  it('azure_ad + tenant_id builds the correct tenant-scoped issuer', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u')`).run();
    const env = envWithDiscoveryStub(db, 'https://login.microsoftonline.com/acme-tenant-id/v2.0');

    const res = await handleSSOConfigUpsert(req({
      org: 'acme', idp_type: 'azure_ad', tenant_id: 'acme-tenant-id', client_id: 'c', client_secret: 's',
    }), env, owner);
    expect(res.status).toBe(200);

    const row = db._sqlite.prepare(`SELECT * FROM sso_configs WHERE org_id = 'org_1'`).get();
    expect(row.issuer).toBe('https://login.microsoftonline.com/acme-tenant-id/v2.0');
    expect(row.provider_name).toBe('azure_ad');
  });

  it('azure_ad without tenant_id falls back to the multi-tenant "organizations" endpoint', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u')`).run();
    const env = envWithDiscoveryStub(db, 'https://login.microsoftonline.com/organizations/v2.0');

    const res = await handleSSOConfigUpsert(req({ org: 'acme', idp_type: 'azure_ad', client_id: 'c', client_secret: 's' }), env, owner);
    expect(res.status).toBe(200);
  });

  it('okta + okta_domain builds the correct issuer', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u')`).run();
    const env = envWithDiscoveryStub(db, 'https://acme.okta.com');

    const res = await handleSSOConfigUpsert(req({
      org: 'acme', idp_type: 'okta', okta_domain: 'acme.okta.com', client_id: 'c', client_secret: 's',
    }), env, owner);
    expect(res.status).toBe(200);
    const row = db._sqlite.prepare(`SELECT * FROM sso_configs WHERE org_id = 'org_1'`).get();
    expect(row.issuer).toBe('https://acme.okta.com');
  });

  it('okta without okta_domain is a clear 400, not a broken discovery call', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u')`).run();
    const env = makeEnv(db);

    const res = await handleSSOConfigUpsert(req({ org: 'acme', idp_type: 'okta', client_id: 'c', client_secret: 's' }), env, owner);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('okta_domain');
  });

  it('the original raw issuer field still works unchanged (backward compatible)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES ('org_1','Acme','acme','ENTERPRISE','u')`).run();
    const env = envWithDiscoveryStub(db, 'https://custom-idp.example.com');

    const res = await handleSSOConfigUpsert(req({
      org: 'acme', issuer: 'https://custom-idp.example.com', client_id: 'c', client_secret: 's',
    }), env, owner);
    expect(res.status).toBe(200);
    const row = db._sqlite.prepare(`SELECT * FROM sso_configs WHERE org_id = 'org_1'`).get();
    expect(row.issuer).toBe('https://custom-idp.example.com');
    expect(row.provider_name).toBe('custom');
  });
});

describe('Retired enterpriseSsoHandler.js customer-facing routes (index.js)', () => {
  const db = makeRealD1();
  const kv = kvStub();
  const env = { DB: db, SECURITY_HUB_DB: db, KV: kv, SECURITY_HUB_KV: kv, WEBSITE: 'https://cyberdudebivash.in' };

  it('GET /api/auth/enterprise/sso redirects to the canonical login route, preserving ?org=', async () => {
    const res = await worker.fetch(new Request(`${B}/api/auth/enterprise/sso?org=acme`, { redirect: 'manual' }), env, ctxStub());
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('Location'));
    expect(loc.pathname).toBe('/api/auth/sso/login');
    expect(loc.searchParams.get('org')).toBe('acme');
  });

  it('GET /api/auth/enterprise/callback redirects to a clean-restart error, not a broken state lookup', async () => {
    const res = await worker.fetch(new Request(`${B}/api/auth/enterprise/callback?code=x&state=y`, { redirect: 'manual' }), env, ctxStub());
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('sso_error=endpoint_moved_please_retry');
  });

  it('POST /api/auth/enterprise/configure is retired with a clear pointer, not silently forwarded', async () => {
    const res = await worker.fetch(new Request(`${B}/api/auth/enterprise/configure`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ org_slug: 'acme' }),
    }), env, ctxStub());
    expect(res.status).toBe(410);
    const body = await res.json();
    expect(body.use_instead).toBe('POST /api/admin/sso/config');
  });

  it('GET /api/auth/enterprise/config still responds, documenting the canonical routes', async () => {
    const res = await worker.fetch(new Request(`${B}/api/auth/enterprise/config`), env, ctxStub());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.initiation_url).toContain('/api/auth/sso/login');
    expect(body.callback_url).toContain('/api/auth/sso/callback');
    expect(JSON.stringify(body)).not.toContain('/api/auth/enterprise/configure');
  });
});
