/* enterpriseSsoHandler.js's SSO-login audit write silently no-op'd on every
 * call: its INSERT referenced a `detail` column that has never existed in
 * any audit_log schema variant (the real column is `metadata`, the same one
 * orgManagement.js's writeOrgAuditLog() and aiSecurityCopilot.js's
 * writeCopilotAuditLog() already write to successfully). The write was
 * wrapped in a bare `try { ... } catch {}`, so the resulting SQL error
 * (no such column) was swallowed with zero trace — opsEngine.js's own
 * handleAdminAudit() comment already documented that SSO logins were
 * "completely invisible" to an admin reviewing the audit log, without
 * realizing the D1 write behind that gap was itself failing every time.
 *
 * adminAuditMerge.test.mjs proves the *read* side (handleAdminAudit) surfaces
 * a correctly-shaped D1 row — but it inserts that row by hand, so it could
 * not have caught this bug. This file proves the *write* side: driving the
 * real handleEnterpriseSSoCallback() end-to-end and confirming it lands a
 * real, correctly-shaped row that the existing admin merge view then picks
 * up — closing the loop for the first time.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/auth/jwt.js', () => ({
  createAccessToken: vi.fn(async () => 'fake.access.token'),
  createRefreshToken: vi.fn(async () => ({ token: 'fake-refresh', hash: 'fake-hash', expires: '2099-01-01T00:00:00.000Z' })),
  storeRefreshToken: vi.fn(async () => {}),
}));

const { handleEnterpriseSSoCallback } = await import('../src/handlers/enterpriseSsoHandler.js');
const { handleAdminAudit } = await import('../src/handlers/opsEngine.js');

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
    user_id TEXT, token_hash TEXT, expires_at TEXT, ip_address TEXT, user_agent TEXT
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

const DISCOVERY_URL  = 'https://idp.example.com/.well-known/openid-configuration';
const TOKEN_ENDPOINT = 'https://idp.example.com/oauth2/token';
const USERINFO_ENDPOINT = 'https://idp.example.com/oauth2/userinfo';

function makeEnv({ db, kv }) {
  return {
    DB: db,
    SECURITY_HUB_KV: kv,
    WEBSITE: 'https://cyberdudebivash.in',
    WORKER_URL: 'https://worker.example.dev',
  };
}

async function runCallback(env) {
  const request = new Request('https://worker.example.dev/api/auth/enterprise/callback?code=authcode123&state=teststate123');
  return handleEnterpriseSSoCallback(request, env);
}

describe('enterpriseSsoHandler — SSO login audit write (regression for the silent `detail` column bug)', () => {
  it('writes a real audit_log row with the correct schema instead of silently no-oping', async () => {
    const db = makeRealD1();
    const kv = makeKV({
      'enterprise_sso:state:teststate123': JSON.stringify({ orgSlug: 'acme' }),
      'enterprise_sso:org:acme': JSON.stringify({
        idp_type: 'generic_oidc',
        discovery_url: DISCOVERY_URL,
        client_id: 'client-123',
        client_secret: 'secret-456',
        default_tier: 'ENTERPRISE',
        org_name: 'Acme Corp',
      }),
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL,
      tokenEndpoint: TOKEN_ENDPOINT,
      userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    const env = makeEnv({ db, kv });

    const res = await runCallback(env);

    // The flow must have completed past token exchange, user upsert, and JWT
    // issuance without an sso_error — otherwise it never reaches the audit
    // write this test exists to verify.
    expect(res.status).toBe(302);
    const location = res.headers.get('Location') || '';
    expect(location).not.toContain('sso_error');

    const row = db._sqlite.prepare(`SELECT * FROM audit_log WHERE action = 'sso.login'`).get();
    expect(row).toBeTruthy();
    expect(row.resource).toBe('sso');
    expect(row.status).toBe('ok');
    expect(row.ip).toBeTruthy();

    // This is the specific assertion that would have caught the original bug:
    // the old INSERT targeted a non-existent `detail` column, so real SQLite
    // (like production D1) would throw "no such column" and the surrounding
    // bare try/catch would swallow it — leaving no row at all, and `row`
    // above would already be undefined. Getting this far means the write
    // succeeded; this confirms the *content* landed in the right column.
    const metadata = JSON.parse(row.metadata);
    expect(metadata).toEqual({ idp: 'generic_oidc', org: 'acme', email: 'jane@acme.com' });
  });

  it('never blocks the SSO login itself if the audit write fails (e.g. DB unavailable)', async () => {
    const kv = makeKV({
      'enterprise_sso:state:teststate123': JSON.stringify({ orgSlug: 'acme' }),
      'enterprise_sso:org:acme': JSON.stringify({
        idp_type: 'generic_oidc', discovery_url: DISCOVERY_URL,
        client_id: 'c', client_secret: 's', default_tier: 'ENTERPRISE', org_name: 'Acme Corp',
      }),
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL, tokenEndpoint: TOKEN_ENDPOINT, userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    // No env.DB at all — the `if (env?.DB)` guard should skip the write
    // cleanly, and the earlier user-upsert branch already handles a missing
    // DB by falling back to a synthetic user id.
    const env = makeEnv({ db: undefined, kv });

    const res = await runCallback(env);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location') || '').not.toContain('sso_error');
  });

  it('the new audit_log row is immediately visible through the existing admin merge view (opsEngine.handleAdminAudit)', async () => {
    const db = makeRealD1();
    const kv = makeKV({
      'enterprise_sso:state:teststate123': JSON.stringify({ orgSlug: 'acme' }),
      'enterprise_sso:org:acme': JSON.stringify({
        idp_type: 'generic_oidc', discovery_url: DISCOVERY_URL,
        client_id: 'c', client_secret: 's', default_tier: 'ENTERPRISE', org_name: 'Acme Corp',
      }),
    });
    globalThis.fetch = mockOidcFetch({
      discoveryUrl: DISCOVERY_URL, tokenEndpoint: TOKEN_ENDPOINT, userinfoEndpoint: USERINFO_ENDPOINT,
      userinfo: { email: 'jane@acme.com', name: 'Jane Doe', sub: 'sub-789' },
    });
    const env = makeEnv({ db, kv });

    await runCallback(env);

    const today = db._sqlite.prepare(`SELECT date(created_at) AS d FROM audit_log WHERE action = 'sso.login'`).get().d;
    const adminEnv = { DB: db, SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminAudit(new Request(`https://x/api/admin/audit?date=${today}`), adminEnv, { isAdmin: true, tier: 'ENTERPRISE' });
    expect(res.status).toBe(200);
    const body = await res.json();
    const ssoEntry = body.entries.find(e => e.type === 'sso.login');
    expect(ssoEntry).toBeTruthy();
    expect(ssoEntry.source).toBe('d1');
    expect(ssoEntry.details.email).toBe('jane@acme.com');
  });
});

describe('enterpriseSsoHandler.js source — the specific column-name defect cannot silently recur', () => {
  const src = readFileSync(resolve(import.meta.dirname, '..', 'src/handlers/enterpriseSsoHandler.js'), 'utf8');
  const ssoLogBlock = src.slice(src.indexOf('// Log SSO event'), src.indexOf('// Log SSO event') + 800);

  it('the SSO-login audit INSERT lists the real `metadata` column', () => {
    expect(ssoLogBlock).toMatch(/INSERT (OR IGNORE )?INTO audit_log \([^)]*\bmetadata\b[^)]*\)/);
  });

  it('the SSO-login audit INSERT does not reintroduce the non-existent `detail` column', () => {
    const columnList = ssoLogBlock.slice(ssoLogBlock.indexOf('('), ssoLogBlock.indexOf(')') + 1);
    expect(columnList.split(',').map(c => c.trim())).not.toContain('detail');
  });

  it('a failed audit write is logged, not fully silent, so this class of bug is observable going forward', () => {
    expect(ssoLogBlock).toMatch(/catch\s*\(\s*err\s*\)\s*\{[\s\S]*console\.error/);
  });
});
