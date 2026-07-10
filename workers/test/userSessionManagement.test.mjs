/* CAP-PORTAL-003 (customer-portal registry): "Session Management (Active
 * Sessions / Per-Session Revoke)" was NOT READY — refresh_tokens has always
 * tracked ip_address/user_agent/created_at per session, but nothing ever
 * exposed it to the customer, and the only self-service control was
 * "sign out everywhere" (POST /api/auth/logout {all:true}). A customer had
 * no way to see which devices were signed in or kick out one they didn't
 * recognize — a real gap versus Stripe/GitHub/Notion/Cloudflare-style
 * account security pages.
 *
 * Adds GET /api/user/sessions (list this customer's own active sessions,
 * optionally flagging "this device" via an X-Session-Hint header carrying
 * the caller's own already-held refresh token) and
 * DELETE /api/user/sessions/:id (ownership-scoped single-session revoke —
 * another user's session id 404s exactly like a nonexistent one, so this
 * can never be used as an IDOR/enumeration oracle).
 *
 * Runs the real handlers against a real SQL engine (node:sqlite), same
 * convention as workers/test/phase10PasswordReset.test.mjs.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import { handleListSessions, handleRevokeSession } from '../src/handlers/auth.js';
import { hashToken } from '../src/auth/jwt.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

const get = (path, headers = {}) => new Request(`https://x${path}`, { method: 'GET', headers });

describe('CAP-PORTAL-003: Active Sessions (list + per-session revoke)', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    db = env.DB._sqlite;
    db.exec(`CREATE TABLE refresh_tokens (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked INTEGER NOT NULL DEFAULT 0, ip_address TEXT, user_agent TEXT
    )`);
  });

  async function seedSession(id, userId, rawToken, opts = {}) {
    const hash = await hashToken(rawToken);
    db.prepare(`INSERT INTO refresh_tokens
        (id, user_id, token_hash, expires_at, created_at, revoked, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      id, userId, hash,
      opts.expires_at ?? '2099-01-01T00:00:00.000Z',
      opts.created_at ?? '2026-01-01T00:00:00.000Z',
      opts.revoked ?? 0,
      opts.ip ?? '1.2.3.4',
      opts.ua ?? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
    );
  }

  it("lists only the caller's own active (non-revoked, non-expired) sessions", async () => {
    await seedSession('s1', 'u1', 'tok-1');
    await seedSession('s2', 'u1', 'tok-2');
    await seedSession('s3', 'u2', 'tok-3');                                   // different user
    await seedSession('s4', 'u1', 'tok-4', { revoked: 1 });                   // revoked
    await seedSession('s5', 'u1', 'tok-5', { expires_at: '2000-01-01T00:00:00.000Z' }); // expired

    const res = await handleListSessions(get('/api/user/sessions'), env, { user_id: 'u1' });
    const d = await res.json();
    expect(res.status).toBe(200);
    expect(d.sessions.map(s => s.id).sort()).toEqual(['s1', 's2']);
  });

  it('flags the current session via X-Session-Hint, without leaking token_hash', async () => {
    await seedSession('s1', 'u1', 'tok-1');
    await seedSession('s2', 'u1', 'tok-2');
    const res = await handleListSessions(get('/api/user/sessions', { 'X-Session-Hint': 'tok-2' }), env, { user_id: 'u1' });
    const d = await res.json();
    expect(d.sessions.find(s => s.id === 's1').is_current).toBe(false);
    expect(d.sessions.find(s => s.id === 's2').is_current).toBe(true);
    expect(d.sessions[0].token_hash).toBeUndefined();
  });

  it('with no hint header, no session is marked current', async () => {
    await seedSession('s1', 'u1', 'tok-1');
    const res = await handleListSessions(get('/api/user/sessions'), env, { user_id: 'u1' });
    const d = await res.json();
    expect(d.sessions[0].is_current).toBe(false);
  });

  it('returns the device/IP/created_at fields the settings page renders', async () => {
    await seedSession('s1', 'u1', 'tok-1', { ip: '9.9.9.9', ua: 'Mozilla/5.0 Firefox/115.0' });
    const res = await handleListSessions(get('/api/user/sessions'), env, { user_id: 'u1' });
    const d = await res.json();
    expect(d.sessions[0].ip_address).toBe('9.9.9.9');
    expect(d.sessions[0].user_agent).toContain('Firefox');
    expect(d.sessions[0].created_at).toBe('2026-01-01T00:00:00.000Z');
  });

  it('requires authentication to list', async () => {
    const res = await handleListSessions(get('/api/user/sessions'), env, {});
    expect(res.status).toBe(401);
  });

  it('revokes an individual session owned by the caller', async () => {
    await seedSession('s1', 'u1', 'tok-1');
    const res = await handleRevokeSession(get('/api/user/sessions/s1'), env, { user_id: 'u1' }, 's1');
    expect(res.status).toBe(200);
    expect(db.prepare(`SELECT revoked FROM refresh_tokens WHERE id='s1'`).get().revoked).toBe(1);
  });

  it("cannot revoke another user's session — 404, ownership-scoped, IDOR-safe, row unchanged", async () => {
    await seedSession('s1', 'victim', 'tok-1');
    const res = await handleRevokeSession(get('/api/user/sessions/s1'), env, { user_id: 'attacker' }, 's1');
    expect(res.status).toBe(404);
    expect(db.prepare(`SELECT revoked FROM refresh_tokens WHERE id='s1'`).get().revoked).toBe(0);
  });

  it('revoking a nonexistent session id → 404', async () => {
    const res = await handleRevokeSession(get('/api/user/sessions/ghost'), env, { user_id: 'u1' }, 'ghost');
    expect(res.status).toBe(404);
  });

  it('revoking an already-revoked session → 404 (idempotent-safe, not a silent success)', async () => {
    await seedSession('s1', 'u1', 'tok-1', { revoked: 1 });
    const res = await handleRevokeSession(get('/api/user/sessions/s1'), env, { user_id: 'u1' }, 's1');
    expect(res.status).toBe(404);
  });

  it('requires authentication to revoke', async () => {
    const res = await handleRevokeSession(get('/api/user/sessions/s1'), env, {}, 's1');
    expect(res.status).toBe(401);
  });
});

describe('CAP-PORTAL-003: route + frontend contract (no drift between UI and real backend)', () => {
  const indexSrc = fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  const dashSrc  = fs.readFileSync(new URL('../../frontend/user-dashboard.html', import.meta.url), 'utf8');

  it('index.js imports and routes both handlers, auth-gated on isRealUser', () => {
    expect(indexSrc).toMatch(/handleListSessions,\s*handleRevokeSession/);
    expect(indexSrc).toMatch(/path === '\/api\/user\/sessions' && method === 'GET'/);
    expect(indexSrc).toMatch(/path\.startsWith\('\/api\/user\/sessions\/'\) && method === 'DELETE'/);
  });

  it('user-dashboard.html calls the real endpoints, not a placeholder/stub', () => {
    expect(dashSrc).toMatch(/apiFetch\('\/api\/user\/sessions',/);
    expect(dashSrc).toMatch(/apiFetch\('\/api\/user\/sessions\/' \+ encodeURIComponent\(id\)/);
    expect(dashSrc).toMatch(/s\.is_current/);
  });

  it('the settings page is wired to lazy-load sessions, and the revoke button uses a data-attribute (not string-interpolated onclick) to stay immune to the CAP-ADMIN-004 injection bug class', () => {
    expect(dashSrc).toMatch(/if \(id === 'settings' && typeof loadSessions === 'function'\) loadSessions\(\);/);
    expect(dashSrc).toMatch(/data-session-id="'\s*\+\s*sessEsc\(s\.id\)/);
    expect(dashSrc).toMatch(/onclick="revokeSession\(this\.dataset\.sessionId\)"/);
  });
});
