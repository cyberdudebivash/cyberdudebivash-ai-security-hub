/* P1 incident regression — GET /api/enterprise/capability threw "Cannot
 * access 'authCtx' before initialization" in production (request id
 * cdb_mrb42p2q_af46kr).
 *
 * Root cause: routeRequest() (src/index.js) is one large function. Later in
 * its body (~line 7503) it declares `const authCtx = await resolveAuthV5(...)`
 * directly in the function scope — not inside any if-block — intended to be
 * shared by the "v28+ enterprise & scanner routes" beneath it. A `const`
 * declared anywhere in a scope is hoisted for the *entire* scope and stays in
 * the temporal dead zone until that line actually executes. The
 * /api/enterprise/capability route, registered earlier in the same function
 * (~line 2788), referenced the bare identifier `authCtx` without declaring
 * its own local copy — every sibling route around it does declare one. Any
 * request to this endpoint hit the TDZ before line 7503 ever ran, and the
 * global exception boundary (see globalErrorBoundary.test.mjs) converted the
 * ReferenceError into a 500 ERR_UNHANDLED — so the endpoint was completely
 * non-functional, though callers saw a clean JSON error rather than a raw
 * crash page.
 *
 * A systematic scan of every route registered before line 7503 confirmed
 * this was the ONLY block with this exact pattern (bare `authCtx` reference,
 * no local declaration) — an isolated, single-endpoint bug, not a systemic
 * routing issue.
 *
 * Fix: declare `const authCtx = await resolveAuthV5(request, env).catch(...)`
 * locally inside the /api/enterprise/capability block, matching every
 * neighboring route. authCtx is not even read inside handleEnterpriseCapability
 * (it's a public capability-matrix endpoint), so this is a pure
 * declaration-ordering fix with zero authorization/behavior change. */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function kvStub() {
  return { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) };
}
function dbStub() {
  const results = { results: [], success: true };
  const stmt = { bind: () => stmt, first: async () => null, all: async () => results, run: async () => ({ success: true }) };
  return { prepare: () => stmt, batch: async () => [] };
}
function baseEnv() {
  return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub() };
}
function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

describe('GET /api/enterprise/capability — TDZ regression', () => {
  it('does not throw "Cannot access before initialization" and returns the capability matrix', async () => {
    const req = new Request('https://cyberdudebivash.in/api/enterprise/capability');
    const res = await worker.fetch(req, baseEnv(), ctxStub());

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.platform).toMatch(/Enterprise Capability Matrix/);
    expect(body.platform_health).toBeDefined();
  });

  it('is reachable by both anonymous and authenticated callers (authCtx is unused by the handler, but must resolve without throwing either way)', async () => {
    const anon = await worker.fetch(new Request('https://cyberdudebivash.in/api/enterprise/capability'), baseEnv(), ctxStub());
    expect(anon.status).toBe(200);

    const authed = await worker.fetch(new Request('https://cyberdudebivash.in/api/enterprise/capability', {
      headers: { Authorization: 'Bearer not-a-real-token' },
    }), baseEnv(), ctxStub());
    // An invalid bearer token must not crash the route — resolveAuthV5 degrades
    // to its .catch(() => ({ tier: 'FREE' })) fallback, same as every sibling route.
    expect(authed.status).toBe(200);
  });
});
