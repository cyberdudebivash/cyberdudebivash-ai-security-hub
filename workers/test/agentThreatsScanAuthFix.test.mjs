/* Regression test — agent-threats.html's "Scan My Agent" tool never sent an
 * Authorization header (Tier 2 backlog item #7; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * runAgentScan() posts to /api/ai-security/agents/scan with no auth header
 * at all — anywhere on this page. handleScanAgent (workers/src/handlers/
 * aiThreatIntel.js) hard-requires a real authenticated user
 * (`if (!authCtx?.userId) return err('Auth required', 401)`), so this
 * always 401'd for every visitor, including logged-in customers. Because
 * the frontend has a fully-functional client-side fallback (an identical
 * OWASP LLM Top 10 rule engine) the bug was invisible in the UI — visitors
 * always saw a complete-looking report — but it was never the real,
 * D1-persisted assessment: no real agent_id, so "Register & Save Report",
 * advisory alerts, and automated rescans never had anything real to attach
 * to, for anyone, ever.
 *
 * Verifies: the backend really does 401 with no token and really does
 * succeed with one (confirming the root cause), and the frontend now reads
 * the real session token (sessionStorage['cdb_access'], the same key
 * user-dashboard.html's real login flow writes) and attaches it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { handleScanAgent } from '../src/handlers/aiThreatIntel.js';

function makeEnv() {
  return {
    DB: {
      prepare: () => ({ bind: () => ({ run: async () => ({}) }) }),
    },
  };
}

describe('backend: handleScanAgent requires a real authenticated user', () => {
  it('401s an anonymous caller (authCtx with no userId) — confirms the root cause', async () => {
    const req = new Request('https://x/api/ai-security/agents/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test Agent', framework: 'langchain', tools: [] }),
    });
    const res = await handleScanAgent(req, makeEnv(), {});
    expect(res.status).toBe(401);
  });

  it('succeeds with a real agent_id for an authenticated caller', async () => {
    const req = new Request('https://x/api/ai-security/agents/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test Agent', framework: 'langchain', tools: ['file_write'] }),
    });
    const res = await handleScanAgent(req, makeEnv(), { userId: 'u_1', orgId: 'org_1' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.agent_id).toMatch(/^agt_/);
  });
});

describe('frontend: runAgentScan() now attaches the real session token', () => {
  const root = resolve(import.meta.dirname, '..');
  const fe = readFileSync(resolve(root, '../frontend/agent-threats.html'), 'utf8');

  it('defines getAuthToken() checking sessionStorage cdb_access before the legacy cdb_token keys', () => {
    const start = fe.indexOf('function getAuthToken()');
    expect(start, 'getAuthToken must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('\n}', start);
    const body = fe.slice(start, end);
    const accessIdx = body.indexOf("sessionStorage.getItem('cdb_access')");
    const tokenIdx  = body.indexOf("localStorage.getItem('cdb_token')");
    expect(accessIdx).toBeGreaterThan(-1);
    expect(tokenIdx).toBeGreaterThan(-1);
    expect(accessIdx).toBeLessThan(tokenIdx);
  });

  it('runAgentScan() calls getAuthToken() and conditionally attaches an Authorization header', () => {
    const start = fe.indexOf('async function runAgentScan()');
    expect(start, 'runAgentScan must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('/api/ai-security/agents/scan', start) + 200;
    const body = fe.slice(start, end);
    expect(body).toContain('getAuthToken()');
    expect(body).toMatch(/Authorization.*Bearer .\s*\+\s*_authToken/);
  });

  it('still sends the Content-Type header and JSON body (existing behavior preserved)', () => {
    const start = fe.indexOf('async function runAgentScan()');
    const end = fe.indexOf('/api/ai-security/agents/scan', start) + 400;
    const body = fe.slice(start, end);
    expect(body).toContain("'Content-Type':'application/json'");
    expect(body).toContain('JSON.stringify({name,framework:fw,permissions:caps,internet_access:net,tools:caps})');
  });
});
