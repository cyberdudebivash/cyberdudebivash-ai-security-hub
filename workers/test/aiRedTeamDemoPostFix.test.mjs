/* Regression test — ai-security-assessment.html's "Live MITRE ATLAS Probe"
 * free demo modal (Tier 2 backlog item #6; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * openRedTeamDemo() fetched POST-only /api/ai-redteam/probe/jailbreak with
 * the default GET method (workers/src/handlers/aiRedTeamPro.js's internal
 * router only matches this path for method==='POST'; any other method falls
 * through to its final 404). Since the modal's own code does
 * `if (!techRes.ok || !promptRes.ok) throw ...`, the always-404 probe
 * request meant this entire "free, no payment" demo — explicitly marketed
 * as proof the ₹99,999 paid engagement is "the real engine, not a mockup" —
 * always fell straight to the generic "temporarily unavailable" fallback
 * and never showed real MITRE ATLAS data to a single visitor.
 *
 * Verifies: the backend route is genuinely POST-only (confirming the root
 * cause), and the frontend now sends a real POST with a valid JSON body
 * (probeJailbreak does `await request.json()` unconditionally — a POST with
 * no body at all would 500, not fix anything).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { handleAIRedTeamPro } from '../src/handlers/aiRedTeamPro.js';

describe('backend: /api/ai-redteam/probe/jailbreak is genuinely POST-only', () => {
  it('returns 404 for GET (confirms the root cause — this is why the demo always failed)', async () => {
    const req = new Request('https://x/api/ai-redteam/probe/jailbreak', { method: 'GET' });
    const res = await handleAIRedTeamPro(req, {});
    expect(res.status).toBe(404);
  });

  it('returns 200 with real probe data for POST with a valid (even empty) JSON body', async () => {
    const req = new Request('https://x/api/ai-redteam/probe/jailbreak', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const res = await handleAIRedTeamPro(req, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.probeType).toBe('JAILBREAK');
    expect(Array.isArray(body.probes)).toBe(true);
    expect(body.probeCount).toBeGreaterThan(0);
  });

  it('500s for POST with no body at all (confirms a bare method fix without a body would not be enough)', async () => {
    const req = new Request('https://x/api/ai-redteam/probe/jailbreak', { method: 'POST' });
    const res = await handleAIRedTeamPro(req, {});
    expect(res.status).toBe(500);
  });
});

describe('frontend: openRedTeamDemo() now sends a real POST with a JSON body', () => {
  const root = resolve(import.meta.dirname, '..');
  const fe = readFileSync(resolve(root, '../frontend/ai-security-assessment.html'), 'utf8');

  function openRedTeamDemoBody() {
    const start = fe.indexOf('async function openRedTeamDemo()');
    expect(start, 'openRedTeamDemo must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('\n}', start);
    expect(end, "openRedTeamDemo's closing brace must be found").toBeGreaterThan(-1);
    return fe.slice(start, end);
  }

  it("the probe/jailbreak fetch specifies method: 'POST'", () => {
    const body = openRedTeamDemoBody();
    const idx = body.indexOf("fetch(API_BASE + '/api/ai-redteam/probe/jailbreak'");
    expect(idx, 'the actual fetch() call site must be found').toBeGreaterThan(-1);
    const callSite = body.slice(idx, idx + 300);
    expect(callSite).toMatch(/method:\s*'POST'/);
  });

  it('sends a JSON Content-Type header and a valid (parseable) JSON body', () => {
    const body = openRedTeamDemoBody();
    const idx = body.indexOf("fetch(API_BASE + '/api/ai-redteam/probe/jailbreak'");
    const callSite = body.slice(idx, idx + 300);
    expect(callSite).toMatch(/'Content-Type':\s*'application\/json'/);
    expect(callSite).toMatch(/body:\s*JSON\.stringify\(\{\}\)/);
  });

  it('the sibling /api/ai-redteam/techniques call is untouched (it is genuinely GET-only)', () => {
    const body = openRedTeamDemoBody();
    const idx = body.indexOf('/api/ai-redteam/techniques');
    expect(idx).toBeGreaterThan(-1);
    const callSite = body.slice(idx, idx + 100);
    expect(callSite).not.toContain("method: 'POST'");
  });
});
