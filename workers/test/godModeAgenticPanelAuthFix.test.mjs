/* Regression test — god-mode.html's Agentic AI Command Center panels
 * (Anomaly Detection / Predictive Threat Intel / Agent Bus) never sent an
 * Authorization header, always 401'ing (Tier 2 backlog item #5; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * loadAnomaly()/loadPredict()/loadAgentBus() all call fetchJson(), which
 * only ever sent {Accept: 'application/json'} — no auth of any kind. Their
 * backend routes (/api/anomaly/*, /api/predict/*, /api/agent/* in
 * workers/src/index.js) all hard-require a real authenticated user
 * (isRealUser(authCtx) gate, 401 otherwise), so every visitor to this page —
 * including a real, logged-in ENTERPRISE customer — always got "endpoint
 * error: HTTP 401" on all three panels, regardless of login state.
 *
 * getUserToken() (used elsewhere on this same page for the ENTERPRISE
 * run-trigger) had the identical root cause: it only read the legacy
 * 'cdb_token' key, never the real session key
 * frontend/user-dashboard.html's login/signup flow actually writes to
 * (sessionStorage['cdb_access']) — the same class of bug already found and
 * fixed in frontend/assets/copilot-widget.js (see
 * copilotWidgetDashboardFix.test.mjs).
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/god-mode.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

describe('getUserToken() checks the real session key before the legacy fallback', () => {
  it("reads sessionStorage['cdb_access'] before localStorage/sessionStorage 'cdb_token'", () => {
    const body = fnBody('getUserToken');
    const accessIdx = body.indexOf("sessionStorage.getItem('cdb_access')");
    const tokenIdx  = body.indexOf("localStorage.getItem('cdb_token')");
    expect(accessIdx).toBeGreaterThan(-1);
    expect(tokenIdx).toBeGreaterThan(-1);
    expect(accessIdx).toBeLessThan(tokenIdx);
  });

  it('still falls back to the legacy keys (does not break existing admin/OAuth flows)', () => {
    const body = fnBody('getUserToken');
    expect(body).toContain("localStorage.getItem('cdb_token')");
    expect(body).toContain("sessionStorage.getItem('cdb_token')");
  });
});

describe('fetchJson() — the Agentic AI panels\' shared loader now attaches the real token', () => {
  it('calls getUserToken() and conditionally sets an Authorization header', () => {
    const body = fnBody('fetchJson');
    expect(body).toContain('getUserToken()');
    expect(body).toMatch(/headers\[.Authorization.\]\s*=\s*.Bearer .\s*\+\s*token/);
  });

  it('still requests JSON (Accept header preserved)', () => {
    const body = fnBody('fetchJson');
    expect(body).toContain("'Accept': 'application/json'");
  });
});

describe('the 3 Agentic AI panel loaders all go through the fixed fetchJson()', () => {
  it('loadAnomaly, loadPredict and loadAgentBus all call fetchJson(...)', () => {
    for (const [loader, path] of [
      ['loadAnomaly', "'/api/anomaly/stats'"],
      ['loadPredict', "'/api/predict/stats'"],
      ['loadAgentBus', "'/api/agent/status'"],
    ]) {
      const body = fnBody(loader);
      expect(body, `${loader} must call fetchJson(${path})`).toContain(`fetchJson(${path})`);
    }
  });
});
