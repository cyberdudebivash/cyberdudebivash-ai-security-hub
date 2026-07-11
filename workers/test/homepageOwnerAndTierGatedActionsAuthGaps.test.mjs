/* Regression test — frontend/index.html's Autonomous SOC, SIEM Integration
 * Deploy, and Org Memory widgets (full-frontend-audit follow-up, Tier 1
 * item #2; see docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * Two distinct bugs, same section of the page:
 *
 * 1. Autonomous SOC is a real customer-facing ENTERPRISE/MSSP/TEAM/PRO
 *    feature (workers/src/index.js's `/api/auto-soc/` prefix gate resolves
 *    auth from the request itself via resolveAuthV5() and requires one of
 *    those tiers, or owner/admin). 6 of its fetch() calls never attached the
 *    Authorization bearer token, so real paying customers clicking "Run Now",
 *    polling pipeline status, refreshing the log, viewing generated rules, or
 *    setting a schedule always hit an anonymous 403 — "Enterprise plan
 *    required" — regardless of their real tier. Only 2 calls
 *    (cdbAutoSOCLoad, cdbAutoSOCToggle) already attached it correctly.
 * 2. SIEM Integration Deploy and Org Memory are genuinely owner-only tools
 *    server-side (workers/src/index.js's `/api/(integrations|org-memory|...)`
 *    prefix gate requires isOwner(), the same strict check used by the
 *    already-correct proposal-gen/growth-analytics/CRM sections elsewhere on
 *    this page) — but both sections were marked data-auth-gate="true"
 *    (reveals for ANY authenticated user, not just the owner) instead of
 *    data-auth-gate="owner" (reveals ONLY for the server-verified owner,
 *    same as their true peers), and none of their fetch() calls attached any
 *    auth header at all — broken even for the real owner.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

// Most of this page's action functions are assigned as `window.NAME = function() {`
// rather than the `function NAME() {` declaration form homepageSignInPath.test.mjs's
// helper targets. Finds the real end of the block (the closing `\n};`) instead of
// guessing a fixed slice length.
function fnBody(name) {
  const start = fe.indexOf(`${name} = function`);
  expect(start, `${name} must exist as a window.* assignment`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n};', start);
  expect(end, `${name}'s closing "};" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

function plainFnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist as a function declaration`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

const BEARER_HEADER_RE = /Authorization['"]?\s*:\s*['"]Bearer ['"]?\s*\+/;

function expectAttachesToken(body) {
  expect(body).toContain('SUBSCRIPTION.getToken');
  expect(body).toMatch(BEARER_HEADER_RE);
}

describe('Autonomous SOC — every action attaches the real auth token (customer-facing, tier-gated)', () => {
  it('cdbAutoSOCLoad still attaches it (pre-existing, must not regress)', () => {
    expectAttachesToken(fnBody('window.cdbAutoSOCLoad'));
  });

  it('cdbAutoSOCToggle still attaches it (pre-existing, must not regress)', () => {
    expectAttachesToken(fnBody('window.cdbAutoSOCToggle'));
  });

  it('cdbAutoSOCRun now attaches it on both the pipeline poll and the run POST', () => {
    const body = fnBody('window.cdbAutoSOCRun');
    expectAttachesToken(body);
    const runCallIdx = body.indexOf("fetch('/api/auto-soc/run'");
    expect(runCallIdx).toBeGreaterThan(-1);
    expect(body.slice(runCallIdx, runCallIdx + 250)).toMatch(BEARER_HEADER_RE);
  });

  it('cdbAutoSOCPollPipeline now attaches it', () => {
    expectAttachesToken(fnBody('window.cdbAutoSOCPollPipeline'));
  });

  it('cdbAutoSOCRefreshLog now attaches it', () => {
    expectAttachesToken(fnBody('window.cdbAutoSOCRefreshLog'));
  });

  it('cdbAutoSOCSetSchedule now attaches it', () => {
    expectAttachesToken(fnBody('window.cdbAutoSOCSetSchedule'));
  });

  it('showGeneratedRules (latest-rules panel shown after a successful run) now attaches it', () => {
    const body = plainFnBody('showGeneratedRules');
    expect(body).toContain("fetch('/api/auto-soc/latest-rules'");
    expectAttachesToken(body);
  });
});

describe('SIEM Integration Deploy — owner-only backend, now correctly gated + authenticated', () => {
  it('the section is gated data-auth-gate="owner", not "true" (matches its real backend requirement)', () => {
    expect(fe).toContain('data-auth-gate="owner" data-section-id="siem-deploy-2"');
    expect(fe).not.toContain('data-auth-gate="true" data-section-id="siem-deploy-2"');
  });

  it('cdbSIEMLoad attaches the auth token', () => {
    expectAttachesToken(fnBody('window.cdbSIEMLoad'));
  });

  it('cdbSIEMSaveConfig attaches the auth token', () => {
    expectAttachesToken(fnBody('window.cdbSIEMSaveConfig'));
  });

  it('cdbSIEMTestIntegration attaches the auth token', () => {
    expectAttachesToken(fnBody('window.cdbSIEMTestIntegration'));
  });

  it('cdbSIEMDeployRule attaches the auth token', () => {
    expectAttachesToken(fnBody('window.cdbSIEMDeployRule'));
  });

  it('cdbSIEMDeployLatestRules attaches the auth token on both its fetch calls', () => {
    const body = fnBody('window.cdbSIEMDeployLatestRules');
    expectAttachesToken(body);
    const deployCallIdx = body.indexOf("fetch('/api/integrations/deploy'");
    expect(deployCallIdx).toBeGreaterThan(-1);
    expect(body.slice(deployCallIdx, deployCallIdx + 250)).toMatch(BEARER_HEADER_RE);
  });

  it('cdbSIEMRefreshLog attaches the auth token', () => {
    expectAttachesToken(fnBody('window.cdbSIEMRefreshLog'));
  });
});

describe('Org Memory — owner-only backend, now correctly gated + authenticated', () => {
  it('the section is gated data-auth-gate="owner", not "true" (matches its real backend requirement)', () => {
    expect(fe).toContain('data-auth-gate="owner" data-section-id="org-memory-2"');
    expect(fe).not.toContain('data-auth-gate="true" data-section-id="org-memory-2"');
  });

  it('cdbMemoryRefresh attaches the auth token on both its fetch calls', () => {
    const body = fnBody('window.cdbMemoryRefresh');
    expectAttachesToken(body);
    const historyCallIdx = body.indexOf("fetch('/api/org-memory/history?limit=10'");
    expect(historyCallIdx).toBeGreaterThan(-1);
    expect(body.slice(historyCallIdx, historyCallIdx + 250)).toMatch(BEARER_HEADER_RE);
  });
});

describe('Autonomous SOC section itself is unaffected (regression guard)', () => {
  it('stays data-auth-gate="true" — it is a real tier-gated customer feature, not owner-only', () => {
    expect(fe).toContain('data-auth-gate="true" data-section-id="autonomous-soc-2"');
  });
});
