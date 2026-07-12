/* Regression test — user-dashboard.html's My Trainings / My Purchases / My
 * Reports tabs (full-frontend-audit follow-up, Tier 1 item #8; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * handleMyPurchases and handleUserReports (workers/src/handlers/delivery.js)
 * both wrap their response in the standard jsonOk() {success,data,error}
 * envelope — the real payload is nested under `.data`, and the real field
 * names are `purchases` and `reports` respectively. Three call sites read
 * the top-level, unenveloped object under the wrong field name
 * (`.deliveries`, which doesn't exist anywhere in either handler's real
 * response): loadMyTrainings(), loadMyDeliveries(), and loadUserReports()'s
 * both primary (/api/user/reports) and fallback (/api/delivery/my-purchases)
 * paths — every one of these always returned an empty list, regardless of
 * real purchase/delivery history, and the tabs permanently showed
 * "no purchases found" / "no reports found".
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n  }', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

const ENVELOPE_UNWRAP_RE = /\(raw\d?\s*&&\s*raw\d?\.success\s*&&\s*raw\d?\.data\)\s*\?\s*raw\d?\.data\s*:\s*raw\d?/;

describe('loadMyTrainings — unwraps the envelope and reads the real `purchases` field', () => {
  it('no longer reads data.deliveries', () => {
    const body = fnBody('loadMyTrainings');
    expect(body).not.toContain('.deliveries');
    expect(body).toContain('data?.purchases');
  });
  it('unwraps the {success,data,error} envelope before reading it', () => {
    const body = fnBody('loadMyTrainings');
    expect(body).toMatch(ENVELOPE_UNWRAP_RE);
  });
});

describe('loadMyDeliveries — unwraps the envelope and reads the real `purchases` field', () => {
  it('no longer reads data.deliveries', () => {
    const body = fnBody('loadMyDeliveries');
    expect(body).not.toContain('data?.deliveries');
    expect(body).toContain('data?.purchases');
  });
  it('unwraps the {success,data,error} envelope before reading it', () => {
    const body = fnBody('loadMyDeliveries');
    expect(body).toMatch(ENVELOPE_UNWRAP_RE);
  });
});

describe('loadUserReports — both the primary and fallback paths unwrap the envelope', () => {
  it('the primary /api/user/reports path unwraps the envelope and reads d.reports (not d.deliveries)', () => {
    const body = fnBody('loadUserReports');
    const primaryIdx = body.indexOf('/api/user/reports');
    expect(primaryIdx).toBeGreaterThan(-1);
    const primarySection = body.slice(primaryIdx, primaryIdx + 400);
    expect(primarySection).toMatch(ENVELOPE_UNWRAP_RE);
    expect(primarySection).toContain('d?.reports');
    expect(primarySection).not.toContain('d?.deliveries');
  });

  it('the fallback /api/delivery/my-purchases path unwraps the envelope and reads d2.purchases (not d2.deliveries)', () => {
    const body = fnBody('loadUserReports');
    const fallbackIdx = body.indexOf('/api/delivery/my-purchases');
    expect(fallbackIdx).toBeGreaterThan(-1);
    const fallbackSection = body.slice(fallbackIdx, fallbackIdx + 500);
    expect(fallbackSection).toMatch(ENVELOPE_UNWRAP_RE);
    expect(fallbackSection).toContain('d2?.purchases');
    expect(fallbackSection).not.toContain('d2?.deliveries');
  });
});
