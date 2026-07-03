// Enterprise Real-Time Intelligence Assurance Program.
//
// Static guards against three fabrications found live in the Agent Console's
// MYTHOS widget (frontend/index.html):
//
// 1. A self-documented "Demo fallback" that showed hardcoded numbers
//    (847 tools, 823 published, 99.8% uptime) whenever the real
//    /api/mythos/status call failed — a sibling function 30 lines below
//    (_loadAnomalyAndPredict) already established the correct pattern
//    ("show honest placeholders, never demo data") in the same file.
// 2. 'ag-m-uptime' was hardcoded to a literal on BOTH the success path
//    ('100%') and the failure path ('99.8%') — never a computed value in
//    either branch.
// 3. triggerMythos() read `d.job_id` off the response and unconditionally
//    logged "✅ MYTHOS run triggered" WITHOUT checking r.ok/d.success —
//    so a 403 rejection (the expected outcome, since this public page
//    never holds a real x-admin-key) still displayed a fabricated success
//    message with a fake "job queued" id.
//
// Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

function extractFn(name) {
  const start = HTML.indexOf(`async function ${name}(`);
  expect(start, `function ${name} not found`).toBeGreaterThan(-1);
  return HTML.slice(start, start + 2200);
}

describe('_loadMythos — no demo/fabricated fallback', () => {
  const fn = extractFn('_loadMythos');

  it('does not contain a "Demo fallback" comment or its hardcoded numbers', () => {
    expect(fn).not.toMatch(/Demo fallback/i);
    expect(fn).not.toContain("'847'");
    expect(fn).not.toContain("'823'");
    expect(fn).not.toContain("'99.8%'");
  });

  it('never hardcodes ag-m-uptime to a literal percentage on any path', () => {
    expect(fn).not.toMatch(/ag-m-uptime['"]?\)?\.textContent\s*=\s*['"]100%['"]/);
    expect(fn).not.toMatch(/ag-m-uptime['"]?\)?\.textContent\s*=\s*['"]99\.8%['"]/);
  });

  it('the catch path sets honest "—" placeholders, matching the sibling _loadAnomalyAndPredict convention', () => {
    expect(fn).toMatch(/never demo data/i);
  });

  it('reads from the canonical, currently-fresh god-mode status endpoint, not the stale legacy one', () => {
    expect(fn).toContain('/api/mythos/god-mode/status');
  });
});

describe('CDB_AGCONSOLE.triggerMythos — no fabricated success on a rejected trigger', () => {
  const start = HTML.indexOf('async triggerMythos(){');
  const fn = HTML.slice(start, start + 1800);

  it('checks the response before reporting success', () => {
    expect(start).toBeGreaterThan(-1);
    expect(fn).toMatch(/r\.ok\s*&&\s*d\.success\s*!==\s*false/);
  });

  it('does not ship a hardcoded admin-key literal in client JS', () => {
    expect(fn).not.toMatch(/x-admin-key['"]?\s*:\s*['"][A-Za-z0-9_]+['"]/);
  });

  it('surfaces the real backend rejection reason instead of a fake success', () => {
    expect(fn).toMatch(/Trigger not authorized/);
  });
});
