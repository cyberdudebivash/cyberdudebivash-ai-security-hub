// Regression guard — several "Executive Hub" dashboard widgets read fields
// straight off the raw fetch response, but their backing handlers all go
// through the shared ok()/response.js helper, which wraps every payload as
// { success, data: {...}, error, timestamp }. Reading e.g. `resp.posture`
// instead of `resp.data.posture` silently no-ops forever, regardless of how
// much real data the backend has. Confirmed and fixed for: AI Autonomous
// Threat Response (defense-engine mode/posture), Organization Memory
// (org-memory + history), and the Autonomous AI SOC Command Center
// (pipeline/run/log/schedule). Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

function fnBody(name) {
  const start = HTML.indexOf(`window.${name} = function`);
  expect(start, `${name} not found in index.html`).toBeGreaterThan(-1);
  // Slice to the block's real closing "};" rather than a fixed-length guess —
  // a fixed 2500-char window previously broke silently-adjacent-in-spirit
  // when an unrelated fix (auth-header wiring) added a few lines earlier in
  // cdbMemoryRefresh, pushing histRaw.success past the old cutoff.
  const end = HTML.indexOf('\n};', start);
  expect(end, `${name}'s closing "};" not found`).toBeGreaterThan(-1);
  return HTML.slice(start, end);
}

describe('Executive Hub dashboard widgets — unwrap the {success,data,error} envelope', () => {
  it('cdbDefenseLoad unwraps both defense-engine/mode and defense-engine/posture', () => {
    const body = fnBody('cdbDefenseLoad');
    expect(body).toMatch(/p3Unwrap\(raw\)/);
    // Both fetch callbacks must unwrap before checking config/posture
    expect((body.match(/p3Unwrap\(raw\)/g) || []).length).toBeGreaterThanOrEqual(2);
  });

  it('cdbMemoryRefresh unwraps org-memory and org-memory/history responses', () => {
    const body = fnBody('cdbMemoryRefresh');
    expect(body).toMatch(/raw\.success\s*&&\s*raw\.data/);
    expect(body).toMatch(/histRaw\.success\s*&&\s*histRaw\.data/);
  });

  it('Auto-SOC pipeline polling, run, log, and schedule all unwrap the envelope', () => {
    const run = fnBody('cdbAutoSOCRun');
    expect(run).toMatch(/raw\.success\s*&&\s*raw\.data/);

    const poll = fnBody('cdbAutoSOCPollPipeline');
    expect(poll).toMatch(/raw\.success\s*&&\s*raw\.data/);

    const log = fnBody('cdbAutoSOCRefreshLog');
    expect(log).toMatch(/raw\.success\s*&&\s*raw\.data/);

    const sched = fnBody('cdbAutoSOCSetSchedule');
    expect(sched).toMatch(/raw\.success\s*&&\s*raw\.data/);
  });
});

describe('Revenue Funnel widget — real field mapping', () => {
  it('unwraps the envelope and reads unique_leads for Total Emails, not a nonexistent total_emails field', () => {
    const start = HTML.indexOf('function loadFunnelDashboard()');
    expect(start).toBeGreaterThan(-1);
    const body = HTML.slice(start, start + 2200);
    expect(body).toMatch(/raw\.success\s*&&\s*raw\.data/);
    expect(body).toContain('metrics.unique_leads');
  });
});
