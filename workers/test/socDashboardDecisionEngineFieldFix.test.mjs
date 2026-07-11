/* Regression test — soc-dashboard.html's AI Decision Engine panel
 * (full-frontend-audit follow-up, Tier 1 item #6; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * Real decision objects (services/decisionEngine.js's own header comment:
 * `{ decision, reason, confidence, priority, actions_recommended,
 * risk_score }`, plus `decided_at`) never matched what loadDecisions() read
 * (action/reasoning/timestamp) — every real decision rendered as a generic
 * "ANALYZE" badge with "Processing threat data..." text. confidence is
 * already 0-100 (computeConfidence()'s own `Math.min(100, Math.round(...))`)
 * — the frontend multiplied it by 100 again, so a real 75 rendered as
 * "7500%" with a confidence bar ~6000px wide. Separately, any real fetch
 * failure for a genuine ENTERPRISE customer silently substituted
 * buildMockDecisions()'s fabricated CVE/IP data with no "this is
 * placeholder" indication — unlike the legitimate non-ENTERPRISE teaser
 * path, which sits behind a clearly-labeled "Upgrade to Enterprise" overlay
 * (frontend/soc-dashboard.html's #decision-gate).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/soc-dashboard.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

describe('loadDecisions — reads the real decisionEngine.js field names', () => {
  it('reads d.decision/d.reason/d.decided_at, not the old action/reasoning/timestamp', () => {
    const body = fnBody('loadDecisions');
    expect(body).toContain('d.decision');
    expect(body).toContain('d.reason');
    expect(body).toContain('d.decided_at');
    expect(body).not.toMatch(/\bd\.action\b/);
    expect(body).not.toContain('d.reasoning');
    expect(body).not.toMatch(/d\.timestamp\|\|Date\.now/);
  });

  it('does not multiply confidence by 100 (it is already a 0-100 value server-side)', () => {
    const body = fnBody('loadDecisions');
    expect(body).not.toMatch(/d\.confidence\s*\*\s*100/);
    expect(body).toMatch(/Math\.round\(d\.confidence\)/);
  });

  it('the confidence bar scales by 0.8 (px-per-percent), not 80 (would be ~80x too wide for a 0-100 value)', () => {
    const body = fnBody('loadDecisions');
    expect(body).toMatch(/\*\s*0\.8\b/);
    expect(body).not.toMatch(/confidence[^`]*\*\s*80\b/);
  });
});

describe('loadDecisions catch block — a real fetch failure no longer masquerades as live data', () => {
  it('no longer calls buildMockDecisions() on a real fetch failure', () => {
    const body = fnBody('loadDecisions');
    const catchBlock = body.slice(body.indexOf('} catch'));
    expect(catchBlock).not.toMatch(/=\s*buildMockDecisions\(\)/);
    expect(catchBlock).toMatch(/Unable to load decisions/);
  });

  it('buildMockDecisions is still used for the legitimate, clearly-overlaid non-ENTERPRISE teaser path', () => {
    const body = fnBody('loadDecisions');
    const beforeTry = body.slice(0, body.indexOf('try {'));
    expect(beforeTry).toContain('buildMockDecisions()');
    expect(beforeTry).toContain("gate.style.display = 'flex'");
  });

  it('the non-ENTERPRISE overlay clearly discloses this is a gated/preview state', () => {
    const idx = fe.indexOf('id="decision-gate"');
    expect(idx).toBeGreaterThan(-1);
    const overlay = fe.slice(idx, idx + 400);
    expect(overlay).toMatch(/ENTERPRISE plan/);
    expect(overlay).toContain('Upgrade to Enterprise');
  });
});

describe('Decision-type badges — CSS exists for every real decision value', () => {
  it('covers all 6 real DECISIONS values from services/decisionEngine.js', () => {
    for (const cls of ['dt-escalate', 'dt-auto_contain', 'dt-fast_patch', 'dt-monitor_closely', 'dt-low_priority', 'dt-false_positive']) {
      expect(fe).toContain(`.${cls}{`);
    }
  });
});
