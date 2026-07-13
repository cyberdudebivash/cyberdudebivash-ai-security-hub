// EPIS #6 — MYTHOS AI Intelligence Brief surfaced in scan results UI.
//
// Every domain/ai/redteam/identity/compliance scan on the homepage already
// computes a rich mythos_intelligence block server-side (MITRE ATT&CK
// mapping, CyberBrain risk scoring, attack-path prediction, AI executive
// narrative, autonomous remediation plan — see
// workers/src/services/mythosEnrichmentEngine.js) but frontend/index.html's
// renderResults() previously discarded it at render time. This locks in the
// fix: the field is rendered, premium content is gated behind
// is_premium_locked (not leaked to FREE-tier responses that already show
// locked findings), and any AI-generated narrative text is HTML-escaped
// before interpolation (defense in depth against a compromised/odd LLM
// output containing markup).
//
// Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

function extractFn(name) {
  const start = HTML.indexOf(`function ${name}(`);
  expect(start, `function ${name} not found`).toBeGreaterThan(-1);
  const end = HTML.indexOf('\nfunction _buildTrainingUpsell', start);
  expect(end, `end marker not found after ${name}`).toBeGreaterThan(start);
  return HTML.slice(start, end);
}

describe('renderResults — surfaces mythos_intelligence instead of discarding it', () => {
  it('calls _buildMythosIntelligenceSection with the scan data', () => {
    const start = HTML.indexOf('function renderResults(module, data)');
    const end   = HTML.indexOf('function _mythosEsc(', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const fn = HTML.slice(start, end);
    expect(fn).toContain('_buildMythosIntelligenceSection(data, module)');
  });
});

describe('_buildMythosIntelligenceSection — real data only, premium content gated', () => {
  const fn = extractFn('_buildMythosIntelligenceSection');

  it('returns early with no section when the scan has no mythos_intelligence block', () => {
    expect(fn).toMatch(/if\s*\(!mi\)\s*return\s*'';/);
  });

  it('gates the AI narrative, attack paths, MITRE mapping and remediation plan behind is_premium_locked', () => {
    expect(fn).toContain("data.is_premium_locked === false");
    expect(fn).toMatch(/if\s*\(!unlocked\)\s*\{/);
    // The locked branch must return before any of the detailed premium blocks render.
    const lockedBranchStart = fn.indexOf('if (!unlocked) {');
    const lockedBranchEnd   = fn.indexOf('return html;', lockedBranchStart);
    const narrativeBlockPos = fn.indexOf('AI Executive Brief');
    expect(lockedBranchStart).toBeGreaterThan(-1);
    expect(lockedBranchEnd).toBeGreaterThan(lockedBranchStart);
    expect(narrativeBlockPos).toBeGreaterThan(lockedBranchEnd);
  });

  it('escapes AI-generated narrative text before interpolation (no raw ${brief.narrative})', () => {
    expect(fn).not.toMatch(/\$\{brief\.narrative\}/);
    expect(fn).toContain('_mythosEsc(brief.narrative)');
  });

  it('escapes risk signals, attack paths, MITRE tactic names, and threat actor fields', () => {
    expect(fn).toMatch(/_mythosEsc\([^)]*signal/);
    expect(fn).toMatch(/_mythosEsc\(label\)/);
    expect(fn).toMatch(/_mythosEsc\(m\.tactic\)/);
    expect(fn).toMatch(/_mythosEsc\(a\.name\)/);
  });

  it('does not fabricate a confidence score — reads it from the real backend field', () => {
    expect(fn).toContain('mi.mythos_confidence');
    expect(fn).not.toMatch(/confidence\s*=\s*\d+;/);
  });
});
