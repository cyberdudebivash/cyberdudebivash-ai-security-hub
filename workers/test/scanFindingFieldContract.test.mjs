// Regression test — a customer escalation found that the shared finding-card
// renderer (frontend/index.html renderFinding()) reads a fixed field contract
// (title/description/recommendation/mitre_id) that three scan engines didn't
// actually produce:
//  - redteamEngine findings only had name/desc/tech — every card literally
//    rendered the text "undefined" and had no description, MITRE badge, or
//    remediation box.
//  - aiScanEngine's prompt-injection findings used `mitigation` instead of
//    `recommendation` — remediation text silently dropped for half the free
//    findings shown to every AI Security scan customer.
//  - complianceEngine never exposed a top-level `findings` array at all (real
//    gap data only lived under domain_assessments), so lockFindings() always
//    saw zero findings — the "Total Findings" strip showed 0, no individual
//    gaps ever rendered, and the paid unlock CTA never appeared.
import { describe, it, expect } from 'vitest';
import { redteamEngine, aiScanEngine, complianceEngine } from '../src/engine.js';

describe('redteamEngine — findings match the shared render contract', () => {
  const result = redteamEngine('Acme Corp', 'external');

  it('every finding has a real title, description, and mitre_id (not undefined)', () => {
    expect(result.findings.length).toBeGreaterThan(0);
    result.findings.forEach(f => {
      expect(f.title).toBeTruthy();
      expect(f.description).toBeTruthy();
      expect(f.mitre_id).toMatch(/^T\d/);
    });
  });

  it('every finding has real, technique-specific remediation guidance', () => {
    result.findings.forEach(f => {
      expect(f.recommendation).toBeTruthy();
      expect(typeof f.recommendation).toBe('string');
    });
    // Guidance should differ per technique, not be one generic string
    const distinct = new Set(result.findings.map(f => f.recommendation));
    expect(distinct.size).toBeGreaterThan(1);
  });
});

describe('aiScanEngine — prompt-injection findings expose recommendation, not mitigation', () => {
  const result = aiScanEngine('gpt-4', {});
  const injectionFindings = result.findings.filter(f => f.category === 'Prompt Injection');

  it('has free prompt-injection findings to check', () => {
    expect(injectionFindings.length).toBeGreaterThan(0);
  });

  it('every free prompt-injection finding has real recommendation text (not the old mitigation field)', () => {
    injectionFindings.forEach(f => {
      expect(f.recommendation).toBeTruthy();
      expect(f.recommendation).not.toBe('[UNLOCK TO VIEW]');
      expect(f.mitigation).toBeUndefined();
    });
  });
});

describe('complianceEngine — top-level findings array feeds monetization + rendering', () => {
  const result = complianceEngine('Acme Corp', 'iso27001');

  it('exposes a top-level findings array (not just domain_assessments)', () => {
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('every finding has the fields renderFinding() and lockFindings() require', () => {
    result.findings.forEach(f => {
      expect(f.title).toBeTruthy();
      expect(f.description).toBeTruthy();
      expect(f.recommendation).toBeTruthy();
      expect(f.severity).toBeTruthy();
      expect(typeof f.is_premium).toBe('boolean');
    });
  });

  it('has at least one free (non-premium) finding for the paywall to show', () => {
    expect(result.findings.some(f => !f.is_premium)).toBe(true);
  });

  it('has at least one premium finding so the unlock CTA has something to lock', () => {
    expect(result.findings.some(f => f.is_premium)).toBe(true);
  });
});
