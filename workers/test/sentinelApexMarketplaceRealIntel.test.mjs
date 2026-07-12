/* Regression test — sentinel-apex-marketplace.html's Threat Actor and Malware
 * intel cards (Tier 2 backlog item #2; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * loadThreatActorCards() and loadMalwareCards() were 100% hardcoded — a fixed
 * static array of fictional/fabricated entries (fake risk scores, fake attack
 * vectors, a wholly invented "AI-Enhanced RAT" and "BianLian" group not present
 * in this codebase's own real threat-actor/malware databases), rendered on a
 * page whose own meta description and hero copy advertise "Live CVE
 * intelligence, threat actor dossiers, malware reports... powered by SENTINEL
 * APEX™". Every visitor saw the identical static content presented as live
 * intelligence, regardless of what the platform's real APT actor database
 * (workers/src/services/aptActorProfiles.js, 60+ groups, already served live
 * at GET /api/intel/actors) or malware-family database
 * (workers/src/handlers/intelligencePreview.js's MALWARE_FAMILIES, served at
 * GET /api/preview/malware/:familyId) actually contain.
 *
 * This mirrors the exact pattern the sibling loadCVECards()/renderFallbackCVEs()
 * in this same file already established correctly: fetch real data, and on
 * failure show an honest "temporarily unavailable" state — never a fabricated
 * list presented as live.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/sentinel-apex-marketplace.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end + 2);
}

describe('loadThreatActorCards — fetches the real APT actor database', () => {
  const body = () => fnBody('loadThreatActorCards');

  it('fetches GET /api/intel/actors (the same backend threat-intel-workbench.html uses)', () => {
    expect(body()).toContain('/api/intel/actors');
    expect(body()).toMatch(/fetch\(`\$\{API_BASE\}\/api\/intel\/actors/);
  });

  it('reads the real response shape (d.actors) rather than a fabricated array', () => {
    expect(body()).toContain('d.actors');
    expect(body()).not.toContain('const actors = [');
  });

  it('no longer contains the fabricated static actor roster', () => {
    // Distinctive literal strings from the old hardcoded array that cannot
    // coincidentally reappear from real backend data.
    expect(fe).not.toContain("'SideCopy (Pakistan)'");
    expect(fe).not.toContain("'Scattered Spider'");
    expect(fe).not.toContain('India Government, Defence');
  });

  it('falls back to an honest unavailable state, not fabricated data, when the real feed is empty or the fetch fails', () => {
    const body = fnBody('loadThreatActorCards');
    expect(body).toContain('renderFallbackThreatActors()');
    const fallback = fnBody('renderFallbackThreatActors');
    expect(fallback).toContain('temporarily unavailable');
    expect(fallback).not.toContain('APT29');
  });
});

describe('loadMalwareCards — fetches the real malware-family preview API', () => {
  const body = () => fnBody('loadMalwareCards');

  it('fetches GET /api/preview/malware/:id for each known family, not a hardcoded array', () => {
    expect(body()).toContain('/api/preview/malware/');
    expect(body()).not.toContain('const malware = [');
  });

  it('reads the real preview-card fields (name, malware_type, severity, active_in_wild, summary)', () => {
    const b = body();
    expect(b).toContain('m.name');
    expect(b).toContain('m.malware_type');
    expect(b).toContain('m.severity');
    expect(b).toContain('m.active_in_wild');
    expect(b).toContain('m.summary');
  });

  it('no longer contains the fabricated static malware roster (fake risk scores / invented families)', () => {
    // "AI-Enhanced RAT" and "BianLian" were invented for the old fallback and
    // are not present in the real MALWARE_FAMILIES dict; 9.8/9.5/9.1 were
    // fabricated risk-score literals with no backing field in the real API.
    expect(fe).not.toContain('AI-Enhanced RAT');
    expect(fe).not.toContain('BianLian');
    expect(fe).not.toContain('risk: 9.8');
    expect(fe).not.toContain('RDP brute-force, phishing, exposed VPN');
  });

  it('falls back to an honest unavailable state, not fabricated data, when every fetch fails', () => {
    const b = body();
    expect(b).toContain('renderFallbackMalware()');
    const fallback = fnBody('renderFallbackMalware');
    expect(fallback).toContain('temporarily unavailable');
    expect(fallback).not.toContain('LockBit 4.0');
  });
});

describe('both loaders escape backend-sourced text before injecting into innerHTML', () => {
  it('loadThreatActorCards wraps actor-derived display fields in escHtml()', () => {
    const body = fnBody('loadThreatActorCards');
    expect(body).toMatch(/escHtml\(displayName\)/);
    expect(body).toMatch(/escHtml\(tactics\)/);
  });

  it('loadMalwareCards wraps family-derived display fields in escHtml()', () => {
    const body = fnBody('loadMalwareCards');
    expect(body).toMatch(/escHtml\(m\.name\)/);
    expect(body).toMatch(/escHtml\(m\.summary/);
  });
});
