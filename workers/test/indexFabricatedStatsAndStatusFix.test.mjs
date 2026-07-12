/* Regression test — index.html's fabricated "PATCHED" counter, the hardcoded
 * "Platform: Operational" status dot, and the false "CyberBrain V2" claims
 * (Tier 2 backlog item #3; see docs/capability-registry/PROGRAM_BOARD.md
 * session log).
 *
 * Three independent misleading-data bugs:
 *
 * 1. The Vulnerability Management section's "PATCHED" KPI tile computed
 *    Math.floor(s.confirmed_exploited / 10) — an invented formula with zero
 *    factual relationship to how many vulnerabilities have actually been
 *    remediated. No field on this platform's real /api/threat-intel/stats
 *    response (nor anywhere in the ingested threat_intel schema) tracks a
 *    "patched" concept at all; every visible CVE from that feed is hardcoded
 *    to stage:'open' in workers/src/handlers/vulnManagement.js. Fixed to the
 *    honest "no data" dash, matching this exact file's own statOrDash()
 *    convention used by every sibling KPI when real data isn't available.
 *
 * 2. The Command Centers header's "Platform: Operational" badge + its green
 *    pulsing "live" dot were 100% static HTML, never once touched by any
 *    JavaScript — always "Operational" regardless of actual backend health.
 *    Meanwhile an entirely separate, already-real "V21.0 PRODUCTION ENGINE"
 *    health poller already existed on the same page, already fetching
 *    /api/platform/health every 90 seconds and correctly branching on real
 *    OK/DEGRADED/DOWN status for a warning banner — it just never updated
 *    this badge/dot. Fixed by wiring the badge and dot into that existing
 *    real poller instead of adding a new one.
 *
 * 3. Two UI badges claimed "CYBERBRAIN V2" is what powers MYTHOS AI Analyst
 *    features. The platform's real CyberBrain engine
 *    (workers/src/core/cyberBrain.js / services/cyberBrainEngine.js) is
 *    versioned v20.0 in its own source, is used for scan-result enrichment,
 *    and is architecturally unrelated to these two panels — the homepage
 *    chat calls /api/ai/chat -> handleAIChat (workers/src/handlers/
 *    aiAnalysis.js), a template-based MYTHOS response builder that never
 *    touches CyberBrain at all. "V2" does not correspond to any real
 *    version of anything. Fixed to accurate MYTHOS-only branding.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

describe('Vulnerability Management "PATCHED" tile is honest, not fabricated', () => {
  it('no longer computes a fake count via Math.floor(confirmed_exploited/10)', () => {
    expect(fe).not.toContain('Math.floor(s.confirmed_exploited/10)');
  });

  it("both the success and failure paths pass null (the honest '—' dash) for vm-patched", () => {
    const calls = fe.match(/statOrDash\('vm-patched'[^)]*\)/g) || [];
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const call of calls) {
      expect(call).toBe("statOrDash('vm-patched',null)");
    }
  });
});

describe('Command Centers "Platform" badge and dot are wired to the real health poller', () => {
  it('the dot element has an id so JS can target it (previously untargetable, unset by any script)', () => {
    expect(fe).toContain('class="cdb-live-dot" id="cdb-platform-dot"');
  });

  it('a red status class exists for the DOWN case (only green/amber existed before)', () => {
    expect(fe).toMatch(/\.cdb-status-red\s*\{[^}]*rgba\(239,68,68/);
  });

  it('the existing real /api/platform/health poller now updates both the badge text/class and the dot color', () => {
    const start = fe.indexOf('/* 1. Real Platform Health Monitor */');
    expect(start, 'the real health poller IIFE must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('/* 2. Real Activity Feed */', start);
    expect(end, 'the next IIFE marker must be found').toBeGreaterThan(-1);
    const body = fe.slice(start, end);

    expect(body).toContain("fetch('/api/platform/health'");
    expect(body).toContain("getElementById('cdb-platform-status')");
    expect(body).toContain("getElementById('cdb-platform-dot')");
    // Every real status value drives a distinct, real label/class — not a
    // single hardcoded "Operational" regardless of st.
    expect(body).toMatch(/st==='OK'\?'Operational'/);
    expect(body).toMatch(/st==='DEGRADED'\?'Degraded'/);
    expect(body).toMatch(/st==='DOWN'\?'Down'/);
    // Even a failed health-check request itself updates the badge (not left
    // silently stuck on the last-known or default "Operational" state).
    const catchIdx = body.indexOf('.catch(function(e){');
    expect(catchIdx).toBeGreaterThan(-1);
    expect(body.slice(catchIdx)).toContain("getElementById('cdb-platform-status')");
  });
});

describe('no false "CyberBrain V2" claims remain anywhere on the homepage', () => {
  it('the string "CYBERBRAIN V2" (any case) does not appear in the file', () => {
    expect(fe.toUpperCase()).not.toContain('CYBERBRAIN V2');
  });

  it('the MYTHOS AI Analyst header badge drops the false claim, keeping the real MYTHOS branding', () => {
    expect(fe).toContain('🧠 MYTHOS AI ENGINE');
  });

  it('the MYTHOS chat panel\'s status line names the real engine, not CyberBrain', () => {
    expect(fe).toContain('ONLINE · MYTHOS Analyst active');
  });

  it('the Autonomous SOC Mode badge names the real engine, not CyberBrain', () => {
    expect(fe).toContain('🤖 AUTONOMOUS SOC MODE · MYTHOS');
  });
});
