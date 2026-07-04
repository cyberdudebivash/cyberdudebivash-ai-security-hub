/* Phase VI cycle 2 regression — truth-to-customer locks.
 *
 * Live-production audit of 2026-07-04 found four claim/metric defects:
 *   1. Customer notifications fabricated from /api/seed/threats (a PRNG demo
 *      generator whose first three events are ALWAYS CRITICAL) — customers
 *      received a fake "New CRITICAL Threat" alert on every poll.
 *   2. /api/seed/stats served fabricated platform metrics (scans, users,
 *      revenue, uptime 99.97%) with no synthetic-data labeling at all.
 *   3. Bare "SOC 2 Type II" / "ISO 27001:2022" / "PCI-DSS" / "HIPAA" badges
 *      in the homepage ticker and CISO-hub trust bar read as certification
 *      claims the company does not hold.
 *   4. Frontend advertised "MYTHOS GOD MODE v4.0 · 12-Phase" while the
 *      deployed engine self-describes as v5.0 APEX NEXUS with 16 phase
 *      functions; the dashboard card printed "0 critical, 0 KEV exploited"
 *      when the stats API merely omitted the fields.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(join(here, rel), 'utf8');

describe('customer alerts come only from verified intelligence', () => {
  it('no frontend page polls the seeded demo threat generator', () => {
    for (const page of ['index.html', 'user-dashboard.html', 'intel.html', 'ciso-hub.html', 'god-mode.html']) {
      expect(read(`../../frontend/${page}`)).not.toContain("fetch('/api/seed/threats'");
    }
  });

  it('every frontend page begins with a clean doctype (no committed tool banners)', () => {
    // user-dashboard.html shipped for weeks with a "successfully downloaded
    // text file (SHA: ...)" banner BEFORE <!DOCTYPE html> — visible to every
    // logged-in customer and forcing quirks mode.
    for (const page of ['index.html', 'user-dashboard.html', 'intel.html', 'ciso-hub.html', 'god-mode.html', 'api-docs.html']) {
      const html = read(`../../frontend/${page}`).replace(/^﻿/, ''); // BOM is harmless
      expect(html.slice(0, 15), `${page} must start with <!DOCTYPE html>`).toBe('<!DOCTYPE html>');
    }
  });

  it('the dashboard notification poller reads the real KEV feed and dedupes', () => {
    const html = read('../../frontend/user-dashboard.html');
    const fnStart = html.indexOf('function startNotifPoller');
    expect(fnStart).toBeGreaterThan(-1);
    const fn = html.slice(fnStart, fnStart + 2500);
    expect(fn).toContain('/api/threat-intel/live');
    expect(fn).toContain('actively_exploited');
    expect(fn).toContain('cdb_notif_last_kev'); // never re-notify the same CVE
  });
});

describe('seeded demo endpoints declare themselves synthetic', () => {
  it('every seed handler response carries a seeded/synthetic marker', () => {
    const src = read('../src/services/seedEngine.js');
    // One marker per handler: threats, cves, stats, soc, siem, apt (+ seed:all note).
    const markers = src.match(/source: 'seeded'/g) || [];
    expect(markers.length).toBeGreaterThanOrEqual(6);
    expect(src).toMatch(/synthetic: true/);
    expect(src).toMatch(/NOT live platform metrics/);
  });
});

describe('compliance badges never imply attestations the company lacks', () => {
  it('homepage ticker uses aligned/ready/mapped phrasing for attestation standards', () => {
    const html = read('../../frontend/index.html');
    expect(html).not.toContain('<span class="ticker-item">🔒 SOC 2 Type II</span>');
    expect(html).not.toContain('<span class="ticker-item">🛡️ ISO 27001:2022</span>');
    expect(html).not.toContain('<span class="ticker-item">💳 PCI-DSS v4.0</span>');
    expect(html).not.toContain('<span class="ticker-item">🏥 HIPAA/HITECH</span>');
    expect((html.match(/SOC 2 Type II Ready/g) || []).length).toBeGreaterThanOrEqual(2);
  });

  it('ciso-hub trust bar matches', () => {
    const html = read('../../frontend/ciso-hub.html');
    expect(html).not.toContain('<div class="trust-badge"><span class="icon">🔒</span> SOC 2 Type II</div>');
    expect(html).toContain('SOC 2 Type II Ready');
  });
});

describe('product claims match the deployed engine', () => {
  it('frontend GOD MODE labels agree with the backend (v5.0, 16 phases)', () => {
    const backend = read('../src/services/mythosGodMode.js');
    const phaseFns = backend.match(/async function phase\d+_/g) || [];
    expect(phaseFns.length).toBe(16);
    expect(backend).toContain('GOD MODE v5.0');
    for (const page of ['index.html', 'god-mode.html', 'api-docs.html', 'intel.html']) {
      const html = read(`../../frontend/${page}`);
      expect(html).not.toMatch(/GOD MODE v4\.0|God Mode v4\.0/);
      expect(html).not.toMatch(/12-[Pp]hase/);
    }
  });

  it('dashboard never fabricates zero-counts for absent API fields', () => {
    const html = read('../../frontend/index.html');
    expect(html).not.toContain('${critCnt || 0} critical');
    expect(html).not.toContain('${kevCnt || 0} KEV');
  });

  it('generated-tools and marketplace counts carry distinct, precise labels', () => {
    const html = read('../../frontend/index.html');
    expect(html).not.toContain('AI-generated defense tools from live CVE intelligence');
    expect(html).toContain('defense tools generated across MYTHOS runs');
    expect(html).toContain('<span>Marketplace Solutions</span>');
  });
});
