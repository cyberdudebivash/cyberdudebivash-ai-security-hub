/* Phase VI regression — one business truth for the global threat level.
 *
 * Live evidence 2026-07-04 12:50 UTC: the homepage showed three DIFFERENT
 * global threat levels at the same moment — MODERATE in the top status bar
 * (canonical, from the API's platform_threat_level), HIGH in the Security
 * Command Center header (hardcoded in the HTML, never updated by any JS),
 * and CRITICAL in the SOC agent-console rail (recomputed locally from the
 * 8 visible feed items). Fix: updateThreatLevelUI is the ONLY writer for
 * every threat-level display, fed solely by platform_threat_level; static
 * markup renders an honest "THREAT: —" placeholder until data arrives.
 *
 * These locks fail if anyone reintroduces a hardcoded level, a second
 * local computation, or a fabricated fallback. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '../../frontend/index.html'), 'utf8');

describe('global threat level has a single source of truth', () => {
  it('static markup never hardcodes a threat level (placeholder until data)', () => {
    // Every occurrence of a concrete "THREAT: <LEVEL>" string must live inside
    // updateThreatLevelUI's level map — nowhere in static markup.
    const concrete = html.match(/THREAT: (CRITICAL|HIGH|MODERATE|LOW)/g) || [];
    expect(concrete.length).toBe(4); // exactly the 4 entries of updateThreatLevelUI's map
    // All three known display sites boot with the honest placeholder.
    expect(html).toMatch(/id="soc-threat-label"[^>]*>THREAT: —</);
    expect(html).toMatch(/id="dash-threat-level"[^>]*>—</);
    expect(html).toMatch(/id="soc-rail-threat-lbl">THREAT: —</);
  });

  it('updateThreatLevelUI updates all three display sites', () => {
    const fnStart = html.indexOf('function updateThreatLevelUI');
    expect(fnStart).toBeGreaterThan(-1);
    const fn = html.slice(fnStart, fnStart + 2000);
    expect(fn).toContain("getElementById('soc-threat-label')");
    expect(fn).toContain("getElementById('dash-threat-level')");
    expect(fn).toContain("getElementById('soc-rail-threat-lbl')");
  });

  it('no code outside updateThreatLevelUI writes the rail or dash labels', () => {
    // Exactly one JS reference each (inside updateThreatLevelUI) plus the
    // static element declaration.
    const railRefs = html.match(/soc-rail-threat-lbl/g) || [];
    expect(railRefs.length).toBe(2); // 1 markup id + 1 updater lookup
    const dashRefs = html.match(/dash-threat-level/g) || [];
    expect(dashRefs.length).toBe(2); // 1 markup id + 1 updater lookup
  });

  it('unknown level renders an honest placeholder, not a fabricated HIGH', () => {
    const fnStart = html.indexOf('function updateThreatLevelUI');
    const fn = html.slice(fnStart, fnStart + 2000);
    expect(fn).not.toMatch(/\|\|\s*map\.HIGH/);
    expect(fn).toContain("text: 'THREAT: —'");
    // The cached value must not default to a made-up level either.
    expect(html).toMatch(/_INTEL\.threat_level = data\.platform_threat_level \|\| null/);
  });
});
