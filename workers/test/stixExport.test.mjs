/**
 * STIX 2.1 export — content correctness + robustness.
 *
 * Regression: actorToSTIX() dereferenced actor.motivation.includes(...) with no
 * guard, so a single actor row missing `motivation` (or supplying a scalar) threw
 * a TypeError that 500'd the ENTIRE bundle export — a Pro+ SIEM/TIP feature. The
 * bundle must be built for any well-formed-but-partial actor.
 */
import { describe, it, expect } from 'vitest';
import { buildSTIXBundle } from '../src/services/stix21Engine.js';

const ENTRY = {
  id: 'CVE-2026-45659', title: 'SharePoint Deserialization', cvss: 9.8, severity: 'CRITICAL',
  attack_mapping: { techniques: [{ technique_id: 'T1190', technique_name: 'Exploit Public-Facing App' }] },
};

describe('STIX 2.1 bundle — content correctness', () => {
  it('produces a spec-compliant bundle with expected object types and matching counts', () => {
    const b = buildSTIXBundle({
      entries: [ENTRY],
      actors:  [{ id: 'APT41', motivation: ['espionage'], cve_associations: ['CVE-2026-45659'] }],
      iocData: [{ value: '1.2.3.4', type: 'ip', intel_id: 'CVE-2026-45659' }],
    });
    expect(b.type).toBe('bundle');
    expect(b.spec_version).toBe('2.1');
    expect(b.id.startsWith('bundle--')).toBe(true);
    expect(b._meta.object_count).toBe(b.objects.length);
    const types = new Set(b.objects.map(o => o.type));
    for (const t of ['identity', 'vulnerability', 'attack-pattern', 'threat-actor', 'indicator', 'relationship']) {
      expect(types.has(t)).toBe(true);
    }
    expect(() => JSON.stringify(b)).not.toThrow();
  });
});

describe('STIX 2.1 bundle — robustness (no crash on partial actors)', () => {
  it('builds a bundle when an actor has NO motivation field', () => {
    const build = () => buildSTIXBundle({ entries: [ENTRY], actors: [{ id: 'UNK-1' }] });
    expect(build).not.toThrow();
    const b = build();
    const ta = b.objects.find(o => o.type === 'threat-actor');
    expect(ta).toBeDefined();
    expect(ta.threat_actor_types).toEqual(['unknown']);
    expect(ta.labels).toEqual([]);
  });

  it('accepts a scalar (non-array) motivation without throwing', () => {
    const b = buildSTIXBundle({ entries: [], actors: [{ id: 'FIN-X', motivation: 'financial-gain' }] });
    const ta = b.objects.find(o => o.type === 'threat-actor');
    expect(ta.primary_motivation).toBe('personal-gain');
    expect(ta.labels).toEqual(['financial-gain']);
  });
});
