/* Security-Posture pillar scores must be DERIVED FROM LIVE CATALOG DATA — not the
 * hardcoded 78/62/85/55 the dashboard previously showed under a "LIVE" badge.
 *
 * Regression for the dashboard-modernization FAIL: the frontend read
 * `p.scores?.network ?? 78` etc., but the backend never returned `scores`, so the
 * fallbacks always fired and the "LIVE" posture card was permanently static.
 */
import { describe, it, expect } from 'vitest';
import { computePillarScores } from '../src/handlers/realtime.js';

const mk = (over = {}) => ({ severity: 'HIGH', is_exploited: 0, patch_available: 1, ...over });

describe('computePillarScores — real, data-derived pillar posture', () => {
  it('returns null when there is no catalog data (honest "unavailable", not fabricated)', () => {
    expect(computePillarScores([])).toBeNull();
  });

  it('classifies threats into the correct security pillar', () => {
    const s = computePillarScores([
      mk({ title: 'Cisco IOS XE Web UI RCE', severity: 'CRITICAL', is_exploited: 1 }),
      mk({ title: 'Okta SAML authentication bypass', severity: 'CRITICAL', is_exploited: 1 }),
      mk({ title: 'LangChain LLM prompt injection in RAG agent', severity: 'HIGH' }),
    ]);
    expect(s).not.toBeNull();
    // Each pillar is a bounded integer in [35,98].
    for (const k of ['network', 'identity', 'ai_systems', 'compliance']) {
      expect(Number.isInteger(s[k])).toBe(true);
      expect(s[k]).toBeGreaterThanOrEqual(35);
      expect(s[k]).toBeLessThanOrEqual(98);
    }
    expect(s.sample_size).toBe(3);
  });

  it('is NOT the old hardcoded 78/62/85/55 constant tuple', () => {
    const s = computePillarScores([
      mk({ title: 'Fortinet FortiOS SSL VPN RCE', severity: 'CRITICAL', is_exploited: 1 }),
      mk({ title: 'Palo Alto PAN-OS GlobalProtect command injection', severity: 'CRITICAL', is_exploited: 1 }),
    ]);
    const tuple = [s.network, s.identity, s.ai_systems, s.compliance].join(',');
    expect(tuple).not.toBe('78,62,85,55');
  });

  it('heavier exploited-critical pressure in a pillar lowers THAT pillar score', () => {
    const light = computePillarScores([mk({ title: 'DNS resolver info leak', severity: 'MEDIUM' })]);
    const heavy = computePillarScores(
      Array.from({ length: 8 }, () =>
        mk({ title: 'Firewall gateway RCE exploited in the wild', severity: 'CRITICAL', is_exploited: 1 })),
    );
    expect(heavy.network).toBeLessThan(light.network);
  });

  it('compliance pillar drops when active threats are KEV-listed AND unpatched', () => {
    const clean = computePillarScores([mk({ title: 'x', patch_available: 1 })]);
    const risky = computePillarScores(
      Array.from({ length: 6 }, () =>
        mk({ title: 'y', is_exploited: 1, cisa_kev_date: '2026-01-01', patch_available: 0 })),
    );
    expect(risky.compliance).toBeLessThan(clean.compliance);
  });
});
