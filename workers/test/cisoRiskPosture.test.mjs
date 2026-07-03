/* CISO risk-posture and MTTD/MTTR must be real or honestly null — never the old
 * hardcoded 74.2 / "+4.1" / 68 / 31 / 2.8h / 24h constants.
 */
import { describe, it, expect } from 'vitest';
import { computeRiskPosture } from '../src/handlers/cisoMetrics.js';

describe('computeRiskPosture — real or honest-null, never fabricated', () => {
  it('returns an honest null block when there is no underlying data', () => {
    const p = computeRiskPosture([], [], []);
    expect(p.data_available).toBe(false);
    expect(p.composite_score).toBeNull();
    expect(p.grade).toBeNull();
    expect(p.trend_30d).toBeNull();
    expect(p.attack_surface_score).toBeNull();
  });

  it('never emits the old hardcoded constant tuple', () => {
    const p = computeRiskPosture([], [], []);
    expect(p.composite_score).not.toBe(74.2);
    // trend must never be the invented "+4.1"
    expect(p.trend_30d).not.toBe('+4.1');
  });

  it('computes a real composite from compliance coverage', () => {
    const comp = [{ controls_met: 80, controls_total: 100 }]; // 80% coverage
    const p = computeRiskPosture(comp, [], []);
    expect(p.data_available).toBe(true);
    expect(p.composite_score).toBe(80);
    expect(p.grade).not.toBeNull();
  });

  it('open critical/high risks drive the composite down and attack surface up', () => {
    const comp = [{ controls_met: 100, controls_total: 100 }]; // 100% coverage
    const risks = [
      { status: 'OPEN', risk_level: 'CRITICAL' },
      { status: 'OPEN', risk_level: 'HIGH' },
    ];
    const p = computeRiskPosture(comp, risks, []);
    expect(p.composite_score).toBe(100 - (12 + 5)); // 83
    expect(p.open_risks).toBe(2);
    expect(p.critical_risks).toBe(1);
    expect(p.attack_surface_score).toBeGreaterThan(0);
  });

  it('trend is always null (no historical snapshots to compute a real trend)', () => {
    const p = computeRiskPosture([{ controls_met: 50, controls_total: 100 }], [], []);
    expect(p.trend_30d).toBeNull();
  });
});
