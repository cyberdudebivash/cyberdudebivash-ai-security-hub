/* Regression tests — fabricated security metrics replaced with deterministic
 * or honest behavior. Five fixes, one change: Math.random()/Math.sin() output
 * that was presented as real scoring/telemetry is now either a deterministic
 * function of real input, or an honest "no data" signal.
 * (1) computeEPSS (enterpriseIntelligence.js) — the CVSS-banded EPSS
 *     approximation no longer rolls Math.random() per call; the same CVSS
 *     input always yields the same EPSS output.
 * (2) getRiskTrendPanel (executiveReport.js, via handleCEOView) — days with
 *     no real KV snapshot are marked has_data:false and excluded from the
 *     aggregates; an org with zero snapshots gets an honest
 *     direction:'INSUFFICIENT_DATA' instead of a fabricated Math.sin() curve.
 * (3)+(4) analyzeThreat — ai_score / mitre_ttps (autonomousSocMode.js) — the
 *     AI-analysis pipeline stage no longer jitters CVSS by a random ±0.25,
 *     and no longer returns a random-length slice of the same 3 hardcoded
 *     TTPs; extracted to its own exported function so it's testable directly
 *     instead of only reachable inside the non-exported pipeline executor.
 * (5) correlateThretActors — active_campaigns (cyberBrainEngine.js) — dropped
 *     a `Math.floor(Math.random()*10+1)` "active campaign count" that had no
 *     backing data source (THREAT_ACTORS_DB carries no such field). */
import { describe, it, expect } from 'vitest';
import { computeEPSS } from '../src/services/enterpriseIntelligence.js';
import { correlateThretActors } from '../src/services/cyberBrainEngine.js';
import { analyzeThreat, handleRunPipeline } from '../src/handlers/autonomousSocMode.js';
import { handleCEOView } from '../src/handlers/executiveReport.js';

function makeKV(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    async list() { return { keys: [] }; },
    _store: store,
  };
}

// ── (1) computeEPSS ───────────────────────────────────────────────────────────
describe('computeEPSS — deterministic CVSS-banded approximation', () => {
  it('returns an identical value for the same CVSS across repeated calls', () => {
    const a = computeEPSS(9.8, { id: 'X' }, 0);
    const b = computeEPSS(9.8, { id: 'X' }, 0);
    expect(a).toBe(b);
  });

  it.each([
    [10.0, 0.63],
    [9.0,  0.48],
    [8.0,  0.27],
    [7.0,  0.18],
    [5.0,  0.06],
    [3.0,  0.01],
    [0,    0.002],
  ])('cvss=%s deterministically maps to epss=%s', (cvss, expected) => {
    expect(computeEPSS(cvss, {}, 0)).toBeCloseTo(expected, 4);
  });

  it('clamps out-of-range CVSS instead of throwing or going negative', () => {
    expect(computeEPSS(-5, {}, 0)).toBeCloseTo(0.002, 4);
    expect(computeEPSS(15, {}, 0)).toBeCloseTo(0.63, 4);
  });

  it('still applies the DOM-002 / DOM-008 / DOM-004 finding multipliers on top of the deterministic base', () => {
    expect(computeEPSS(9.0, { id: 'DOM-002' }, 0)).toBeCloseTo(0.864, 4);
    expect(computeEPSS(9.0, { id: 'DOM-008' }, 50)).toBeCloseTo(0.9, 4);
    expect(computeEPSS(9.0, { id: 'DOM-004' }, 0)).toBeCloseTo(0.672, 4);
  });
});

// ── (3)+(4) analyzeThreat ──────────────────────────────────────────────────────
describe('analyzeThreat — deterministic ai_score and mitre_ttps', () => {
  it('ai_score is exactly the CVSS (clamped to 10), with no random jitter', () => {
    expect(analyzeThreat({ cvss: 9.8 }).ai_score).toBe(9.8);
    expect(analyzeThreat({ cvss: 10.0 }).ai_score).toBe(10);
    expect(analyzeThreat({ cvss: 7.0 }).ai_score).toBe(7);
  });

  it('produces an identical ai_score for the same input across repeated calls', () => {
    const calls = Array.from({ length: 20 }, () => analyzeThreat({ cvss: 9.1 }).ai_score);
    expect(new Set(calls).size).toBe(1);
  });

  it('mitre_ttps is always the full fixed-length baseline, never a random-length slice', () => {
    for (let i = 0; i < 20; i++) {
      expect(analyzeThreat({ cvss: 9.1 }).mitre_ttps).toEqual(['T1190', 'T1059', 'T1055']);
    }
  });

  it('exploitability is deterministic — uses KEV + CVSS tiers (no Math.random)', () => {
    // KEV + high CVSS = ACTIVE_EXPLOITATION
    expect(analyzeThreat({ cvss_score: 9.8, is_kev: true }).exploitability).toBe('ACTIVE_EXPLOITATION');
    // KEV alone = ACTIVELY_EXPLOITED_KEV
    expect(analyzeThreat({ cvss_score: 7.5, is_kev: true }).exploitability).toBe('ACTIVELY_EXPLOITED_KEV');
    // High CVSS, no KEV
    expect(analyzeThreat({ cvss_score: 9.8 }).exploitability).toBe('CRITICAL_EXPOSURE');
    expect(analyzeThreat({ cvss: 8.5 }).exploitability).toBe('HIGH_EXPOSURE');
    expect(analyzeThreat({ cvss: 6.0 }).exploitability).toBe('PROBABLE');
    // Same input always produces same output (no randomness)
    for (let i = 0; i < 10; i++) {
      expect(analyzeThreat({ cvss_score: 9.6 }).exploitability).toBe('CRITICAL_EXPOSURE');
      expect(analyzeThreat({ cvss_score: 9.1 }).exploitability).toBe('HIGH_EXPOSURE');
    }
  });
});

describe('handleRunPipeline — end-to-end determinism through the real handler', () => {
  it('repeated runs produce identical metrics and stage output (no Math.random leaking into observable state)', async () => {
    const req = new Request('https://x/api/auto-soc/run', { method: 'POST', body: '{}' });
    const [res1, res2] = await Promise.all([
      handleRunPipeline(req, {}, {}),
      handleRunPipeline(req, {}, {}),
    ]);
    const body1 = await res1.json();
    const body2 = await res2.json();
    expect(body1.data.metrics).toEqual(body2.data.metrics);
    expect(body1.data.pipeline.stages.map(s => ({ status: s.status, last_output: s.last_output, count: s.count })))
      .toEqual(body2.data.pipeline.stages.map(s => ({ status: s.status, last_output: s.last_output, count: s.count })));
  });
});

// ── (5) correlateThretActors ───────────────────────────────────────────────────
describe('correlateThretActors — no fabricated active_campaigns', () => {
  it('never returns an active_campaigns field', () => {
    const actors = correlateThretActors([], 'technology');
    expect(actors.length).toBeGreaterThan(0);
    for (const a of actors) expect(a).not.toHaveProperty('active_campaigns');
  });

  it('returned shape still carries the real, non-fabricated fields', () => {
    const [actor] = correlateThretActors([], 'finance');
    expect(actor).toMatchObject({
      id:           expect.any(String),
      name:         expect.any(String),
      nation_state: expect.any(String),
      motivation:   expect.any(String),
      threat_level: expect.stringMatching(/^(HIGH|MEDIUM)$/),
    });
    expect(Array.isArray(actor.relevant_ttps)).toBe(true);
  });
});

// ── (2) getRiskTrendPanel (via handleCEOView) ──────────────────────────────────
describe('CEO view risk trend — honest insufficient-data instead of a fabricated curve', () => {
  const enterpriseCtx = { tier: 'ENTERPRISE', orgId: 'org1' };

  it('reports INSUFFICIENT_DATA (not a fake Math.sin() curve) when no real snapshots exist', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const res = await handleCEOView(new Request('https://x/api/executive/ceo-view'), env, enterpriseCtx);
    const body = await res.json();
    expect(body.risk_trend.direction).toBe('INSUFFICIENT_DATA');
    expect(body.risk_trend.current_score).toBeNull();
    expect(body.risk_trend.avg_30d).toBeNull();
    expect(body.risk_trend.delta_7d).toBeNull();
    expect(body.risk_trend.trend).toHaveLength(30);
    expect(body.risk_trend.trend.every(t => t.has_data === false && t.risk_score === null)).toBe(true);
  });

  it('uses the real snapshot value (not a fabricated one) for the one day that has data', async () => {
    const today = new Date().toISOString().slice(0, 10);
    const env = { SECURITY_HUB_KV: makeKV({ [`risk_snapshot:org1:${today}`]: '72' }) };
    const res = await handleCEOView(new Request('https://x/api/executive/ceo-view'), env, enterpriseCtx);
    const body = await res.json();
    expect(body.risk_trend.direction).not.toBe('INSUFFICIENT_DATA');
    expect(body.risk_trend.current_score).toBe(72);
    expect(body.risk_trend.avg_30d).toBe(72);
    const todayEntry = body.risk_trend.trend.find(t => t.date === today);
    expect(todayEntry).toEqual({ date: today, risk_score: 72, has_data: true });
  });
});
