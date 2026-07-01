// Regression test — GET /api/defense-engine/posture omitted rules_deployed,
// pending_count, rolled_back_count and posture_score, so the "AI Autonomous
// Threat Response" dashboard widget (frontend/index.html cdbDefenseLoad)
// always showed "—" for all four stats regardless of real execution history.
import { describe, it, expect } from 'vitest';
import { handleGetDefensePosture } from '../src/handlers/autoDefenseEngine.js';

function makeKV(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const v = store.get(key);
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
  };
}

function req() { return new Request('https://cyberdudebivash.in/api/defense-engine/posture'); }

describe('handleGetDefensePosture — real field wiring for the dashboard widget', () => {
  it('returns rules_deployed aliased from the real total_rules_deployed field', async () => {
    const env = { SECURITY_HUB_KV: makeKV({
      'autodefense:posture': JSON.stringify({ total_executions: 5, total_rules_deployed: 12, threats_blocked: 4, last_execution: null }),
    }) };
    const res  = await handleGetDefensePosture(req(), env, {});
    const body = await res.json();
    expect(body.data.posture.rules_deployed).toBe(12);
  });

  it('counts real pending approvals instead of returning undefined', async () => {
    const env = { SECURITY_HUB_KV: makeKV({
      'autodefense:posture': JSON.stringify({ total_executions: 2, total_rules_deployed: 4, threats_blocked: 1, last_execution: null }),
      'autodefense:pending_approvals': JSON.stringify([{ id: 'p1' }, { id: 'p2' }]),
    }) };
    const res  = await handleGetDefensePosture(req(), env, {});
    const body = await res.json();
    expect(body.data.posture.pending_count).toBe(2);
  });

  it('counts real rollback events from execution history instead of returning undefined', async () => {
    const env = { SECURITY_HUB_KV: makeKV({
      'autodefense:posture': JSON.stringify({ total_executions: 3, total_rules_deployed: 6, threats_blocked: 2, last_execution: null }),
      'autodefense:executions': JSON.stringify([
        { id: 'e1', status: 'EXECUTED' },
        { id: 'rb_1', status: 'ROLLBACK' },
        { id: 'e2', status: 'EXECUTED' },
      ]),
    }) };
    const res  = await handleGetDefensePosture(req(), env, {});
    const body = await res.json();
    expect(body.data.posture.rolled_back_count).toBe(1);
  });

  it('computes a real posture_score from execution outcomes, not a fabricated number', async () => {
    const env = { SECURITY_HUB_KV: makeKV({
      'autodefense:posture': JSON.stringify({ total_executions: 4, total_rules_deployed: 8, threats_blocked: 3, last_execution: null }),
      'autodefense:executions': JSON.stringify([
        { id: 'e1', status: 'EXECUTED' },
        { id: 'rb_1', status: 'ROLLBACK' },
      ]),
    }) };
    const res  = await handleGetDefensePosture(req(), env, {});
    const body = await res.json();
    // (4 total - 1 rolled back) / 4 = 75%, no pending backlog penalty
    expect(body.data.posture.posture_score).toBe(75);
  });

  it('returns posture_score:null (honest "no data") when nothing has ever executed', async () => {
    const env = { SECURITY_HUB_KV: makeKV({}) };
    const res  = await handleGetDefensePosture(req(), env, {});
    const body = await res.json();
    expect(body.data.posture.total_executions).toBe(0);
    expect(body.data.posture.posture_score).toBeNull();
    expect(body.data.posture.pending_count).toBe(0);
    expect(body.data.posture.rolled_back_count).toBe(0);
  });
});
