/* Coverage for the v44 Attack Library engine — the real backend that
 * replaces the static "AI Attack Library" page's 11 hardcoded technique
 * cards and the fabricated "87 Attack Techniques" / "Weekly Updated" hero
 * stats, which never matched the real dataset. */
import { describe, it, expect } from 'vitest';
import {
  handleListAttackTechniques,
  handleAttackLibraryOverview,
  handleCreateAttackTechnique,
} from '../src/handlers/attackLibrary.js';

function makeRows(rows) {
  return rows.map(r => ({
    technique_id: r.technique_id, name: r.name, category: r.category, severity: r.severity,
    icon: '🎯', description: r.description, full_description: r.full_description || null,
    example_payload: r.example_payload || null, defenses: r.defenses ? JSON.stringify(r.defenses) : null,
    tags: '["x"]', complexity: 'Low', impact: 'High', detectability: 'Medium',
    mitre_atlas_id: null, owasp_llm_id: null, cwe_id: null,
    published_at: r.published_at, updated_at: r.published_at, source: 'cyberdudebivash_research',
  }));
}

function makeEnv(seedRows, { adminToken = 'sek_admin_test' } = {}) {
  const rows = makeRows(seedRows);
  const inserted = [];
  return {
    ADMIN_TOKEN: adminToken,
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async all() {
            if (/SELECT \* FROM attack_library_techniques/.test(sql)) {
              let filtered = rows;
              if (sql.includes('category = ?')) filtered = filtered.filter(r => r.category === bound[0]);
              return { results: filtered };
            }
            return { results: [] };
          },
          async first() {
            if (/SELECT COUNT\(\*\) as total FROM/.test(sql)) {
              let filtered = rows;
              if (sql.includes('category = ?')) filtered = filtered.filter(r => r.category === bound[0]);
              return { total: filtered.length };
            }
            if (/COUNT\(\*\) as total_techniques/.test(sql)) {
              return { total_techniques: rows.length, total_categories: new Set(rows.map(r => r.category)).size };
            }
            if (/MAX\(updated_at\)/.test(sql)) {
              return { last_updated: rows.map(r => r.updated_at).sort().pop() || null };
            }
            return null;
          },
          async run() {
            if (/INSERT INTO attack_library_techniques/.test(sql)) {
              if (rows.some(r => r.technique_id === bound[0])) {
                throw new Error('UNIQUE constraint failed: attack_library_techniques.technique_id');
              }
              inserted.push(bound);
              return { success: true };
            }
            return { success: true };
          },
        };
      },
    },
    __inserted: inserted,
  };
}

const SEED = [
  { technique_id: 'ATK-PI-001', name: 'Direct Prompt Injection', category: 'prompt-injection', severity: 'CRITICAL', description: 'd', published_at: '2025-06-01', full_description: 'full', example_payload: 'ex', defenses: ['x'] },
  { technique_id: 'ATK-JB-001', name: 'Role-Play Jailbreak', category: 'jailbreak', severity: 'CRITICAL', description: 'd', published_at: '2025-05-01' },
  { technique_id: 'ATK-MA-001', name: 'LLM DoS', category: 'model-abuse', severity: 'HIGH', description: 'd', published_at: '2025-04-01' },
];

function req(url, opts) { return new Request(url, opts); }

describe('handleListAttackTechniques', () => {
  it('returns the real seeded techniques', async () => {
    const env = makeEnv(SEED);
    const res = await handleListAttackTechniques(req('https://x.test/api/attack-library/techniques'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.techniques.length).toBe(3);
    expect(body.total).toBe(3);
  });

  it('flags only fully-detailed techniques as has_full_detail', async () => {
    const env = makeEnv(SEED);
    const res = await handleListAttackTechniques(req('https://x.test/api/attack-library/techniques'), env);
    const body = await res.json();
    const pi = body.techniques.find(t => t.technique_id === 'ATK-PI-001');
    const jb = body.techniques.find(t => t.technique_id === 'ATK-JB-001');
    expect(pi.has_full_detail).toBe(true);
    expect(jb.has_full_detail).toBe(false);
  });

  it('filters by category', async () => {
    const env = makeEnv(SEED);
    const res = await handleListAttackTechniques(req('https://x.test/api/attack-library/techniques?category=jailbreak'), env);
    const body = await res.json();
    expect(body.techniques.every(t => t.category === 'jailbreak')).toBe(true);
  });

  it('fails closed (503) with no DB binding, never falls back to fake data', async () => {
    const res = await handleListAttackTechniques(req('https://x.test/api/attack-library/techniques'), {});
    expect(res.status).toBe(503);
    expect((await res.json()).techniques).toEqual([]);
  });
});

describe('handleAttackLibraryOverview', () => {
  it('computes real technique/category counts instead of the hardcoded 87/6', async () => {
    const env = makeEnv(SEED);
    const res = await handleAttackLibraryOverview(req('https://x.test/api/attack-library/overview'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total_techniques).toBe(3);
    expect(body.total_categories).toBe(3);
    expect(body.last_updated).toBeTruthy();
  });
});

describe('handleCreateAttackTechnique', () => {
  it('rejects without a valid admin bearer token (fail-closed)', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAttackTechnique(req('https://x.test/api/admin/attack-library/techniques', {
      method: 'POST',
      body: JSON.stringify({ technique_id: 'X', name: 'n', category: 'jailbreak', severity: 'HIGH', description: 'd' }),
    }), env);
    expect(res.status).toBe(401);
  });

  it('publishes a new technique with a valid admin token', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAttackTechnique(req('https://x.test/api/admin/attack-library/techniques', {
      method: 'POST',
      headers: { Authorization: 'Bearer sek_admin_test' },
      body: JSON.stringify({ technique_id: 'ATK-NEW-001', name: 'New Finding', category: 'jailbreak', severity: 'HIGH', description: 'd' }),
    }), env);
    expect(res.status).toBe(201);
    expect(env.__inserted.length).toBe(1);
  });

  it('rejects an unknown category', async () => {
    const env = makeEnv(SEED);
    const res = await handleCreateAttackTechnique(req('https://x.test/api/admin/attack-library/techniques', {
      method: 'POST',
      headers: { Authorization: 'Bearer sek_admin_test' },
      body: JSON.stringify({ technique_id: 'X', name: 'n', category: 'not-real', severity: 'HIGH', description: 'd' }),
    }), env);
    expect(res.status).toBe(400);
  });
});
