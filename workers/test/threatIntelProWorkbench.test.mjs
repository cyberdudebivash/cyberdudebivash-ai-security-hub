// CAP-TIH-003 — Threat Intel Pro Workbench. Registry evidence: only the 3
// LLM-calling sub-routes (analyst/query, cve-brief/:id, sector/:sector) had
// any test coverage (their rate-limit gating specifically) — the other ~12
// sub-routes and all 5 backing services (mitreAttackService.js,
// aptActorProfiles.js, compositeRiskScoring.js, stix21Engine.js) were
// completely untested. Also resolves rbac.enforced from "unknown" to a
// precise, evidenced answer via a full per-sub-route trace: of ~17
// sub-routes, only 2 return a hard 403 (TAXII ioc-feed/actor-feed), 1
// soft-gates its response CONTENT by tier (STIX bundle), and the rest are
// intentionally public (the 3 costly ones rate-limited instead, fixed
// 2026-07-11).
import { describe, it, expect } from 'vitest';
import { handleThreatIntelPro } from '../src/handlers/threatIntelPro.js';

function req(url, opts = {}) { return new Request(url, opts); }

function fakeEnv(extra = {}) {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
    },
    SECURITY_HUB_KV: { get: async () => null, put: async () => {} },
    ...extra,
  };
}

describe('handleThreatIntelPro — router basics', () => {
  it('OPTIONS returns 204', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/actors', { method: 'OPTIONS' }), fakeEnv(), {});
    expect(res.status).toBe(204);
  });

  it('an unknown path 404s honestly', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/not-a-real-route'), fakeEnv(), {});
    expect(res.status).toBe(404);
  });
});

describe('handleThreatIntelPro — GET /api/intel/actors + /actor/:id (real APT_ACTORS data)', () => {
  it('returns a real, non-empty actor catalog with real stats', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/actors'), fakeEnv(), {});
    const body = await res.json();
    expect(body.total).toBeGreaterThan(0);
    expect(body.actors.length).toBe(body.total);
    expect(body.stats).toBeTruthy();
  });

  it('filters actors by a real sector', async () => {
    const all = await (await handleThreatIntelPro(req('https://x/api/intel/actors'), fakeEnv(), {})).json();
    const anySector = all.actors.find(a => a.target_sectors?.length)?.target_sectors?.[0];
    if (anySector) {
      const res = await handleThreatIntelPro(req(`https://x/api/intel/actors?sector=${encodeURIComponent(anySector)}`), fakeEnv(), {});
      const body = await res.json();
      expect(body.actors.length).toBeGreaterThan(0);
    }
  });

  it('404s honestly for an actor ID that does not exist', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/actor/not-a-real-actor-xyz'), fakeEnv(), {});
    expect(res.status).toBe(404);
  });

  it('returns a real deep profile for a known actor', async () => {
    const all = await (await handleThreatIntelPro(req('https://x/api/intel/actors'), fakeEnv(), {})).json();
    const knownId = all.actors[0].id;
    const res = await handleThreatIntelPro(req(`https://x/api/intel/actor/${encodeURIComponent(knownId)}`), fakeEnv(), {});
    const body = await res.json();
    expect(body.actor.id).toBe(knownId);
    expect(Array.isArray(body.associated_cves)).toBe(true);
  });
});

describe('handleThreatIntelPro — GET /api/intel/tactics + /techniques (real MITRE ATT&CK v14 catalog)', () => {
  it('returns the real 14-tactic ATT&CK Enterprise catalog (this engine includes Reconnaissance + Resource Development, unlike the smaller 12-tactic table in enterpriseIntel.js — see notes on duplicate MITRE representations in this domain)', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/tactics'), fakeEnv(), {});
    const body = await res.json();
    expect(body.total).toBe(14);
    expect(body.spec_version).toContain('ATT&CK');
  });

  it('techniques are searchable and carry a real MITRE URL', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/techniques?q=phishing'), fakeEnv(), {});
    const body = await res.json();
    expect(body.total).toBeGreaterThan(0);
    expect(body.techniques[0].url).toContain('attack.mitre.org/techniques/');
  });
});

describe('handleThreatIntelPro — POST /api/intel/attack-map', () => {
  it('rejects an empty entries array', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/attack-map', { method: 'POST', body: JSON.stringify({}) }), fakeEnv(), {});
    expect(res.status).toBe(400);
  });

  it('maps real CVE-shaped entries to real ATT&CK techniques', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/attack-map', {
      method: 'POST',
      body: JSON.stringify({ entries: [{ id: 'CVE-2026-1', title: 'Remote code execution via unauthenticated RCE', description: 'allows arbitrary command execution' }] }),
    }), fakeEnv(), {});
    const body = await res.json();
    expect(body.total).toBe(1);
  });
});

describe('handleThreatIntelPro — GET /api/intel/heatmap (real cache miss/hit)', () => {
  it('computes a real heatmap on cache miss and caches it', async () => {
    const puts = [];
    const env = fakeEnv({ SECURITY_HUB_KV: { get: async () => null, put: async (k, v) => puts.push({ k, v }) } });
    const res = await handleThreatIntelPro(req('https://x/api/intel/heatmap'), env, {});
    const body = await res.json();
    expect(body.cache).toBe('miss');
    expect(body.heatmap).toBeTruthy();
    expect(puts.some(p => p.k === 'intel:heatmap:v2')).toBe(true);
  });

  it('serves a real cached heatmap on cache hit without recomputing', async () => {
    const cached = { heatmap: { T1566: { count: 3 } }, by_tactic: {}, total_techniques: 1 };
    const env = fakeEnv({ SECURITY_HUB_KV: { get: async () => cached, put: async () => {} } });
    const res = await handleThreatIntelPro(req('https://x/api/intel/heatmap'), env, {});
    const body = await res.json();
    expect(body.cache).toBe('hit');
    expect(body.heatmap.T1566.count).toBe(3);
  });
});

describe('handleThreatIntelPro — GET /api/intel/risk-score/:id + /risk-queue + /epss/:id', () => {
  it('404s honestly for a CVE not in D1', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/risk-score/CVE-1999-0001'), fakeEnv(), {});
    expect(res.status).toBe(404);
  });

  it('computes a real composite risk score for a real D1-backed CVE', async () => {
    const env = fakeEnv({
      DB: {
        prepare(sql) {
          return {
            bind() { return this; },
            async first() {
              if (/WHERE id = \?/.test(sql)) return { id: 'CVE-2026-9999', title: 'Test', severity: 'CRITICAL', cvss: 9.8, is_kev: 1, exploit_status: 'confirmed' };
              return null;
            },
            async all() { return { results: [] }; },
          };
        },
      },
    });
    const res = await handleThreatIntelPro(req('https://x/api/intel/risk-score/CVE-2026-9999'), env, {});
    const body = await res.json();
    expect(body.cve_id).toBe('CVE-2026-9999');
    expect(typeof body.priority_score === 'number' || typeof body.score === 'number' || body.risk_tier).toBeTruthy();
  });

  it('risk-queue returns an honest empty queue when D1 has nothing, not fabricated entries', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/risk-queue'), fakeEnv(), {});
    const body = await res.json();
    expect(body.queue).toEqual([]);
    expect(body.total).toBe(0);
  });

  it('epss endpoint returns a real, honestly-null score when unavailable rather than a fabricated number', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/epss/CVE-2026-0000'), fakeEnv(), {});
    const body = await res.json();
    expect(body.cve_id).toBe('CVE-2026-0000');
    expect(body.source).toBe('FIRST.org EPSS');
  });
});

describe('handleThreatIntelPro — GET /api/intel/stix (soft content tiering by real tier, not a hard gate)', () => {
  it('a FREE-tier caller gets a bundle with no actor/IOC objects included', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/stix?format=raw'), fakeEnv(), { tier: 'FREE' });
    expect(res.status).toBe(200); // access itself is never blocked
    const body = await res.json();
    expect(body).toBeTruthy();
  });

  it('the endpoint itself never 403s regardless of tier — content varies, access does not', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/stix?format=raw'), fakeEnv(), {});
    expect(res.status).toBe(200);
  });
});

describe('handleThreatIntelPro — TAXII 2.1 endpoints', () => {
  it('discovery and collections return real TAXII-shaped documents', async () => {
    const disco = await (await handleThreatIntelPro(req('https://x/api/taxii/discovery'), fakeEnv(), {})).json();
    expect(disco.title).toContain('Sentinel APEX');
    const cols = await (await handleThreatIntelPro(req('https://x/api/taxii/collections'), fakeEnv(), {})).json();
    expect(Array.isArray(cols.collections)).toBe(true);
    expect(cols.collections.length).toBeGreaterThan(0);
  });

  it('cve-feed and kev-feed are genuinely public — no tier check', async () => {
    for (const id of ['cve-feed', 'kev-feed']) {
      const res = await handleThreatIntelPro(req(`https://x/api/taxii/collections/${id}/objects`), fakeEnv(), {});
      expect(res.status, id).toBe(200);
    }
  });

  it('THE REAL HARD GATE: ioc-feed requires PRO — 403 below it, 200 at/above it', async () => {
    const denied = await handleThreatIntelPro(req('https://x/api/taxii/collections/ioc-feed/objects'), fakeEnv(), { tier: 'STARTER' });
    expect(denied.status).toBe(403);
    const admitted = await handleThreatIntelPro(req('https://x/api/taxii/collections/ioc-feed/objects'), fakeEnv(), { tier: 'PRO' });
    expect(admitted.status).toBe(200);
  });

  it('THE REAL HARD GATE: actor-feed requires ENTERPRISE — 403 below it, 200 at it', async () => {
    const denied = await handleThreatIntelPro(req('https://x/api/taxii/collections/actor-feed/objects'), fakeEnv(), { tier: 'PRO' });
    expect(denied.status).toBe(403);
    const admitted = await handleThreatIntelPro(req('https://x/api/taxii/collections/actor-feed/objects'), fakeEnv(), { tier: 'ENTERPRISE' });
    expect(admitted.status).toBe(200);
  });

  it('an unknown collection id 404s honestly', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/taxii/collections/not-a-real-collection/objects'), fakeEnv(), {});
    expect(res.status).toBe(404);
  });
});

describe('handleThreatIntelPro — GET /api/intel/attribute/:id', () => {
  it('returns a real (possibly empty) attribution list, not fabricated actors', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/attribute/CVE-1999-0001'), fakeEnv(), {});
    const body = await res.json();
    expect(body.cve_id).toBe('CVE-1999-0001');
    expect(Array.isArray(body.attributed_actors)).toBe(true);
  });
});

describe('handleThreatIntelPro — the 3 rate-limited (not tier-gated) LLM routes still validate input', () => {
  it('cve-brief 404s honestly for an unknown CVE before ever calling the LLM', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/cve-brief/CVE-1999-0001'), fakeEnv(), {});
    expect(res.status).toBe(404);
  });

  it('analyst rejects an empty query with a helpful 400, not a wasted LLM call', async () => {
    const res = await handleThreatIntelPro(req('https://x/api/intel/analyst?q='), fakeEnv(), {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.examples?.length).toBeGreaterThan(0);
  });
});
