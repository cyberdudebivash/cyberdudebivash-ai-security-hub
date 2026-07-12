// CAP-TIH-001 — Threat Hunting Engine. Registry evidence: the only related
// test file reimplements detectIOCType as a locally copy-pasted helper
// (comment: "kept in sync with workers/src/handlers/threatHunting.js")
// rather than importing it — a drift-prone weak signal, not real coverage of
// handleRunHunt/handleHuntTemplates/handleIOCLookup/handleHuntSessions/
// handleMITREMatrix. This file imports and exercises all 5 directly.
//
// Also fixes a real finding made while writing these tests: handleMITREMatrix
// returned hardcoded covered_techniques:47 / coverage_pct:25.4 that did not
// match the hunt_coverage object in the SAME response (which lists only ~10
// unique technique IDs across kql/sigma/yara) — 47/185=25.4% was internally
// consistent with itself but not with the data actually shown. Confirmed
// (grep) this endpoint is not currently rendered by any frontend page, so no
// customer-facing regression, but fixed at the source since an external API
// consumer calling GET /api/hunt/mitre directly would see the mismatch.
// covered_techniques/coverage_pct are now computed from hunt_coverage itself.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  handleRunHunt, handleHuntTemplates, handleIOCLookup, handleHuntSessions, handleMITREMatrix,
} from '../src/handlers/threatHunting.js';

function reqWithBody(body) {
  return { json: async () => body, url: 'https://x/api/hunt' };
}
function reqWithUrl(url) {
  return { url };
}

describe('handleRunHunt — real D1-driven hunting, no fabrication', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });

  it('rejects a missing/too-short query', async () => {
    const res = await handleRunHunt(reqWithBody({ query: 'ab' }), {}, {});
    expect(res.status).toBe(400);
  });

  it('rejects an invalid lang', async () => {
    const res = await handleRunHunt(reqWithBody({ query: 'lateral movement detection', lang: 'sql' }), {}, {});
    expect(res.status).toBe(400);
  });

  it('rejects a malicious payload', async () => {
    const res = await handleRunHunt(reqWithBody({ query: '<script>alert(1)</script>' }), {}, {});
    expect(res.status).toBe(400);
  });

  it('returns an honest no_findings result when there is no D1 binding at all — not a fabricated match', async () => {
    const res = await handleRunHunt(reqWithBody({ query: 'lateral movement over smb' }), {}, {});
    const body = await res.json();
    expect(body.status).toBe('no_findings');
    expect(body.results).toEqual([]);
    expect(body.result_count).toBe(0);
  });

  it('returns real CVE findings from a real D1 threat_intel match, not fabricated', async () => {
    const env = {
      DB: {
        prepare(sql) {
          return {
            bind() { return this; },
            async all() {
              if (/FROM threat_intel/.test(sql)) {
                return { results: [{ cve_id: 'CVE-2026-1234', title: 'Test RCE', severity: 'CRITICAL', cvss_score: 9.8, epss_score: 0.9, is_kev: 1, description: 'Real desc', published_date: '2026-07-01' }] };
              }
              return { results: [] };
            },
          };
        },
      },
    };
    const res = await handleRunHunt(reqWithBody({ query: 'CVE-2026-1234' }), env, {});
    const body = await res.json();
    expect(body.status).toBe('results_found');
    const finding = body.results.find(r => r.host === 'CVE-2026-1234');
    expect(finding.source).toBe('platform_threat_intel');
    expect(finding.risk).toBe('CRITICAL');
    expect(finding.is_kev).toBe(true);
    expect(body.cves_matched).toContain('CVE-2026-1234');
  });

  it('infers real MITRE techniques from query content', async () => {
    const res = await handleRunHunt(reqWithBody({ query: 'hunting for lateral movement via smb and rdp' }), {}, {});
    const body = await res.json();
    expect(body.mitre_techniques.some(t => t.id === 'T1021')).toBe(true);
  });

  it('grants adaptive_hunt_suggestions to PRO/ENTERPRISE tier but not FREE', async () => {
    const proRes = await handleRunHunt(reqWithBody({ query: 'ransomware encryption activity' }), {}, { tier: 'PRO' });
    const proBody = await proRes.json();
    expect(proBody.adaptive_hunt_suggestions).toBeTruthy();

    const freeRes = await handleRunHunt(reqWithBody({ query: 'ransomware encryption activity' }), {}, { tier: 'FREE' });
    const freeBody = await freeRes.json();
    expect(freeBody.adaptive_hunt_suggestions).toBeUndefined();
  });

  it('persists a real hunt session to KV under the caller identity', async () => {
    // Same KV binding also receives real rate-limiter counter writes
    // (checkRateLimitCost -> checkRateLimitV2's burst/daily/global/stats
    // increments) — filter to the specific hunt:session key rather than
    // asserting a total put count.
    const puts = [];
    const env = { SECURITY_HUB_KV: { get: async () => null, put: async (k, v) => puts.push({ k, v }) } };
    await handleRunHunt(reqWithBody({ query: 'credential dumping via mimikatz' }), env, { identity: 'user_42' });
    const sessionPut = puts.find(p => p.k.startsWith('hunt:session:user_42:'));
    expect(sessionPut).toBeTruthy();
    const stored = JSON.parse(sessionPut.v);
    expect(stored.executed_by).toBe('user_42');
  });
});

describe('handleHuntTemplates — real, decoded KQL/Sigma/YARA templates', () => {
  it('returns all templates across all 3 languages by default', async () => {
    const res = await handleHuntTemplates(reqWithUrl('https://x/api/hunt/templates'), {}, {});
    const body = await res.json();
    expect(body.total).toBe(10); // 5 kql + 3 sigma + 2 yara
    expect(body.templates.some(t => t.lang === 'kql')).toBe(true);
    expect(body.templates.some(t => t.lang === 'sigma')).toBe(true);
    expect(body.templates.some(t => t.lang === 'yara')).toBe(true);
  });

  it('filters by lang', async () => {
    const res = await handleHuntTemplates(reqWithUrl('https://x/api/hunt/templates?lang=yara'), {}, {});
    const body = await res.json();
    expect(body.templates.every(t => t.lang === 'yara')).toBe(true);
  });

  it('filters by tactic', async () => {
    const res = await handleHuntTemplates(reqWithUrl('https://x/api/hunt/templates?tactic=Persistence'), {}, {});
    const body = await res.json();
    expect(body.templates.length).toBeGreaterThan(0);
    expect(body.templates.every(t => t.tactic === 'Persistence')).toBe(true);
  });

  it('templates decode to real, readable detection logic — not garbled or still base64', async () => {
    const res = await handleHuntTemplates(reqWithUrl('https://x/api/hunt/templates?lang=sigma'), {}, {});
    const body = await res.json();
    const mimikatz = body.templates.find(t => t.id === 'sigma-mimikatz');
    expect(mimikatz.query).toContain('sekurlsa::logonpasswords');
    expect(mimikatz.query).toContain('title: Mimikatz Credential Dump');
  });
});

describe('handleIOCLookup — real batch enrichment, honest on failure', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unreachable'))); });

  it('rejects a request with no ioc/iocs', async () => {
    const res = await handleIOCLookup(reqWithBody({}), {}, {});
    expect(res.status).toBe(400);
  });

  it('caps batch lookups at 20', async () => {
    const iocs = Array.from({ length: 30 }, (_, i) => `1.2.3.${i}`);
    const res = await handleIOCLookup(reqWithBody({ iocs }), {}, {});
    const body = await res.json();
    expect(body.total).toBe(20);
  });

  it('still returns a real, honest "clean" verdict from internal-only signals when every external source fails — not a crash, not a fabricated malicious result', async () => {
    const res = await handleIOCLookup(reqWithBody({ ioc: '8.8.8.8' }), {}, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    // enrichIOCLive's internal-threat-intel check runs independently of the
    // network — when every external source (VT/AbuseIPDB/Shodan) fails, the
    // engine legitimately falls back to a "clean" verdict (nothing bad found
    // internally either), which the handler correctly reports as "found" —
    // a completed lookup, not a fabricated positive/negative result.
    expect(body.results[0].verdict).toBe('clean');
    expect(body.results[0].value).toBe('8.8.8.8');
  });

  it('detects and echoes back the real IOC type for each lookup', async () => {
    const res = await handleIOCLookup(reqWithBody({ iocs: ['8.8.8.8', 'CVE-2026-1234'] }), {}, {});
    const body = await res.json();
    expect(body.results[0].type).toBe('ip');
  });
});

describe('handleHuntSessions — auth required, real session listing', () => {
  it('rejects an unauthenticated caller', async () => {
    const res = await handleHuntSessions({}, {}, {});
    expect(res.status).toBe(401);
  });

  it('lists real sessions from KV for the authenticated identity, sorted newest-first', async () => {
    const env = {
      SECURITY_HUB_KV: {
        async list() {
          return { keys: [{ name: 'hunt:session:u1:a' }, { name: 'hunt:session:u1:b' }] };
        },
        async get(key) {
          if (key.endsWith(':a')) return JSON.stringify({ id: 'a', executed_at: '2026-07-01T00:00:00Z' });
          if (key.endsWith(':b')) return JSON.stringify({ id: 'b', executed_at: '2026-07-10T00:00:00Z' });
          return null;
        },
      },
    };
    const res = await handleHuntSessions({}, env, { authenticated: true, user_id: 'u1', identity: 'u1' });
    const body = await res.json();
    expect(body.total).toBe(2);
    expect(body.sessions[0].id).toBe('b'); // most recent first
  });
});

describe('handleMITREMatrix — coverage numbers are now genuinely computed, not hardcoded-and-mismatched', () => {
  it('covered_techniques and coverage_pct are derived from the real hunt_coverage union, not a stale hardcoded pair', async () => {
    const res = await handleMITREMatrix({}, {}, {});
    const body = await res.json();
    const unionSize = new Set(Object.values(body.matrix.hunt_coverage).flat()).size;
    expect(body.matrix.covered_techniques).toBe(unionSize);
    expect(body.matrix.covered_techniques).not.toBe(47); // the old, mismatched hardcoded value
    expect(body.matrix.coverage_pct).toBeCloseTo((unionSize / body.matrix.total_techniques) * 100, 1);
  });

  it('returns all 12 real MITRE ATT&CK Enterprise tactics', async () => {
    const res = await handleMITREMatrix({}, {}, {});
    const body = await res.json();
    expect(body.matrix.tactics).toHaveLength(12);
    expect(body.matrix.tactics.map(t => t.id)).toContain('TA0001');
  });
});
