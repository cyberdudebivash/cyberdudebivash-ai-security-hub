// Enterprise AI Security Services — Mitigation & Response Playbook Engine.
//
// Fills a gap the platform's own capability inventory found completely
// MISSING: no handler anywhere generated investigation guides, pivot paths,
// SOC playbooks, or IR playbooks. This locks in a deterministic generator
// grounded entirely in real threat_intel fields plus the already-production
// mapToAttack()/scoreCVE() engines — no LLM dependency, no invented facts.
import { describe, it, expect } from 'vitest';
import {
  buildPlaybook,
  handleGeneratePlaybook,
  handleGetPlaybook,
  handleListPlaybooks,
} from '../src/handlers/mitigationPlaybook.js';

const RICH_ENTRY = {
  id: 'CVE-2026-11111',
  title: 'Remote Code Execution in Acme WebGate via Deserialization',
  severity: 'CRITICAL',
  cvss: 9.8,
  cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  description: 'Unauthenticated remote code execution via unsafe deserialization of the exploit-vulnerability parameter.',
  source: 'Acme PSIRT',
  source_url: 'https://acme.example/advisories/PSIRT-2026-004',
  published_at: '2026-06-01T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
  exploit_status: 'confirmed',
  known_ransomware: 1,
  tags: '["rce","deserialization"]',
  iocs: '["185.220.101.7","evil-c2.example.net"]',
  affected_products: '["Acme WebGate 4.x","Acme WebGate 5.0-5.2"]',
  weakness_types: '["CWE-502"]',
  epss_score: 0.94,
  epss_percentile: 0.99,
  actively_exploited: 1,
  exploit_available: 1,
};

const SPARSE_ENTRY = {
  id: 'INTEL-9001',
  title: 'Unattributed suspicious activity cluster',
  severity: 'LOW',
  cvss: null,
  description: '',
  source: 'Internal telemetry',
  source_url: null,
  published_at: '2026-05-01T00:00:00Z',
  updated_at: '2026-05-01T00:00:00Z',
  exploit_status: null,
  known_ransomware: 0,
  tags: '[]',
  iocs: '[]',
  affected_products: '[]',
  weakness_types: '[]',
  epss_score: null,
  epss_percentile: null,
  actively_exploited: 0,
  exploit_available: 0,
};

describe('buildPlaybook — every section is grounded in real fields, nothing invented', () => {
  it('surfaces real IOCs verbatim and cites the real source URL', () => {
    const pb = buildPlaybook(RICH_ENTRY);
    expect(pb.detection_guidance.join(' ')).toContain('185.220.101.7');
    expect(pb.references.some(r => r.url === RICH_ENTRY.source_url)).toBe(true);
    expect(pb.references.some(r => r.url === 'https://nvd.nist.gov/vuln/detail/CVE-2026-11111')).toBe(true);
  });

  it('flags active exploitation and ransomware linkage in immediate actions', () => {
    const pb = buildPlaybook(RICH_ENTRY);
    expect(pb.immediate_actions.join(' ')).toMatch(/active exploitation is confirmed/i);
    expect(pb.immediate_actions.join(' ')).toMatch(/ransomware linkage/i);
  });

  it('maps real ATT&CK techniques into detection guidance and architecture guidance', () => {
    const pb = buildPlaybook(RICH_ENTRY);
    expect(pb.supporting_evidence.attack_mapping.techniques.length).toBeGreaterThan(0);
    const mappedIds = pb.supporting_evidence.attack_mapping.techniques.map(t => t.technique_id);
    expect(pb.detection_guidance.some(line => mappedIds.some(id => line.includes(id)))).toBe(true);
    expect(pb.security_architecture_guidance.length).toBeGreaterThan(0);
  });

  it('echoes every real evidentiary field verbatim in supporting_evidence', () => {
    const pb = buildPlaybook(RICH_ENTRY);
    expect(pb.supporting_evidence.cvss).toBe(9.8);
    expect(pb.supporting_evidence.epss_score).toBe(0.94);
    expect(pb.supporting_evidence.exploit_status).toBe('confirmed');
    expect(pb.supporting_evidence.affected_products).toEqual(['Acme WebGate 4.x', 'Acme WebGate 5.0-5.2']);
  });

  it('does not fabricate IOCs, products, or ATT&CK mappings when none exist — says so honestly instead', () => {
    const pb = buildPlaybook(SPARSE_ENTRY);
    expect(pb.detection_guidance.some(l => /no indicators of compromise have been published/i.test(l))).toBe(true);
    expect(pb.immediate_actions.some(l => /affected-product list has not been published/i.test(l))).toBe(true);
    expect(pb.supporting_evidence.iocs).toEqual([]);
    expect(pb.supporting_evidence.affected_products).toEqual([]);
  });

  it('produces all 10 mandated sections', () => {
    const pb = buildPlaybook(RICH_ENTRY);
    for (const key of ['immediate_actions', 'detection_guidance', 'threat_hunting_guide', 'soc_playbook',
      'incident_response_playbook', 'executive_advisory', 'security_architecture_guidance',
      'operational_checklist', 'references', 'supporting_evidence']) {
      expect(pb[key], `missing section: ${key}`).toBeDefined();
    }
  });

  it('is deterministic given the same input (ignoring generation timestamps)', () => {
    const strip = (pb) => {
      delete pb.generated_at;
      delete pb.supporting_evidence.attack_mapping.mapped_at;
      delete pb.supporting_evidence.risk_score.scored_at;
      return pb;
    };
    const a = strip(buildPlaybook(RICH_ENTRY));
    const b = strip(buildPlaybook(RICH_ENTRY));
    expect(a).toEqual(b);
  });
});

// ─── D1-backed handler tests ─────────────────────────────────────────────────
function makeDB(threatIntelRows) {
  const playbooks = [];
  return {
    _playbooks: playbooks,
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async run() {
          if (/CREATE TABLE|CREATE INDEX/.test(sql)) return { success: true };
          if (/INSERT INTO threat_playbooks/.test(sql)) {
            const [id, threat_intel_id, org_id, generated_by, playbook_json, source_updated_at] = bound;
            playbooks.push({ id, threat_intel_id, org_id, generated_by, playbook_json, source_updated_at, created_at: new Date().toISOString() });
            return { success: true };
          }
          return { success: true };
        },
        async first() {
          if (/FROM threat_intel WHERE id = \?/.test(sql)) {
            return threatIntelRows.find(r => r.id === bound[0]) || null;
          }
          if (/FROM threat_playbooks WHERE threat_intel_id = \?/.test(sql)) {
            const matches = playbooks.filter(p => p.threat_intel_id === bound[0]);
            return matches.length ? matches[matches.length - 1] : null;
          }
          return null;
        },
        async all() {
          if (/FROM threat_playbooks WHERE org_id = \?/.test(sql)) {
            return { results: playbooks.filter(p => p.org_id === bound[0]) };
          }
          if (/FROM threat_playbooks WHERE generated_by = \?/.test(sql)) {
            return { results: playbooks.filter(p => p.generated_by === bound[0]) };
          }
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}

function req(url, method = 'GET') { return new Request(url, { method }); }

describe('handleGeneratePlaybook — POST persists a real, D1-backed playbook', () => {
  it('404s honestly when the threat_intel id does not exist', async () => {
    const env = { DB: makeDB([]) };
    const res = await handleGeneratePlaybook(req('https://x/api/threat-intel/NOPE/playbook', 'POST'), env, {});
    expect(res.status).toBe(404);
  });

  it('generates and persists a playbook for a real threat_intel row', async () => {
    const env = { DB: makeDB([RICH_ENTRY]) };
    const res = await handleGeneratePlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook', 'POST'), env, { user_id: 'u1', org_id: 'org1' });
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.playbook.threat_intel_id).toBe('CVE-2026-11111');
    expect(env.DB._playbooks.length).toBe(1);
    expect(env.DB._playbooks[0].generated_by).toBe('u1');
  });
});

describe('handleGetPlaybook — GET lazy-generates once, then reuses, and flags staleness', () => {
  it('lazy-generates on first visit when nothing has been persisted yet', async () => {
    const env = { DB: makeDB([RICH_ENTRY]) };
    const res = await handleGetPlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook'), env, {});
    const body = await res.json();
    expect(body.generated_now).toBe(true);
    expect(env.DB._playbooks.length).toBe(1);
  });

  it('reuses the persisted playbook on a second visit instead of regenerating', async () => {
    const env = { DB: makeDB([RICH_ENTRY]) };
    await handleGetPlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook'), env, {});
    const res2 = await handleGetPlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook'), env, {});
    const body2 = await res2.json();
    expect(body2.generated_now).toBeUndefined();
    expect(env.DB._playbooks.length).toBe(1);
    expect(body2.stale).toBe(false);
  });

  it('flags stale:true when the underlying threat_intel row changed since generation', async () => {
    const entry = { ...RICH_ENTRY };
    const env = { DB: makeDB([entry]) };
    await handleGetPlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook'), env, {});
    entry.updated_at = '2026-06-09T00:00:00Z'; // simulate re-enrichment
    const res2 = await handleGetPlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook'), env, {});
    const body2 = await res2.json();
    expect(body2.stale).toBe(true);
    expect(body2.stale_reason).toMatch(/updated since this playbook was generated/i);
  });
});

describe('handleListPlaybooks — org-scoped history requires authentication', () => {
  it('rejects an anonymous caller', async () => {
    const env = { DB: makeDB([RICH_ENTRY]) };
    const res = await handleListPlaybooks(req('https://x/api/threat-intel/playbooks/history'), env, {});
    expect(res.status).toBe(401);
  });

  it('returns only the calling org\'s generation history', async () => {
    const env = { DB: makeDB([RICH_ENTRY]) };
    await handleGeneratePlaybook(req('https://x/api/threat-intel/CVE-2026-11111/playbook', 'POST'), env, { user_id: 'u1', org_id: 'org1' });
    const res = await handleListPlaybooks(req('https://x/api/threat-intel/playbooks/history'), env, { user_id: 'u1', org_id: 'org1' });
    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.history[0].threat_intel_id).toBe('CVE-2026-11111');
  });
});
