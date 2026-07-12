// CAP-TIH-013 — Enterprise Premium Intelligence API. 3 of its 4 endpoints
// (risk/campaigns/actors) were already wired into frontend/enterprise-dashboard.html;
// handleEnterpriseIntelligence — the full, filterable (industry/severity/min_risk)
// signal feed — had zero frontend caller. workers/src/handlers/enterpriseIntel.js
// also had zero import-confirmed tests for any of its 4 handlers.
//
// FIX: added a "Full Signal Intelligence Feed" section to enterprise-dashboard.html
// with industry/severity/min-risk filter controls, wired into the same
// apiFetch()/refreshAll() pattern already used by the page's other 3 sections.
// No backend change.
//
// Also resolved navigation.discoverable from "unknown" to a verified "false"
// (grepped frontend/sitemap.html, frontend/index.html, and every other
// frontend/*.html for "enterprise-dashboard" — zero real links, only two
// coincidental CSS-comment mentions) — fixed with a real nav-item in
// user-dashboard.html's Developer section, the same treatment already given
// to automation-dashboard.html under CAP-DEVPORTAL-002.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const {
  handleEnterpriseIntelligence, handleEnterpriseRisk, handleEnterpriseCampaigns, handleEnterpriseActors,
} = await import('../src/handlers/enterpriseIntel.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/enterprise-dashboard.html'), 'utf8');
const userDash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function req(url) { return new Request(url); }

// Real D1 fixtures matching the exact columns radarService.js's collectFromD1()
// actually selects (threat_intel does NOT select threat_actor/campaign_name/
// ransomware_group; only ai_threat_feed selects threat_actor).
function fakeEnv() {
  const threatIntelRow = {
    cve_id: 'CVE-2026-9001', id: 'CVE-2026-9001',
    title: 'Critical RCE in Acme Gateway', severity: 'CRITICAL',
    cvss: 9.8, cvss_score: 9.8, epss_score: 0.9,
    actively_exploited: 1, known_ransomware: 0,
    source: 'NVD', published_at: '2026-07-01', created_at: '2026-07-01',
    weakness_types: '["finance","banking"]', exploit_status: 'confirmed',
  };
  const aiThreatFeedRow = {
    id: 'AI-AGT-001', advisory_id: 'AI-AGT-001',
    title: 'Prompt injection in customer support LLM agent', severity: 'HIGH',
    cvss: 7.5, epss_score: 0.4, actively_exploited: 0, known_ransomware: 0,
    source: 'Internal AI Radar', published_at: '2026-07-05', created_at: '2026-07-05',
    owasp_categories: '["LLM01"]', mitre_atlas_techniques: '[]', threat_actor: 'APT41',
  };
  return {
    SECURITY_HUB_KV: { get: async () => null, put: async () => {} },
    SECURITY_HUB_DB: {
      prepare(sql) {
        return {
          bind() { return this; },
          async all() {
            if (/FROM threat_intel/.test(sql)) return { results: [threatIntelRow] };
            if (/FROM ai_threat_feed/.test(sql)) return { results: [aiThreatFeedRow] };
            return { results: [] };
          },
        };
      },
    },
  };
}

function realUser(tier) { return { authenticated: true, user_id: 'u1', tier }; }

describe('CAP-TIH-013 backend — real auth gate on all 4 handlers (no prior test coverage existed)', () => {
  it('handleEnterpriseIntelligence rejects an unauthenticated caller with 401', async () => {
    const res = await handleEnterpriseIntelligence(req('https://x/api/enterprise/intelligence'), fakeEnv(), {});
    expect(res.status).toBe(401);
  });
  it('handleEnterpriseIntelligence rejects a FREE-tier authenticated caller with 403', async () => {
    const res = await handleEnterpriseIntelligence(req('https://x/api/enterprise/intelligence'), fakeEnv(), realUser('FREE'));
    expect(res.status).toBe(403);
  });
  it('handleEnterpriseRisk, handleEnterpriseCampaigns, handleEnterpriseActors all enforce the same gate', async () => {
    for (const fn of [handleEnterpriseRisk, handleEnterpriseCampaigns, handleEnterpriseActors]) {
      const res = await fn(req('https://x/api/enterprise/x'), fakeEnv(), {});
      expect(res.status).toBe(401);
    }
  });
});

describe('CAP-TIH-013 backend — real, non-fabricated D1-driven responses', () => {
  it('handleEnterpriseIntelligence returns a real enriched signal with computed risk_score and targeted_sectors', async () => {
    const res = await handleEnterpriseIntelligence(req('https://x/api/enterprise/intelligence'), fakeEnv(), realUser('ENTERPRISE'));
    const body = await res.json();
    expect(body.signals.length).toBeGreaterThan(0);
    const cve = body.signals.find(s => s.id === 'CVE-2026-9001');
    expect(cve).toBeTruthy();
    expect(cve.risk_score).toBeGreaterThan(0);
    expect(cve.targeted_sectors).toContain('Finance');
    expect(body.total_signals).toBe(body.signals.length);
  });

  it('handleEnterpriseIntelligence honors severity and min_risk filters against real data', async () => {
    const res = await handleEnterpriseIntelligence(req('https://x/api/enterprise/intelligence?severity=HIGH&min_risk=90'), fakeEnv(), realUser('PRO'));
    const body = await res.json();
    // The CRITICAL 9.8/KEV signal is filtered out by severity=HIGH; the HIGH
    // signal's own risk score won't reach 90 — expect an honest empty result,
    // not a fabricated match.
    expect(body.signals).toEqual([]);
  });

  it('handleEnterpriseActors correlates a real actor from ai_threat_feed against the static MITRE table', async () => {
    const res = await handleEnterpriseActors(req('https://x/api/enterprise/actors'), fakeEnv(), realUser('ENTERPRISE'));
    const body = await res.json();
    const apt41 = body.threat_actors.find(a => a.name === 'APT41');
    expect(apt41).toBeTruthy();
    expect(apt41.mitre_group_id).toBe('G0096');
    expect(apt41.country).toBe('China');
  });

  it('handleEnterpriseCampaigns returns an honest empty list (real D1 query never selects a campaign column — not fabricated)', async () => {
    const res = await handleEnterpriseCampaigns(req('https://x/api/enterprise/campaigns'), fakeEnv(), realUser('ENTERPRISE'));
    const body = await res.json();
    expect(body.campaigns).toEqual([]);
  });

  it('handleEnterpriseRisk computes a real risk distribution from real signals', async () => {
    const res = await handleEnterpriseRisk(req('https://x/api/enterprise/risk?min_risk=0'), fakeEnv(), realUser('ENTERPRISE'));
    const body = await res.json();
    expect(body.risk_distribution.CRITICAL).toBeGreaterThanOrEqual(1);
    expect(body.total_signals).toBeGreaterThan(0);
  });
});

describe('enterprise-dashboard.html — Full Signal Intelligence Feed section (CAP-TIH-013)', () => {
  it('has the new section with filter controls', () => {
    expect(dash).toContain('Full Signal Intelligence Feed');
    expect(dash).toContain('id="feed-industry"');
    expect(dash).toContain('id="feed-severity"');
    expect(dash).toContain('id="feed-min-risk"');
    expect(dash).toContain('id="feed-wrap"');
  });

  it('loadFeed() calls the real, previously-unwired /api/enterprise/intelligence endpoint', () => {
    const fn = dash.slice(dash.indexOf('async function loadFeed'), dash.indexOf('function renderFeedTable'));
    expect(fn).toContain('/api/enterprise/intelligence?');
    expect(fn).toContain("params.set('industry'");
    expect(fn).toContain("params.set('severity'");
    expect(fn).toContain("params.set('min_risk'");
  });

  it('is wired into refreshAll() so it loads automatically, not only on manual filter', () => {
    const fn = dash.slice(dash.indexOf('async function refreshAll'), dash.indexOf('async function loadRisk'));
    expect(fn).toContain('loadFeed()');
  });

  it('the existing risk/actors/campaigns sections are untouched', () => {
    expect(dash).toContain(`apiFetch('/api/enterprise/risk?min_risk=0&limit=15')`);
    expect(dash).toContain(`apiFetch('/api/enterprise/actors?limit=10')`);
    expect(dash).toContain(`apiFetch('/api/enterprise/campaigns')`);
  });
});

describe('user-dashboard.html — Enterprise Dashboard is now discoverable (CAP-TIH-013 navigation fix)', () => {
  it('has a real nav-item linking to enterprise-dashboard.html', () => {
    expect(userDash).toContain(`onclick="location.href='/enterprise-dashboard.html'"`);
  });

  it('sits in the Developer sidebar section, alongside the other own-page/own-key tools', () => {
    const idx = userDash.indexOf(`onclick="location.href='/enterprise-dashboard.html'"`);
    expect(idx).toBeGreaterThan(-1);
    const before = userDash.slice(Math.max(0, idx - 700), idx);
    expect(before).toContain('sidebar-section');
    expect(before).toContain('Developer');
  });
});
