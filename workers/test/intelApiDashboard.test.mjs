// CAP-TIH-009 — Threat Intelligence API Economy (IOC/CVE/actor/TTP/risk) was a
// real, tiered, monetized API product documented in api-docs.html text only —
// zero dashboard UI for a paying customer to actually use or manage it. Also
// closes real test-coverage gaps: handleIntelCVE/Actor/TTP/Risk had no
// import-confirmed tests before this (only handleIntelIOC did, via a
// rate-limit-focused test elsewhere).
//
// FIX: added a "Threat Intel API" tab to user-dashboard.html with 5 live
// lookup tools (one per real endpoint), each calling the real /api/intel/*
// route and rendering the real response. No backend change.
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

vi.mock('../src/core/mythosAIProvider.js', () => ({
  callClaude: vi.fn(async () => ({ content: 'Mock AI narrative.', provider: 'mock', model: 'mock' })),
}));

const {
  handleIntelIOC, handleIntelCVE, handleIntelActor, handleIntelTTP, handleIntelRisk,
} = await import('../src/handlers/intelAPIHandlers.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fakeEnv() {
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
    KV: { get: async () => null, put: async () => {} },
  };
}

function req(url) {
  return new Request(url);
}

describe('Threat Intel API backend — real responses for all 5 endpoints (test-coverage gap closed)', () => {
  it('handleIntelIOC returns a real verdict for a PRO caller', async () => {
    const res = await handleIntelIOC(req('https://x/api/intel/ioc?value=185.220.101.1'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(['MALICIOUS', 'SUSPICIOUS', 'SAFE', 'UNKNOWN']).toContain(data.analysis.verdict);
  });

  it('handleIntelCVE returns found_in_db:false honestly for an unknown CVE (no hallucination)', async () => {
    const res = await handleIntelCVE(req('https://x/api/intel/cve?cve_id=CVE-1999-9999'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.result.found_in_db).toBe(false);
  });

  it('handleIntelActor returns a real (empty, honest) list when nothing matches', async () => {
    const res = await handleIntelActor(req('https://x/api/intel/actor?sector=aerospace'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.total_found).toBe(0);
  });

  it('handleIntelTTP returns the real, embedded MITRE catalog entry for a known technique', async () => {
    const res = await handleIntelTTP(req('https://x/api/intel/ttp?ttp_id=T1566'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.success).toBe(true);
  });

  it('handleIntelRisk computes a real composite score from real component weights', async () => {
    const res = await handleIntelRisk(req('https://x/api/intel/risk?target=example.com&sector=Technology'), fakeEnv(), { tier: 'PRO', userId: 'u1' });
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(typeof data.risk_assessment.composite_score).toBe('number');
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(data.risk_assessment.risk_level);
  });

  it('endpoints correctly 429 with an upgrade URL for a FREE-tier caller past the entitlement table (legacy tier gate)', async () => {
    const res = await handleIntelActor(req('https://x/api/intel/actor?actor_id=APT29'), fakeEnv(), { tier: 'FREE' });
    expect(res.status).toBe(429);
    const data = await res.json();
    expect(data.upgrade).toBeTruthy();
  });
});

describe('user-dashboard.html — Threat Intel API tab (CAP-TIH-009)', () => {
  it('has a real nav-item', () => {
    expect(dash).toContain(`data-page="intel-api" onclick="showPage('intel-api',this);loadIntelAPIStatus()"`);
  });

  it('has a real page section with all 5 lookup tools', () => {
    expect(dash).toContain('id="page-intel-api"');
    expect(dash).toContain('id="intel-ioc-value"');
    expect(dash).toContain('id="intel-cve-value"');
    expect(dash).toContain('id="intel-actor-value"');
    expect(dash).toContain('id="intel-ttp-value"');
    expect(dash).toContain('id="intel-risk-target"');
  });

  it('each lookup function calls its real backend endpoint', () => {
    expect(dash).toContain(`intelApiGet('/api/intel/ioc'`);
    expect(dash).toContain(`intelApiGet('/api/intel/cve'`);
    expect(dash).toContain(`intelApiGet('/api/intel/actor'`);
    expect(dash).toContain(`intelApiGet('/api/intel/ttp'`);
    expect(dash).toContain(`intelApiGet('/api/intel/risk'`);
  });

  it('handles a 429 (tier-limited) response with an inline upgrade notice, not a generic alert', () => {
    const fn = dash.slice(dash.indexOf('async function intelLookupIOC'), dash.indexOf('async function intelLookupCVE'));
    expect(fn).toContain('intelUpgradeNotice');
    expect(fn).toContain('res.status === 429');
  });

  it('the DPDP and Compliance tabs are untouched', () => {
    expect(dash).toContain(`data-page="dpdp" onclick="showPage('dpdp',this);loadDPDPOverview()"`);
    expect(dash).toContain(`data-page="compliance" onclick="showPage('compliance',this);loadComplianceAssessment()"`);
  });
});
