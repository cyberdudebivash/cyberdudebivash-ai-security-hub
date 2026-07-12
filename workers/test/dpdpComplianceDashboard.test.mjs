// CAP-COMP-004 — DPDP Act 2023 Compliance Management Engine had a real,
// substantial, tier-gated backend (section-by-section gap analysis against 9
// real DPDP Act 2023 sections, AI-powered remediation roadmap, Record of
// Processing Activities generation) but ZERO frontend anywhere on the
// platform — a PRO/ENTERPRISE/MSSP subscriber had no way to ever reach it.
//
// FIX: added a real "DPDP Act 2023" tab to user-dashboard.html (assessment
// questionnaire -> POST /api/compliance/dpdp/assess -> render the real
// section-by-section report + roadmap; a "Generate RoPA" action ->
// POST /api/compliance/dpdp/ropa -> render the real processing-activities
// table). No backend change.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const {
  handleDPDPOverview, handleDPDPAssess, handleDPDPSections, handleDPDPRoPA,
} = await import('../src/handlers/dpdpCompliance.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function req(url, body) {
  return new Request(url, {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function fakeDB() {
  return {
    prepare() {
      return {
        bind() { return this; },
        async first() { return null; },
        async all() { return { results: [] }; },
        async run() { return { success: true }; },
      };
    },
  };
}

describe('DPDP backend — unchanged, still correctly tier-gated', () => {
  it('handleDPDPOverview rejects a FREE-tier caller', async () => {
    const res = await handleDPDPOverview(req('https://x/api/compliance/dpdp'), fakeDB(), { tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('handleDPDPAssess runs a real, input-driven assessment for a PRO caller', async () => {
    const res = await handleDPDPAssess(
      req('https://x/api/compliance/dpdp/assess', { org_name: 'Acme', has_dpo: true, has_consent_mechanism: true }),
      fakeDB(), { tier: 'PRO', userId: 'u1' },
    );
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.gap_analysis.length).toBe(9);
    expect(typeof data.overall_score).toBe('number');
  });

  it('two different control-input sets produce different real scores', async () => {
    const weak = await (await handleDPDPAssess(req('https://x/api/compliance/dpdp/assess', { org_name: 'Weak Co' }), fakeDB(), { tier: 'PRO' })).json();
    const strong = await (await handleDPDPAssess(req('https://x/api/compliance/dpdp/assess', {
      org_name: 'Strong Co', has_dpo: true, has_privacy_notice: true, has_consent_mechanism: true,
      has_dsr_process: true, has_breach_process: true, has_data_retention_policy: true, has_security_audit: true,
    }), fakeDB(), { tier: 'PRO' })).json();
    expect(strong.data.overall_score).toBeGreaterThan(weak.data.overall_score);
  });

  it('handleDPDPRoPA generates a real, structured RoPA document', async () => {
    const res = await handleDPDPRoPA(req('https://x/api/compliance/dpdp/ropa', { org_name: 'Acme' }), fakeDB(), { tier: 'ENTERPRISE', userId: 'u1' });
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.processing_activities.length).toBeGreaterThan(0);
    expect(data.prepared_for).toBe('Acme');
  });

  it('handleDPDPSections still returns all 9 real sections unmodified', async () => {
    const res = await handleDPDPSections(req('https://x/api/compliance/dpdp/sections'), fakeDB(), { tier: 'MSSP' });
    const { data } = await res.json();
    expect(data.sections.length).toBe(9);
  });
});

describe('user-dashboard.html — DPDP Act 2023 tab (CAP-COMP-004)', () => {
  it('has a real nav-item for DPDP', () => {
    expect(dash).toContain(`data-page="dpdp" onclick="showPage('dpdp',this);loadDPDPOverview()"`);
  });

  it('has a real page section with the upsell banner and the assessment form', () => {
    expect(dash).toContain('id="page-dpdp"');
    expect(dash).toContain('id="dpdp-upsell"');
    expect(dash).toContain('id="dpdp-assess-btn"');
  });

  it('loadDPDPOverview() gates on PRO/ENTERPRISE/MSSP, matching the backend gate exactly', () => {
    const fn = dash.slice(dash.indexOf('async function loadDPDPOverview'), dash.indexOf('async function runDPDPAssessment'));
    expect(fn).toContain(`plan === 'pro' || plan === 'enterprise' || plan === 'mssp'`);
  });

  it('runDPDPAssessment() posts to the real backend route with the real questionnaire fields', () => {
    const fn = dash.slice(dash.indexOf('async function runDPDPAssessment'), dash.indexOf('function renderDPDPResults'));
    expect(fn).toContain(`apiFetch('/api/compliance/dpdp/assess'`);
    expect(fn).toContain('has_consent_mechanism');
    expect(fn).toContain('has_dpo');
  });

  it('renderDPDPResults() reads the real report field names, not placeholders', () => {
    const fn = dash.slice(dash.indexOf('function renderDPDPResults'), dash.indexOf('async function generateDPDPRoPA'));
    expect(fn).toContain('report.gap_analysis');
    expect(fn).toContain('report.remediation_roadmap');
    expect(fn).toContain('report.next_steps');
  });

  it('generateDPDPRoPA() posts to the real RoPA endpoint', () => {
    const fn = dash.slice(dash.indexOf('async function generateDPDPRoPA'), dash.indexOf('function renderDPDPRoPA'));
    expect(fn).toContain(`apiFetch('/api/compliance/dpdp/ropa'`);
  });

  it('the existing Compliance (CAP-COMP-002) and CISO Metrics tabs are untouched', () => {
    expect(dash).toContain(`data-page="compliance" onclick="showPage('compliance',this);loadComplianceAssessment()"`);
    expect(dash).toContain(`data-page="ciso" onclick="showPage('ciso',this);loadCisoMetrics()"`);
  });
});
