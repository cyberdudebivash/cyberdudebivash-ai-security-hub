// CAP-COMP-002 — Compliance Readiness Assessment (CDB-COMP-001, ₹24,999-value
// engine: 93 ISO 27001:2022 controls, NIST CSF 2.0, GDPR) had a real, tested-
// adjacent, tier-gated backend (POST /api/scan/compliance) but ZERO frontend
// anywhere in the platform — a PRO/ENTERPRISE subscriber had no way to ever
// discover or run an assessment they were already entitled to.
//
// FIX: added a real "Compliance" tab to user-dashboard.html (10-checkbox
// control form -> POST /api/scan/compliance -> render the real report), gated
// to PRO/ENTERPRISE exactly like the backend, with the same honest-locked-
// state convention already used for the CISO Metrics tab. No backend change —
// handleComplianceScan/runComplianceAssessment were already correct.
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

vi.mock('../src/services/mythosEnrichmentEngine.js', () => ({
  enrichAssessmentWithMYTHOS: vi.fn(async (env, { report }) => report),
}));

const { handleComplianceScan } = await import('../src/handlers/serviceHandlers.js');

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function req(body) {
  return new Request('https://x/api/scan/compliance', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('handleComplianceScan backend — unchanged, still correctly tier-gated', () => {
  it('rejects a FREE-tier caller', async () => {
    const res = await handleComplianceScan(req({ domain: 'acme.com' }), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('runs a real, input-driven assessment for a PRO caller', async () => {
    const res = await handleComplianceScan(
      req({ domain: 'acme.com', has_mfa: true, has_backups: true }),
      {}, { tier: 'PRO', userId: 'u1' },
    );
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.executive_summary).toBeTruthy();
    expect(data.iso27001_assessment.domain_scores.length).toBeGreaterThan(0);
    expect(data.nist_csf_assessment.functions.length).toBe(6);
  });

  it('two different control inputs produce different real scores (proves it is not a fixed template)', async () => {
    const weak = await (await handleComplianceScan(req({ domain: 'weak.com' }), {}, { tier: 'PRO' })).json();
    const strong = await (await handleComplianceScan(req({
      domain: 'strong.com', has_policy: true, has_isms: true, has_mfa: true, has_backups: true,
      has_monitoring: true, has_incident_plan: true, has_training: true, has_asset_inventory: true,
      has_dlp: true, has_vuln_mgmt: true,
    }), {}, { tier: 'PRO' })).json();
    expect(strong.executive_summary.overall_compliance).toBeGreaterThan(weak.executive_summary.overall_compliance);
  });
});

describe('user-dashboard.html — Compliance Assessment tab (CAP-COMP-002)', () => {
  it('has a real nav-item for Compliance', () => {
    expect(dash).toContain(`data-page="compliance" onclick="showPage('compliance',this);loadComplianceAssessment()"`);
  });

  it('has a real page section with the upsell banner and the assessment form', () => {
    expect(dash).toContain('id="page-compliance"');
    expect(dash).toContain('id="compliance-upsell"');
    expect(dash).toContain('id="compliance-form-card"');
  });

  it('the 10-control form matches the real backend scoreOrganization() input keys exactly', () => {
    const block = dash.slice(dash.indexOf('id="page-compliance"'), dash.indexOf('id="page-compliance"') + 6000);
    const keys = [
      'has_policy', 'has_isms', 'has_mfa', 'has_backups', 'has_monitoring',
      'has_incident_plan', 'has_training', 'has_asset_inventory', 'has_dlp', 'has_vuln_mgmt',
    ];
    for (const k of keys) expect(block).toContain(`id="cc-${k}"`);
  });

  it('loadComplianceAssessment() gates on PRO/ENTERPRISE, matching the backend gate exactly', () => {
    const fn = dash.slice(dash.indexOf('function loadComplianceAssessment'), dash.indexOf('const COMPLIANCE_CONTROL_KEYS'));
    expect(fn).toContain(`plan === 'pro' || plan === 'enterprise'`);
  });

  it('runComplianceAssessment() posts to the real backend route with the real control keys', () => {
    const fn = dash.slice(dash.indexOf('async function runComplianceAssessment'), dash.indexOf('function renderComplianceResults'));
    expect(fn).toContain(`apiFetch('/api/scan/compliance'`);
    expect(fn).toContain('COMPLIANCE_CONTROL_KEYS');
  });

  it('renderComplianceResults() reads the real report field names, not placeholders', () => {
    const fn = dash.slice(dash.indexOf('function renderComplianceResults'), dash.indexOf('function renderCisoTrend'));
    expect(fn).toContain('data.executive_summary');
    expect(fn).toContain('data.iso27001_assessment');
    expect(fn).toContain('data.nist_csf_assessment');
    expect(fn).toContain('data.certification_roadmap');
  });

  it('the existing CISO Metrics tab is untouched by this fix', () => {
    expect(dash).toContain(`data-page="ciso" onclick="showPage('ciso',this);loadCisoMetrics()"`);
  });
});
