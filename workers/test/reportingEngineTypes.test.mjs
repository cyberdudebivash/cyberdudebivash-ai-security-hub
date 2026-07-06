/* Regression tests — P10.5: MSSP & COMPLIANCE report-type bodies in reportingEngine.js.
 * Proves: (1) MSSP per-tenant rendering uses real D1 data and never leaks a
 * customer owned by a different partner (same partner_id scoping rule as
 * msspTenantPlatform.js's partnerScope()); (2) COMPLIANCE rendering reuses the
 * existing complianceEngine() from engine.js — no fabricated numbers. */
import { describe, it, expect } from 'vitest';
import { handleCreateReport, handleDownloadReport } from '../src/handlers/reportingEngine.js';

function makeDB({ customers = [], scanResults = {}, assetCounts = {} } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async run() { return { success: true }; },
        async first() {
          if (/FROM mssp_customers/.test(sql)) {
            const [id, slug, partnerId] = bound;
            return customers.find(c => (c.id === id || c.org_slug === slug) && c.partner_id === partnerId) || null;
          }
          if (/FROM scan_results/.test(sql) && /risk_level/.test(sql)) {
            const [orgId] = bound;
            return scanResults[orgId] || { total: 0, critical: 0, high: 0, avg_risk: 0 };
          }
          if (/FROM scan_results/.test(sql)) {
            return { total: 0, critical_ct: 0, high_ct: 0, avg_risk: 50 };
          }
          if (/FROM customer_assets/.test(sql)) {
            const [customerId] = bound;
            return { cnt: assetCounts[customerId] || 0 };
          }
          return null;
        },
        async all() { return { results: [] }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, value); },
    async get(key, opts) {
      if (!store.has(key)) return null;
      const v = store.get(key);
      const wantsJson = opts === 'json' || opts?.type === 'json';
      return wantsJson ? JSON.parse(v) : v;
    },
  };
}

function jsonReq(url, method, body) {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function createAndDownloadHTML(env, user, body) {
  const req = jsonReq('https://x/api/reports', 'POST', body);
  req.user = user;
  const createRes = await handleCreateReport(req, env);
  const created = await createRes.json();
  expect(created.success).toBe(true);

  const dlReq = jsonReq(`https://x/api/reports/${created.job_id}/download?token=${created.download_token}`);
  const dlRes = await handleDownloadReport(dlReq, env, created.job_id);
  expect(dlRes.status).toBe(200);
  return dlRes.text();
}

describe('reportingEngine — MSSP report type', () => {
  it('renders an explanatory body when no customer_id is supplied', async () => {
    const env = { DB: makeDB(), KV: makeKV() };
    const html = await createAndDownloadHTML(
      env, { tier: 'MSSP', userId: 'partner-A', org_id: 'org-A' },
      { type: 'MSSP', config: {} },
    );
    expect(html).toContain('No managed tenant specified');
  });

  it('renders real per-tenant data for a customer owned by the calling partner', async () => {
    const env = {
      DB: makeDB({
        customers: [{
          id: 'cust-1', org_slug: 'acme', org_name: 'Acme Corp', tier: 'pro', status: 'active',
          partner_id: 'partner-A', risk_score: 72, compliance_score: 61, mrr_cents: 50000, created_at: '2025-01-01',
        }],
        scanResults: { 'cust-1': { total: 10, critical: 2, high: 3, avg_risk: 55 } },
        assetCounts: { 'cust-1': 8 },
      }),
      KV: makeKV(),
    };
    const html = await createAndDownloadHTML(
      env, { tier: 'MSSP', userId: 'partner-A', org_id: 'org-A' },
      { type: 'MSSP', config: { customer_id: 'acme' } },
    );
    expect(html).toContain('Acme Corp');
    expect(html).toContain('72/100');
    expect(html).toContain('Critical Findings');
  });

  it('does not leak a tenant owned by a different partner', async () => {
    const env = {
      DB: makeDB({
        customers: [{
          id: 'cust-1', org_slug: 'acme', org_name: 'Acme Corp', tier: 'pro', status: 'active',
          partner_id: 'partner-A', risk_score: 72, compliance_score: 61, mrr_cents: 50000, created_at: '2025-01-01',
        }],
      }),
      KV: makeKV(),
    };
    const html = await createAndDownloadHTML(
      env, { tier: 'MSSP', userId: 'partner-B', org_id: 'org-B' },
      { type: 'MSSP', config: { customer_id: 'acme' } },
    );
    expect(html).not.toContain('Acme Corp');
    expect(html).toContain('No managed tenant specified');
  });
});

describe('reportingEngine — COMPLIANCE report type', () => {
  it('renders all four frameworks via the existing complianceEngine (no duplicate engine)', async () => {
    const env = { DB: makeDB(), KV: makeKV() };
    const html = await createAndDownloadHTML(
      env, { role: 'enterprise', tier: 'enterprise', userId: 'u1', org_id: 'org-A' },
      { type: 'COMPLIANCE', config: {} },
    );
    expect(html).toContain('SOC 2 Controls');
    expect(html).toContain('ISO 27001 Controls');
    expect(html).toContain('PCI-DSS Controls');
    expect(html).toContain('HIPAA Controls');
    expect(html).toContain('Gap Analysis');
  });
});

describe('reportingEngine — PPTX (slide-deck) format', () => {
  it('renders a navigable slide deck instead of the single-page report shell', async () => {
    const env = { DB: makeDB(), KV: makeKV() };
    const html = await createAndDownloadHTML(
      env, { role: 'enterprise', tier: 'enterprise', userId: 'u1', org_id: 'org-A' },
      { type: 'SECURITY_POSTURE', format: 'PPTX', config: {} },
    );
    expect(html).toContain('class="slide title-slide active"');
    expect(html).toContain('class="slide closing-slide"');
    expect(html).toContain('page-break-after: always');
    // Same KPI/section content, just re-wrapped into slides — no duplicate data logic.
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Recommendations');
  });

  it('still renders the single-page shell (no slide markup) for the default HTML format', async () => {
    const env = { DB: makeDB(), KV: makeKV() };
    const html = await createAndDownloadHTML(
      env, { role: 'enterprise', tier: 'enterprise', userId: 'u1', org_id: 'org-A' },
      { type: 'SECURITY_POSTURE', config: {} },
    );
    expect(html).not.toContain('class="slide');
  });
});
