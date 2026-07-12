/* Regression test — handleExecutiveRiskBrief/handleExecutiveDashboard in
 * executiveRiskHandlers.js folded 2 undisclosed hardcoded constants
 * (compliance_posture: 45, ai_security: 65) into the composite enterprise
 * risk score shown to paying ENTERPRISE customers, identically for every
 * org, with no indication they were placeholders. `trend`/`risk_trend` were
 * also always 'STABLE' with no historical data behind that claim.
 *
 * Proves: both drivers are now real D1-derived values (compliance from the
 * same compliance_results source cisoMetrics.js uses; AI security from this
 * org's own registered ai_assets), or honestly `null` — excluded from the
 * composite average, not defaulted to a fabricated number — when the org
 * has no assessment/no registered assets on file yet. trend is `null`, not
 * a fabricated 'STABLE'.
 */
import { describe, it, expect } from 'vitest';
import { handleExecutiveRiskBrief, handleExecutiveDashboard } from '../src/handlers/executiveRiskHandlers.js';

function makeDB({ complianceRows = [], aiAssetRow = null } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async all() {
          if (/FROM compliance_results/.test(sql)) return { results: complianceRows };
          return { results: [] };
        },
        async first() {
          if (/FROM ai_assets WHERE org_id/.test(sql)) return aiAssetRow;
          // Every other KPI query in fetchPlatformKPIs/fetchCVEKPIs reads with
          // `|| 0` fallbacks — an empty object is a safe, neutral default.
          return {};
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  return { async get() { return null; }, async put() {} };
}

function makeEnv(dbOpts) {
  return { DB: makeDB(dbOpts), SECURITY_HUB_KV: makeKV() };
}

function jsonReq(path, body = {}) {
  return new Request(`https://hub.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const ENTERPRISE_CTX = { authenticated: true, tier: 'ENTERPRISE', userId: 'org_real_data', isAdmin: false };

describe('handleExecutiveRiskBrief — risk driver honesty', () => {
  it('computes real compliance_posture/ai_security from D1 — not the old hardcoded 45/65', async () => {
    const env = makeEnv({
      complianceRows: [{ framework: 'ISO 27001', controls_met: 50, controls_total: 100, status: 'IN_PROGRESS', trend: '0', gap_details: null }],
      aiAssetRow: { avg_score: 80, cnt: 3 },
    });
    const res  = await handleExecutiveRiskBrief(jsonReq('/api/executive/risk-brief', { organization: 'Acme' }), env, ENTERPRISE_CTX);
    const body = await res.json();

    // coverage 50% -> risk 100-50=50 (was hardcoded 45)
    expect(body.risk_snapshot.drivers.compliance_posture).toBe(50);
    // avg security score 80 -> risk 100-80=20 (was hardcoded 65)
    expect(body.risk_snapshot.drivers.ai_security).toBe(20);
    expect(body.risk_snapshot.driver_data_coverage).toContain('5/5');
    // trend was previously always the string 'STABLE' with no data behind it
    expect(body.risk_snapshot.trend).toBeNull();
  });

  it('honestly returns null (not a fabricated number) when the org has no compliance assessment or registered AI assets', async () => {
    const env = makeEnv({ complianceRows: [], aiAssetRow: { avg_score: null, cnt: 0 } });
    const res  = await handleExecutiveRiskBrief(jsonReq('/api/executive/risk-brief', { organization: 'Acme' }), env, ENTERPRISE_CTX);
    const body = await res.json();

    expect(body.risk_snapshot.drivers.compliance_posture).toBeNull();
    expect(body.risk_snapshot.drivers.ai_security).toBeNull();
    expect(body.risk_snapshot.driver_data_coverage).toContain('3/5');
    // composite score must still be a real number, averaged over the 3 real signals only
    expect(typeof body.risk_snapshot.composite_risk_score).toBe('number');
  });

  it('the board-ready HTML brief shows "No data yet" instead of a fabricated score', async () => {
    const env = makeEnv({ complianceRows: [], aiAssetRow: null });
    const res  = await handleExecutiveRiskBrief(
      jsonReq('/api/executive/risk-brief', { organization: 'Acme', format: 'html' }),
      env, ENTERPRISE_CTX,
    );
    const html = await res.text();
    expect(html).toContain('No data yet');
    expect(html).not.toContain('45/100');
    expect(html).not.toContain('65/100');
  });
});

describe('handleExecutiveDashboard — risk_trend honesty', () => {
  it('risk_trend is null, not a fabricated "STABLE"', async () => {
    const env = makeEnv({});
    const req = new Request('https://hub.test/api/executive/dashboard');
    const res  = await handleExecutiveDashboard(req, env, ENTERPRISE_CTX);
    const body = await res.json();
    expect(body.security_kpis.risk_trend).toBeNull();
  });
});
