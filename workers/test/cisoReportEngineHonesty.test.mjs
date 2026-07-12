/* Regression test — generateCISOReport in services/revos/cisoReportEngine.js
 * shipped 5 hardcoded framework compliance scores (ALIGNED/COMPLIANT/90+ for
 * every org, never querying the real compliance_results table cisoMetrics.js
 * uses elsewhere), hardcoded mttd_hours/mttr_hours/sla_compliance_pct, an
 * unconditional invented "61% of scanned targets lack DNSSEC" recommendation,
 * and a variable-aliasing bug that made revenue_metrics.mrr_inr always read
 * undefined (defaulting to 0) on every executive report.
 *
 * Proves: compliance_status is real D1 data (or an honest NO_DATA sentinel
 * per framework), MTTD/MTTR are computed from the same per-user incident log
 * cisoMetrics.js reads (or null with no fabricated fallback), sla_compliance_pct
 * is honestly null, the DNSSEC line is gone, and revenue_metrics reads the
 * correct latest-snapshot row. */
import { describe, it, expect } from 'vitest';
import { generateCISOReport } from '../src/services/revos/cisoReportEngine.js';

function makeDB({ complianceRows = [], latestMRRRow = null, mrrTrendRows = [] } = {}) {
  return {
    prepare(sql) {
      const stmt = {
        bind(...args) { return stmt; },
        async first() {
          if (/FROM mrr_snapshots ORDER BY snapshot_date DESC LIMIT 1/.test(sql)) return latestMRRRow;
          if (/FROM threat_intel/.test(sql)) return { total: 0, critical: 0, high: 0, exploited: 0, avg_cvss: 0 };
          if (/FROM scan_jobs/.test(sql))    return { total_scans: 0, critical_scans: 0, high_scans: 0, unique_targets: 0 };
          return null;
        },
        async all() {
          if (/FROM compliance_results/.test(sql)) return { results: complianceRows };
          if (/FROM mrr_snapshots/.test(sql))       return { results: mrrTrendRows };
          return { results: [] };
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV(seed = {}) {
  const store = new Map(Object.entries(seed).map(([k, v]) => [k, JSON.stringify(v)]));
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const v = store.get(key);
      return (opts === 'json' || opts?.type === 'json') ? JSON.parse(v) : v;
    },
    async put(key, val) { store.set(key, val); },
  };
}

describe('generateCISOReport — compliance/MTTD/MTTR/SLA honesty', () => {
  it('compliance_status is real D1 data for matched frameworks, NO_DATA sentinel for the rest — not hardcoded ALIGNED/COMPLIANT scores', async () => {
    const db = makeDB({
      complianceRows: [{ framework: 'SOC 2', controls_met: 40, controls_total: 61, status: 'IN_PROGRESS', trend: '0', gap_details: null }],
    });
    const { report } = await generateCISOReport(db, makeKV(), { reportType: 'monthly' });

    // 40/61 = 65.57% -> toFixed(1)=65.6 -> Math.round=66 (was hardcoded 85/ALIGNED)
    expect(report.compliance_status.soc2).toEqual({ status: 'IN_PROGRESS', score: 66, gaps: 0 });
    // No ISO 27001 row on file -> honest NO_DATA, not a fabricated 72/IN_PROGRESS
    expect(report.compliance_status.iso_27001).toEqual({ status: 'NO_DATA', score: null, gaps: null });
  });

  it('mttd_hours/mttr_hours are computed from the real incident log, not hardcoded 2.3/18.5', async () => {
    const incidents = [{
      id: 'INC-1', status: 'RESOLVED',
      created_at:  '2026-01-01T00:00:00.000Z',
      detected_at: '2026-01-01T05:00:00.000Z',   // 5h detect
      resolved_at: '2026-01-01T15:00:00.000Z',   // +10h respond
    }];
    const db = makeDB({});
    const kv = makeKV({ 'ciso:incidents:u_test': incidents });
    const { report } = await generateCISOReport(db, kv, { reportType: 'monthly', userId: 'u_test' });

    expect(report.security_operations.mttd_hours).toBe(5);
    expect(report.security_operations.mttr_hours).toBe(10);
    expect(report.security_operations.incidents_resolved).toBe(1);
    expect(report.executive_summary).toContain('MTTD: 5 hours');
  });

  it('mttd_hours/mttr_hours/sla_compliance_pct are honestly null (not fabricated) with no incident data', async () => {
    const db = makeDB({});
    const { report } = await generateCISOReport(db, makeKV(), { reportType: 'monthly' });

    expect(report.security_operations.mttd_hours).toBeNull();
    expect(report.security_operations.mttr_hours).toBeNull();
    expect(report.security_operations.sla_compliance_pct).toBeNull();
    expect(report.executive_summary).not.toContain('MTTD: 2.3');
    expect(report.executive_summary).not.toContain('98.5%');
  });

  it('no longer injects the unconditional fabricated "61% lack DNSSEC" recommendation', async () => {
    const db = makeDB({});
    const { report } = await generateCISOReport(db, makeKV(), { reportType: 'monthly' });
    const detail = JSON.stringify(report.recommendations);
    expect(detail).not.toContain('DNSSEC');
    expect(detail).not.toContain('61%');
  });

  it('revenue_metrics reads the correct latest-snapshot row (was aliased to the trend array, always reading undefined)', async () => {
    const db = makeDB({
      latestMRRRow: { mrr_inr: 500000, active_subs: 42, churn_rate: 2.1, nrr: 105 },
      mrrTrendRows: [{ snapshot_date: '2026-07-01', mrr_inr: 500000, churn_rate: 2.1 }],
    });
    const { report } = await generateCISOReport(db, makeKV(), { reportType: 'executive' });

    expect(report.revenue_metrics.mrr_inr).toBe(500000);
    expect(report.revenue_metrics.arr_inr).toBe(6000000);
    expect(report.revenue_metrics.active_subs).toBe(42);
    expect(report.revenue_metrics.mrr_trend.length).toBe(1);
  });
});
