/**
 * CYBERDUDEBIVASH AI Security Hub — CISO Report Generator v23.0
 * Board-ready monthly/quarterly/executive security reports
 *
 * Routes:
 *   POST /api/revos/ciso-report/generate
 *   GET  /api/revos/ciso-report/list
 *   GET  /api/revos/ciso-report/:id
 */

import { queryComplianceResults, calculateMTTX, loadIncidents } from '../../handlers/cisoMetrics.js';

// ─── Generate CISO report data snapshot ──────────────────────────────────────
export async function generateCISOReport(db, kv, options = {}) {
  const { reportType = 'monthly', userId, clientId, period } = options;
  const reportPeriod = period || new Date().toISOString().slice(0, 7);

  try {
    // Gather all data in parallel
    const [threatStats, scanStats, latestMRRRow, mrrTrend, topCVEs, csSignals, complianceRows, incidents] = await Promise.all([
      // Threat landscape
      db?.prepare(`
        SELECT
          COUNT(*) as total,
          COUNT(CASE WHEN severity='CRITICAL' THEN 1 END) as critical,
          COUNT(CASE WHEN severity='HIGH' THEN 1 END) as high,
          COUNT(CASE WHEN actively_exploited=1 THEN 1 END) as exploited,
          AVG(COALESCE(cvss, cvss_score, 0)) as avg_cvss
        FROM threat_intel
        WHERE created_at > datetime('now','-30 days')
      `).first().catch(() => null),

      // Scan activity
      db?.prepare(`
        SELECT
          COUNT(*) as total_scans,
          COUNT(CASE WHEN risk_level='CRITICAL' THEN 1 END) as critical_scans,
          COUNT(CASE WHEN risk_level='HIGH' THEN 1 END) as high_scans,
          COUNT(DISTINCT target) as unique_targets
        FROM scan_jobs
        WHERE created_at > datetime('now','-30 days')
      `).first().catch(() => null),

      // MRR (for executive reports) — latest single snapshot row
      db?.prepare(`SELECT * FROM mrr_snapshots ORDER BY snapshot_date DESC LIMIT 1`).first().catch(() => null),

      // MRR trend
      db?.prepare(`
        SELECT snapshot_date, mrr_inr, churn_rate
        FROM mrr_snapshots
        ORDER BY snapshot_date DESC LIMIT 30
      `).all().catch(() => ({ results: [] })),

      // Top CVEs this period
      db?.prepare(`
        SELECT id, title, severity, cvss, exploit_status, known_ransomware
        FROM threat_intel
        WHERE severity IN ('CRITICAL','HIGH')
        ORDER BY COALESCE(cvss, cvss_score, 0) DESC LIMIT 10
      `).all().catch(() => ({ results: [] })),

      // CS signals (churn risks)
      db?.prepare(`
        SELECT signal_type, COUNT(*) as count
        FROM cs_signals WHERE resolved=0
        GROUP BY signal_type
      `).all().catch(() => ({ results: [] })),

      // Real compliance posture — same D1-authoritative compliance_results
      // source cisoMetrics.js uses. Previously never queried here at all;
      // compliance_status below was 5 hardcoded framework scores
      // (ALIGNED/COMPLIANT/90+) shown identically on every report.
      queryComplianceResults(db),

      // Real incident log for MTTD/MTTR — same per-user KV source
      // cisoMetrics.js reads. Only available when this report is for a
      // specific user; an MSSP clientId-only report has no incident log
      // keyed by clientId, so it honestly gets no MTTD/MTTR rather than a
      // guess.
      userId ? loadIncidents({ SECURITY_HUB_KV: kv }, userId) : Promise.resolve([]),
    ]);

    const now = new Date();
    const periodLabel = now.toLocaleString('en-IN', { month: 'long', year: 'numeric' });
    // Was wrongly aliased to `mrrData` (the MRR *trend* array from the query
    // below, `{results:[...]}`) instead of this single latest-snapshot row —
    // mrr_inr/churn_rate/nrr were reading undefined off the wrong shape on
    // every executive report.
    const latestMRR = latestMRRRow;
    const mttx = calculateMTTX(incidents);

    const report = {
      report_id:    `RPT-${Date.now().toString(36).toUpperCase()}`,
      type:         reportType,
      period:       reportPeriod,
      period_label: periodLabel,
      generated_at: now.toISOString(),
      generated_by: 'CYBERDUDEBIVASH MYTHOS AI Engine',

      executive_summary: buildExecutiveSummary(threatStats, scanStats, latestMRR, reportType, mttx),

      threat_landscape: {
        total_cves_tracked:    threatStats?.total || 0,
        critical:              threatStats?.critical || 0,
        high:                  threatStats?.high || 0,
        actively_exploited:    threatStats?.exploited || 0,
        avg_cvss:              Math.round((threatStats?.avg_cvss || 0) * 10) / 10,
        threat_level:          getThreatLevel(threatStats),
        top_cves:              topCVEs.results || [],
        key_findings: [
          `${threatStats?.critical || 0} CRITICAL vulnerabilities tracked with active exploitation`,
          `${threatStats?.exploited || 0} CVEs confirmed exploited in the wild`,
          `Average CVSS score: ${Math.round((threatStats?.avg_cvss || 0) * 10) / 10}/10`,
          'APT groups actively targeting BFSI and healthcare sectors',
        ],
      },

      security_operations: {
        total_scans:     scanStats?.total_scans || 0,
        critical_scans:  scanStats?.critical_scans || 0,
        high_risk_scans: scanStats?.high_scans || 0,
        unique_targets:  scanStats?.unique_targets || 0,
        mttd_hours:      mttx.mttd_hours,     // real, from incident log — null if no incidents on file (was hardcoded 2.3)
        mttr_hours:      mttx.mttr_hours,     // real, from incident log — null if no resolved incidents (was hardcoded 18.5)
        rules_generated: 0,
        incidents_resolved: incidents.filter(i => i.status === 'RESOLVED').length,
        sla_compliance_pct: null,   // no SLA-incident tracking data source yet — honest null, not a fabricated 98.5
      },

      revenue_metrics: reportType === 'executive' ? {
        mrr_inr:         latestMRR?.mrr_inr || 0,
        arr_inr:         (latestMRR?.mrr_inr || 0) * 12,
        active_subs:     latestMRR?.active_subs || 0,
        churn_rate:      latestMRR?.churn_rate || 0,
        nrr:             latestMRR?.nrr || 100,
        mrr_trend:       (mrrTrend?.results || []).slice(0, 12).reverse(),
      } : null,

      // Real D1 compliance_results data (same source cisoMetrics.js uses) —
      // NO_DATA/null per framework, not a fabricated ALIGNED/COMPLIANT score,
      // when this org/client has no assessment on file for it yet.
      compliance_status: buildComplianceStatusSection(complianceRows),

      recommendations: buildRecommendations(threatStats, scanStats, latestMRR),

      branding: {
        platform:  'CYBERDUDEBIVASH AI Security Hub',
        version:   '23.0.0',
        contact:   'contact@cyberdudebivash.in',
        phone:     '+91 8179881447',
        company:   'CYBERDUDEBIVASH PRIVATE LIMITED',
        gst:       '21ARKPN8270G1ZP',
      },
    };

    // Save to D1
    if (db) {
      const reportId = report.report_id;
      await db.prepare(`
        INSERT INTO ciso_reports (id, user_id, client_id, report_type, period, status, data_snapshot)
        VALUES (?, ?, ?, ?, ?, 'ready', ?)
      `).bind(
        reportId, userId || null, clientId || null,
        reportType, reportPeriod,
        JSON.stringify(report).slice(0, 50000), // D1 text limit safety
      ).run().catch(() => {});
    }

    return { success: true, report };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─── Map real compliance_results rows onto the report's 5 known frameworks ────
// Preserves the original object shape (iso_27001/soc2/gdpr/dpdp_2023/pci_dss
// keys) so existing consumers of this report don't break — but each value is
// now real (matched by framework name) or an honest NO_DATA/null sentinel,
// never a fabricated score.
const FRAMEWORK_KEY_MATCHERS = [
  { key: 'iso_27001', test: f => /iso\s*27001/i.test(f || '') },
  { key: 'soc2',      test: f => /soc\s*2/i.test(f || '') },
  { key: 'gdpr',      test: f => /gdpr/i.test(f || '') },
  { key: 'dpdp_2023', test: f => /dpdp/i.test(f || '') },
  { key: 'pci_dss',   test: f => /pci/i.test(f || '') },
];

function buildComplianceStatusSection(rows) {
  const out = {};
  for (const { key } of FRAMEWORK_KEY_MATCHERS) out[key] = { status: 'NO_DATA', score: null, gaps: null };
  for (const row of rows || []) {
    const match = FRAMEWORK_KEY_MATCHERS.find(m => m.test(row.framework));
    if (match) out[match.key] = { status: row.status, score: Math.round(row.compliance_pct), gaps: row.open_gaps };
  }
  return out;
}

// ─── Build executive summary ──────────────────────────────────────────────────
function buildExecutiveSummary(threats, scans, mrr, type, mttx) {
  const threatLevel = getThreatLevel(threats);
  const lines = [
    `**Threat Level: ${threatLevel}** — ${threats?.critical || 0} critical CVEs tracked this period`,
    `${scans?.total_scans || 0} security scans performed across ${scans?.unique_targets || 0} unique targets`,
    `${threats?.exploited || 0} vulnerabilities confirmed exploited in the wild — immediate patching required`,
  ];

  if (type === 'executive' && mrr?.mrr_inr) {
    lines.push(`Platform MRR: ₹${mrr.mrr_inr.toLocaleString('en-IN')} | ARR: ₹${(mrr.mrr_inr * 12).toLocaleString('en-IN')}`);
    lines.push(`Churn rate: ${mrr.churn_rate || 0}% | NRR: ${mrr.nrr || 100}%`);
  }

  // Real MTTD/MTTR from this user's incident log — omitted (not fabricated as
  // a fixed 2.3h/18.5h) when there's no incident history yet to compute them from.
  if (mttx && (mttx.mttd_hours != null || mttx.mttr_hours != null)) {
    lines.push(`MTTD: ${mttx.mttd_hours ?? '—'} hours (industry avg: ${mttx.industry_mttd_hours} hours) | MTTR: ${mttx.mttr_hours ?? '—'} hours`);
  }

  return lines.join('\n\n');
}

// ─── Build actionable recommendations ────────────────────────────────────────
function buildRecommendations(threats, scans, mrr) {
  const recs = [];

  if ((threats?.critical || 0) > 5) {
    recs.push({
      priority: 'CRITICAL',
      title: 'Immediate patch cycle required',
      detail: `${threats.critical} critical CVEs tracked — initiate emergency patch cycle within 24 hours`,
      effort: 'HIGH', impact: 'HIGH',
    });
  }

  if ((threats?.exploited || 0) > 3) {
    recs.push({
      priority: 'HIGH',
      title: 'Deploy KEV detection rules',
      detail: `${threats.exploited} CVEs in active exploitation — deploy SIGMA/YARA rules immediately`,
      effort: 'LOW', impact: 'HIGH',
    });
  }

  if ((scans?.critical_scans || 0) > 0) {
    recs.push({
      priority: 'HIGH',
      title: 'Remediate critical scan findings',
      detail: `${scans.critical_scans} scans returned CRITICAL risk — schedule remediation sprint`,
      effort: 'MEDIUM', impact: 'HIGH',
    });
  }

  recs.push({
    priority: 'MEDIUM',
    title: 'MFA enforcement review',
    detail: 'Ensure MFA is enforced across all privileged accounts — focus on admin and API access',
    effort: 'LOW', impact: 'HIGH',
  });

  return recs;
}

function getThreatLevel(threats) {
  const critical = threats?.critical || 0;
  const exploited = threats?.exploited || 0;
  if (critical > 10 || exploited > 5) return 'CRITICAL';
  if (critical > 5 || exploited > 2) return 'HIGH';
  if (critical > 2) return 'ELEVATED';
  return 'MODERATE';
}
