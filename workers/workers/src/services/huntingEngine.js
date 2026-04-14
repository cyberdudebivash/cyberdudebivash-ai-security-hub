/**
 * CYBERDUDEBIVASH AI Security Hub — AI Threat Hunting Engine v1.0
 * Sentinel APEX Phase 5: Autonomous Anomaly Detection & Pattern Analysis
 *
 * Detects:
 *   - Clustered exploitation (multiple high CVEs targeting same vendor)
 *   - Exploit surge (CVSS distribution spike in recent window)
 *   - Ransomware campaign correlation (KEV + ransomware tag clusters)
 *   - Supply chain risk (CI/CD, npm, pypi, package manager CVEs)
 *   - Zero-day cluster (multiple 0-days in same timeframe)
 *   - EPSS anomaly (sudden score spike = imminent exploitation)
 *   - Repeated IOC patterns (same IP/domain across multiple CVEs)
 *   - High-risk CWE combinations (e.g., RCE + auth bypass on same product)
 *
 * Output: { alerts: [...], risk_posture, hunting_summary }
 */

// ─── Parse helpers ────────────────────────────────────────────────────────────
function parseTags(entry) {
  try { return JSON.parse(entry.tags || '[]'); } catch { return []; }
}
function parseWeakness(entry) {
  try { return JSON.parse(entry.weakness_types || '[]'); } catch { return []; }
}
function parseIOCs(entry) {
  try {
    const v = entry.ioc_list;
    return Array.isArray(v) ? v : JSON.parse(v || '[]');
  } catch { return []; }
}

// ─── Vendor extractor ─────────────────────────────────────────────────────────
const VENDOR_PATTERNS = [
  ['palo alto', 'panos', 'pan-os'],
  ['fortinet', 'fortigate', 'fortios'],
  ['cisco', 'ios xe', 'asa'],
  ['microsoft', 'windows', 'exchange', 'azure'],
  ['ivanti', 'pulse', 'mobileiron'],
  ['citrix', 'netscaler'],
  ['apache', 'log4j'],
  ['vmware', 'vcenter', 'esxi'],
  ['connectwise', 'screenconnect'],
  ['jetbrains', 'teamcity'],
];

function extractVendor(entry) {
  const text = `${entry.title} ${entry.description || ''}`.toLowerCase();
  for (const group of VENDOR_PATTERNS) {
    if (group.some(k => text.includes(k))) return group[0];
  }
  return null;
}

// ─── Alert factory ─────────────────────────────────────────────────────────────
function makeAlert(type, severity, message, evidence = {}) {
  return {
    id:        `hunt_${type}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    type,
    severity,
    message,
    evidence,
    detected_at: new Date().toISOString(),
  };
}

// ─── Detection 1: Vendor clustering ──────────────────────────────────────────
function detectVendorClusters(entries) {
  const vendorMap = {};

  for (const e of entries) {
    const vendor = extractVendor(e);
    if (!vendor) continue;
    if (!vendorMap[vendor]) vendorMap[vendor] = [];
    vendorMap[vendor].push(e);
  }

  const alerts = [];

  for (const [vendor, cves] of Object.entries(vendorMap)) {
    const criticals = cves.filter(e => e.severity === 'CRITICAL' || e.cvss >= 9.0);
    const exploited = cves.filter(e => e.exploit_status === 'confirmed');

    if (criticals.length >= 3) {
      alerts.push(makeAlert(
        'clustered_exploitation',
        criticals.length >= 5 ? 'critical' : 'high',
        `${criticals.length} CRITICAL/9.0+ CVEs targeting ${vendor} — likely active exploitation campaign`,
        {
          vendor,
          cve_count:    criticals.length,
          exploited:    exploited.length,
          cve_ids:      criticals.slice(0, 5).map(e => e.id),
          avg_cvss:     +(criticals.reduce((s, e) => s + (e.cvss || 0), 0) / criticals.length).toFixed(1),
        }
      ));
    }

    if (exploited.length >= 2) {
      alerts.push(makeAlert(
        'multi_exploit_vendor',
        'high',
        `${exploited.length} actively exploited CVEs confirmed for ${vendor} — immediate patching required`,
        {
          vendor,
          exploited_cves: exploited.slice(0, 5).map(e => e.id),
        }
      ));
    }
  }

  return alerts;
}

// ─── Detection 2: Ransomware campaign cluster ─────────────────────────────────
function detectRansomwareCampaign(entries) {
  const ransomware = entries.filter(e => {
    const tags = parseTags(e);
    return e.known_ransomware || tags.some(t =>
      ['Ransomware', 'ransomware', 'RansomwareLinked'].includes(t)
    );
  });

  if (ransomware.length < 2) return [];

  const alerts = [];

  if (ransomware.length >= 3) {
    alerts.push(makeAlert(
      'ransomware_campaign',
      'critical',
      `${ransomware.length} ransomware-linked CVEs detected — active campaign indicators present`,
      {
        count:   ransomware.length,
        cve_ids: ransomware.slice(0, 6).map(e => e.id),
        highest_cvss: Math.max(...ransomware.map(e => e.cvss || 0)),
      }
    ));
  }

  return alerts;
}

// ─── Detection 3: Zero-day cluster ───────────────────────────────────────────
function detectZeroDayCluster(entries) {
  const zeroDays = entries.filter(e => {
    const tags = parseTags(e);
    return tags.some(t => ['ZeroDay', '0day', 'zero-day'].includes(t)) ||
           (e.exploit_status === 'confirmed' && e.cvss >= 9.0);
  });

  if (zeroDays.length < 2) return [];

  return [makeAlert(
    'zero_day_cluster',
    zeroDays.length >= 4 ? 'critical' : 'high',
    `${zeroDays.length} zero-day or confirmed-exploit CVEs detected in current feed — elevated risk posture`,
    {
      count:       zeroDays.length,
      cve_ids:     zeroDays.slice(0, 6).map(e => e.id),
      avg_cvss:    +(zeroDays.reduce((s, e) => s + (e.cvss || 0), 0) / zeroDays.length).toFixed(1),
    }
  )];
}

// ─── Detection 4: Supply chain risk ──────────────────────────────────────────
function detectSupplyChainRisk(entries) {
  const supplyChainKw = ['supply chain', 'ci/cd', 'npm', 'pypi', 'github', 'bitbucket', 'artifactory',
                         'jenkins', 'teamcity', 'sonarqube', 'maven', 'gradle', 'composer'];
  const scEntries = entries.filter(e => {
    const text = `${e.title} ${e.description || ''}`.toLowerCase();
    const tags  = parseTags(e).map(t => t.toLowerCase());
    return supplyChainKw.some(k => text.includes(k) || tags.includes(k));
  });

  if (scEntries.length === 0) return [];

  return [makeAlert(
    'supply_chain_risk',
    scEntries.length >= 3 ? 'high' : 'medium',
    `${scEntries.length} CVEs target software supply chain components — code pipeline integrity at risk`,
    {
      count:   scEntries.length,
      cve_ids: scEntries.slice(0, 5).map(e => e.id),
      targets: scEntries.slice(0, 3).map(e => e.title),
    }
  )];
}

// ─── Detection 5: EPSS anomaly (high probability, not yet confirmed) ──────────
function detectEPSSAnomalies(entries) {
  const highEPSS = entries.filter(e => (e.epss_score || 0) >= 0.7 && e.exploit_status !== 'confirmed');

  if (highEPSS.length === 0) return [];

  return [makeAlert(
    'epss_high_risk',
    highEPSS.length >= 3 ? 'high' : 'medium',
    `${highEPSS.length} CVEs with EPSS ≥ 0.70 (imminent exploitation predicted) — not yet confirmed exploited`,
    {
      count:         highEPSS.length,
      cve_ids:       highEPSS.slice(0, 5).map(e => e.id),
      max_epss:      Math.max(...highEPSS.map(e => e.epss_score || 0)).toFixed(3),
      avg_cvss:      +(highEPSS.reduce((s, e) => s + (e.cvss || 0), 0) / highEPSS.length).toFixed(1),
    }
  )];
}

// ─── Detection 6: Dangerous CWE combinations on same product ─────────────────
function detectDangerousCWECombinations(entries) {
  const RCE_CWES  = ['CWE-77', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-787'];
  const AUTH_CWES = ['CWE-287', 'CWE-288', 'CWE-306', 'CWE-798'];

  const vendorRCE  = {};
  const vendorAuth = {};

  for (const e of entries) {
    const vendor    = extractVendor(e);
    const weakness  = parseWeakness(e);
    if (!vendor) continue;

    if (weakness.some(w => RCE_CWES.includes(w)))  vendorRCE[vendor]  = [...(vendorRCE[vendor]  || []), e.id];
    if (weakness.some(w => AUTH_CWES.includes(w))) vendorAuth[vendor] = [...(vendorAuth[vendor] || []), e.id];
  }

  const alerts = [];

  for (const vendor of Object.keys(vendorRCE)) {
    if (vendorAuth[vendor]) {
      alerts.push(makeAlert(
        'rce_plus_auth_bypass',
        'critical',
        `RCE + Auth Bypass CVEs detected for same vendor (${vendor}) — maximum exploitation risk (unauthenticated RCE possible)`,
        {
          vendor,
          rce_cves:  vendorRCE[vendor].slice(0, 3),
          auth_cves: vendorAuth[vendor].slice(0, 3),
        }
      ));
    }
  }

  return alerts;
}

// ─── Detection 7: IOC repetition (same IP/domain across multiple CVEs) ────────
function detectRepeatedIOCs(entries) {
  const iocCVEMap = {};

  for (const entry of entries) {
    const iocs = parseIOCs(entry);
    for (const ioc of iocs) {
      const val = typeof ioc === 'string' ? ioc : (ioc.value || '');
      if (!val) continue;
      if (!iocCVEMap[val]) iocCVEMap[val] = [];
      iocCVEMap[val].push(entry.id);
    }
  }

  const repeated = Object.entries(iocCVEMap)
    .filter(([, cves]) => cves.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 10);

  if (repeated.length === 0) return [];

  return [makeAlert(
    'repeated_ioc',
    repeated.some(([, cves]) => cves.length >= 3) ? 'high' : 'medium',
    `${repeated.length} IOCs appear across multiple CVEs — indicates shared C2 or exploitation infrastructure`,
    {
      repeated_iocs: repeated.slice(0, 5).map(([ioc, cves]) => ({ ioc, cve_count: cves.length, cves: cves.slice(0, 3) })),
    }
  )];
}

// ─── Detection 8: CVSS spike (many new high-score CVEs in feed) ───────────────
function detectCVSSSurge(entries) {
  const critical = entries.filter(e => (e.cvss || 0) >= 9.0);
  const ratio    = entries.length > 0 ? critical.length / entries.length : 0;

  if (ratio < 0.4 || critical.length < 5) return [];

  return [makeAlert(
    'cvss_surge',
    ratio >= 0.6 ? 'critical' : 'high',
    `${(ratio * 100).toFixed(0)}% of current feed is CVSS 9.0+ (${critical.length}/${entries.length} entries) — feed reflects an active threat surge`,
    {
      critical_count: critical.length,
      total:          entries.length,
      ratio:          ratio.toFixed(2),
      avg_cvss:       +(critical.reduce((s, e) => s + (e.cvss || 0), 0) / critical.length).toFixed(1),
    }
  )];
}

// ─── Risk posture score (0-100) ───────────────────────────────────────────────
function computeRiskPosture(entries, alerts) {
  if (entries.length === 0) return { score: 0, level: 'UNKNOWN' };

  const criticals     = entries.filter(e => e.severity === 'CRITICAL' || e.cvss >= 9.0).length;
  const exploited     = entries.filter(e => e.exploit_status === 'confirmed').length;
  const ransomware    = entries.filter(e => e.known_ransomware).length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const highAlerts     = alerts.filter(a => a.severity === 'high').length;

  const base = Math.min(100,
    (criticals  / Math.max(entries.length, 1)) * 30 +
    (exploited  / Math.max(entries.length, 1)) * 35 +
    (ransomware / Math.max(entries.length, 1)) * 20 +
    criticalAlerts * 4 +
    highAlerts     * 2
  );

  const score = Math.round(base);
  const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';

  return { score, level };
}

// ─── Master hunting function ──────────────────────────────────────────────────
export function runHunting(entries = []) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      alerts:          [],
      risk_posture:    { score: 0, level: 'UNKNOWN' },
      hunting_summary: { total_alerts: 0, by_severity: {}, by_type: {} },
      hunted_at:       new Date().toISOString(),
    };
  }

  const alerts = [
    ...detectVendorClusters(entries),
    ...detectRansomwareCampaign(entries),
    ...detectZeroDayCluster(entries),
    ...detectSupplyChainRisk(entries),
    ...detectEPSSAnomalies(entries),
    ...detectDangerousCWECombinations(entries),
    ...detectRepeatedIOCs(entries),
    ...detectCVSSSurge(entries),
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });

  const riskPosture = computeRiskPosture(entries, alerts);

  const bySeverity = {};
  const byType     = {};
  for (const alert of alerts) {
    bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
    byType[alert.type]         = (byType[alert.type]         || 0) + 1;
  }

  return {
    alerts,
    risk_posture: riskPosture,
    hunting_summary: {
      total_alerts: alerts.length,
      by_severity:  bySeverity,
      by_type:      byType,
    },
    hunted_at: new Date().toISOString(),
  };
}

// ─── Filter alerts by severity threshold ──────────────────────────────────────
export function getAlertsBySeverity(huntResults, minSeverity = 'high') {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const min   = order[minSeverity] ?? 1;
  return (huntResults.alerts || []).filter(a => (order[a.severity] ?? 4) <= min);
}

// ─── Quick single check: should this entry trigger a hunt alert? ──────────────
export function shouldAlertEntry(entry) {
  const isCritical = (entry.cvss || 0) >= 9.0 || entry.severity === 'CRITICAL';
  const isExploited = entry.exploit_status === 'confirmed';
  const isKEV       = !!entry.known_ransomware;
  const isHighEPSS  = (entry.epss_score || 0) >= 0.7;

  return isCritical && (isExploited || isKEV || isHighEPSS);
}
